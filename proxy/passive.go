package proxy

import (
	"errors"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"goproxy/config"
	"goproxy/storage"
)

// nodeStat holds in-memory passive health for one upstream address.
// Only a few dozen bytes per node, no SQLite writes on the hot path.
type nodeStat struct {
	consecEarly int       // consecutive early-close demerits
	ejectCount  int       // times ejected (for exponential backoff)
	clientAbort int       // client-first closes (not penalized, tracked only)
	lastSeen    time.Time // for map expiry
}

// targetStat aggregates stalls per destination so a site-wide packet drop
// (blocked domain) is not blamed on whichever upstreams happened to carry it.
type targetStat struct {
	nodes      map[string]bool // distinct upstreams seen on this target
	stallNodes map[string]bool // distinct upstreams that stalled on this target
	stalls     int
	lastSeen   time.Time
}

// 站点级丢包判定：多个不同节点在同一目标集体 stall 才豁免节点。
// 单个节点主导流量时（nodes 少）不会触发豁免，照罚。
const (
	targetFlakyMinStallNodes = 2
	targetFlakyMinNodes      = 3
	stallGrace               = 250 * time.Millisecond
	// demeritLatencyPenaltyMs 每次 demerit 抬高的延迟，让坏节点在最低延迟选路里下沉
	demeritLatencyPenaltyMs = 1000
)

// PassiveScorer is a process-global passive health scorer.
// Signals come only from real client traffic corpses: dial results are
// handled inline, tunnel lifetime/bytes/close-reason arrive via ReportTunnel.
type PassiveScorer struct {
	mu      sync.Mutex
	nodes   map[string]*nodeStat
	targets map[string]*targetStat
}

var (
	globalScorer     *PassiveScorer
	globalScorerOnce sync.Once
)

// GetScorer returns the process-global scorer, creating it on first use.
func GetScorer() *PassiveScorer {
	globalScorerOnce.Do(func() {
		globalScorer = &PassiveScorer{
			nodes:   make(map[string]*nodeStat),
			targets: make(map[string]*targetStat),
		}
	})
	return globalScorer
}

// isResetError reports whether err looks like TCP RST / broken pipe.
func isResetError(err error) bool {
	if err == nil {
		return false
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if errors.Is(opErr.Err, syscall.ECONNRESET) {
			return true
		}
		if errors.Is(opErr.Err, syscall.EPIPE) {
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "reset") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "connection aborted")
}

// classifyClose maps a relay copy error to a short close type.
func classifyClose(err error) string {
	if err == nil || errors.Is(err, io.EOF) {
		return "EOF"
	}
	if isResetError(err) {
		return "RST"
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline") {
		return "TIMEOUT"
	}
	if strings.Contains(msg, "closed") {
		return "CLOSED"
	}
	return "ERR"
}

// drainGrace 客户端先关后，在短暂宽限期内读走上游真实在途字节，
// 避免"响应已在路上"被判成上游 stall。
func drainGrace(conn net.Conn, grace time.Duration) int64 {
	_ = conn.SetReadDeadline(time.Now().Add(grace))
	buf := make([]byte, 32*1024)
	var n int64
	for {
		r, err := conn.Read(buf)
		n += int64(r)
		if err != nil {
			return n
		}
	}
}

// relayTunnel forwards bytes in both directions and reports corpse stats.
// It returns upBytes (client->upstream), downBytes (upstream->client),
// lifetime, closerSide ("upstream" or "client"), and closeType
// ("EOF"/"RST"/"TIMEOUT"/"CLOSED"/"ERR").
// Both conns are closed before return.
func relayTunnel(upstream, client net.Conn) (upBytes, downBytes int64, lifetime time.Duration, closerSide, closeType string) {
	start := time.Now()
	type res struct {
		n    int64
		err  error
		from string // "c2u" = client->upstream copy, "u2c" = upstream->client copy
	}
	ch := make(chan res, 2)
	go func() {
		n, err := io.Copy(upstream, client)
		ch <- res{n: n, err: err, from: "c2u"}
	}()
	go func() {
		n, err := io.Copy(client, upstream)
		ch <- res{n: n, err: err, from: "u2c"}
	}()

	first := <-ch
	lifetime = time.Since(start)
	if first.from == "c2u" {
		// 客户端先关：关客户端解套 c2u，再宽限读上游在途字节
		_ = client.Close()
		trailing := drainGrace(upstream, stallGrace)
		_ = upstream.Close()
		upBytes = first.n
		downBytes = trailing
		closerSide = "client"
	} else {
		_ = upstream.Close()
		_ = client.Close()
		downBytes = first.n
		closerSide = "upstream"
	}
	second := <-ch
	if second.n > 0 && second.from == "c2u" && second.n > upBytes {
		upBytes = second.n
	}
	if second.n > 0 && second.from == "u2c" && second.n > downBytes {
		downBytes = second.n
	}
	closeType = classifyClose(first.err)
	return upBytes, downBytes, lifetime, closerSide, closeType
}

// ReportTunnel consumes one tunnel corpse and decides success/demerit/eject.
// Success paths reset consecutive counters. Early-close (short life + small
// bytes + upstream-first close) increments demerit; reaching the consecutive
// threshold ejects the node via SetCooldown with exponential backoff.
// Client-first closes only bump the abort counter and never penalize upstream,
// except a stalled corpse: client sent data, upstream never delivered a byte.
// Stalls are cross-checked per target: when many distinct upstreams stall on
// the same destination the destination is dropping packets, not the nodes.
func (ps *PassiveScorer) ReportTunnel(address, target string, lifetime time.Duration, upBytes, downBytes int64, closerSide, closeType string, store *storage.Storage, cfg *config.Config) {
	total := upBytes + downBytes

	earlyLifetime := time.Duration(cfg.PassiveEarlyLifetimeSec) * time.Second
	if earlyLifetime <= 0 {
		earlyLifetime = 5 * time.Second
	}
	earlyBytes := int64(cfg.PassiveEarlyBytes)
	if earlyBytes <= 0 {
		earlyBytes = 8192
	}
	successBytes := int64(cfg.PassiveSuccessBytes)
	if successBytes <= 0 {
		successBytes = 65536
	}
	successLifetime := time.Duration(cfg.PassiveSuccessLifetimeSec) * time.Second
	if successLifetime <= 0 {
		successLifetime = 30 * time.Second
	}
	threshold := cfg.PassiveConsecThreshold
	if threshold <= 0 {
		threshold = 3
	}
	// stall 生效区间是 [stallFloor, successLifetime)，配到大于等于 successLifetime 等于关闭
	stallFloor := time.Duration(cfg.PassiveStallFloorSec) * time.Second
	if stallFloor <= 0 {
		stallFloor = 10 * time.Second
	}
	if stallFloor >= successLifetime {
		stallFloor = successLifetime
	}

	// Long or fat tunnels are always success (SSE / chat lifeline).
	if total >= successBytes || lifetime >= successLifetime {
		ps.reset(address)
		_ = store.RecordProxyUse(address, true)
		return
	}

	// stall：客户端发过数据、上游零下行、存活超过下限
	stalled := upBytes > 0 && downBytes == 0 && lifetime >= stallFloor

	flaky, flakyStallN, flakySeenN := false, 0, 0
	if target != "" {
		ps.mu.Lock()
		t := ps.targetStatLocked(target)
		t.nodes[address] = true
		t.lastSeen = time.Now()
		if stalled {
			t.stalls++
			t.stallNodes[address] = true
			if len(t.stallNodes) >= targetFlakyMinStallNodes &&
				len(t.nodes) >= targetFlakyMinNodes &&
				len(t.stallNodes)*2 > len(t.nodes) {
				flaky = true
				flakyStallN, flakySeenN = len(t.stallNodes), len(t.nodes)
			}
		}
		ps.mu.Unlock()
	}

	// 目标站点级丢包：不罚任何节点（连坐好节点比漏罚烂节点更糟）
	if stalled && flaky {
		log.Printf("[passive] %s stall on %s suppressed: site-wide drop (%d/%d nodes stalled)",
			address, target, flakyStallN, flakySeenN)
		ps.mu.Lock()
		st := ps.statLocked(address)
		st.clientAbort++
		st.lastSeen = time.Now()
		ps.mu.Unlock()
		_ = store.RecordProxyUseNoFail(address)
		return
	}

	if closerSide == "client" {
		if !stalled {
			ps.mu.Lock()
			st := ps.statLocked(address)
			st.clientAbort++
			st.lastSeen = time.Now()
			ps.mu.Unlock()
			_ = store.RecordProxyUse(address, true)
			return
		}
	}

	// Upstream closed first: only short+small (or stalled) counts as demerit.
	if closerSide != "client" && !(lifetime < earlyLifetime && total < earlyBytes) && !stalled {
		ps.reset(address)
		_ = store.RecordProxyUse(address, true)
		return
	}

	// Suspicious early close or stall: same single demerit, log line per kind.
	ps.mu.Lock()
	st := ps.statLocked(address)
	st.consecEarly++
	st.lastSeen = time.Now()
	consec := st.consecEarly
	ejects := st.ejectCount
	ps.mu.Unlock()

	_ = store.RecordProxyUse(address, false)
	_ = store.PenalizeLatency(address, demeritLatencyPenaltyMs)

	if stalled {
		log.Printf("[passive] %s stall corpse target=%s life=%v up=%d down=%d closer=%s type=%s consec=%d/%d",
			address, target, lifetime.Round(time.Millisecond), upBytes, downBytes, closerSide, closeType, consec, threshold)
	} else if closeType == "RST" {
		log.Printf("[passive] %s upstream-RST corpse target=%s life=%v bytes=%d consec=%d/%d",
			address, target, lifetime.Round(time.Millisecond), total, consec, threshold)
	} else {
		log.Printf("[passive] %s early-close corpse target=%s life=%v bytes=%d closer=%s type=%s consec=%d/%d",
			address, target, lifetime.Round(time.Millisecond), total, closerSide, closeType, consec, threshold)
	}

	if consec < threshold {
		ps.expire()
		return
	}

	ps.eject(address, ejects, store, cfg)
	ps.expire()
}

// reset clears consecutive demerits after a healthy tunnel.
func (ps *PassiveScorer) reset(address string) {
	ps.mu.Lock()
	if st, ok := ps.nodes[address]; ok {
		st.consecEarly = 0
		st.lastSeen = time.Now()
	}
	ps.mu.Unlock()
}

func (ps *PassiveScorer) statLocked(address string) *nodeStat {
	st, ok := ps.nodes[address]
	if !ok {
		st = &nodeStat{}
		ps.nodes[address] = st
	}
	return st
}

func (ps *PassiveScorer) targetStatLocked(target string) *targetStat {
	st, ok := ps.targets[target]
	if !ok {
		st = &targetStat{nodes: map[string]bool{}, stallNodes: map[string]bool{}}
		ps.targets[target] = st
	}
	return st
}

// eject parks the node with exponential backoff (base*2^ejects, capped),
// respecting max ejection percent so a pool-wide flap never parks everything.
func (ps *PassiveScorer) eject(address string, ejects int, store *storage.Storage, cfg *config.Config) {
	base := cfg.PassiveEjectBaseSec
	if base <= 0 {
		base = 30
	}
	capSec := cfg.PassiveEjectCapSec
	if capSec <= 0 {
		capSec = 300
	}
	backoffSec := base << uint(ejects)
	if backoffSec <= 0 || backoffSec > capSec {
		backoffSec = capSec
	}

	// Panic guard: never park more than max percent of the pool at once.
	maxPct := cfg.PassiveMaxEjectPercent
	if maxPct <= 0 || maxPct > 1 {
		maxPct = 0.5
	}
	if total, err := store.CountAll(); err == nil && total > 0 {
		if cooling, err := store.GetCooldownProxies(); err == nil {
			if float64(len(cooling)+1)/float64(total) > maxPct {
				log.Printf("[passive] %s reached eject threshold but pool %d/%d cooling (cap %.0f%%), skip eject",
					address, len(cooling), total, maxPct*100)
				return
			}
		}
	}

	d := time.Duration(backoffSec) * time.Second
	if err := store.SetCooldown(address, d); err != nil {
		log.Printf("[passive] SetCooldown %s failed: %v", address, err)
		return
	}
	log.Printf("[passive] eject %s -> cooldown %ds (backoff #%d)", address, backoffSec, ejects+1)

	ps.mu.Lock()
	if st, ok := ps.nodes[address]; ok {
		st.ejectCount++
		st.consecEarly = 0
		st.lastSeen = time.Now()
	}
	ps.mu.Unlock()
}

// expire drops stale entries so the maps stay bounded.
func (ps *PassiveScorer) expire() {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if len(ps.nodes) < 5000 && len(ps.targets) < 2000 {
		return
	}
	cutoff := time.Now().Add(-30 * time.Minute)
	for addr, st := range ps.nodes {
		if st.lastSeen.Before(cutoff) {
			delete(ps.nodes, addr)
		}
	}
	for host, t := range ps.targets {
		if t.lastSeen.Before(cutoff) {
			delete(ps.targets, host)
		}
	}
}
