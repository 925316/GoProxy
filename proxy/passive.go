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

// PassiveScorer is a process-global passive health scorer.
// Signals come only from real client traffic corpses: dial results are
// handled inline, tunnel lifetime/bytes/close-reason arrive via ReportTunnel.
type PassiveScorer struct {
	mu    sync.Mutex
	nodes map[string]*nodeStat
}

var (
	globalScorer     *PassiveScorer
	globalScorerOnce sync.Once
)

// GetScorer returns the process-global scorer, creating it on first use.
func GetScorer() *PassiveScorer {
	globalScorerOnce.Do(func() {
		globalScorer = &PassiveScorer{nodes: make(map[string]*nodeStat)}
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
	// Unblock the other direction: closing both conns forces the peer copy out.
	_ = upstream.Close()
	_ = client.Close()
	second := <-ch

	lifetime = time.Since(start)
	if first.from == "c2u" {
		upBytes = first.n
		downBytes = second.n
		closerSide = "client"
	} else {
		downBytes = first.n
		upBytes = second.n
		closerSide = "upstream"
	}
	closeType = classifyClose(first.err)
	return upBytes, downBytes, lifetime, closerSide, closeType
}

// ReportTunnel consumes one tunnel corpse and decides success/demerit/eject.
// Success paths reset consecutive counters. Early-close (short life + small
// bytes + upstream-first close) increments demerit; reaching the consecutive
// threshold ejects the node via SetCooldown with exponential backoff.
// Client-first closes only bump the abort counter and never penalize upstream.
func (ps *PassiveScorer) ReportTunnel(address string, lifetime time.Duration, upBytes, downBytes int64, closerSide, closeType string, store *storage.Storage, cfg *config.Config) {
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

	// Long or fat tunnels are always success (SSE / chat lifeline).
	if total >= successBytes || lifetime >= successLifetime {
		ps.reset(address)
		_ = store.RecordProxyUse(address, true)
		return
	}

	// Client hung up first: track only, never punish upstream.
	if closerSide == "client" {
		ps.mu.Lock()
		st := ps.statLocked(address)
		st.clientAbort++
		st.lastSeen = time.Now()
		ps.mu.Unlock()
		_ = store.RecordProxyUse(address, true)
		return
	}

	// Upstream closed first. Only short+small counts as demerit.
	if !(lifetime < earlyLifetime && total < earlyBytes) {
		ps.reset(address)
		_ = store.RecordProxyUse(address, true)
		return
	}

	// Suspicious early close: RST weighs the same single demerit but is logged.
	ps.mu.Lock()
	st := ps.statLocked(address)
	st.consecEarly++
	st.lastSeen = time.Now()
	consec := st.consecEarly
	ejects := st.ejectCount
	ps.mu.Unlock()

	_ = store.RecordProxyUse(address, false)

	if closeType == "RST" {
		log.Printf("[passive] %s upstream-RST corpse life=%v bytes=%d consec=%d/%d",
			address, lifetime.Round(time.Millisecond), total, consec, threshold)
	} else {
		log.Printf("[passive] %s early-close corpse life=%v bytes=%d closer=%s type=%s consec=%d/%d",
			address, lifetime.Round(time.Millisecond), total, closerSide, closeType, consec, threshold)
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

// expire drops stale entries so the map stays bounded.
func (ps *PassiveScorer) expire() {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if len(ps.nodes) < 5000 {
		return
	}
	cutoff := time.Now().Add(-30 * time.Minute)
	for addr, st := range ps.nodes {
		if st.lastSeen.Before(cutoff) {
			delete(ps.nodes, addr)
		}
	}
}
