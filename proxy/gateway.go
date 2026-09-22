package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
	"goproxy/config"
	"goproxy/storage"
)

// Gateway API 反向代理网关（HTTP 终端）。
// 客户端 base_url 指向本网关，网关从池中选节点转发到 UPSTREAM_BASE_URL。
// 铁律：任何异常（传输错误/非200/不吐字/流中断/响应体错误信封）-> 冷却当前节点 + 换下一个。
// 429 尊重 Retry-After（封顶 COOLDOWN_SECONDS），其余用默认冷却时长。
type Gateway struct {
	storage *storage.Storage
	cfg     *config.Config
	port    string
}

// NewGateway 创建 API 反向代理网关
func NewGateway(s *storage.Storage, cfg *config.Config, port string) *Gateway {
	return &Gateway{
		storage: s,
		cfg:     cfg,
		port:    port,
	}
}

// Start 启动网关服务
func (g *Gateway) Start() error {
	log.Printf("[gateway] API 网关监听 %s（上游=%s，冷却=%ds）",
		g.port, g.cfg.UpstreamBaseURL, g.cfg.CooldownSeconds)
	return http.ListenAndServe(g.port, g)
}

// ServeHTTP 处理请求：认证 + 原样转发
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if g.cfg.ProxyAuthEnabled {
		if !g.checkAuth(r) {
			w.Header().Set("Proxy-Authenticate", `Basic realm="GoProxy"`)
			http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
			return
		}
	}

	if g.cfg.UpstreamBaseURL == "" {
		http.Error(w, "upstream not configured (UPSTREAM_BASE_URL)", http.StatusInternalServerError)
		return
	}

	g.forward(w, r)
}

// abandon 当前节点判废：记失败 + 冷却，由调用方 continue 换节点。
// 429 场景传入解析后的 Retry-After，其余传默认 cooldown。
func (g *Gateway) abandon(p *storage.Proxy, d time.Duration) {
	g.storage.RecordProxyUse(p.Address, false)
	g.storage.SetCooldown(p.Address, d)
}

// forward 选节点转发：任何异常 -> 冷却 + 换下一个，直到重试耗尽
func (g *Gateway) forward(w http.ResponseWriter, r *http.Request) {
	// 客户端路径以 /v1 开头且上游 base 以 /v1 结尾时剥掉客户端侧 /v1，防双 /v1
	target := strings.TrimSuffix(g.cfg.UpstreamBaseURL, "/")
	reqPath := r.URL.EscapedPath()
	if (reqPath == "/v1" || strings.HasPrefix(reqPath, "/v1/")) && strings.HasSuffix(target, "/v1") {
		reqPath = strings.TrimPrefix(reqPath, "/v1")
	}
	if r.URL.RawQuery != "" {
		target += reqPath + "?" + r.URL.RawQuery
	} else {
		target += reqPath
	}

	cooldown := time.Duration(g.cfg.CooldownSeconds) * time.Second
	firstByteTimeout := time.Duration(g.cfg.ValidateTimeout) * time.Second

	// 请求体提前读入内存：重试时 r.Body 已耗尽，必须用新 Reader 重建
	bodyBytes, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	var tried []string
	for attempt := 0; attempt <= g.cfg.MaxRetry; attempt++ {
		p, err := g.selectProxy(tried)
		if err != nil {
			http.Error(w, "no available proxy", http.StatusServiceUnavailable)
			return
		}
		tried = append(tried, p.Address)

		client, err := g.buildClient(p)
		if err != nil {
			log.Printf("[gateway] %s via %s 构建客户端失败 -> 冷却换节点: %v", reqPath, p.Address, err)
			g.abandon(p, cooldown)
			continue
		}

		var bodyReader io.Reader
		if len(bodyBytes) > 0 {
			bodyReader = bytes.NewReader(bodyBytes)
		}
		req, err := http.NewRequest(r.Method, target, bodyReader)
		if err != nil {
			continue
		}
		if len(bodyBytes) > 0 {
			req.ContentLength = int64(len(bodyBytes))
		}
		req.Header = r.Header.Clone()
		stripHopByHopHeaders(req.Header)
		// transport 只认 req.Host 字段，不认 Header 里的 Host
		req.Host = hostOf(target)

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[gateway] ⚠️  %s via %s 传输异常 -> 冷却换节点: %v", reqPath, p.Address, err)
			g.abandon(p, cooldown)
			continue
		}

		// 非 200 一律判废（429 尊重 Retry-After）
		if resp.StatusCode != http.StatusOK {
			d := cooldown
			if resp.StatusCode == http.StatusTooManyRequests {
				d = retryAfterOr(resp.Header.Get("Retry-After"), cooldown)
			}
			log.Printf("[gateway] ⚠️  %s via %s %d -> 冷却 %s，换节点", reqPath, p.Address, resp.StatusCode, d)
			resp.Body.Close()
			g.abandon(p, d)
			continue
		}

		// 等首字节：拿不到 / 空body（不吐字）都判废。Close body 可解除 Peek 阻塞。
		br := bufio.NewReaderSize(resp.Body, sniffLimitBytes)
		firstCh := make(chan error, 1)
		go func() {
			_, err := br.Peek(1)
			firstCh <- err
		}()
		var firstErr error
		select {
		case firstErr = <-firstCh:
		case <-time.After(firstByteTimeout):
			firstErr = errors.New("timeout waiting for first byte")
		}
		if firstErr != nil {
			// io.EOF = 200 但零字节，同样不算稳定输出
			log.Printf("[gateway] ⚠️  %s via %s 无有效响应体 -> 冷却换节点: %v", reqPath, p.Address, firstErr)
			resp.Body.Close()
			g.abandon(p, cooldown)
			continue
		}

		// JSON/SSE 嗅探响应体头部：200 信封里藏错误（限流/配额/过载）也判废。
		// 其余 Content-Type 不嗅探，直接透传。
		// 只读首个可用块（错误信封总是最先到达），不等满 8KB——
		// 等满会把慢速 SSE 流（10s 凑不齐 8KB）误杀。
		ct := resp.Header.Get("Content-Type")
		var head []byte
		if strings.Contains(ct, "application/json") || strings.Contains(ct, "text/event-stream") {
			headCh := make(chan []byte, 1)
			go func() {
				buf := make([]byte, sniffLimitBytes)
				n, _ := br.Read(buf)
				headCh <- buf[:n]
			}()
			select {
			case head = <-headCh:
			case <-time.After(firstByteTimeout):
				log.Printf("[gateway] ⚠️  %s via %s 响应停滞 -> 冷却换节点", reqPath, p.Address)
				resp.Body.Close()
				g.abandon(p, cooldown)
				continue
			}
			if k := classifyResponseHead(ct, head); k != errNone {
				d := cooldown
				if k == errRateLimit {
					d = retryAfterOr(resp.Header.Get("Retry-After"), cooldown)
				}
				log.Printf("[gateway] ⚠️  %s via %s 响应体错误信封 -> 冷却 %s，换节点", reqPath, p.Address, d)
				resp.Body.Close()
				g.abandon(p, d)
				continue
			}
		}

		// 透传（含 SSE 流式）。写失败=客户端已断开，不罚节点。
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(http.StatusOK)
		if len(head) > 0 {
			if _, werr := w.Write(head); werr != nil {
				resp.Body.Close()
				return
			}
		}
		buf := make([]byte, 32*1024)
		for {
			n, rerr := br.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					resp.Body.Close()
					return
				}
			}
			if rerr != nil {
				if rerr != io.EOF {
					// 流中断：响应已开始无法换节点重试，但节点照罚
					log.Printf("[gateway] ⚠️  %s via %s 流中断 -> 冷却: %v", reqPath, p.Address, rerr)
					g.abandon(p, cooldown)
				} else {
					g.storage.RecordProxyUse(p.Address, true)
				}
				resp.Body.Close()
				return
			}
		}
	}

	log.Printf("[gateway] %s 所有节点失败（重试 %d 次）", reqPath, g.cfg.MaxRetry+1)
	http.Error(w, "all proxies failed", http.StatusBadGateway)
}

// upstreamErrorKind 响应体错误信封分类
type upstreamErrorKind int

const (
	errNone      upstreamErrorKind = iota // 正常内容
	errRateLimit                          // 限流（可用 Retry-After 冷却）
	errAnomaly                            // 其余错误信封（配额/过载/未知错误）
)

// sniffLimitBytes 响应体嗅探上限
const sniffLimitBytes = 8 * 1024

// classifyResponseHead 判断 JSON/SSE 头部字节是否携带错误信封。
// 只认结构化字段（code/status/type），不扫正文，防聊天内容误伤。
func classifyResponseHead(contentType string, head []byte) upstreamErrorKind {
	if len(head) == 0 {
		return errNone
	}
	if strings.Contains(contentType, "text/event-stream") {
		return sseHeadErrorKind(head)
	}
	if strings.Contains(contentType, "application/json") {
		return jsonHeadErrorKind(head)
	}
	return errNone
}

// sseHeadErrorKind SSE data 行判定：首条 data 总判；后续仅紧跟 event:*error* 时判
func sseHeadErrorKind(head []byte) upstreamErrorKind {
	judge := func(payload string) upstreamErrorKind {
		if payload == "" || payload == "[DONE]" {
			return errNone
		}
		return jsonHeadErrorKind([]byte(payload))
	}
	firstDataDone := false
	pendingErrEvent := false
	for _, raw := range strings.Split(string(head), "\n") {
		line := strings.TrimRight(raw, "\r")
		low := strings.ToLower(line)
		if strings.HasPrefix(low, "event:") {
			pendingErrEvent = strings.Contains(low, "error")
			continue
		}
		if strings.HasPrefix(low, "data:") {
			payload := strings.TrimSpace(line[len("data:"):])
			if !firstDataDone {
				if k := judge(payload); k != errNone {
					return k
				}
				firstDataDone = true
				pendingErrEvent = false
				continue
			}
			if pendingErrEvent {
				if k := judge(payload); k != errNone {
					return k
				}
			}
			pendingErrEvent = false
		}
	}
	return errNone
}

// jsonHeadErrorKind 判断 JSON 是否携带错误信号。
// 判定顺序：顶层/嵌套 code/status/type 已知错误码 -> error 字段存在且非空。
// 限流信号优先（可用 Retry-After）；error.message 非空但无已知码也判废。
func jsonHeadErrorKind(b []byte) upstreamErrorKind {
	var probe struct {
		Code   interface{}     `json:"code"`
		Status interface{}     `json:"status"`
		Type   string          `json:"type"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return errNone // 非 JSON / 截断 JSON：不判定
	}
	if k := kindFromSignals(probe.Code, probe.Status, probe.Type); k != errNone {
		return k
	}
	// error 缺失 / null / {} / "" 不算错误信封
	if len(probe.Error) == 0 {
		return errNone
	}
	es := strings.TrimSpace(string(probe.Error))
	if es == "null" || es == "{}" || es == `""` {
		return errNone
	}
	// error 为纯字符串（部分 API 用 "error": "msg"）
	var eObj struct {
		Code    interface{}     `json:"code"`
		Status  interface{}     `json:"status"`
		Type    string          `json:"type"`
		Message string          `json:"message"`
		Error   json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(probe.Error, &eObj); err != nil {
		return errAnomaly
	}
	if k := kindFromSignals(eObj.Code, eObj.Status, eObj.Type); k != errNone {
		return k
	}
	if eObj.Message != "" {
		if isRateLimitText(eObj.Message) {
			return errRateLimit
		}
		return errAnomaly
	}
	// 两层嵌套 error.error
	if len(eObj.Error) > 0 && strings.TrimSpace(string(eObj.Error)) != "null" {
		var e2 struct {
			Code    interface{} `json:"code"`
			Status  interface{} `json:"status"`
			Type    string      `json:"type"`
			Message string      `json:"message"`
		}
		if err := json.Unmarshal(eObj.Error, &e2); err == nil {
			if k := kindFromSignals(e2.Code, e2.Status, e2.Type); k != errNone {
				return k
			}
			if e2.Message != "" {
				if isRateLimitText(e2.Message) {
					return errRateLimit
				}
				return errAnomaly
			}
		}
	}
	return errNone
}

// kindFromSignals 按 code/status/type 已知错误码分类
func kindFromSignals(code, status interface{}, typ string) upstreamErrorKind {
	is429 := func(v interface{}) bool {
		switch t := v.(type) {
		case float64:
			return int(t) == 429
		case string:
			return t == "429"
		}
		return false
	}
	isStr := func(v interface{}, want string) bool {
		s, ok := v.(string)
		return ok && s == want
	}
	if is429(code) || is429(status) ||
		isStr(code, "rate_limit_exceeded") ||
		isStr(status, "RESOURCE_EXHAUSTED") ||
		typ == "rate_limit_error" {
		return errRateLimit
	}
	if code != nil || status != nil || typ != "" {
		if isStr(code, "insufficient_quota") ||
			isStr(code, "exceeded_current_quota_error") ||
			isStr(code, "invalid_api_key") ||
			typ == "exceeded_current_quota_error" ||
			typ == "engine_overloaded_error" ||
			typ == "overloaded_error" ||
			typ == "invalid_request_error" ||
			typ == "authentication_error" ||
			typ == "permission_error" ||
			typ == "api_error" ||
			isStr(status, "INVALID_ARGUMENT") ||
			isStr(status, "UNAUTHENTICATED") ||
			isStr(status, "PERMISSION_DENIED") ||
			isStr(status, "INTERNAL") ||
			isStr(status, "UNAVAILABLE") {
			return errAnomaly
		}
	}
	return errNone
}

// isRateLimitText message 文本中的限流关键词（仅用于 error.message，不扫正文）
func isRateLimitText(msg string) bool {
	m := strings.ToLower(msg)
	return strings.Contains(m, "rate limit") ||
		strings.Contains(m, "too many request") ||
		strings.Contains(m, "quota")
}

// retryAfterOr 解析 Retry-After（秒数或 HTTP-date），缺失/非法回退 fallback，结果封顶 fallback
func retryAfterOr(h string, fallback time.Duration) time.Duration {
	h = strings.TrimSpace(h)
	if h == "" {
		return fallback
	}
	if n, err := strconv.Atoi(h); err == nil && n >= 0 {
		d := time.Duration(n) * time.Second
		if d > fallback {
			return fallback
		}
		return d
	}
	if t, err := http.ParseTime(h); err == nil {
		d := time.Until(t)
		if d <= 0 || d > fallback {
			return fallback
		}
		return d
	}
	return fallback
}

// selectProxy 选节点（网关固定最低延迟模式）
func (g *Gateway) selectProxy(tried []string) (*storage.Proxy, error) {
	cfg := g.cfg
	sourceFilter := sourceFilterFromMode(cfg.CustomProxyMode)

	if cfg.CustomProxyMode == "mixed" && (cfg.CustomPriority || cfg.CustomFreePriority) {
		preferSource := "custom"
		if cfg.CustomFreePriority {
			preferSource = "free"
		}
		if p, err := g.storage.GetLowestLatencyExcludeFiltered(tried, preferSource); err == nil {
			return p, nil
		}
		return g.storage.GetLowestLatencyExcludeFiltered(tried, "")
	}

	return g.storage.GetLowestLatencyExcludeFiltered(tried, sourceFilter)
}

// buildClient 构造经节点拨号的 HTTP 客户端。
// 禁止设 http.Client.Timeout（含 body 流式读取总时限，会截断 SSE）；
// 只限拨号 + 响应头超时。
func (g *Gateway) buildClient(p *storage.Proxy) (*http.Client, error) {
	dialTimeout := time.Duration(g.cfg.ValidateTimeout) * time.Second
	switch p.Protocol {
	case "http":
		proxyURL, err := url.Parse("http://" + p.Address)
		if err != nil {
			return nil, err
		}
		return &http.Client{
			Transport: &http.Transport{
				Proxy:                 http.ProxyURL(proxyURL),
				DialContext:           (&net.Dialer{Timeout: dialTimeout}).DialContext,
				ResponseHeaderTimeout: dialTimeout,
			},
		}, nil
	case "socks5":
		return socks5Client(p, dialTimeout)
	default:
		return nil, errUnsupportedProtocol
	}
}

// checkAuth 验证 Basic Auth（兼容 Authorization 头）
func (g *Gateway) checkAuth(r *http.Request) bool {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		auth = r.Header.Get("Authorization")
		if auth == "" {
			return false
		}
	}

	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return false
	}

	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) != 2 {
		return false
	}

	usernameMatch := subtle.ConstantTimeCompare([]byte(credentials[0]), []byte(g.cfg.ProxyAuthUsername)) == 1
	// config 存的是 hex 字符串（fmt.Sprintf("%x", sha256)），必须同样转 hex 再比
	passwordHash := fmt.Sprintf("%x", sha256.Sum256([]byte(credentials[1])))
	passwordMatch := subtle.ConstantTimeCompare([]byte(passwordHash), []byte(g.cfg.ProxyAuthPasswordHash)) == 1
	return usernameMatch && passwordMatch
}

func hostOf(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return u.Host
	}
	return ""
}

// stripHopByHopHeaders 剥离逐跳头（RFC 9110 §7.6.1）
func stripHopByHopHeaders(h http.Header) {
	for _, name := range h.Values("Connection") {
		for _, token := range strings.Split(name, ",") {
			if t := strings.TrimSpace(token); t != "" {
				h.Del(t)
			}
		}
	}
	h.Del("Connection")
	for _, name := range []string{
		"Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"TE", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		h.Del(name)
	}
}

// socks5Client SOCKS5 节点客户端：同 buildClient，不设 Client.Timeout
func socks5Client(p *storage.Proxy, dialTimeout time.Duration) (*http.Client, error) {
	dialer, err := proxy.SOCKS5("tcp", p.Address, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	dialCtx := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dctx, cancel := context.WithTimeout(ctx, dialTimeout)
		defer cancel()
		if cd, ok := dialer.(proxy.ContextDialer); ok {
			return cd.DialContext(dctx, network, addr)
		}
		type res struct {
			c   net.Conn
			err error
		}
		ch := make(chan res, 1)
		go func() {
			c, err := dialer.Dial(network, addr)
			ch <- res{c, err}
		}()
		select {
		case r := <-ch:
			return r.c, r.err
		case <-dctx.Done():
			return nil, dctx.Err()
		}
	}
	return &http.Client{
		Transport: &http.Transport{
			DialContext:           dialCtx,
			ResponseHeaderTimeout: dialTimeout,
		},
	}, nil
}

// errUnsupportedProtocol 不支持的节点协议错误
var errUnsupportedProtocol = &protocolError{}

type protocolError struct{}

func (e *protocolError) Error() string { return "unsupported protocol" }
