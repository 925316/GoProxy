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

// Gateway API 反向代理网关
//
// 解决的问题: 透明代理模式下 (CONNECT 隧道) 上游的 HTTP 429 对代理不可见。
// 本网关是 HTTP 终端, 客户端把 base_url 指向本网关 (如 http://host:8888),
// 网关收到明文 HTTP 请求后从代理池选节点转发到配置的真实上游 (UPSTREAM_BASE_URL)。
// 上游异常按归属分类处理（业界惯例，参照 LiteLLM/one-api/sub2api）：
//   - 限流（出口 IP 归属：HTTP 429 / 响应体内 429 / RESOURCE_EXHAUSTED /
//     rate_limit_error 等）-> 冷却该节点（尊重 Retry-After，封顶 COOLDOWN_SECONDS）
//     并换节点重试
//   - 配额耗尽（账号归属：insufficient_quota / exceeded_current_quota_error）
//     与上游过载（engine_overloaded_error / overloaded_error）-> 不惩罚节点，
//     原样透传给客户端（换节点同样无效，客户端需要看到真实错误）
//   - WAF 挑战页（403 + cf-mitigated 头或 text/html）-> 记失败换节点重试
//
// 用法: 客户端把 base_url 指向本网关, 请求路径原样转发到上游。
// 例: 上游为 https://my-api.example.com 时,
//   请求 /chat -> https://my-api.example.com/chat
//   请求 /v1/chat/completions -> https://my-api.example.com/v1/chat/completions
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
	// 认证（与透明代理共用同一套凭据）
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

// forward 选节点转发请求，429 时冷却该节点并换下一个
func (g *Gateway) forward(w http.ResponseWriter, r *http.Request) {
	// 拼上游目标地址：base + 原请求路径 + query
	// 仅做一种去重: 客户端路径为 /v1 或以 /v1 开头, 且上游 base 以 /v1 结尾时,
	// 剥掉路径的 /v1, 避免 SDK 自动加 /v1 后与 base 中的 /v1 重复 (https://api.com/v1/v1/chat)。
	// 用 EscapedPath 构建转发路径, 编码字符 (%2F、空格等) 原样透传, 不被二次解码。
	// 其余路径 (含自定义 API 的任意路径) 原样转发。
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

	// 提前整体读入请求 body: 每次重试都要用新的 Reader 构造上游请求,
	// 否则第一次 client.Do 后 r.Body 已耗尽, 429/超时重试时下一节点会收到空 body。
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
			removeOrDisableProxy(g.storage, p)
			continue
		}

		// 构造上游请求（body 已整体读入内存, 每次重试用新 Reader 重建）
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
		// Host 头必须用 req.Host 字段设置——transport 会忽略 Header 表里的 Host
		req.Host = hostOf(target)

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[gateway] %s via %s 失败: %v", reqPath, p.Address, err)
			g.storage.RecordProxyUse(p.Address, false)
			removeOrDisableProxy(g.storage, p)
			continue
		}

		// ===== 异常分类 =====
		// 默认动作由状态行决定；结构化响应体（JSON/SSE）可改写判定。
		kind := errNone
		if resp.StatusCode == http.StatusTooManyRequests {
			// 无更多信息时按出口 IP 限流处理（代理场景最常见的 429 成因）
			kind = errRateLimit
		}

		// 透传前先等首字节，确认节点真的在流数据。
		// 首字节前失败（EOF/断连/超时）：还没给客户端写任何数据，可以安全换节点重试。
		// 缓冲 channel 保证超时后 goroutine 不会阻塞在发送上；
		// resp.Body.Close() 会让阻塞在 Peek 读上的 goroutine 立即返回并退出，不会永久泄漏。
		// 边界竞态：恰好在超时瞬间读到的字节会被丢弃，可接受。
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
		if firstErr != nil && firstErr != io.EOF {
			log.Printf("[gateway] ⚠️  %s via %s 首字节前失败: %v", reqPath, p.Address, firstErr)
			resp.Body.Close()
			continue
		}
		// firstErr == io.EOF：空响应体（HEAD/204 等），无内容可嗅探，直接透传

		// 响应体异常嗅探：仅对结构化响应（JSON/SSE）启用，其余 Content-Type
		// 零改动直通。部分上游/中转把限流、配额、过载等错误放在 HTTP 200
		// 甚至 5xx 的响应体里，仅看状态码会误判（如 5xx 信封包裹 429）。
		ct := resp.Header.Get("Content-Type")
		var head []byte
		if strings.Contains(ct, "application/json") || strings.Contains(ct, "text/event-stream") {
			// 独占 br 读头部字节（读满 sniffLimitBytes 或 EOF），主 goroutine 在
			// 此期间不碰 br，避免并发读取。超时视为节点停滞（首字节已到但后续
			// 内容迟迟不来），换节点重试——此时未向客户端写任何字节，重试安全。
			// resp.Body.Close() 会解除阻塞中的 ReadAll 使 goroutine 退出
			// （channel 缓冲为 1，不会泄漏）。
			headCh := make(chan []byte, 1)
			go func() {
				b, _ := io.ReadAll(io.LimitReader(br, sniffLimitBytes))
				headCh <- b
			}()
			select {
			case head = <-headCh:
			case <-time.After(firstByteTimeout):
				log.Printf("[gateway] ⚠️  %s via %s 首字节后响应停滞 -> 换节点重试", reqPath, p.Address)
				resp.Body.Close()
				continue
			}
			if k := classifyResponseHead(ct, head); k != errNone {
				kind = k
			}
		}

		switch kind {
		case errRateLimit:
			d := retryAfterOr(resp.Header.Get("Retry-After"), cooldown)
			log.Printf("[gateway] ⚠️  %s via %s 限流 -> 冷却 %s，换节点重试", reqPath, p.Address, d)
			resp.Body.Close()
			g.storage.RecordProxyUse(p.Address, false)
			g.storage.SetCooldown(p.Address, d)
			continue
		case errQuotaExhausted:
			log.Printf("[gateway] ⚠️  %s via %s 上游账号配额/余额耗尽 -> 不惩罚节点，原样透传", reqPath, p.Address)
		case errUpstreamOverloaded:
			log.Printf("[gateway] ⚠️  %s via %s 上游过载 -> 不惩罚节点，原样透传", reqPath, p.Address)
		}

		// 403 WAF 挑战页：出口 IP 被上游风控，节点归属 -> 记失败并换节点重试
		// （不直接删/禁，靠 fail_count<3 的既有门槛自然淘汰惯犯）
		if resp.StatusCode == http.StatusForbidden && isWafChallenge(resp) {
			log.Printf("[gateway] ⚠️  %s via %s 疑似 WAF 挑战页(403) -> 记失败，换节点重试", reqPath, p.Address)
			resp.Body.Close()
			g.storage.RecordProxyUse(p.Address, false)
			continue
		}

		// 透传响应（含 SSE 流式）。手动逐块 Copy 以区分：
		//   - 客户端断开（Write 失败）: 不算节点问题
		//   - 节点流中断（读非 EOF 错误，如 chunked 未完成）: 记录 EOF
		//   - 正常结束（读 EOF）: 什么都不做
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		// 先补写嗅探阶段消费掉的头部字节，再继续流式拷贝剩余部分
		if len(head) > 0 {
			if _, werr := w.Write(head); werr != nil {
				// 客户端已断开，无需继续
				resp.Body.Close()
				return
			}
		}
		buf := make([]byte, 32*1024)
		for {
			n, rerr := br.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					// 客户端已断开，无需继续
					resp.Body.Close()
					return
				}
			}
			if rerr != nil {
				if rerr != io.EOF {
					log.Printf("[gateway] ⚠️  %s via %s 流中断: %v", reqPath, p.Address, rerr)
					g.recordEof(p, cooldown)
					g.storage.RecordProxyUse(p.Address, false)
				} else {
					g.storage.RecordProxyUse(p.Address, true)
				}
			resp.Body.Close()
			// 429 若被响应体重分类为配额/过载会走到这里透传，同样值得记录
			if resp.StatusCode >= 400 {
				log.Printf("[gateway] %s via %s -> %d", reqPath, p.Address, resp.StatusCode)
			}
			return
			}
		}
	}

	log.Printf("[gateway] %s 所有节点失败（重试 %d 次）", reqPath, g.cfg.MaxRetry+1)
	http.Error(w, "all proxies failed", http.StatusBadGateway)
}

// recordEof 记录一次流式 EOF（仅中途流中断时调用，首字节前失败不计入），达到阈值后冷却该节点（冷却时长复用 CooldownSeconds）
func (g *Gateway) recordEof(p *storage.Proxy, cooldown time.Duration) {
	count, err := g.storage.RecordEof(p.Address)
	if err != nil {
		return
	}
	if count >= g.cfg.EofThreshold {
		log.Printf("[gateway] ⚠️  节点 %s 达到 %d 次 EOF -> 冷却 %s", p.Address, count, cooldown)
		g.storage.SetCooldown(p.Address, cooldown)
	}
}

// upstreamErrorKind 上游异常的分类（决定网关动作与节点归责）
type upstreamErrorKind int

const (
	errNone             upstreamErrorKind = iota // 非错误信号，正常透传
	errRateLimit                                 // 出口 IP 限流 -> 冷却 + 换节点
	errQuotaExhausted                            // 上游账号配额/余额耗尽 -> 透传不惩罚（换节点无用）
	errUpstreamOverloaded                        // 上游过载 -> 透传不惩罚（换节点同样无用）
)

// sniffLimitBytes 响应体嗅探的最大字节数（限流错误体远小于此值）
const sniffLimitBytes = 8 * 1024

// classifyResponseHead 判断结构化响应头部字节携带的异常类型。防误杀原则：
//   - 只处理 Content-Type 为 application/json 或 text/event-stream 的响应
//   - 只认结构化字段（jsonHeadErrorKind），不扫描正文文本，
//     避免聊天内容里恰好出现 "429" 造成误杀
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

// sseHeadErrorKind 提取 SSE 头部字节中的 data 行载荷做结构化判断：
//   - 首条 data 行总是判定（LLM 类上游的流式错误通常作为首个事件下发）
//   - 后续 data 行仅当紧跟 event:*error* 标记时才判定（Anthropic 风格的
//     中途错误事件），其余属于正常生成内容，不看（防误伤）
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
				pendingErrEvent = false // 首条 data 已消费，未判定出错误则标记失效
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

// jsonHeadErrorKind 判断 JSON 载荷的异常类型。
// 只认结构化字段：顶层及 error 对象内（两层嵌套兜底）的 code/status/type。
// 分类依据（业界惯例）：
//   - 配额耗尽：code/type == insufficient_quota (OpenAI) /
//     exceeded_current_quota_error (Kimi) —— 账号余额问题，换节点无用
//   - 过载：type == engine_overloaded_error (Kimi) / overloaded_error (Anthropic)
//   - 限流：code/status == 429（数字或字符串）、rate_limit_exceeded (OpenAI)、
//     status == RESOURCE_EXHAUSTED (Gemini)、type == rate_limit_error (Anthropic)
func jsonHeadErrorKind(b []byte) upstreamErrorKind {
	var probe struct {
		Code   interface{} `json:"code"`
		Status interface{} `json:"status"`
		Type   string      `json:"type"`
		Error  struct {
			Code   interface{} `json:"code"`
			Status interface{} `json:"status"`
			Type   string      `json:"type"`
			Error  struct {
				Code   interface{} `json:"code"`
				Status interface{} `json:"status"`
			} `json:"error"`
		} `json:"error"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return errNone // 非 JSON 或截断的 JSON（大响应的前 8KB）：不判定
	}
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
	type layer struct {
		code, status interface{}
		typ          string
	}
	for _, l := range []layer{
		{probe.Code, probe.Status, probe.Type},
		{probe.Error.Code, probe.Error.Status, probe.Error.Type},
		{probe.Error.Error.Code, probe.Error.Error.Status, ""},
	} {
		switch {
		case isStr(l.code, "insufficient_quota"),
			isStr(l.code, "exceeded_current_quota_error"),
			l.typ == "exceeded_current_quota_error":
			return errQuotaExhausted
		case l.typ == "engine_overloaded_error", l.typ == "overloaded_error":
			return errUpstreamOverloaded
		case is429(l.code), is429(l.status),
			isStr(l.code, "rate_limit_exceeded"),
			isStr(l.status, "RESOURCE_EXHAUSTED"),
			l.typ == "rate_limit_error":
			return errRateLimit
		}
	}
	return errNone
}

// retryAfterOr 解析 Retry-After 头（RFC 9110 §10.2.3：delay-seconds 或 HTTP-date）。
// 缺失或无法解析时回退 fallback；结果封顶为 fallback（配置值即上限，
// 避免异常大的 Retry-After 长期冻结节点）。
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
		if d <= 0 {
			// 已过期的 HTTP-date 等价于"立即可重试"，无冷却意义，回退默认值
			// （SetCooldown(0) 会顺带清零 eof_count，属副作用，避免）
			return fallback
		}
		if d > fallback {
			return fallback
		}
		return d
	}
	return fallback
}

// isWafChallenge 判断 403 响应是否为 WAF 挑战页（出口 IP 被风控的信号）。
// Cloudflare 用 cf-mitigated: challenge 头显式标记；挑战页 body 为 text/html。
// 业务性的 JSON 403（权限不足等）不算，避免把客户端/账号问题算到节点头上。
func isWafChallenge(resp *http.Response) bool {
	if strings.Contains(strings.ToLower(resp.Header.Get("Cf-Mitigated")), "challenge") {
		return true
	}
	return strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html")
}

// selectProxy 选节点（网关固定用最低延迟模式，兼顾稳定性）
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

// buildClient 构造通过节点拨号的 HTTP 客户端
//
// 注意：不能设置 http.Client.Timeout —— 那是整个请求（含 body 流式读取）的总时限，
// SSE 长流式响应超过几秒就会被强制截断，表现为客户端收到 EOF。
// 这里只用 Transport 层超时：拨号超时 + 响应头超时，body 流式读取不受限。
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

// checkAuth 验证 Basic Auth（与透明代理一致）
func (g *Gateway) checkAuth(r *http.Request) bool {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		// 也接受 Authorization header（部分 SDK 用这种）
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
	passwordHash := sha256.Sum256([]byte(credentials[1]))
	passwordMatch := subtle.ConstantTimeCompare([]byte(passwordHash[:]), []byte(g.cfg.ProxyAuthPasswordHash)) == 1
	return usernameMatch && passwordMatch
}

func hostOf(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return u.Host
	}
	return ""
}

// stripHopByHopHeaders 剥离逐跳头（RFC 9110 §7.6.1）：这些头部只作用于
// 单一 TCP 连接，端到端转发会破坏连接语义（如 Connection: keep-alive、
// Transfer-Encoding 由 transport 自管）。Connection 头中列出的附属字段一并剥离。
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

// socks5Client 通过 SOCKS5 节点拨号的 HTTP 客户端
// 同样只限制拨号/响应头超时，不设 Client.Timeout，避免截断 SSE 长流
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
		// 兜底：不支持 ContextDialer 时用 goroutine 包装
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
