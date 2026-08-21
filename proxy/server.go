package proxy

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
	"goproxy/config"
	"goproxy/storage"
)

type Server struct {
	storage *storage.Storage
	cfg     *config.Config
	mode    string // "random" 或 "lowest-latency"
	port    string
}

func New(s *storage.Storage, cfg *config.Config, mode string, port string) *Server {
	return &Server{
		storage: s,
		cfg:     cfg,
		mode:    mode,
		port:    port,
	}
}

func (s *Server) Start() error {
	modeDesc := "随机轮换"
	if s.mode == "lowest-latency" {
		modeDesc = "最低延迟"
	}
	authStatus := "无认证"
	if s.cfg.ProxyAuthEnabled {
		authStatus = fmt.Sprintf("需认证 (用户: %s)", s.cfg.ProxyAuthUsername)
	}
	log.Printf("proxy server listening on %s [%s] [%s]", s.port, modeDesc, authStatus)
	return http.ListenAndServe(s.port, s)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 认证检查（如果启用）
	if s.cfg.ProxyAuthEnabled {
		if !s.checkAuth(r) {
			w.Header().Set("Proxy-Authenticate", `Basic realm="GoProxy"`)
			http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
			return
		}
	}
	
	if r.Method == http.MethodConnect {
		s.handleTunnel(w, r)
	} else {
		s.handleHTTP(w, r)
	}
}

// checkAuth 验证代理 Basic Auth
func (s *Server) checkAuth(r *http.Request) bool {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return false
	}
	
	// 解析 Basic Auth
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
	
	username := credentials[0]
	password := credentials[1]
	
	// 验证用户名和密码
	usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte(s.cfg.ProxyAuthUsername)) == 1
	passwordHash := fmt.Sprintf("%x", sha256.Sum256([]byte(password)))
	passwordMatch := subtle.ConstantTimeCompare([]byte(passwordHash), []byte(s.cfg.ProxyAuthPasswordHash)) == 1
	
	return usernameMatch && passwordMatch
}

// selectProxy 根据使用模式和选择策略获取代理
func (s *Server) selectProxy(tried []string, lowestLatency bool) (*storage.Proxy, error) {
	cfg := config.Get()
	sourceFilter := sourceFilterFromMode(cfg.CustomProxyMode)

	// 混用 + 优先模式：先尝试优先源，无可用则 fallback 全部
	if cfg.CustomProxyMode == "mixed" && (cfg.CustomPriority || cfg.CustomFreePriority) {
		preferSource := "custom"
		if cfg.CustomFreePriority {
			preferSource = "free"
		}
		var p *storage.Proxy
		var err error
		if lowestLatency {
			p, err = s.storage.GetLowestLatencyExcludeFiltered(tried, preferSource)
		} else {
			p, err = s.storage.GetRandomExcludeFiltered(tried, preferSource)
		}
		if err == nil {
			return p, nil
		}
		// fallback 到全部
		if lowestLatency {
			return s.storage.GetLowestLatencyExcludeFiltered(tried, "")
		}
		return s.storage.GetRandomExcludeFiltered(tried, "")
	}

	if lowestLatency {
		return s.storage.GetLowestLatencyExcludeFiltered(tried, sourceFilter)
	}
	return s.storage.GetRandomExcludeFiltered(tried, sourceFilter)
}

// removeOrDisableProxy 根据代理来源决定删除或禁用
func removeOrDisableProxy(store *storage.Storage, p *storage.Proxy) {
	if p.Source == "custom" {
		store.DisableProxy(p.Address)
	} else {
		store.Delete(p.Address)
	}
}

// sourceFilterFromMode 根据使用模式返回来源过滤值
func sourceFilterFromMode(mode string) string {
	switch mode {
	case "custom_only":
		return "custom"
	case "free_only":
		return "free"
	default:
		return "" // mixed
	}
}

// handleHTTP 处理普通 HTTP 请求（带自动重试 + 429 冷却换节点）
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	var tried []string
	// 循环前一次性读取请求体，避免重试时 r.Body 已被耗尽导致空 body
	var bodyBytes []byte
	if r.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}
	}
	for attempt := 0; attempt <= s.cfg.MaxRetry; attempt++ {
		p, err := s.selectProxy(tried, s.mode == "lowest-latency")
		if err != nil {
			http.Error(w, "no available proxy", http.StatusServiceUnavailable)
			return
		}

		tried = append(tried, p.Address)

		client, err := s.buildClient(p)
		if err != nil {
			removeOrDisableProxy(s.storage, p)
			continue
		}

		// 转发请求（使用完整 URL，上游代理通过 client transport 设置）
		var body io.Reader
		if len(bodyBytes) > 0 {
			body = bytes.NewReader(bodyBytes)
		}
		req, err := http.NewRequest(r.Method, r.URL.String(), body)
		if err != nil {
			continue
		}
		req.Header = r.Header.Clone()
		req.Header.Del("Proxy-Connection")
		if len(bodyBytes) > 0 {
			req.ContentLength = int64(len(bodyBytes))
		}

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[proxy] %s via %s failed, removing", r.RequestURI, p.Address)
			s.storage.RecordProxyUse(p.Address, false)
			removeOrDisableProxy(s.storage, p)
			continue
		}

		// 429：上游按出口 IP 限流，冷却该节点并换下一个重试（不删除、不加 fail_count）
		if resp.StatusCode == http.StatusTooManyRequests {
			cd := retryAfterOr(resp.Header.Get("Retry-After"), time.Duration(s.cfg.CooldownSeconds)*time.Second)
			log.Printf("[proxy] ⚠️  429 %s via %s -> 冷却 %s，换节点重试", r.RequestURI, p.Address, cd)
			resp.Body.Close()
			s.storage.RecordProxyUse(p.Address, false)
			s.storage.SetCooldown(p.Address, cd)
			continue
		}

		// 写回响应
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		resp.Body.Close()
		s.storage.RecordProxyUse(p.Address, true)
		if resp.StatusCode >= 400 {
			log.Printf("[proxy] %s via %s -> %d", r.RequestURI, p.Address, resp.StatusCode)
		}
		return
	}

	http.Error(w, "all proxies failed", http.StatusBadGateway)
}

// handleTunnel 处理 HTTPS CONNECT 隧道（带自动重试）
func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	var tried []string
	for attempt := 0; attempt <= s.cfg.MaxRetry; attempt++ {
		p, err := s.selectProxy(tried, s.mode == "lowest-latency")
		if err != nil {
			http.Error(w, "no available proxy", http.StatusServiceUnavailable)
			return
		}

		tried = append(tried, p.Address)

		conn, err := s.dialViaProxy(p, r.Host)
		if err != nil {
			log.Printf("[tunnel] dial %s via %s failed, removing", r.Host, p.Address)
			s.storage.RecordProxyUse(p.Address, false)
			removeOrDisableProxy(s.storage, p)
			continue
		}

		s.storage.RecordProxyUse(p.Address, true)

		// 告知客户端隧道建立
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			conn.Close()
			http.Error(w, "hijack not supported", http.StatusInternalServerError)
			return
		}
		clientConn, _, err := hijacker.Hijack()
		if err != nil {
			conn.Close()
			return
		}

		fmt.Fprintf(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		log.Printf("[tunnel] %s via %s established", r.Host, p.Address)

		// 双向转发
		go transfer(conn, clientConn)
		go transfer(clientConn, conn)
		return
	}

	http.Error(w, "all proxies failed", http.StatusBadGateway)
}

func (s *Server) dialViaProxy(p *storage.Proxy, host string) (net.Conn, error) {
	timeout := time.Duration(s.cfg.ValidateTimeout) * time.Second
	switch p.Protocol {
	case "http":
		conn, err := net.DialTimeout("tcp", p.Address, timeout)
		if err != nil {
			return nil, err
		}
		// 发送 CONNECT 请求给上游 HTTP 代理
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)
		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		if err != nil {
			conn.Close()
			return nil, err
		}
		if n < 12 {
			conn.Close()
			return nil, fmt.Errorf("short response from proxy")
		}
		return conn, nil
	case "socks5":
		dialer, err := proxy.SOCKS5("tcp", p.Address, nil, proxy.Direct)
		if err != nil {
			return nil, err
		}
		return dialer.Dial("tcp", host)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", p.Protocol)
	}
}

func (s *Server) buildClient(p *storage.Proxy) (*http.Client, error) {
	timeout := time.Duration(s.cfg.ValidateTimeout) * time.Second
	switch p.Protocol {
	case "http":
		proxyURL, err := url.Parse(fmt.Sprintf("http://%s", p.Address))
		if err != nil {
			return nil, err
		}
		return &http.Client{
			Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
			Timeout:   timeout,
		}, nil
	case "socks5":
		dialer, err := proxy.SOCKS5("tcp", p.Address, nil, proxy.Direct)
		if err != nil {
			return nil, err
		}
		return &http.Client{
			Transport: &http.Transport{Dial: dialer.Dial},
			Timeout:   timeout,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", p.Protocol)
	}
}

func transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}
