package validator

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
	"goproxy/config"
	"goproxy/storage"
)

type Validator struct {
	concurrency   int
	timeout       time.Duration
	validateURL   string
	maxResponseMs int
	cfg           *config.Config
}

func concurrencyBuffer(total, concurrency int) int {
	if total < concurrency*10 {
		return total
	}
	return concurrency * 10
}

func New(concurrency, timeoutSec int, validateURL string) *Validator {
	cfg := config.Get()
	maxMs := 0
	if cfg != nil {
		maxMs = cfg.MaxResponseMs
	}
	return &Validator{
		concurrency:   concurrency,
		timeout:       time.Duration(timeoutSec) * time.Second,
		validateURL:   validateURL,
		maxResponseMs: maxMs,
		cfg:           cfg,
	}
}

type Result struct {
	Proxy        storage.Proxy
	Valid        bool
	Latency      time.Duration
	ExitIP       string
	ExitLocation string
}

// getExitIPInfo 通过代理获取出口 IP 和地理位置
func getExitIPInfo(client *http.Client) (string, string) {
	// 使用 ip-api.com 返回 JSON 格式的 IP 信息
	resp, err := client.Get("http://ip-api.com/json/?fields=status,country,countryCode,city,query")
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()

	var result struct {
		Status      string `json:"status"`
		Query       string `json:"query"`       // IP 地址
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		City        string `json:"city"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || result.Status != "success" {
		return "", ""
	}

	// 返回格式：IP, "国家代码 城市"
	location := result.CountryCode
	if result.City != "" {
		location = fmt.Sprintf("%s %s", result.CountryCode, result.City)
	}
	
	return result.Query, location
}

// HTTPS 测试目标列表，随机选一个验证代理的 CONNECT 隧道能力
var httpsTestTargets = []string{
	"https://www.google.com",
	"https://www.openai.com",
	"https://www.github.com",
	"https://www.cloudflare.com",
	"https://httpbin.org/ip",
}

// httpsCanaryTarget 用户实际流量域名：注入节点只对特定 SNI 换证书，
// 通用目标测不出来，canary 必须过真实证书链
const httpsCanaryTarget = "https://opencode.ai"

// checkHTTPSConnect 通过 HTTP 代理实际访问一个随机 HTTPS 网站，验证 CONNECT 隧道是否可用
// 首次失败会换一个目标重试一次，避免目标网站偶尔抽风导致误杀
func checkHTTPSConnect(proxyAddr string, timeout time.Duration) bool {
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", proxyAddr))
	if err != nil {
		return false
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:               http.ProxyURL(proxyURL),
			TLSHandshakeTimeout: timeout,
		},
		Timeout: timeout,
	}

	return probeHTTPSGet(client)
}

// checkHTTPSConnectSOCKS5 同 checkHTTPSConnect，经 SOCKS5 拨号（证书走 Go 默认校验）
func checkHTTPSConnectSOCKS5(proxyAddr string, timeout time.Duration) bool {
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		return false
	}

	client := &http.Client{
		Transport: &http.Transport{
			Dial:                 dialer.Dial,
			TLSHandshakeTimeout:  timeout,
		},
		Timeout: timeout,
	}

	return probeHTTPSGet(client)
}

// probeHTTPSGet GET canary 目标验证证书链；证书类错误 = 中间人注入，直接判负不回退；
// 仅传输层不可达时退回通用目标，避免 canary 路由问题误杀
func probeHTTPSGet(client *http.Client) bool {
	defer client.CloseIdleConnections()
	resp, err := client.Get(httpsCanaryTarget)
	if err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return true
	}
	if isTLSError(err) {
		return false
	}
	return probeGenericHTTPS(client)
}

// isTLSError 证书/TLS 层错误（x509 校验失败等），而非网络不可达
func isTLSError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "x509:") || strings.Contains(msg, "tls:")
}

// probeGenericHTTPS 随机通用目标重试一次，拿到任意 HTTP 响应即通过
func probeGenericHTTPS(client *http.Client) bool {
	// 随机起始索引
	start := int(time.Now().UnixNano() % int64(len(httpsTestTargets)))

	for attempt := 0; attempt < 2; attempt++ {
		idx := (start + attempt) % len(httpsTestTargets)
		resp, err := client.Get(httpsTestTargets[idx])
		if err != nil {
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return true
	}

	return false
}

// ValidateAll 并发验证所有代理，返回验证结果
func (v *Validator) ValidateAll(proxies []storage.Proxy) []Result {
	var results []Result
	for r := range v.ValidateStream(proxies) {
		results = append(results, r)
	}
	return results
}

// ValidateStream 并发验证，边验证边通过 channel 返回结果
func (v *Validator) ValidateStream(proxies []storage.Proxy) <-chan Result {
	ch := make(chan Result, concurrencyBuffer(len(proxies), v.concurrency))
	sem := make(chan struct{}, v.concurrency)
	var wg sync.WaitGroup

	go func() {
		for _, p := range proxies {
			wg.Add(1)
			sem <- struct{}{}
			go func(px storage.Proxy) {
				defer wg.Done()
				defer func() { <-sem }()
				valid, latency, exitIP, exitLocation := v.ValidateOne(px)
				ch <- Result{Proxy: px, Valid: valid, Latency: latency, ExitIP: exitIP, ExitLocation: exitLocation}
			}(p)
		}
		wg.Wait()
		close(ch)
	}()

	return ch
}

// ValidateOne 验证单个代理是否可用，返回是否有效、延迟、出口IP和地理位置
func (v *Validator) ValidateOne(p storage.Proxy) (bool, time.Duration, string, string) {
	var client *http.Client
	var err error

	// Normalize protocol: lowercase compare, https shares http validation path
	normalized := strings.ToLower(strings.TrimSpace(p.Protocol))
	if normalized == "https" {
		normalized = "http"
	}

	switch normalized {
	case "http":
		client, err = newHTTPClient(p.Address, v.timeout)
	case "socks5":
		client, err = newSOCKS5Client(p.Address, v.timeout)
	default:
		log.Printf("[validator] unknown protocol %s (normalized %s) for %s", p.Protocol, normalized, p.Address)
		return false, 0, "", ""
	}

	if err != nil {
		return false, 0, "", ""
	}
	defer client.CloseIdleConnections()

	start := time.Now()
	resp, err := client.Get(v.validateURL)
	latency := time.Since(start)
	if err != nil {
		return false, 0, "", ""
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	// 验证状态码（200 或 204 都接受）
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return false, latency, "", ""
	}

	// 响应时间过滤
	if v.maxResponseMs > 0 && latency > time.Duration(v.maxResponseMs)*time.Millisecond {
		return false, latency, "", ""
	}

	// 获取出口 IP 和地理位置（仅在验证通过时）
	exitIP, exitLocation := getExitIPInfo(client)
	
	// 必须能获取到出口信息
	if exitIP == "" || exitLocation == "" {
		return false, latency, exitIP, exitLocation
	}
	
	// 地理过滤：白名单优先，否则走黑名单
	if v.cfg != nil && len(exitLocation) >= 2 {
		countryCode := exitLocation[:2]
		if len(v.cfg.AllowedCountries) > 0 {
			// 白名单模式：不在白名单中则拒绝
			allowed := false
			for _, a := range v.cfg.AllowedCountries {
				if countryCode == a {
					allowed = true
					break
				}
			}
			if !allowed {
				return false, latency, exitIP, exitLocation
			}
		} else if len(v.cfg.BlockedCountries) > 0 {
			// 黑名单模式
			for _, blocked := range v.cfg.BlockedCountries {
				if countryCode == blocked {
					return false, latency, exitIP, exitLocation
				}
			}
		}
	}

	// HTTP 代理额外检测：必须支持 HTTPS CONNECT 隧道 (https nodes share this path)
	if normalized == "http" {
		if !checkHTTPSConnect(p.Address, v.timeout) {
			return false, latency, exitIP, exitLocation
		}
	}
	// SOCKS5 同样过 HTTPS 隧道与证书校验
	if normalized == "socks5" {
		if !checkHTTPSConnectSOCKS5(p.Address, v.timeout) {
			return false, latency, exitIP, exitLocation
		}
	}

	return true, latency, exitIP, exitLocation
}

func newHTTPClient(address string, timeout time.Duration) (*http.Client, error) {
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", address))
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: timeout,
	}, nil
}

func newSOCKS5Client(address string, timeout time.Duration) (*http.Client, error) {
	dialer, err := proxy.SOCKS5("tcp", address, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport: &http.Transport{
			Dial: dialer.Dial,
		},
		Timeout: timeout,
	}, nil
}
