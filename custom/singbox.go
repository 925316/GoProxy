package custom

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SingBoxInsecure 全局强制 sing-box 出站跳过 TLS 证书验证
// （复刻旧版 easy-proxies 的 skip_cert_verify: true 行为，由 config 注入）
var SingBoxInsecure bool

// SingBoxProcess 管理 sing-box 子进程
type SingBoxProcess struct {
	cmd        *exec.Cmd
	binPath    string
	configDir  string
	configFile string
	basePort   int
	portMap    map[string]int // nodeKey → 本地端口
	nodes      []ParsedNode
	mu         sync.Mutex
	running    bool
}

// NewSingBoxProcess 创建 sing-box 进程管理器
func NewSingBoxProcess(binPath, dataDir string, basePort int) *SingBoxProcess {
	if dataDir == "" {
		// 没设置 DATA_DIR 时，使用当前工作目录下的 singbox/
		wd, _ := os.Getwd()
		dataDir = wd
	}
	configDir, _ := filepath.Abs(filepath.Join(dataDir, "singbox"))
	os.MkdirAll(configDir, 0755)

	return &SingBoxProcess{
		binPath:    binPath,
		configDir:  configDir,
		configFile: filepath.Join(configDir, "config.json"),
		basePort:   basePort,
		portMap:    make(map[string]int),
	}
}

// Reload 重新加载节点配置并重启 sing-box
func (s *SingBoxProcess) Reload(nodes []ParsedNode) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 过滤出需要 sing-box 转换的节点
	var tunnelNodes []ParsedNode
	for _, n := range nodes {
		if !n.IsDirect() {
			tunnelNodes = append(tunnelNodes, n)
		}
	}

	if len(tunnelNodes) == 0 {
		log.Println("[custom] 无需 sing-box 转换的节点，停止进程")
		s.stopLocked()
		s.nodes = nil
		s.portMap = make(map[string]int)
		return nil
	}

	// 生成配置
	if err := s.generateConfig(tunnelNodes); err != nil {
		return fmt.Errorf("生成 sing-box 配置失败: %w", err)
	}

	// 重启进程
	s.stopLocked()
	if err := s.startLocked(); err != nil {
		return fmt.Errorf("启动 sing-box 失败: %w", err)
	}

	s.nodes = tunnelNodes
	return nil
}

// generateConfig 生成 sing-box JSON 配置
func (s *SingBoxProcess) generateConfig(nodes []ParsedNode) error {
	s.portMap = make(map[string]int)
	port := s.basePort

	var inbounds []map[string]interface{}
	var outbounds []map[string]interface{}
	var rules []map[string]interface{}

	for i, node := range nodes {
		port++
		key := node.NodeKey()
		s.portMap[key] = port
		tag := fmt.Sprintf("node-%d", i)

		// 入站：本地 SOCKS5 监听
		inbounds = append(inbounds, map[string]interface{}{
			"type":        "socks",
			"tag":         fmt.Sprintf("in-%s", tag),
			"listen":      "127.0.0.1",
			"listen_port": port,
		})

		// 出站：根据节点类型生成
		outbound := buildOutbound(node, tag)
		if outbound == nil {
			log.Printf("[custom] 跳过不支持的节点类型: %s (%s)", node.Name, node.Type)
			delete(s.portMap, key)
			continue
		}
		outbounds = append(outbounds, outbound)

		// 路由规则：入站 → 出站
		rules = append(rules, map[string]interface{}{
			"inbound":  []string{fmt.Sprintf("in-%s", tag)},
			"outbound": fmt.Sprintf("out-%s", tag),
		})
	}

	// 添加 direct 出站作为默认
	outbounds = append(outbounds, map[string]interface{}{
		"type": "direct",
		"tag":  "direct",
	})

	config := map[string]interface{}{
		"log": map[string]interface{}{
			"level": "warn",
		},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route": map[string]interface{}{
			"rules": rules,
			"final": "direct",
		},
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(s.configFile, data, 0644)
}

// buildOutbound 根据节点类型构建 sing-box 出站配置
func buildOutbound(node ParsedNode, tag string) map[string]interface{} {
	raw := node.Raw
	out := map[string]interface{}{
		"tag":    fmt.Sprintf("out-%s", tag),
		"server": node.Server,
	}

	// sing-box 使用 server_port 而不是 port
	out["server_port"] = node.Port

	switch node.Type {
	case "vmess":
		out["type"] = "vmess"
		out["uuid"] = getStr(raw, "uuid")
		out["alter_id"] = getInt(raw, "alterId")
		out["security"] = getStrDefault(raw, "cipher", "auto")
		applyTLS(raw, out)
		applyTransport(raw, out)

	case "vless":
		out["type"] = "vless"
		out["uuid"] = getStr(raw, "uuid")
		out["flow"] = getStr(raw, "flow")
		applyTLS(raw, out)
		applyTransport(raw, out)

	case "trojan":
		out["type"] = "trojan"
		out["password"] = getStr(raw, "password")
		applyTLS(raw, out)
		applyTransport(raw, out)

	case "shadowsocks":
		out["type"] = "shadowsocks"
		out["method"] = getStr(raw, "cipher")
		out["password"] = getStr(raw, "password")
		if plugin := getStr(raw, "plugin"); plugin != "" {
			out["plugin"] = plugin
			if pluginOpts, ok := raw["plugin-opts"].(map[string]interface{}); ok {
				out["plugin_opts"] = convertPluginOpts(plugin, pluginOpts)
			}
		}

	case "hysteria2":
		out["type"] = "hysteria2"
		out["password"] = getStr(raw, "password")
		applyTLS(raw, out)

	case "hysteria":
		out["type"] = "hysteria"
		out["auth_str"] = getStr(raw, "auth-str")
		if up := getStr(raw, "up"); up != "" {
			out["up_mbps"] = parseSpeed(up)
		}
		if down := getStr(raw, "down"); down != "" {
			out["down_mbps"] = parseSpeed(down)
		}
		applyTLS(raw, out)

	case "tuic":
		out["type"] = "tuic"
		out["uuid"] = getStr(raw, "uuid")
		out["password"] = getStr(raw, "password")
		out["congestion_control"] = getStrDefault(raw, "congestion-controller", "bbr")
		applyTLS(raw, out)

	case "anytls":
		out["type"] = "anytls"
		out["password"] = getStr(raw, "password")
		// anytls 强制启用 TLS
		forceTLS(raw, out)

	default:
		return nil
	}

	return out
}

// forceTLS 强制应用 TLS 配置（用于 anytls 等必须 TLS 的协议）
func forceTLS(raw map[string]interface{}, out map[string]interface{}) {
	raw["tls"] = true
	applyTLS(raw, out)
}

// applyTLS 应用 TLS 配置
func applyTLS(raw map[string]interface{}, out map[string]interface{}) {
	tls := getBool(raw, "tls")
	// 如果有 sni/alpn/client-fingerprint 也视为需要 TLS
	if !tls && getStr(raw, "sni") == "" && getStr(raw, "client-fingerprint") == "" {
		return
	}

	tlsConfig := map[string]interface{}{
		"enabled": true,
	}

	if sni := getStr(raw, "sni"); sni != "" {
		tlsConfig["server_name"] = sni
	} else if servername := getStr(raw, "servername"); servername != "" {
		tlsConfig["server_name"] = servername
	}

	if getBool(raw, "skip-cert-verify") || SingBoxInsecure {
		tlsConfig["insecure"] = true
	}

	if alpn, ok := raw["alpn"].([]interface{}); ok {
		var alpnStrs []string
		for _, a := range alpn {
			if s, ok := a.(string); ok {
				alpnStrs = append(alpnStrs, s)
			}
		}
		if len(alpnStrs) > 0 {
			tlsConfig["alpn"] = alpnStrs
		}
	}

	if fp := getStr(raw, "client-fingerprint"); fp != "" {
		tlsConfig["utls"] = map[string]interface{}{
			"enabled":     true,
			"fingerprint": fp,
		}
	}

	// reality 配置
	if realityOpts, ok := raw["reality-opts"].(map[string]interface{}); ok {
		tlsConfig["reality"] = map[string]interface{}{
			"enabled":    true,
			"public_key": getStr(realityOpts, "public-key"),
			"short_id":   getStr(realityOpts, "short-id"),
		}
	}

	out["tls"] = tlsConfig
}

// applyTransport 应用传输层配置
func applyTransport(raw map[string]interface{}, out map[string]interface{}) {
	network := getStrDefault(raw, "network", "tcp")

	switch network {
	case "ws":
		transport := map[string]interface{}{
			"type": "ws",
		}
		if wsOpts, ok := raw["ws-opts"].(map[string]interface{}); ok {
			if path := getStr(wsOpts, "path"); path != "" {
				transport["path"] = path
			}
			if headers, ok := wsOpts["headers"].(map[string]interface{}); ok {
				transport["headers"] = headers
			}
		}
		out["transport"] = transport

	case "grpc":
		transport := map[string]interface{}{
			"type": "grpc",
		}
		if grpcOpts, ok := raw["grpc-opts"].(map[string]interface{}); ok {
			if sn := getStr(grpcOpts, "grpc-service-name"); sn != "" {
				transport["service_name"] = sn
			}
		}
		out["transport"] = transport

	case "h2":
		transport := map[string]interface{}{
			"type": "http",
		}
		if h2Opts, ok := raw["h2-opts"].(map[string]interface{}); ok {
			if path := getStr(h2Opts, "path"); path != "" {
				transport["path"] = path
			}
			if host, ok := h2Opts["host"].([]interface{}); ok && len(host) > 0 {
				if h, ok := host[0].(string); ok {
					transport["host"] = []string{h}
				}
			}
		}
		out["transport"] = transport

	case "httpupgrade":
		transport := map[string]interface{}{
			"type": "httpupgrade",
		}
		if wsOpts, ok := raw["ws-opts"].(map[string]interface{}); ok {
			if path := getStr(wsOpts, "path"); path != "" {
				transport["path"] = path
			}
			if headers, ok := wsOpts["headers"].(map[string]interface{}); ok {
				if host, ok := headers["Host"].(string); ok {
					transport["host"] = host
				}
			}
		}
		out["transport"] = transport
	}
}

// convertPluginOpts 转换 shadowsocks 插件选项
func convertPluginOpts(plugin string, opts map[string]interface{}) string {
	var parts []string
	for k, v := range opts {
		parts = append(parts, fmt.Sprintf("%s=%v", k, v))
	}
	return strings.Join(parts, ";")
}

// startLocked 启动 sing-box（需持有锁）
func (s *SingBoxProcess) startLocked() error {
	binPath, err := exec.LookPath(s.binPath)
	if err != nil {
		return fmt.Errorf("sing-box 未找到: %s（请安装 sing-box 或设置 SINGBOX_PATH）", s.binPath)
	}

	// 先检查配置是否有效
	checkCmd := exec.Command(binPath, "check", "-c", s.configFile, "-D", s.configDir)
	if checkOutput, err := checkCmd.CombinedOutput(); err != nil {
		log.Printf("[custom] ❌ sing-box 配置检查失败:\n%s", string(checkOutput))
		return fmt.Errorf("sing-box 配置无效: %s", string(checkOutput))
	}

	s.cmd = exec.Command(binPath, "run", "-c", s.configFile, "-D", s.configDir)

	// 捕获 stderr 用于错误诊断
	stderrPipe, _ := s.cmd.StderrPipe()
	s.cmd.Stdout = os.Stdout

	if err := s.cmd.Start(); err != nil {
		return fmt.Errorf("sing-box 启动失败: %w", err)
	}
	s.running = true

	// 异步读取 stderr 并输出到日志
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stderrPipe.Read(buf)
			if n > 0 {
				log.Printf("[sing-box] %s", strings.TrimSpace(string(buf[:n])))
			}
			if err != nil {
				break
			}
		}
	}()

	// 监控进程退出
	exitCh := make(chan struct{})
	go func() {
		if s.cmd != nil && s.cmd.Process != nil {
			s.cmd.Wait()
			s.mu.Lock()
			s.running = false
			s.mu.Unlock()
		}
		close(exitCh)
	}()

	// 等待端口就绪（最多 10 秒）
	log.Printf("[custom] sing-box 启动中，等待端口就绪（配置: %s）...", s.configFile)
	ready := false
	for i := 0; i < 20; i++ {
		// 检查进程是否已退出
		select {
		case <-exitCh:
			return fmt.Errorf("sing-box 进程启动后立即退出，请检查日志")
		default:
		}

		time.Sleep(500 * time.Millisecond)
		// 检查第一个端口是否可连
		for _, port := range s.portMap {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
			if err == nil {
				conn.Close()
				ready = true
				break
			}
		}
		if ready {
			break
		}
	}

	if !ready {
		log.Println("[custom] ⚠️ sing-box 端口未就绪，部分节点可能不可用")
	} else {
		log.Printf("[custom] ✅ sing-box 启动成功，管理 %d 个节点", len(s.portMap))
	}

	return nil
}

// stopLocked 停止 sing-box（需持有锁）
func (s *SingBoxProcess) stopLocked() {
	if s.cmd != nil && s.cmd.Process != nil && s.running {
		log.Println("[custom] 停止 sing-box 进程...")
		s.cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() {
			s.cmd.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			s.cmd.Process.Kill()
		}
		s.running = false
	}
}

// Stop 停止 sing-box
func (s *SingBoxProcess) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopLocked()
}

// IsRunning 检查进程是否运行中
func (s *SingBoxProcess) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// GetLocalAddress 获取节点的本地 SOCKS5 地址
func (s *SingBoxProcess) GetLocalAddress(nodeKey string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if port, ok := s.portMap[nodeKey]; ok {
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	}
	return ""
}

// GetPortMap 获取所有端口映射
func (s *SingBoxProcess) GetPortMap() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make(map[string]int, len(s.portMap))
	for k, v := range s.portMap {
		result[k] = v
	}
	return result
}

// GetNodeCount 获取管理的节点数
func (s *SingBoxProcess) GetNodeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.portMap)
}

// 辅助函数

func getStr(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getStrDefault(m map[string]interface{}, key, def string) string {
	if s := getStr(m, key); s != "" {
		return s
	}
	return def
}

func getInt(m map[string]interface{}, key string) int {
	if v, ok := m[key]; ok {
		switch val := v.(type) {
		case int:
			return val
		case float64:
			return int(val)
		case string:
			n, _ := strconv.Atoi(val)
			return n
		}
	}
	return 0
}

func getBool(m map[string]interface{}, key string) bool {
	if v, ok := m[key]; ok {
		switch val := v.(type) {
		case bool:
			return val
		case string:
			return val == "true"
		}
	}
	return false
}

func parseSpeed(s string) int {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, " Mbps")
	s = strings.TrimSuffix(s, "Mbps")
	n, _ := strconv.Atoi(s)
	if n == 0 {
		n = 100 // 默认 100 Mbps
	}
	return n
}
