package custom

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParsedNode 解析后的代理节点
type ParsedNode struct {
	Name   string                 // 节点名称
	Type   string                 // vmess/trojan/ss/vless/hysteria2/http/socks5 等
	Server string                 // 远程服务器地址
	Port   int                    // 远程服务器端口
	Raw    map[string]interface{} // 原始配置字段（用于生成 sing-box 配置）
}

// NodeKey 节点去重 key
func (n *ParsedNode) NodeKey() string {
	return fmt.Sprintf("%s:%s:%d", n.Type, n.Server, n.Port)
}

// IsDirect 是否可以直接作为代理使用（不需要 sing-box 转换）
func (n *ParsedNode) IsDirect() bool {
	return n.Type == "http" || n.Type == "socks5"
}

// DirectAddress 返回直接代理的地址
func (n *ParsedNode) DirectAddress() string {
	return net.JoinHostPort(n.Server, strconv.Itoa(n.Port))
}

// DirectProtocol 返回直接代理的协议名
func (n *ParsedNode) DirectProtocol() string {
	if n.Type == "socks5" {
		return "socks5"
	}
	return "http"
}

// Parse 解析订阅内容（全自动检测格式）
func Parse(data []byte, format string) ([]ParsedNode, error) {
	// 无论用户选择什么格式，都走自动检测
	return parseAutoDetect(data)
}

// parseAutoDetect 自动检测订阅格式并解析
func parseAutoDetect(data []byte) ([]ParsedNode, error) {
	content := strings.TrimSpace(string(data))
	log.Printf("[custom] 自动检测格式: 内容长度=%d", len(content))

	// 1. 尝试 Clash YAML
	if looksLikeYAML(content) {
		log.Println("[custom] 检测到 Clash YAML 格式")
		nodes, err := parseClash(data)
		if err == nil && len(nodes) > 0 {
			return nodes, nil
		}
		log.Printf("[custom] YAML 解析无有效节点，继续尝试其他格式...")
	}

	// 2. 直接包含协议链接（vmess://、vless:// 等）
	if looksLikeProxyLinks(content) {
		log.Println("[custom] 检测到协议链接格式")
		return parseProxyLinks(content)
	}

	// 3. 尝试 Base64 解码
	decoded, err := tryBase64Decode(content)
	if err != nil {
		return nil, fmt.Errorf("无法识别订阅内容格式（非 YAML / 非协议链接 / 非 Base64）")
	}

	decodedStr := strings.TrimSpace(string(decoded))
	if decodedStr == "" {
		return nil, fmt.Errorf("Base64 解码后内容为空")
	}
	log.Printf("[custom] Base64 解码成功: %d bytes", len(decoded))

	// 解码后是 YAML？
	if looksLikeYAML(decodedStr) {
		log.Println("[custom] Base64 解码后为 Clash YAML 格式")
		return parseClash(decoded)
	}

	// 解码后是协议链接？
	if looksLikeProxyLinks(decodedStr) {
		log.Println("[custom] Base64 解码后为协议链接格式")
		return parseProxyLinks(decodedStr)
	}

	// 解码后尝试纯文本
	nodes, err := parsePlain(decoded)
	if err == nil && len(nodes) > 0 {
		return nodes, nil
	}

	return nil, fmt.Errorf("无法识别订阅内容格式")
}

func safePreview(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// looksLikeProxyLinks 判断内容是否包含代理协议链接
func looksLikeProxyLinks(s string) bool {
	return strings.Contains(s, "vmess://") ||
		strings.Contains(s, "vless://") ||
		strings.Contains(s, "trojan://") ||
		strings.Contains(s, "ss://") ||
		strings.Contains(s, "ssr://") ||
		strings.Contains(s, "hysteria2://") ||
		strings.Contains(s, "hy2://") ||
		strings.Contains(s, "tuic://") ||
		strings.Contains(s, "anytls://") ||
		strings.Contains(s, "socks5://") ||
		strings.Contains(s, "http://") ||
		strings.Contains(s, "https://")
}

// clashConfig Clash YAML 配置结构（兼容新旧格式）
type clashConfig struct {
	Proxies    []map[string]interface{} `yaml:"proxies"`
	ProxyOld   []map[string]interface{} `yaml:"Proxy"`    // 旧版 Clash 格式
}

// getProxies 兼容获取代理列表
func (c *clashConfig) getProxies() []map[string]interface{} {
	if len(c.Proxies) > 0 {
		return c.Proxies
	}
	return c.ProxyOld
}

// parseClash 解析 Clash YAML 格式
func parseClash(data []byte) ([]ParsedNode, error) {
	content := strings.TrimSpace(string(data))

	// 打印前 100 字符帮助调试
	preview := content
	if len(preview) > 100 {
		preview = preview[:100]
	}
	log.Printf("[custom] 订阅内容预览: %s...", preview)

	// 自动检测：如果内容不像 YAML（不以常见 YAML 字段开头），尝试 base64 解码
	if !looksLikeYAML(content) {
		log.Println("[custom] 内容不像 YAML，尝试 Base64 解码...")
		decoded, err := tryBase64Decode(content)
		if err == nil && looksLikeYAML(string(decoded)) {
			log.Println("[custom] Base64 解码成功，使用解码后的 YAML")
			data = decoded
		} else {
			log.Println("[custom] Base64 解码后仍不是 YAML，按原始内容解析")
		}
	}

	// 使用 yaml.Node 解析，精确提取 proxies 列表
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("解析 Clash YAML 失败: %w", err)
	}

	var proxies []map[string]interface{}
	proxies = extractProxiesFromNode(&doc)

	if len(proxies) == 0 {
		log.Printf("[custom] ⚠️ YAML 中未找到有效的代理节点（内容长度: %d 字节）", len(data))
	} else {
		log.Printf("[custom] 从 YAML 中提取到 %d 个代理节点", len(proxies))
	}

	var nodes []ParsedNode
	for _, proxy := range proxies {
		node, err := parseClashProxy(proxy)
		if err != nil {
			log.Printf("[custom] 跳过无效节点: %v", err)
			continue
		}
		nodes = append(nodes, *node)
	}

	log.Printf("[custom] Clash YAML 解析完成，共 %d 个节点", len(nodes))
	return nodes, nil
}

// extractProxiesFromNode 从 yaml.Node 树中提取 proxies 列表
func extractProxiesFromNode(doc *yaml.Node) []map[string]interface{} {
	if doc == nil {
		return nil
	}

	// doc 是 DocumentNode，内容在 Content[0]（MappingNode）
	var root *yaml.Node
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		root = doc.Content[0]
	} else if doc.Kind == yaml.MappingNode {
		root = doc
	} else {
		return nil
	}

	// 在 MappingNode 中找 proxies 或 Proxy key
	for i := 0; i < len(root.Content)-1; i += 2 {
		keyNode := root.Content[i]
		valNode := root.Content[i+1]
		if keyNode.Value == "proxies" || keyNode.Value == "Proxy" {
			log.Printf("[custom] 找到 %s 字段: kind=%d tag=%s 子节点数=%d",
				keyNode.Value, valNode.Kind, valNode.Tag, len(valNode.Content))

			// 把 proxies 段的原始 YAML 写到临时文件方便调试
			debugData, _ := yaml.Marshal(valNode)
			os.WriteFile("/tmp/goproxy_debug_proxies.yaml", debugData, 0644)
			log.Printf("[custom] 调试: proxies 原始数据已写入 /tmp/goproxy_debug_proxies.yaml (%d bytes)", len(debugData))

			if valNode.Kind != yaml.SequenceNode {
				log.Printf("[custom] proxies 字段不是列表（kind=%d tag=%s）", valNode.Kind, valNode.Tag)
				return nil
			}
			// 每个 item 是一个 MappingNode，解码为 map
			var proxies []map[string]interface{}
			for idx, itemNode := range valNode.Content {
				var m map[string]interface{}
				if err := itemNode.Decode(&m); err != nil {
					log.Printf("[custom] 解码代理节点 #%d 失败: %v (kind=%d tag=%s)", idx, err, itemNode.Kind, itemNode.Tag)
					continue
				}
				proxies = append(proxies, m)
			}
			log.Printf("[custom] 成功解码 %d/%d 个代理节点", len(proxies), len(valNode.Content))
			return proxies
		}
	}
	log.Printf("[custom] 遍历 %d 个顶级 key 未找到 proxies", len(root.Content)/2)
	return nil
}

// looksLikeYAML 判断内容是否看起来像 YAML/Clash 配置
func looksLikeYAML(s string) bool {
	s = strings.TrimSpace(s)
	// Clash YAML 通常包含 proxies: 或 port: 或以 # 注释开头
	return strings.Contains(s, "proxies:") ||
		strings.Contains(s, "proxy-groups:") ||
		strings.HasPrefix(s, "port:") ||
		strings.HasPrefix(s, "mixed-port:") ||
		strings.HasPrefix(s, "#") ||
		strings.HasPrefix(s, "---")
}

// tryBase64Decode 尝试多种 Base64 变体解码
func tryBase64Decode(s string) ([]byte, error) {
	// 去掉所有空白字符（换行、回车、空格）再解码
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, " ", "")
	// 标准 Base64
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	// URL-safe Base64
	if decoded, err := base64.URLEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	// 无填充 Base64
	if decoded, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	// 无填充 URL-safe
	if decoded, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	return nil, fmt.Errorf("Base64 解码失败")
}

// parseClashProxy 解析单个 Clash 代理节点
func parseClashProxy(proxy map[string]interface{}) (*ParsedNode, error) {
	name, _ := proxy["name"].(string)
	typ, _ := proxy["type"].(string)
	server, _ := proxy["server"].(string)

	if typ == "" || server == "" {
		return nil, fmt.Errorf("缺少 type 或 server 字段")
	}

	port := 0
	switch v := proxy["port"].(type) {
	case int:
		port = v
	case float64:
		port = int(v)
	case string:
		p, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("无效端口: %s", v)
		}
		port = p
	default:
		return nil, fmt.Errorf("缺少 port 字段")
	}

	// 标准化类型名
	typ = strings.ToLower(typ)
	switch typ {
	case "ss":
		typ = "shadowsocks"
	case "ssr":
		typ = "shadowsocksr"
	}

	// 支持的类型
	supported := map[string]bool{
		"vmess": true, "vless": true, "trojan": true,
		"shadowsocks": true, "shadowsocksr": true,
		"hysteria": true, "hysteria2": true, "tuic": true,
		"anytls": true,
		"http": true, "socks5": true,
	}
	if !supported[typ] {
		return nil, fmt.Errorf("不支持的代理类型: %s", typ)
	}

	return &ParsedNode{
		Name:   name,
		Type:   typ,
		Server: server,
		Port:   port,
		Raw:    proxy,
	}, nil
}

// parseBase64 解析 Base64 编码的纯文本
func parseBase64(data []byte) ([]ParsedNode, error) {
	// 尝试标准 Base64 解码
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		// 尝试 URL-safe Base64
		decoded, err = base64.URLEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			// 尝试无填充的 Base64
			decoded, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(data)))
			if err != nil {
				return nil, fmt.Errorf("Base64 解码失败: %w", err)
			}
		}
	}
	return parsePlain(decoded)
}

// parsePlain 解析纯文本格式（每行一个 IP:PORT）
func parsePlain(data []byte) ([]ParsedNode, error) {
	lines := strings.Split(string(data), "\n")
	var nodes []ParsedNode

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		protocol := "http"
		addr := line

		// 解析协议前缀
		if strings.HasPrefix(line, "socks5://") {
			protocol = "socks5"
			addr = strings.TrimPrefix(line, "socks5://")
		} else if strings.HasPrefix(line, "socks4://") {
			protocol = "socks5" // socks4 当 socks5 处理
			addr = strings.TrimPrefix(line, "socks4://")
		} else if strings.HasPrefix(line, "http://") {
			protocol = "http"
			addr = strings.TrimPrefix(line, "http://")
		} else if strings.HasPrefix(line, "https://") {
			protocol = "http"
			addr = strings.TrimPrefix(line, "https://")
		}

		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}

		nodes = append(nodes, ParsedNode{
			Name:   addr,
			Type:   protocol,
			Server: host,
			Port:   port,
			Raw:    map[string]interface{}{"type": protocol, "server": host, "port": port},
		})
	}

	log.Printf("[custom] 纯文本解析完成，共 %d 个节点", len(nodes))
	return nodes, nil
}

// parseProxyLinks 解析协议链接格式（vmess://, trojan://, ss://, vless:// 等）
func parseProxyLinks(content string) ([]ParsedNode, error) {
	lines := strings.Split(content, "\n")
	var nodes []ParsedNode

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		node, err := parseProxyLink(line)
		if err != nil {
			continue
		}
		nodes = append(nodes, *node)
	}

	log.Printf("[custom] 协议链接解析完成，共 %d 个节点", len(nodes))
	return nodes, nil
}

// parseProxyLink 解析单个协议链接
func parseProxyLink(link string) (*ParsedNode, error) {
	link = strings.TrimSpace(link)

	switch {
	case strings.HasPrefix(link, "vmess://"):
		return parseVmessLink(link)
	case strings.HasPrefix(link, "vless://"):
		return parseStandardLink(link, "vless")
	case strings.HasPrefix(link, "trojan://"):
		return parseStandardLink(link, "trojan")
	case strings.HasPrefix(link, "ss://"):
		return parseShadowsocksLink(link)
	case strings.HasPrefix(link, "hysteria2://"), strings.HasPrefix(link, "hy2://"):
		return parseStandardLink(link, "hysteria2")
	case strings.HasPrefix(link, "tuic://"):
		return parseStandardLink(link, "tuic")
	case strings.HasPrefix(link, "anytls://"):
		return parseStandardLink(link, "anytls")
	case strings.HasPrefix(link, "socks5://"), strings.HasPrefix(link, "socks5h://"):
		return parseDirectLink(link, "socks5")
	case strings.HasPrefix(link, "http://"), strings.HasPrefix(link, "https://"):
		return parseDirectLink(link, "http")
	default:
		return nil, fmt.Errorf("不支持的协议链接: %s", link[:min(20, len(link))])
	}
}

// parseDirectLink 解析直连代理链接（socks5://、http://、https://）
// 这类节点无需 sing-box 转换，直接以 address:port 形式入池
func parseDirectLink(link string, typ string) (*ParsedNode, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("链接解析失败: %w", err)
	}
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	if host == "" || port == 0 {
		return nil, fmt.Errorf("缺少 host 或 port: %s", link[:min(20, len(link))])
	}
	name := u.Fragment
	if name == "" {
		name = net.JoinHostPort(host, strconv.Itoa(port))
	}
	return &ParsedNode{
		Name:   name,
		Type:   typ,
		Server: host,
		Port:   port,
		Raw:    map[string]interface{}{"type": typ, "server": host, "port": port},
	}, nil
}

// parseVmessLink 解析 vmess:// 链接（V2rayN JSON base64 格式）
func parseVmessLink(link string) (*ParsedNode, error) {
	encoded := strings.TrimPrefix(link, "vmess://")
	decoded, err := tryBase64Decode(encoded)
	if err != nil {
		return nil, fmt.Errorf("vmess base64 解码失败: %w", err)
	}

	var info map[string]interface{}
	if err := json.Unmarshal(decoded, &info); err != nil {
		return nil, fmt.Errorf("vmess JSON 解析失败: %w", err)
	}

	server := fmt.Sprintf("%v", info["add"])
	portStr := fmt.Sprintf("%v", info["port"])
	port, _ := strconv.Atoi(portStr)
	name := fmt.Sprintf("%v", info["ps"])
	if name == "" || name == "<nil>" {
		name = server
	}

	// 构建 Clash 兼容的 raw 配置
	raw := map[string]interface{}{
		"type":   "vmess",
		"name":   name,
		"server": server,
		"port":   port,
		"uuid":   fmt.Sprintf("%v", info["id"]),
		"alterId": getInt(info, "aid"),
		"cipher": getStrDefault(info, "scy", "auto"),
	}

	// TLS
	if fmt.Sprintf("%v", info["tls"]) == "tls" {
		raw["tls"] = true
		if sni, ok := info["sni"]; ok {
			raw["sni"] = sni
		}
	}

	// 传输层
	net := getStrDefault(info, "net", "tcp")
	raw["network"] = net
	if net == "ws" {
		wsOpts := map[string]interface{}{}
		if path := getStr(info, "path"); path != "" {
			wsOpts["path"] = path
		}
		if host := getStr(info, "host"); host != "" {
			wsOpts["headers"] = map[string]interface{}{"Host": host}
		}
		raw["ws-opts"] = wsOpts
	} else if net == "grpc" {
		grpcOpts := map[string]interface{}{}
		if path := getStr(info, "path"); path != "" {
			grpcOpts["grpc-service-name"] = path
		}
		raw["grpc-opts"] = grpcOpts
	}

	return &ParsedNode{
		Name:   name,
		Type:   "vmess",
		Server: server,
		Port:   port,
		Raw:    raw,
	}, nil
}

// parseStandardLink 解析标准 URI 格式链接（vless://, trojan://, hysteria2://, tuic://）
// 格式: protocol://userinfo@host:port?params#fragment
func parseStandardLink(link string, typ string) (*ParsedNode, error) {
	// 去除协议前缀，统一处理
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("链接解析失败: %w", err)
	}

	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 443
	}
	name := u.Fragment
	if name == "" {
		name = host
	}

	raw := map[string]interface{}{
		"type":   typ,
		"name":   name,
		"server": host,
		"port":   port,
	}

	// 用户信息（password/uuid）
	if u.User != nil {
		password := u.User.Username()
		if typ == "trojan" || typ == "hysteria2" || typ == "anytls" {
			raw["password"] = password
		} else if typ == "vless" || typ == "tuic" {
			raw["uuid"] = password
			if p, ok := u.User.Password(); ok {
				raw["password"] = p // tuic 的 password
			}
		}
	}

	// 查询参数
	params := u.Query()

	// TLS
	security := params.Get("security")
	if security == "" {
		security = params.Get("type") // 有些链接用 type 表示
	}
	if security != "none" && security != "" || typ == "trojan" || typ == "hysteria2" || typ == "anytls" {
		raw["tls"] = true
		if sni := params.Get("sni"); sni != "" {
			raw["sni"] = sni
		}
		if fp := params.Get("fp"); fp != "" {
			raw["client-fingerprint"] = fp
		}
		if alpn := params.Get("alpn"); alpn != "" {
			raw["alpn"] = strings.Split(alpn, ",")
		}
		if params.Get("allowInsecure") == "1" || params.Get("insecure") == "1" {
			raw["skip-cert-verify"] = true
		}
	}

	// Reality
	if security == "reality" {
		raw["tls"] = true
		realityOpts := map[string]interface{}{}
		if pbk := params.Get("pbk"); pbk != "" {
			realityOpts["public-key"] = pbk
		}
		if sid := params.Get("sid"); sid != "" {
			realityOpts["short-id"] = sid
		}
		raw["reality-opts"] = realityOpts
	}

	// 传输层
	netType := params.Get("type")
	if netType == "" {
		netType = "tcp"
	}
	raw["network"] = netType

	if netType == "ws" {
		wsOpts := map[string]interface{}{}
		if path := params.Get("path"); path != "" {
			wsOpts["path"] = path
		}
		if host := params.Get("host"); host != "" {
			wsOpts["headers"] = map[string]interface{}{"Host": host}
		}
		raw["ws-opts"] = wsOpts
	} else if netType == "grpc" {
		grpcOpts := map[string]interface{}{}
		if sn := params.Get("serviceName"); sn != "" {
			grpcOpts["grpc-service-name"] = sn
		}
		raw["grpc-opts"] = grpcOpts
	}

	// Hysteria2 特有
	if typ == "hysteria2" {
		if obfs := params.Get("obfs"); obfs != "" {
			raw["obfs"] = obfs
			raw["obfs-password"] = params.Get("obfs-password")
		}
	}

	// VLESS flow
	if typ == "vless" {
		if flow := params.Get("flow"); flow != "" {
			raw["flow"] = flow
		}
	}

	return &ParsedNode{
		Name:   name,
		Type:   typ,
		Server: host,
		Port:   port,
		Raw:    raw,
	}, nil
}

// parseShadowsocksLink 解析 ss:// 链接
// 格式1: ss://base64(method:password)@host:port#name
// 格式2: ss://base64(method:password@host:port)#name
func parseShadowsocksLink(link string) (*ParsedNode, error) {
	link = strings.TrimPrefix(link, "ss://")

	// 分离 fragment (节点名)
	name := ""
	if idx := strings.Index(link, "#"); idx >= 0 {
		name, _ = url.QueryUnescape(link[idx+1:])
		link = link[:idx]
	}

	var server, method, password string
	var port int

	// 尝试格式1: base64(method:password)@host:port
	if idx := strings.LastIndex(link, "@"); idx >= 0 {
		userInfo := link[:idx]
		hostPort := link[idx+1:]

		// 解码 userInfo
		decoded, err := tryBase64Decode(userInfo)
		if err != nil {
			// 可能未编码
			decoded = []byte(userInfo)
		}
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) == 2 {
			method = parts[0]
			password = parts[1]
		}

		// 分离 host:port（去掉查询参数）
		if qIdx := strings.Index(hostPort, "?"); qIdx >= 0 {
			hostPort = hostPort[:qIdx]
		}
		h, p, err := net.SplitHostPort(hostPort)
		if err != nil {
			return nil, fmt.Errorf("ss 地址解析失败: %w", err)
		}
		server = h
		port, _ = strconv.Atoi(p)
	} else {
		// 格式2: 整个 base64 编码
		if qIdx := strings.Index(link, "?"); qIdx >= 0 {
			link = link[:qIdx]
		}
		decoded, err := tryBase64Decode(link)
		if err != nil {
			return nil, fmt.Errorf("ss base64 解码失败: %w", err)
		}
		// method:password@host:port
		s := string(decoded)
		atIdx := strings.LastIndex(s, "@")
		if atIdx < 0 {
			return nil, fmt.Errorf("ss 格式无效")
		}
		parts := strings.SplitN(s[:atIdx], ":", 2)
		if len(parts) == 2 {
			method = parts[0]
			password = parts[1]
		}
		h, p, err := net.SplitHostPort(s[atIdx+1:])
		if err != nil {
			return nil, fmt.Errorf("ss 地址解析失败: %w", err)
		}
		server = h
		port, _ = strconv.Atoi(p)
	}

	if name == "" {
		name = server
	}

	raw := map[string]interface{}{
		"type":     "ss",
		"name":     name,
		"server":   server,
		"port":     port,
		"cipher":   method,
		"password": password,
	}

	return &ParsedNode{
		Name:   name,
		Type:   "shadowsocks",
		Server: server,
		Port:   port,
		Raw:    raw,
	}, nil
}
