# GoProxy

> **智能代理池系统** — 基于 Go 的轻量级、自适应代理池服务，支持免费代理自动抓取 + 付费订阅导入

[![GitHub Container Registry](https://img.shields.io/badge/GHCR-latest-blue?logo=github)](https://github.com/925316/GoProxy/pkgs/container/goproxy)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go)](https://go.dev/)

GoProxy 从公开代理源自动抓取 HTTP/SOCKS5 代理，同时支持导入 Clash/V2ray 付费订阅，通过出口 IP + 地理位置 + 延迟三重验证后统一入池，对外提供 HTTP 和 SOCKS5 双协议代理服务。

**GitHub**：[github.com/925316/GoProxy](https://github.com/925316/GoProxy)

![](https://cdn.amux.ai/data/1322149f78ab57adb821ce731c11a9e944504649.png)

## 核心特性

### 双池架构

- **免费代理池** — 自动从 20+ 公开源抓取，质量分级（S/A/B/C），智能补充与替换
- **订阅代理池** — 导入 Clash/V2ray 订阅，通过 sing-box 自动转换加密协议（vmess/vless/trojan/ss/hysteria2/anytls 等）为本地 SOCKS5 代理
- **5 种使用模式** — 混合·订阅优先 / 混合·免费优先 / 混合·平等 / 仅订阅 / 仅免费，WebUI 随时切换

### 智能池子管理

- **固定容量 + 动态状态** — Healthy → Warning → Critical → Emergency 四级自适应
- **严格准入** — 出口 IP + 地理位置 + 延迟验证，HTTP 代理额外验证 HTTPS CONNECT 隧道
- **自动优化** — 按需抓取（Emergency/Refill/Optimize 三模式），定时替换慢代理
- **故障自愈** — 请求失败自动切换代理重试（最多 3 次），用户无感知

### 订阅管理

- **格式自动识别** — Clash YAML / V2ray 链接 / Base64 / 纯文本，无需手动选格式
- **sing-box 内置** — Docker 镜像自带 sing-box，加密协议节点自动转为本地 SOCKS5
- **软删除机制** — 订阅代理失败不删除只禁用，定时探测唤醒恢复
- **访客贡献** — 未登录用户可贡献订阅 URL/文件，管理员统一管理
- **自动清理** — 连续 7 天无可用节点的订阅自动移除

### 多端口多协议

| 端口 | 协议 | 模式 | 适用场景 |
|------|------|------|---------|
| 7777 | HTTP | 随机轮换 | 爬虫、数据采集、IP 多样性 |
| 7776 | HTTP | 最低延迟 | 长连接、流媒体、稳定优先 |
| 7779 | SOCKS5 | 随机轮换 | 浏览器、SSH、游戏 |
| 7780 | SOCKS5 | 最低延迟 | 稳定应用、固定连接 |
| 7778 | HTTP | WebUI | 管理面板（双角色权限） |

### WebUI 仪表盘

- 免费池 / 订阅池分离展示，实时状态监控
- 订阅管理：添加 URL / 上传文件 / 刷新 / 暂停 / 删除
- 系统设置：5 种代理模式切换、池子参数、地理过滤
- 双角色权限：访客只读 + 管理员完全控制
- 中英文切换

## 快速开始

### Docker 部署（推荐）

```bash
# 一键启动（自动拉取最新镜像）
docker compose up -d

# 访问 WebUI
# http://localhost:7778（默认密码：goproxy）
```

自定义配置：

```bash
cp .env.example .env
vim .env  # 修改密码、认证、地理过滤等
docker compose up -d
```

### 本地运行

```bash
# 需要 Go 1.25 + CGO（依赖 go-sqlite3）
go run .

# 或编译后运行
go build -o proxygo . && ./proxygo
```

> 如需订阅导入功能，本地需安装 [sing-box](https://sing-box.sagernet.org/)：`brew install sing-box`

## 使用代理

### HTTP 代理

```bash
# 随机轮换（IP 多样性）
curl -x http://localhost:7777 https://httpbin.org/ip

# 最低延迟（稳定优先）
curl -x http://localhost:7776 https://httpbin.org/ip

# 环境变量方式
export http_proxy=http://localhost:7777
export https_proxy=http://localhost:7777
```

### SOCKS5 代理

```bash
# 随机轮换
curl --socks5 localhost:7779 https://httpbin.org/ip

# 最低延迟
curl --socks5 localhost:7780 https://httpbin.org/ip

# 环境变量方式
export ALL_PROXY=socks5://localhost:7779
```

### 带认证使用

```bash
# HTTP
curl -x http://user:pass@your-server:7777 https://httpbin.org/ip

# SOCKS5
curl --socks5 user:pass@your-server:7779 https://httpbin.org/ip

# 环境变量
export http_proxy=http://user:pass@your-server:7777
export ALL_PROXY=socks5://user:pass@your-server:7779
```

### 编程语言示例

**Python**：
```python
import requests

# HTTP 代理
proxies = {'http': 'http://localhost:7777', 'https': 'http://localhost:7777'}
requests.get('https://httpbin.org/ip', proxies=proxies)

# SOCKS5 代理（需 pip install requests[socks]）
proxies = {'http': 'socks5://localhost:7779', 'https': 'socks5://localhost:7779'}
requests.get('https://httpbin.org/ip', proxies=proxies)
```

**Node.js**：
```javascript
// SOCKS5（需 npm install socks-proxy-agent node-fetch）
const { SocksProxyAgent } = require('socks-proxy-agent');
const fetch = require('node-fetch');
const agent = new SocksProxyAgent('socks5://localhost:7779');
fetch('https://httpbin.org/ip', { agent }).then(r => r.json()).then(console.log);
```

**浏览器 / SSH**：
```bash
# 浏览器：设置 → 代理 → SOCKS5 → localhost:7779
# SSH 隧道：
ssh -o ProxyCommand='nc -X 5 -x localhost:7779 %h %p' user@remote-server
```

## 订阅导入

通过 WebUI 管理订阅（管理员登录后）：

1. **订阅 URL** — 填入 Clash/V2ray 订阅地址，自动识别格式并解析
2. **上传文件** — 拖拽或选择 Clash YAML / V2ray 配置文件

支持的节点协议：vmess、vless、trojan、shadowsocks、hysteria2、anytls、http、socks5

订阅代理与免费代理的区别：
- 健康检查失败 → 禁用（不删除），定时探测唤醒
- 不受免费池 slot 容量限制
- 地理过滤 → 禁用（不删除）
- 连续 7 天无可用节点 → 自动移除订阅

访客可通过顶部「贡献订阅」按钮分享自己的订阅 URL 或配置文件。

## Docker 部署详解

### docker run 方式

```bash
docker run -d --name proxygo \
  -p 7776:7776 -p 7777:7777 -p 7778:7778 -p 7779:7779 -p 7780:7780 \
  -e WEBUI_PASSWORD=your_password \
  -e PROXY_AUTH_ENABLED=true \
  -e PROXY_AUTH_USERNAME=myuser \
  -e PROXY_AUTH_PASSWORD=mypass \
  -v goproxy-data:/app/data \
  ghcr.io/925316/goproxy:latest
```

### 数据持久化

- docker-compose 使用 Named Volume `goproxy-data`，容器重启/更新不丢数据
- 数据包含：SQLite 数据库（代理池）、config.json（配置）、sing-box 配置

**备份**：
```bash
docker run --rm -v goproxy-data:/data -v $(pwd):/backup \
  alpine tar czf /backup/goproxy-backup-$(date +%Y%m%d).tar.gz -C /data .
```

**恢复**：
```bash
docker compose down
docker run --rm -v goproxy-data:/data -v $(pwd):/backup \
  alpine sh -c "cd /data && tar xzf /backup/goproxy-backup-*.tar.gz"
docker compose up -d
```

### 安全建议

| 场景 | 建议 |
|------|------|
| 公网部署 | 启用代理认证 + 修改 WebUI 密码 |
| 内网部署 | 启用代理认证 或 防火墙白名单 |
| 本地测试 | 默认配置即可 |

## 环境变量

| 变量 | 默认值 | 必须 | 说明 |
|------|--------|------|------|
| `WEBUI_PASSWORD` | `goproxy` | 是 | WebUI 登录密码，生产环境务必修改 |
| `PROXY_AUTH_ENABLED` | `false` | 否 | 代理认证开关，公网部署建议启用 |
| `PROXY_AUTH_USERNAME` | `proxy` | 否 | 代理认证用户名 |
| `PROXY_AUTH_PASSWORD` | 空 | 否 | 代理认证密码，启用认证时必填 |
| `BLOCKED_COUNTRIES` | `CN` | 否 | 屏蔽国家代码（逗号分隔，留空不屏蔽） |
| `ALLOWED_COUNTRIES` | 空 | 否 | 允许国家白名单（非空时优先于黑名单） |
| `CUSTOM_PROXY_MODE` | `mixed` | 否 | 代理模式：mixed / custom_only / free_only |
| `SINGBOX_PATH` | `sing-box` | 否 | sing-box 路径（Docker 内置，无需修改） |
| `TZ` | `Asia/Shanghai` | 否 | 时区 |

完整配置见 [.env.example](.env.example)，更多池子参数可通过 WebUI 设置面板调整。

## 项目结构

```text
main.go                    # 入口，协调所有模块
├── config/                # 配置（环境变量 + config.json）
├── storage/               # SQLite 持久化（proxies + subscriptions + source_status）
├── fetcher/               # 多源代理抓取 + 断路器
├── validator/             # 代理验证（连接 + IP + 地理 + 延迟）
├── pool/                  # 池子管理（准入 + 替换 + 状态机）
├── checker/               # 健康检查（free 删除 / custom 禁用）
├── optimizer/             # 质量优化（仅免费池）
├── custom/                # 订阅管理
│   ├── parser.go          #   格式自动识别解析
│   ├── singbox.go         #   sing-box 进程管理
│   └── manager.go         #   刷新循环 + 探测唤醒 + 过期清理
├── proxy/                 # 代理服务（HTTP + SOCKS5，4 端口）
├── webui/                 # 管理面板（嵌入式 HTML + REST API）
└── logger/                # 日志收集
```

## 扩展文档

- [架构设计文档](POOL_DESIGN.md) — 状态机、数据模型、选择策略、sing-box 集成
- [地理过滤配置](GEO_FILTER.md) — 国家代码、白名单/黑名单、测试方法
- [数据目录说明](DATA_DIRECTORY.md) — 数据库、配置文件、备份恢复
- [测试脚本](test/README.md) — HTTP + SOCKS5 测试脚本
- [更新日志](CHANGELOG.md) — 版本历史

## 免责声明

本项目仅供学习交流和技术研究使用。

- 本项目抓取的代理均来自互联网公开资源，不保证其可用性、稳定性和安全性
- 用户应自行承担使用本项目的一切风险，包括但不限于网络安全风险、法律风险等
- 请遵守当地法律法规，不得将本项目用于任何违法违规活动
- 订阅导入功能仅为方便用户管理自有代理资源，用户应确保其订阅来源合法合规
- 访客贡献的订阅由贡献者自行负责，项目维护者不对其内容承担任何责任
- 本项目不提供任何形式的代理服务，不对通过本系统传输的内容负责
- 作者不对因使用本项目造成的任何直接或间接损失承担责任

使用本项目即表示您已阅读并同意以上声明。

## 友情链接

- [LINUX DO](https://linux.do/) — 真诚、友善、团结、专业，共建你我引以为傲的社区

## License

[MIT](LICENSE)
