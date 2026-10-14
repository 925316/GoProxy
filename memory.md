# Memory

## 部署形态（2026-10-13 实查）
- 服务器：DediRock 173.254.220.22，SSH 端口 48888，密钥 `~/.ssh/dedirock`，本地经 Clash 7890 连接（桌面 `connect-dedirock.bat`）。
- 编排：compose 目录 `docker.yaml`（桌面副本同源），服务 `cli-proxy-api` + `cpa-usage-keeper` + `goproxy`（本仓库容器化，数据 `./goproxy-data:/app/data`）。
- 流量链：probe.py → `rlkt.indevs.in` → cli-proxy-api:8317 → `socks5://goproxy:7780`（config.yaml 全局 proxy-url，容器名解析）→ 池内节点 → 目标站。WebUI 域名 `proxies.rlkt.indevs.in`，密码在 docker.yaml。
- 用户 Probe 脚本：`C:\Users\Hying\PycharmProjects\Tools\src\openai_compatible_tools\rlkt_model_probe.py`（base=https://rlkt.indevs.in/v1，20s 超时，失败死循环重试）。

## 关键修复（2026-10-13，未发布）
免费 MITM/黑洞节点不被清理的根因及修法：
1. validator 只对 HTTP 节点做 HTTPS 证书检查 → 补 SOCKS5 版（checkHTTPSConnectSOCKS5 + probeHTTPSGet）。
2. passive 只判"早关闭尸体"，20s 客户端超时（client-first）全面放生 → 新增 stall 判定（`PASSIVE_STALL_FLOOR_SEC`，默认 10s，客户端有上行、上游零下行、存活超限即 demerit 并计 fail_count）。
3. S 级节点被整批跳过体检（88/99 S 级），MITM 节点靠假低延迟永生 → 豁免只保零前科节点，批次按 fail_count DESC 插队。
4. fail_count 只增不减 + `fail_count<3` 过滤导致攒满节点永不清理、`DeleteInvalid` 是死代码 → 验证通过 ResetFail，体检末尾 DeleteInvalid 兜底。
5. **proxy/server.go 的 429 改动（RecordProxyUseNoFail）被还原过，待用户确认是否重新应用**。

## 协作偏好
- 注释一行以内，只写代码说不出的信息；不要写 rationale 小作文、不要叙述控制流、不要抒情。

## 待办 / 遗留
- 镜像需重新构建并更新 goproxy 容器才会生效（未执行构建，命令已给用户）。
- 订阅节点从服务器大面积 `dial i/o timeout`（sing-box out-node 报错），不在本次修复范围。
- goproxy 容器 `Up` 时间很短但日志量巨大（用户 probe 死循环刷屏）；2021 过期证书报错来自 MITM 节点。
