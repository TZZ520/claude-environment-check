# 诊断排查记录

## 这次为什么 UI 显示“暂未测到”

已用旧版 CLI 实测过一次：实时连接能力可以测到，并返回正常；代理路径检查显示“暂未测到”的直接原因是旧版程序只用单一公网出口观察方法，直连路径在 Go HTTP 客户端里超时，导致直连出口 IP 为空。

随后用 curl 交叉验证：

- 直连出口可以被多个服务测到：`113.244.64.51`
- 代理出口可以被多个服务测到：`125.230.97.10`
- WebSocket 至少一个公共测试端点 443 可达，另一个端点当前 DNS 失败

所以问题不是“这几项不能测”，而是旧版检测方法太单一、前端旧包还存在空值/乱码导致的显示问题。

## 已补的多方法检测

- 公网出口：`api64.ipify.org`、`checkip.amazonaws.com`、`icanhazip.com`、`ifconfig.me/ip`
- Claude 官方接口：`https://api.anthropic.com/`、`https://api.anthropic.com/v1/models`
- DNS：系统解析 + Cloudflare DoH + Google DoH + Quad9 DoH
- WebSocket：`wss://ws.postman-echo.com/raw`、`wss://echo.websocket.events/`
- 代理：TCP 端口、HTTP/HTTPS CONNECT、带 Basic 认证的 CONNECT、SOCKS5 握手与目标连接
- 前端：报告字段统一空值兜底，避免部分检测失败时黑屏

## 可参考的开源项目

- [gorilla/websocket](https://github.com/gorilla/websocket)：Go WebSocket 客户端/服务端，当前项目已使用。
- [miekg/dns](https://github.com/miekg/dns)：Go DNS 库，适合自建权威 DNS 探针，当前项目已使用。
- [dreadl0ck/ja3](https://github.com/dreadl0ck/ja3)：Go JA3 指纹实现，BSD-3-Clause，可作为未来“诊断客户端指纹”参考。
- [salesforce/ja3](https://github.com/salesforce/ja3)：JA3 原始标准实现，BSD-3-Clause。
- [projectdiscovery/tlsx](https://github.com/projectdiscovery/tlsx)：TLS 信息采集工具，MIT，可参考 TLS 证书/ALPN/握手采集结构。
- [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx)：多方法 HTTP 探测工具，MIT，可参考重试和探测结果结构。
- `golang.org/x/net/proxy`：官方扩展库，可用于更完整的 SOCKS5 Dialer。

注意：搜索结果里有不少项目明确用于伪装、绕过或规避风控。这个工具只做诊断和解释性评分，不应直接引入绕过逻辑。

## GitHub 高级搜索语句

```text
"Claude Code" Anthropic region lock
"api.anthropic.com" "HTTP 451" OR "region" language:Go
JA3 ClientHello fingerprint language:Go
"gorilla/websocket" "ProxyURL" "Dialer" language:Go
"dns-query?name=" "cloudflare-dns.com" language:Go
"ipify" "checkip.amazonaws.com" public ip language:Go
"SOCKS5" "CONNECT" "api.anthropic.com" language:Go
```

## 当前构建状态

前端已通过：

```powershell
cd frontend
npm run build
```

本机当前没有可用 Go。官方下载 zip 与 winget 下载在当前网络下卡住或校验失败，Chocolatey 因非管理员和锁文件失败。因此本次没有生成新版 exe。

安装 Go 后，在项目根目录运行：

```powershell
go test ./...
go build -trimpath -ldflags "-s -w" -o build\bin\claude-env-check.exe ./cmd/claude-env-check
go build -trimpath -ldflags "-s -w" -o build\bin\probe-server.exe ./cmd/probe-server
go install github.com/wailsapp/wails/v2/cmd/wails@latest
wails build -clean -webview2 embed -trimpath -o ClaudeEnvironmentCheck.exe -v 1
```
