# 独立网页版环境检测

本目录说明的是独立网页版本，源码位于项目根目录的 `web/`。它和 Windows 桌面版没有 Wails、Go bridge 或 exe 依赖关系；部署后用户打开网址即可检测当前浏览器网络环境。

## 能检测什么

- 浏览器公开信息：语言、时区、UTC 偏移、数字/日期格式、浏览器平台。
- Claude 官方端点基础连通性：使用浏览器 `fetch(..., mode: "no-cors")` 判断 DNS/TCP/TLS 基础链路是否能完成。
- 自建 Probe 观测：公网出口 IP、国家/ASN、HTTP 连接、WebSocket 连接、服务端看到的浏览器 TLS/JA3 信息。
- DNS 出口观测：通过一次性子域触发浏览器解析，再查询 Probe 记录到的权威 DNS 请求来源。
- 出口 IP 类型启发式判断：只有明显住宅宽带/静态住宅倾向的出口通过；云服务器、机房、VPN、代理、共享出口或未知类型都按风险处理。

## 不能检测什么

浏览器安全模型禁止网页读取以下本机信息：

- 系统代理、PAC、代理认证信息。
- 本机 DNS 服务器配置。
- 操作系统 CA 信任库、企业证书或 TLS 中间人证书。
- Claude Code 是否安装、版本、登录状态或 `claude doctor` 输出。
- API Key、CLI 配置文件或本机私有文件。

这些项目在报告中显示为“未知/网页无法检测”，只降低检测完整度，不会被当作正常通过。

## 构建网页版本

在项目根目录运行：

```powershell
cd web
npm install
npm run build
npm run preview
```

输出目录为：

```text
web/dist
```

可以将 `web/dist` 部署到任意静态网页托管服务。若要获得完整的出口、WebSocket、DNS 和 TLS 观测能力，需要同时部署 Probe Server，并在网页输入框中填写 Probe 地址。

## Probe 要求

- Probe 需要直接终止 TLS，不建议放在会改写 TLS 信息的 CDN 后方。
- HTTPS 接口需要允许 CORS；服务端已经为 `/v1/session`、`/v1/observe`、`/v1/ws`、`/v1/session/{token}/dns` 返回浏览器所需 CORS 头。
- DNS 服务只响应自己的权威区域，不提供递归解析，避免成为 DNS 放大器。
- 会话默认只保存在内存中，10 分钟后删除。

## 隐私说明

网页版不会读取本机文件，也不会保存 API Key。报告可能包含公网 IP、国家/ASN、浏览器语言和时区。导出报告前请确认这些信息可以分享。

