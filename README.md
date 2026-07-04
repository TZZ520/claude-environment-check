# Claude Environment Check（非官方）中文环境检测工具

> 默认中文说明。English version: [README.en.md](docs/README.en.md)

**Claude Environment Check** 是一个面向 **Claude Code / Anthropic** 使用环境的非官方诊断工具，重点帮助中国大陆用户检查：当前电脑、浏览器、网络、代理/VPN、DNS、TLS、WebSocket、公网出口 IP、时区语言等信号，是否可能导致 Claude Code 无法正常连接、被地区限制、被环境识别、被误判为中国大陆环境，或者存在账号环境风险。

本项目包含两个版本：

- **PC 本地端 / Windows 桌面端**：检测能力更完整，适合认真排查电脑本机环境。
- **独立网页版**：打开网址即可检测，适合快速自测浏览器和当前网络出口，但权限有限。

> 说明：本项目不声称掌握 Anthropic 内部风控算法，只展示可观测事实和保守启发式判断。它不是绕过工具，不提供违规规避教程。

---

## 立即使用

### 1. 下载 PC / Windows 本地端

请到 GitHub Releases 下载 Windows 压缩包：

[下载最新版 Windows / PC 端](https://github.com/TZZ520/claude-environment-check/releases/latest)

下载后解压，运行：

~~~text
build/bin/ClaudeEnvironmentCheck.exe
~~~

压缩包里同时包含命令行工具：

~~~text
build/bin/claude-env-check.exe
build/bin/probe-server.exe
~~~

### 2. 打开网页版检测

网页版地址：

[https://tzz520.github.io/claude-environment-check/](https://tzz520.github.io/claude-environment-check/)

网页版不需要安装软件，直接打开网页即可检测。  
但网页版受浏览器权限限制，不能读取本机系统代理、PAC、本机 DNS 配置、证书库、Claude Code 安装状态等信息。

---

## 这个工具适合谁？

如果你搜索或遇到这些问题，本项目可能适合你：

- Claude Code 中国大陆能不能用？
- Claude Code 连不上、黑屏、卡住、请求失败怎么办？
- Anthropic / Claude Code 是否识别中国地区？
- 我的 VPN / 代理节点是否适合 Claude Code？
- DNS 是否泄漏到中国大陆解析器？
- 当前公网 IP 是住宅 IP、机房 IP、公共云 IP 还是高风险代理？
- 时区、系统语言、浏览器语言是否会暴露中国大陆使用习惯？
- Anthropic API 是否能正常连接？
- Claude Code 环境匹配度和大陆环境暴露风险分别是多少？

---

## 核心功能

### PC 本地端可检测

- 电脑系统、架构、时区、语言、区域格式、代码页。
- 系统 DNS、常见中国大陆 DNS 信号、DNS 泄漏迹象。
- 代理环境变量、系统代理痕迹，并自动脱敏账号密码。
- 公网出口 IP、国家/地区、ASN、运营商组织。
- Anthropic / Claude API 端点连通性。
- TLS 证书、ALPN、加密套件、诊断指纹。
- WebSocket 连接能力。
- Claude Code 是否安装及版本信息。
- 可选 API Key 认证检测：只在用户主动提供时运行，不保存密钥。

### 网页版可检测

- 浏览器语言、时区、UTC 偏移、日期/数字格式、平台信息。
- 浏览器访问 Anthropic 端点的基础连通性。
- 当前公网出口 IP。
- WebSocket 出口一致性。
- 浏览器连接 Probe 时的 TLS / JA3 观测。
- 通过一次性 DNS token 观察 DNS 解析器出口。
- IP 类型风险：仅明确住宅/静态住宅倾向时通过；机房、公有云、VPN、共享代理、移动网络、未知类型均提示风险。

---

## 评分说明

软件会显示三个核心结果：

1. **顺利使用可能性**  
   当前环境与目标 Claude Code 使用环境的匹配程度。分数越高，越接近“看起来正常”的使用环境。

2. **大陆环境暴露可能性**  
   当前出口 IP、DNS、语言、时区、系统/浏览器习惯等信号，看起来像中国大陆环境的程度。分数越高，风险越高。

3. **检测完整度**  
   本次实际完成了多少检查。测不到的项目会标记为“未知”并降低完整度，不会假装通过。

---

## 隐私与安全承诺

本工具是诊断工具，不是代理、隧道、注入器、抓包器或流量劫持器。

它不会：

- 窃取 API Key。
- 把 API Key 写入磁盘。
- 把 API Key 发送到自建 Probe。
- 读取你的私人本地文件。
- 修改你的代理、DNS、证书库、hosts 或系统网络设置。
- 劫持、重定向、中间人拦截你的网络流量。
- 未经用户操作安装后台服务。

导出的报告可能包含公网 IP、国家/ASN、浏览器语言、时区和网络诊断证据。分享前请自行检查。

---

## 搜索关键词

Claude Code 环境检测、Claude Code 诊断工具、Claude Code 中国检测、Claude Code 中国大陆检测、Claude Code 地区限制检测、Claude Code 是否能用、Claude Code 连不上排查、Claude Code 网络环境评分、Claude Code 顺利使用检测、Claude Code 防封环境自检、Claude Code 账号风险环境检测、Claude Code 大陆环境暴露检测、Claude Code 代理检测、Claude Code VPN 检测、Claude Code 节点质量检测、Claude Code 住宅 IP 检测、Claude Code 静态住宅 IP 检测、Claude Code 机房 IP 风险检测、Claude Code 公共云 IP 风险检测、Claude Code 共享代理风险检测、Claude Code DNS 泄漏检测、Claude Code DNS 污染检测、Claude Code TLS 指纹检测、Claude Code JA3 指纹检测、Claude Code WebSocket 检测、Claude Code API 可达性检测、Claude Code 时区语言检测、Claude Code 电脑环境检测、Claude Code 浏览器环境检测、Claude Code 网页版检测、Claude Code Windows 检测工具、Claude Code 桌面端检测工具、Anthropic 地区检测、Anthropic 中国地区检测、Anthropic 访问测试、Anthropic API 可达性检测、Anthropic 网络诊断、Anthropic 地区暴露风险、AI CLI 网络诊断、AI 编程工具网络检测、AI 代码助手网络检测、中国大陆用户环境检测、中国用户 Claude 使用环境自检、代理质量检测、VPN 质量检测、DNS 解析器泄漏、DNS 出口检测、TLS 证书检测、浏览器 JA3 指纹、跨平台 Claude 检测工具、GitHub Pages 在线检测工具。

---

## 项目结构

~~~text
frontend/        Wails 桌面端 UI
web/             独立网页版
internal/        Go 检测核心、评分、规则、Probe Server
cmd/             CLI 与 Probe Server 入口
docs/            文档
packaging/       打包模板
.github/         CI、Release、GitHub Pages 工作流
~~~

---

## 当前状态

- Windows / PC 本地端：可用。
- CLI：可用。
- 独立网页版：可用。
- Probe Server：可用。
- Android 端：计划中，暂未实现。

---

## 免责声明

这是非官方社区诊断项目，与 Anthropic 无关。本项目不绕过访问控制，不提供规避限制教程，也不保证账号安全。请遵守 Anthropic 官方条款、支持地区政策和适用法律。
