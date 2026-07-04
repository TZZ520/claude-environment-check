# Claude Environment Check / Claude 环境检测工具

> Unofficial diagnostic toolkit for checking whether a PC or browser network environment looks suitable for Claude Code, with a special focus on Mainland China users who may face region restrictions, network blocking, DNS leakage, proxy misconfiguration, and device-region exposure.
>
> 非官方 Claude Code 环境诊断工具，重点面向中国大陆地区用户：检测当前 PC 或浏览器网络环境是否容易暴露中国大陆地区信号，是否可能受到地区限制、网络阻断、DNS 泄漏、代理配置异常、设备地区环境不匹配等问题影响。



## Keywords / 搜索关键词

Claude Code environment checker, Claude Code diagnostic tool, Anthropic region check, Anthropic access test, Claude China region detection, Mainland China Claude Code check, Claude Code proxy test, Claude Code VPN test, Claude Code DNS leak test, Claude Code TLS fingerprint check, Claude Code WebSocket test, AI CLI network diagnostic, Claude Code unblock readiness, Claude Code usage environment, residential IP check, static residential IP checker, proxy quality test, VPN quality test, DNS pollution detection, DNS resolver leak, JA3 browser fingerprint, Anthropic API reachability, Claude Code risk score, China user environment check, cross-platform Claude checker, web-based Claude environment test.

Claude Code 环境检测、Claude Code 诊断工具、Anthropic 地区检测、Anthropic 访问测试、Claude 中国地区检测、中国大陆 Claude Code 检测、Claude Code 代理检测、Claude Code VPN 检测、Claude Code DNS 泄漏检测、Claude Code TLS 指纹检测、Claude Code WebSocket 检测、AI CLI 网络诊断、Claude Code 使用环境评分、Claude Code 顺利使用检测、住宅 IP 检测、静态住宅 IP 检测、代理质量检测、VPN 质量检测、DNS 污染检测、DNS 解析器泄漏、JA3 浏览器指纹、Anthropic API 可达性检测、Claude Code 风险评分、中国用户环境检测、跨平台 Claude 检测工具、网页版 Claude 环境检测、本地端 Claude 环境检测、Claude Code 防封环境自检、Claude Code 账号风险环境检测。

## Why this project exists / 为什么做这个项目

Claude Code and Anthropic services are widely reported by users to be sensitive to supported-location policy, public egress IP, proxy/VPN quality, DNS behavior, TLS behavior, locale, timezone, and device environment. For users in Mainland China, this often creates a frustrating experience: even when a proxy is configured, DNS, browser settings, system language, timezone, or non-residential IP signals may still expose the real environment.

This project is built to make those signals visible. It does **not** claim to know Anthropic's private risk engine or internal enforcement algorithm. It only reports observable facts and conservative heuristic conclusions.

Claude Code / Anthropic 服务经常被用户反馈与支持地区政策、公网出口 IP、代理/VPN 质量、DNS 行为、TLS 行为、系统语言、时区、设备环境等因素相关。对中国大陆用户来说，这种限制和环境识别非常不友好：即使配置了代理，DNS、浏览器地区、系统语言、时区、非住宅 IP 等信号仍可能暴露真实环境。

本项目的目的就是把这些信号可视化。它**不声称掌握 Anthropic 内部风控算法**，只展示可观测事实和保守的启发式判断。

## What it checks / 可以检测什么

### Desktop app / PC 本地端

The desktop version is for Windows/macOS/Linux style local diagnosis. The current packaged build focuses on Windows.

桌面端用于本机完整诊断，目前已打包 Windows 版本。

It can check:

- Device timezone, locale, language, code page, text/format habits.
- System DNS servers and known Mainland China DNS signals.
- Proxy environment variables and system proxy traces, with credentials redacted.
- Public egress IP, country, ASN, and organization.
- Claude/Anthropic endpoint reachability.
- TLS certificate, ALPN, cipher, and diagnostic fingerprint information.
- WebSocket connectivity.
- Claude Code installation/version when available.
- Optional authenticated API check only when the user explicitly provides a key.

可检测：

- 电脑时区、语言、地区、代码页、文字格式习惯。
- 系统 DNS 和常见中国大陆 DNS 信号。
- 代理环境变量、系统代理痕迹，并自动脱敏账号密码。
- 公网出口 IP、国家、ASN、运营商组织。
- Claude / Anthropic 官方接口可达性。
- TLS 证书、ALPN、加密套件、诊断指纹。
- WebSocket 连接能力。
- Claude Code 是否安装及版本。
- 仅在用户主动提供时执行 API Key 认证检测。

### Standalone web version / 独立网页版

The web version lives in `web/`. It is independent from the Windows desktop app. After deployment, users can open a URL and run browser-side checks directly.

网页版源码位于 `web/`，与 Windows 桌面端完全独立。部署后用户打开网址即可直接检测浏览器网络环境。

It can check:

- Browser language, timezone, UTC offset, number/date format, platform.
- Anthropic endpoint basic connectivity using browser `no-cors` requests.
- Public egress IP via self-hosted Probe or public fallback service.
- WebSocket egress consistency through the Probe.
- Browser-to-Probe TLS/JA3 observation.
- DNS resolver egress observation through a one-time authoritative DNS token.
- Conservative IP type classification: only clearly residential/static-like ISP exits pass; cloud, datacenter, VPN, proxy, shared, mobile, or unknown exits are treated as risk.

网页版可检测：

- 浏览器语言、时区、UTC 偏移、数字/日期格式、平台。
- 使用浏览器 `no-cors` 请求检测 Anthropic 基础连通性。
- 通过自建 Probe 或公开回退服务观察公网出口。
- 通过 Probe 比较 WebSocket 出口。
- 观察浏览器访问 Probe 时的 TLS/JA3 信息。
- 通过一次性权威 DNS token 观察 DNS 解析器出口。
- 保守判断 IP 类型：只有明确住宅/静态住宅倾向的运营商出口通过；云服务器、机房、VPN、代理、共享、移动或未知出口均按风险处理。

## Privacy and safety / 隐私与安全

This tool is designed as a diagnostic tool, not a proxy, tunnel, injector, credential collector, or traffic hijacker.

本工具是诊断工具，不是代理、隧道、注入器、凭据收集器，也不会劫持网络。

It does **not**:

- Steal API keys.
- Store API keys on disk.
- Send API keys to the self-hosted Probe.
- Read private local files.
- Modify your proxy, DNS, certificate store, hosts file, or system network settings.
- Hijack, redirect, or MITM your traffic.
- Install background services without your action.

它**不会**：

- 窃取 API Key。
- 把 API Key 写入磁盘。
- 把 API Key 发送给自建 Probe。
- 读取本地私人文件。
- 修改代理、DNS、证书库、hosts 或系统网络设置。
- 劫持、重定向或中间人拦截你的网络流量。
- 未经用户操作安装后台服务。

Reports may include public IP, country/ASN, browser language, timezone, and diagnostic network evidence. Review exported reports before sharing.

报告可能包含公网 IP、国家/ASN、浏览器语言、时区和网络诊断证据，分享前请自行检查。

## Scores / 评分说明

The tool displays:

- **Working likelihood / 顺利使用可能性**: how closely the environment matches a target Claude Code usage profile.
- **Mainland exposure likelihood / 大陆环境暴露可能性**: how strongly the current exit route, DNS, browser/system locale, timezone, and related signals look Mainland-China-like.
- **Coverage / 检测完整度**: how many checks actually completed. Unknown checks reduce coverage instead of pretending to pass.

工具展示：

- **顺利使用可能性**：当前环境与目标 Claude Code 使用环境的匹配程度。
- **大陆环境暴露可能性**：出口、DNS、语言、时区等信号像中国大陆环境的程度。
- **检测完整度**：本次实际完成了多少检测。测不到会降低完整度，不会伪装成通过。

## Quick start / 快速开始

### Windows desktop / Windows 桌面端

Download the Windows package from Releases, unzip it, and run:

从 Releases 下载 Windows 包，解压后运行：

```text
build/bin/ClaudeEnvironmentCheck.exe
```

CLI tools are also included:

同时包含 CLI 工具：

```text
build/bin/claude-env-check.exe
build/bin/probe-server.exe
```

### Web version / 网页版

Build locally:

本地构建：

```powershell
cd web
npm install
npm run build
npm run preview
```

Deploy `web/dist` to any static hosting provider, or use the included GitHub Pages workflow.

部署 `web/dist` 到任意静态网页托管服务，也可以使用仓库内置 GitHub Pages 工作流。

### Probe server / 自建 Probe

The Probe server is optional but recommended for the web version. Without it, the browser can only perform limited checks.

Probe 服务可选但推荐，尤其是网页版。没有 Probe 时，浏览器只能做有限检测。

```powershell
go run ./cmd/probe-server --listen :8443 --cert cert.pem --key key.pem --dns-zone dns-probe.example.com.
```

Production notes:

生产注意事项：

- Terminate TLS directly on the Probe if you want useful TLS/JA3 observations.
- Do not put the Probe behind a CDN that rewrites TLS if TLS diagnosis matters.
- Authoritative DNS only responds for its own zone and does not recurse.
- Sessions are short-lived and in-memory by default.

## Project layout / 项目结构

```text
frontend/        Desktop UI for Wails / 桌面端 UI
web/             Standalone browser-only web app / 独立网页版
internal/        Go scanner, scoring, rules, probe server / Go 检测核心
cmd/             CLI and Probe server entrypoints / CLI 与 Probe 入口
docs/            Documentation / 文档
packaging/       Packaging templates / 打包模板
.github/         CI, release, GitHub Pages workflows / 自动化工作流
```

## Status / 当前状态

- Windows desktop build: available.
- CLI: available.
- Standalone web version: available.
- Probe server: available.
- Android version: planned, not implemented yet.

- Windows 桌面端：已可用。
- CLI：已可用。
- 独立网页版：已可用。
- Probe 服务：已可用。
- Android 端：计划中，暂未实现。

## Disclaimer / 免责声明

This is an unofficial community diagnostic project. It is not affiliated with Anthropic. It does not bypass access controls, does not provide evasion instructions, and does not guarantee account safety. Always follow Anthropic's official terms, supported-location policy, and applicable local laws.

这是非官方社区诊断项目，与 Anthropic 无关。本项目不绕过访问控制，不提供规避教程，也不保证账号安全。请遵守 Anthropic 官方条款、支持地区政策和当地法律。

