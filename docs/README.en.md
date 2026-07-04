# Claude Environment Check (Unofficial)

> 中文说明: [README.md](../README.md)

**Claude Environment Check** is an unofficial diagnostic toolkit for **Claude Code / Anthropic** usage environments. It focuses on helping Mainland China users inspect whether their PC, browser, network route, proxy/VPN, DNS, TLS, WebSocket, public egress IP, timezone, locale, and language signals may cause Claude Code connection failures, region restrictions, environment detection, or account-environment risk.

This project provides:

- **PC / desktop version**: deeper local checks for Windows and future desktop platforms.
- **Standalone web version**: open a URL and run browser-side checks immediately, with limited browser permissions.

This project does **not** claim to know Anthropic's private risk engine. It only reports observable facts and conservative heuristic conclusions. It is not an evasion tool.

## Download

Latest Windows / PC build:

[Download from GitHub Releases](https://github.com/TZZ520/claude-environment-check/releases/latest)

Run after unzip:

~~~text
build/bin/ClaudeEnvironmentCheck.exe
~~~

Included CLI tools:

~~~text
build/bin/claude-env-check.exe
build/bin/probe-server.exe
~~~

## Web version

[https://tzz520.github.io/claude-environment-check/](https://tzz520.github.io/claude-environment-check/)

The web version can check browser language, timezone, public egress IP, basic Anthropic connectivity, WebSocket/probe observations, DNS resolver egress when a Probe is available, and browser-to-Probe TLS/JA3 metadata. It cannot read local system proxy, PAC, CA store, DNS config, or Claude Code installation state.

## What it checks

Desktop version:

- OS, architecture, timezone, locale, language, code page.
- System DNS and Mainland-China DNS signals.
- Proxy environment variables and system proxy traces, with credentials redacted.
- Public egress IP, country, ASN, and organization.
- Anthropic API endpoint reachability.
- TLS certificate, ALPN, cipher, and diagnostic fingerprint information.
- WebSocket connectivity.
- Claude Code installation/version when available.
- Optional authenticated API check only when explicitly enabled by the user.

Web version:

- Browser language, timezone, UTC offset, number/date format, platform.
- Basic Anthropic endpoint reachability via browser requests.
- Public egress IP through Probe or public fallback.
- WebSocket egress consistency.
- Browser-to-Probe TLS/JA3 observation.
- DNS resolver egress observation through one-time DNS tokens.
- Conservative IP type classification: only clearly residential/static-like ISP exits pass; cloud, datacenter, VPN, proxy, shared, mobile, or unknown exits are treated as risk.

## Privacy and safety

This tool is a diagnostic tool, not a proxy, tunnel, injector, credential collector, or traffic hijacker.

It does **not**:

- Steal API keys.
- Store API keys on disk.
- Send API keys to the self-hosted Probe.
- Read private local files.
- Modify proxy, DNS, certificate store, hosts file, or system network settings.
- Hijack, redirect, or MITM traffic.
- Install background services without user action.

Reports may include public IP, country/ASN, browser language, timezone, and diagnostic network evidence. Review exported reports before sharing.

## SEO keywords

Claude Code environment checker, Claude Code diagnostic tool, Claude Code China checker, Claude Code Mainland China test, Anthropic region check, Anthropic access test, Anthropic blocked region diagnostic, Anthropic API reachability test, Claude Code proxy test, Claude Code VPN test, Claude Code DNS leak test, Claude Code TLS fingerprint check, Claude Code JA3 test, Claude Code WebSocket test, Claude Code network diagnostic, Claude Code account risk environment check, Claude Code ban risk self-check, Claude Code usage readiness score, Claude Code smooth usage checker, Claude Code connection troubleshooting, Claude Code firewall test, Claude Code region exposure score, Claude Code device environment score, AI CLI network diagnostic, Windows Claude Code checker, browser Claude Code checker, web-based Claude environment test, residential IP check, static residential IP checker, datacenter IP risk test, public cloud IP risk detection, shared proxy risk check, DNS pollution detection, DNS resolver leak, TLS certificate inspection, browser JA3 fingerprint, WebSocket egress test, China user environment check.

## Disclaimer

This is an unofficial community diagnostic project. It is not affiliated with Anthropic. It does not bypass access controls, does not provide evasion instructions, and does not guarantee account safety. Always follow Anthropic's official terms, supported-location policy, and applicable local laws.
