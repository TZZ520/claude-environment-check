import type { Check, Evidence, Report, Route, ScanOptions, Status } from './types'

type ProbeSession = { token: string; dns_name?: string }
type Observe = { ip?: string; country?: string; countryCode?: string; country_code?: string; asn?: string | number; organization?: string; tls?: Record<string, unknown>; http_version?: string }
type DNSObserve = { observed?: boolean; resolver_ip?: string; country?: string; country_code?: string; asn?: string | number; organization?: string }

export async function scanEnvironment(opts: ScanOptions): Promise<Report> {
  const started = Date.now()
  const timeoutMs = Math.max(3000, (Number(opts.timeout_seconds) || 8) * 1000)
  const platform = collectPlatform()
  const checks: Check[] = []
  const routes: Route[] = []
  const evidence: Evidence[] = []

  checks.push(browserProfileCheck(platform))

  const probe = normalizeProbe(opts.probe_url)
  let session: ProbeSession | null = null
  if (probe) {
    try {
      session = await withTimeout(createSession(probe), timeoutMs, 'Probe 会话超时')
      const obs = await withTimeout(observeProbe(probe, session.token), timeoutMs, 'Probe 出口观察超时')
      const route = routeFromObserve(obs, 'browser-probe', probe)
      routes.push(route)
      checks.push(check('route.web_probe', 'proxy', '网页观察到的公网出口', route.public_ip ? 'pass' : 'unknown', route.public_ip ? 'Probe 看到的公网出口：' + route.public_ip + ' ' + (route.country_code || '') : 'Probe 没有返回公网出口。', 20, Boolean(route.public_ip), probe, { observe: obs }))
      checks.push(check('tls.web_probe', 'tls', '浏览器 TLS 指纹观察', obs.tls ? 'pass' : 'unknown', obs.tls ? '已记录浏览器访问 Probe 时的 TLS/JA3 信息；这不代表 Claude Code 客户端。' : 'Probe 没有返回 TLS 信息。', 10, Boolean(obs.tls), probe, obs.tls || {}))
    } catch (err) {
      checks.push(unknown('route.web_probe', 'proxy', '网页观察到的公网出口', '自建 Probe 不可用：' + errorText(err), 20, probe))
      checks.push(unknown('tls.web_probe', 'tls', '浏览器 TLS 指纹观察', '没有可用 Probe，无法观察 TLS 指纹。', 10, probe))
    }
  } else {
    checks.push(unknown('route.web_probe', 'proxy', '网页观察到的公网出口', '未填写 Probe 地址，网页只能使用公开回退服务做有限检测。', 20, 'browser'))
    checks.push(unknown('tls.web_probe', 'tls', '浏览器 TLS 指纹观察', '未填写 Probe 地址，无法观察 TLS 指纹。', 10, 'browser'))
  }

  if (!routes.length && opts.public_fallback) {
    try {
      const route = await withTimeout(publicFallback(), timeoutMs, '公开 IP 服务超时')
      routes.push(route)
      checks.push(check('route.public_fallback', 'proxy', '公开服务看到的公网出口', route.public_ip ? 'warn' : 'unknown', route.public_ip ? '公开服务看到公网出口：' + route.public_ip + ' ' + (route.country_code || '') : '公开服务未返回公网出口。', 10, Boolean(route.public_ip), route.source || 'public', { route }))
    } catch (err) {
      checks.push(unknown('route.public_fallback', 'proxy', '公开服务看到的公网出口', '公开回退服务不可用：' + errorText(err), 10, 'public fallback'))
    }
  }

  const route = routes[0]
  checks.push(ipTypeCheck(route))

  if (probe && session) {
    const ws = await websocketCheck(probe, session.token, route?.public_ip, timeoutMs)
    checks.push(ws.check)
    if (route && ws.ip) {
      route.websocket = ws.check.status
      route.websocket_ip = ws.ip
    }
    checks.push(await dnsCheck(probe, session, timeoutMs))
  } else {
    checks.push(unknown('websocket.web_probe', 'websocket', 'WebSocket 出口观察', '未填写 Probe 地址，无法比较 WebSocket 出口。', 10, 'browser'))
    checks.push(unknown('dns.web_probe', 'dns', 'DNS 解析出口观察', '未填写 Probe 地址，无法观察 DNS 解析器出口。', 10, 'browser'))
  }

  checks.push(await anthropicCheck(timeoutMs))
  checks.push(unknown('local.proxy.web_limit', 'proxy', '系统代理/PAC 读取', '网页没有本地权限，不能读取系统代理、PAC 或代理认证信息。', 5, 'browser limitation'))
  checks.push(unknown('local.ca.web_limit', 'tls', '系统证书库读取', '网页没有本地权限，不能读取系统 CA、企业证书或证书替换情况。', 5, 'browser limitation'))
  checks.push(unknown('local.claude.web_limit', 'system', 'Claude Code 安装状态', '网页没有本地权限，不能检查 Claude Code 是否安装或登录。', 5, 'browser limitation'))

  const scores = calculateScore(checks, routes, platform, evidence)
  const limitations = [
    '网页版不能读取系统代理/PAC、本机 DNS 配置、CA 证书库、Claude Code 安装状态或 CLI 登录状态。',
    'Claude 官方服务检测使用浏览器 no-cors 请求，只判断基础连通性，无法读取真实 HTTP 状态码。',
    'TLS/JA3 只代表浏览器访问 Probe 时的观测结果，不代表 Claude Code 客户端。'
  ]
  const recommendations = []
  if (scores.compatibility_score < 70) recommendations.push('建议先查看红色/黄色项目，尤其是电脑地区环境、出口 IP 类型、DNS、WebSocket 和 Claude 官方服务连通性。')
  if (scores.region_exposure_score >= 50) recommendations.push('当前出现较明显中国大陆相关信号；请查看 Anthropic 官方支持地区政策，并只使用合规网络配置。')
  recommendations.push(...limitations)

  return {
    schema_version: '1.0.0',
    tool_version: '0.1.0-web',
    rules_version: '2026.07.04-web',
    generated_at: new Date().toISOString(),
    duration_ms: Date.now() - started,
    platform,
    routes,
    checks,
    compatibility_score: scores.compatibility_score,
    region_exposure_score: scores.region_exposure_score,
    coverage: scores.coverage,
    evidence,
    recommendations,
    privacy_redactions: ['API Key、代理密码、本机文件不会被网页读取或写入报告。'],
    metadata: { mode: 'standalone-web', limitations }
  }
}

function collectPlatform(): Record<string, unknown> {
  const intl = Intl.DateTimeFormat().resolvedOptions()
  const parts = new Intl.NumberFormat().formatToParts(12345.6)
  return {
    os: browserOS(),
    architecture: browserArch(),
    browser: browserName(),
    timezone: intl.timeZone || '',
    utc_offset: offset(),
    locale: navigator.language || intl.locale || '',
    system_locale: intl.locale || navigator.language || '',
    user_languages: Array.from(navigator.languages || []),
    format_settings: {
      decimal: parts.find(p => p.type === 'decimal')?.value || '',
      group: parts.find(p => p.type === 'group')?.value || '',
      calendar: intl.calendar,
      numbering_system: intl.numberingSystem
    },
    online: navigator.onLine,
    hardware_concurrency: navigator.hardwareConcurrency,
    device_memory_gb: (navigator as any).deviceMemory
  }
}

function browserProfileCheck(platform: Record<string, unknown>): Check {
  const cn = mainlandSignals(platform)
  const us = targetSignals(platform)
  if (cn.length) return check('browser.region_profile', 'system', '浏览器地区环境匹配', 'fail', '浏览器侧出现中国大陆相关语言、时区或格式信号。', 20, true, 'browser Intl/Navigator', { mainland_device_signals: cn, platform })
  if (us.length >= 2) return check('browser.region_profile', 'system', '浏览器地区环境匹配', 'pass', '浏览器语言和时区更接近目标环境。', 20, true, 'browser Intl/Navigator', { target_device_signals: us, platform })
  return check('browser.region_profile', 'system', '浏览器地区环境匹配', 'warn', '没有明显中国大陆信号，但也没有完全匹配目标环境。', 20, true, 'browser Intl/Navigator', { target_device_signals: us, platform })
}

async function createSession(probe: string): Promise<ProbeSession> {
  const r = await fetch(probe + '/v1/session', { method: 'POST', cache: 'no-store' })
  if (!r.ok) throw new Error('HTTP ' + r.status)
  const j = await r.json()
  if (!j.token) throw new Error('Probe 未返回 token')
  return j
}

async function observeProbe(probe: string, token: string): Promise<Observe> {
  const r = await fetch(probe + '/v1/observe?session=' + encodeURIComponent(token), { cache: 'no-store' })
  if (!r.ok) throw new Error('HTTP ' + r.status)
  return await r.json()
}

function routeFromObserve(o: Observe, name: string, source: string): Route {
  return { name, public_ip: o.ip || '', country: o.country || '', country_code: o.country_code || o.countryCode || '', asn: asn(o.asn), organization: o.organization || '', source, websocket: 'unknown', tls: o.tls || {} }
}

async function publicFallback(): Promise<Route> {
  const r = await fetch('https://ipwho.is/?_=' + Date.now(), { cache: 'no-store' })
  if (!r.ok) throw new Error('HTTP ' + r.status)
  const j = await r.json()
  if (j.success === false) throw new Error(j.message || 'ipwho.is failed')
  const c = j.connection || {}
  return { name: 'public-fallback', public_ip: j.ip || '', country: j.country || '', country_code: j.country_code || '', asn: asn(c.asn), organization: c.org || c.isp || '', source: 'ipwho.is', websocket: 'unknown' }
}

async function websocketCheck(probe: string, token: string, httpIP: string | undefined, timeoutMs: number): Promise<{ check: Check; ip?: string }> {
  const started = Date.now()
  try {
    const url = probe.replace(/^https:/, 'wss:').replace(/^http:/, 'ws:') + '/v1/ws?session=' + encodeURIComponent(token)
    const data = await withTimeout(openWS(url), timeoutMs, 'WebSocket 超时') as Record<string, unknown>
    const ip = String(data.ip || '')
    const same = Boolean(ip && httpIP && ip === httpIP)
    return { ip, check: check('websocket.web_probe', 'websocket', 'WebSocket 出口观察', ip ? (same || !httpIP ? 'pass' : 'warn') : 'unknown', ip ? (same ? 'WebSocket 与 HTTP 出口一致。' : 'WebSocket 与 HTTP 出口不一致或无法比较。') : 'WebSocket 没有返回出口。', 10, Boolean(ip), probe, { websocket_ip: ip, http_ip: httpIP || '', same_exit: same }, Date.now() - started) }
  } catch (err) {
    return { check: unknown('websocket.web_probe', 'websocket', 'WebSocket 出口观察', 'WebSocket 连接失败：' + errorText(err), 10, probe) }
  }
}

function openWS(url: string): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url)
    const timer = window.setTimeout(() => { try { ws.close() } catch {}; reject(new Error('timeout')) }, 8000)
    ws.onmessage = e => { window.clearTimeout(timer); try { resolve(JSON.parse(String(e.data))) } catch { resolve({ raw: String(e.data) }) }; try { ws.close() } catch {} }
    ws.onerror = () => { window.clearTimeout(timer); reject(new Error('websocket error')) }
    ws.onclose = () => window.clearTimeout(timer)
  })
}

async function dnsCheck(probe: string, session: ProbeSession, timeoutMs: number): Promise<Check> {
  if (!session.dns_name) return unknown('dns.web_probe', 'dns', 'DNS 解析出口观察', 'Probe 没有返回一次性 DNS 名称。', 10, probe)
  try {
    triggerDNS(session.dns_name)
    await sleep(900)
    const r = await withTimeout(fetch(probe + '/v1/session/' + encodeURIComponent(session.token) + '/dns', { cache: 'no-store' }), timeoutMs, 'DNS 观察超时')
    if (!r.ok) throw new Error('HTTP ' + r.status)
    const j = await r.json() as DNSObserve
    const observed = Boolean(j.observed && j.resolver_ip)
    const status: Status = observed ? (String(j.country_code || '').toUpperCase() === 'CN' ? 'fail' : 'pass') : 'unknown'
    return check('dns.web_probe', 'dns', 'DNS 解析出口观察', status, observed ? '权威 DNS 看到解析器出口：' + j.resolver_ip + ' ' + (j.country_code || '') : '权威 DNS 没有收到本次浏览器触发的解析记录。', 10, observed, probe, j as Record<string, unknown>)
  } catch (err) {
    return unknown('dns.web_probe', 'dns', 'DNS 解析出口观察', 'DNS 观察失败：' + errorText(err), 10, probe)
  }
}

function triggerDNS(name: string) {
  const host = name.replace(/.$/, '')
  const link = document.createElement('link')
  link.rel = 'dns-prefetch'
  link.href = '//' + host
  document.head.appendChild(link)
  const img = new Image()
  img.src = 'https://' + host + '/favicon.ico?_=' + Date.now()
  window.setTimeout(() => { try { document.head.removeChild(link) } catch {} }, 3000)
}

async function anthropicCheck(timeoutMs: number): Promise<Check> {
  const started = Date.now()
  try {
    const r = await withTimeout(fetch('https://api.anthropic.com/', { mode: 'no-cors', cache: 'no-store' }), timeoutMs, 'Claude 官方服务请求超时')
    return check('anthropic.web_access', 'network', 'Claude 官方服务基础连通性', 'pass', '浏览器完成 no-cors 请求，说明 DNS/TCP/TLS 基础链路大概率可用；网页无法读取真实 HTTP 状态码。', 25, true, 'api.anthropic.com no-cors', { response_type: r.type }, Date.now() - started)
  } catch (err) {
    return check('anthropic.web_access', 'network', 'Claude 官方服务基础连通性', 'fail', '浏览器无法完成到 api.anthropic.com 的基础请求：' + errorText(err), 25, true, 'api.anthropic.com no-cors', { error: errorText(err) }, Date.now() - started)
  }
}

function ipTypeCheck(route?: Route): Check {
  if (!route?.public_ip) return unknown('egress.ip_type', 'proxy', '当前出口 IP 类型', '没有测到公网出口，无法判断是否为住宅静态 IP。', 15, 'browser')
  const cls = classifyIP([route.organization, route.asn, route.source].join(' '))
  return check('egress.ip_type', 'proxy', '当前代理/VPN 出口 IP 类型', cls.residential ? 'pass' : 'fail', cls.residential ? '当前出口更像住宅运营商/静态住宅 IP。' : '当前出口未确认是住宅静态 IP，或更像公用机房/云/VPN/代理出口。', 15, true, route.source || 'browser', { route, classification: cls })
}

function classifyIP(s: string): { residential: boolean; reason: string } {
  const t = s.toLowerCase()
  const bad = ['amazon','aws','google cloud','microsoft','azure','digitalocean','linode','akamai','ovh','hetzner','vultr','oracle cloud','cloudflare','datacenter','data center','hosting','colo','vpn','proxy','tor','leaseweb','contabo']
  if (bad.some(x => t.includes(x))) return { residential: false, reason: '云服务器、机房、VPN、代理或共享托管特征' }
  const good = ['comcast','charter','spectrum','verizon','at&t','cox','frontier','centurylink','bt broadband','deutsche telekom','orange','telefonica','vodafone','telstra','bell canada','rogers','xfinity','residential','broadband','cable','fiber']
  if (good.some(x => t.includes(x))) return { residential: true, reason: '消费级宽带/住宅运营商特征' }
  return { residential: false, reason: '无法明确确认是住宅静态 IP' }
}

function calculateScore(checks: Check[], routes: Route[], platform: Record<string, unknown>, evidence: Evidence[]) {
  let total = 0, known = 0, earned = 0
  for (const c of checks) {
    total += c.weight
    if (c.status === 'unknown') continue
    known += c.weight
    if (c.status === 'pass') earned += c.weight
    if (c.status === 'warn') earned += c.weight * 0.55
  }
  let compatibility = known ? Math.round(earned / known * 100) : 0
  let risk = 0
  const route = routes[0]
  if (route?.country_code?.toUpperCase() === 'CN') {
    risk += 55
    evidence.push({ kind: 'observed', message: '浏览器观察到的公网出口位于中国大陆。', impact: 55, confidence: 'high', check_id: 'route.web_probe' })
  }
  const cn = mainlandSignals(platform)
  if (cn.length) {
    risk += 45
    compatibility = Math.min(compatibility, 59)
    evidence.push({ kind: 'observed', message: '浏览器语言、时区或格式包含中国大陆相关信号。', impact: 45, confidence: 'high', check_id: 'browser.region_profile' })
  }
  if (checks.find(c => c.id === 'dns.web_probe')?.status === 'fail') risk += 25
  if (checks.find(c => c.id === 'egress.ip_type')?.status === 'fail') risk += 20
  return { compatibility_score: clamp(compatibility), region_exposure_score: clamp(risk), coverage: clamp(total ? Math.round(known / total * 100) : 0) }
}

function mainlandSignals(p: Record<string, unknown>) {
  const text = [p.timezone, p.utc_offset, p.locale, p.system_locale, ...(Array.isArray(p.user_languages) ? p.user_languages : [])].join(' ').toLowerCase()
  const out = []
  if (text.includes('asia/shanghai') || text.includes('+08:00')) out.push('时区或 UTC 偏移接近中国大陆常见设置')
  if (/(zh-cn|zh_cn|zh-hans-cn|zh_hans_cn|zh-hans|simplified|chs)/.test(text)) out.push('浏览器语言/地区包含中国大陆标记')
  return out
}

function targetSignals(p: Record<string, unknown>) {
  const text = [p.timezone, p.utc_offset, p.locale, p.system_locale, ...(Array.isArray(p.user_languages) ? p.user_languages : [])].join(' ').toLowerCase()
  const out = []
  if (text.includes('en-us')) out.push('语言/地区包含 en-US')
  if (text.includes('america/') || /-(04|05|06|07|08|09|10):00/.test(text)) out.push('时区或 UTC 偏移接近美国常见设置')
  return out
}

function check(id: string, category: string, title: string, status: Status, summary: string, weight: number, observed: boolean, source?: string, evidence?: Record<string, unknown>, duration_ms?: number): Check {
  return { id, category, title, status, summary, weight, observed, source, evidence, duration_ms }
}
function unknown(id: string, category: string, title: string, summary: string, weight: number, source: string) { return check(id, category, title, 'unknown', summary, weight, false, source) }
function normalizeProbe(v: string) { const s = String(v || '').trim().replace(/\/+$/, ''); return s ? (/^https?:\/\//i.test(s) ? s : 'https://' + s) : '' }
function withTimeout<T>(p: Promise<T>, ms: number, msg: string): Promise<T> { return new Promise((res, rej) => { const t = window.setTimeout(() => rej(new Error(msg)), ms); p.then(v => { window.clearTimeout(t); res(v) }, e => { window.clearTimeout(t); rej(e) }) }) }
function sleep(ms: number) { return new Promise(r => window.setTimeout(r, ms)) }
function errorText(e: unknown) { return e instanceof Error ? e.message : String(e) }
function asn(v: unknown) { return v ? (String(v).startsWith('AS') ? String(v) : 'AS' + String(v)) : '' }
function offset() { const m = -new Date().getTimezoneOffset(); const s = m >= 0 ? '+' : '-'; const a = Math.abs(m); return s + String(Math.floor(a / 60)).padStart(2, '0') + ':' + String(a % 60).padStart(2, '0') }
function clamp(v: number) { return Math.max(0, Math.min(100, Math.round(v))) }
function browserOS() { const u = navigator.userAgent; if (/Windows/i.test(u)) return 'Windows 浏览器'; if (/Mac/i.test(u)) return 'macOS 浏览器'; if (/Linux/i.test(u)) return 'Linux 浏览器'; if (/Android/i.test(u)) return 'Android 浏览器'; if (/iPhone|iPad/i.test(u)) return 'iOS 浏览器'; return '未知浏览器平台' }
function browserArch() { const u = navigator.userAgent.toLowerCase(); if (u.includes('arm64') || u.includes('aarch64')) return 'arm64'; if (u.includes('win64') || u.includes('x86_64') || u.includes('wow64')) return 'amd64'; return 'browser-managed' }
function browserName() { const u = navigator.userAgent; if (/Edg\//.test(u)) return 'Edge'; if (/Chrome\//.test(u)) return 'Chrome/Chromium'; if (/Firefox\//.test(u)) return 'Firefox'; if (/Safari\//.test(u)) return 'Safari'; return 'Unknown' }
