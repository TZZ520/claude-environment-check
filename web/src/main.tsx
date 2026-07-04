import React, { useState } from 'react'
import { createRoot } from 'react-dom/client'
import { scanEnvironment } from './browserScan'
import type { Check, Report, Status } from './types'
import './style.css'

const defaultProbe = ''

function App() {
  const [probe, setProbe] = useState(defaultProbe)
  const [timeout, setTimeoutSeconds] = useState(8)
  const [fallback, setFallback] = useState(true)
  const [running, setRunning] = useState(false)
  const [report, setReport] = useState<Report | null>(null)
  const [error, setError] = useState('')
  const [expert, setExpert] = useState(false)

  async function run() {
    setRunning(true)
    setError('')
    try {
      setReport(await scanEnvironment({ probe_url: probe, timeout_seconds: timeout, public_fallback: fallback }))
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setRunning(false)
    }
  }

  return <div className="app">
    <header>
      <div>
        <b>Claude Environment Check Web</b>
        <span>网页版独立检测工具</span>
      </div>
      <a href="https://docs.anthropic.com/" target="_blank" rel="noreferrer">官方文档</a>
    </header>

    <main>
      <section className="hero">
        <div>
          <p className="eyebrow">Browser-only / 不依赖 Windows 客户端</p>
          <h1>打开网址即可检测当前浏览器网络环境</h1>
          <p>网页只能检测浏览器能看到的信息；本机代理、证书库、Claude Code 安装状态等项目会显示为无法检测，并降低完整度。</p>
        </div>
        <button className="primary" onClick={run} disabled={running}>{running ? '正在检测...' : report ? '重新检测' : '开始检测'}</button>
      </section>

      <section className="settings">
        <label>自建 Probe 地址（推荐）
          <input value={probe} onChange={e => setProbe(e.target.value)} placeholder="https://probe.example.com" />
        </label>
        <label>每项最多等待秒数
          <input type="number" min={3} max={30} value={timeout} onChange={e => setTimeoutSeconds(Number(e.target.value) || 8)} />
        </label>
        <label className="checkline">
          <input type="checkbox" checked={fallback} onChange={e => setFallback(e.target.checked)} />
          Probe 不可用时允许公开 IP 服务回退
        </label>
      </section>

      {error && <div className="error">{error}</div>}
      {report ? <ReportView report={report} expert={expert} setExpert={setExpert} /> : <Empty running={running} />}
    </main>
  </div>
}

function Empty({ running }: { running: boolean }) {
  return <section className="empty">
    <div className="orb">⌁</div>
    <h2>{running ? '检测中，请稍等' : '还没有检测结果'}</h2>
    <p>建议部署自建 Probe，这样才能测公网出口、WebSocket、DNS 出口和浏览器 TLS 指纹。</p>
  </section>
}

function ReportView({ report, expert, setExpert }: { report: Report; expert: boolean; setExpert: (v: boolean) => void }) {
  const groups = groupChecks(report.checks)
  return <>
    <section className="scores">
      <Score title="顺利使用可能性" value={report.compatibility_score} mode="good" />
      <Score title="大陆环境暴露可能性" value={report.region_exposure_score} mode="risk" />
      <Score title="检测完整度" value={report.coverage} mode="coverage" />
      <div className="summary">
        <b>{summary(report)}</b>
        <span>用时 {(report.duration_ms / 1000).toFixed(1)} 秒 · {report.checks.length} 项检查</span>
      </div>
    </section>

    <section className="panel warn-panel">
      <h2>网页版能做什么，不能做什么？</h2>
      <ul>
        {(report.metadata.limitations as string[] || []).map((x, i) => <li key={i}>{x}</li>)}
      </ul>
    </section>

    <section className="panel">
      <div className="panel-head">
        <h2>访问路径</h2>
      </div>
      <div className="route">
        <RouteNode title="浏览器" text={String(report.platform.browser || report.platform.os || 'Browser')} />
        <i>→</i>
        <RouteNode title="公网出口" text={report.routes[0]?.public_ip ? report.routes[0].public_ip + ' / ' + (report.routes[0].country_code || '?') : '未测到'} />
        <i>→</i>
        <RouteNode title="Claude 官方服务" text={statusText(report.checks.find(c => c.id === 'anthropic.web_access')?.status || 'unknown')} />
      </div>
    </section>

    <section className="panel">
      <div className="panel-head">
        <h2>检查结果</h2>
        <button onClick={() => setExpert(!expert)}>{expert ? '隐藏技术细节' : '显示技术细节'}</button>
      </div>
      {Object.entries(groups).map(([name, items]) => <div className="group" key={name}>
        <h3>{categoryName(name)}</h3>
        {items.map(c => <CheckRow key={c.id} check={c} expert={expert} />)}
      </div>)}
    </section>

    {report.evidence.length > 0 && <section className="panel">
      <h2>为什么这样判断</h2>
      {report.evidence.map((e, i) => <div className="evidence" key={i}><b>+{e.impact}</b><span>{e.message}</span><em>{e.confidence}</em></div>)}
    </section>}

    <section className="panel">
      <h2>建议</h2>
      <ul>{report.recommendations.map((x, i) => <li key={i}>{x}</li>)}</ul>
      <div className="export">
        <button onClick={() => exportJSON(report)}>导出 JSON</button>
        <button onClick={() => exportHTML(report)}>导出 HTML</button>
      </div>
    </section>
  </>
}

function Score({ title, value, mode }: { title: string; value: number; mode: 'good' | 'risk' | 'coverage' }) {
  const level = mode === 'risk' ? (value >= 70 ? 'red' : value >= 50 ? 'yellow' : 'green') : (value < 65 ? 'red' : value < 80 ? 'yellow' : 'green')
  return <div className={'score ' + level}>
    <div className="circle" style={{ '--p': String(value * 3.6) + 'deg' } as React.CSSProperties}><b>{value}</b><span>%</span></div>
    <div><strong>{title}</strong><small>{scoreText(value, mode)}</small></div>
  </div>
}

function RouteNode({ title, text }: { title: string; text: string }) {
  return <div className="route-node"><b>{title}</b><span>{text}</span></div>
}

function CheckRow({ check, expert }: { check: Check; expert: boolean }) {
  return <details className={'check ' + check.status} open={expert || check.status === 'fail'}>
    <summary><StatusBadge status={check.status} /><b>{check.title}</b><span>{check.summary}</span></summary>
    <pre>{JSON.stringify({ id: check.id, source: check.source, evidence: check.evidence }, null, 2)}</pre>
  </details>
}

function StatusBadge({ status }: { status: Status }) {
  return <i className={'badge ' + status}>{statusText(status)}</i>
}

function statusText(status: Status) {
  return status === 'pass' ? '正常' : status === 'warn' ? '需留意' : status === 'fail' ? '有风险' : '未测到'
}

function scoreText(value: number, mode: 'good' | 'risk' | 'coverage') {
  if (mode === 'risk') return value >= 70 ? '大陆信号明显' : value >= 50 ? '需要留意' : '大陆信号较少'
  if (mode === 'coverage') return value >= 80 ? '检测较完整' : value >= 50 ? '部分完成' : '很多项目无法检测'
  return value >= 80 ? '目标环境匹配较高' : value >= 65 ? '部分匹配' : '不符合目标环境'
}

function summary(r: Report) {
  if (r.compatibility_score < 65 || r.region_exposure_score >= 70) return '当前环境不建议直接使用，先看红色项目。'
  if (r.compatibility_score < 80 || r.region_exposure_score >= 50) return '当前环境部分匹配，建议检查黄色项目。'
  return '当前浏览器网络环境较符合目标使用环境。'
}

function groupChecks(checks: Check[]) {
  const out: Record<string, Check[]> = {}
  for (const c of checks) (out[c.category] ||= []).push(c)
  return out
}

function categoryName(name: string) {
  return ({ system: '电脑/浏览器地区环境', proxy: '公网出口和代理类型', dns: '网址解析', tls: '加密连接', websocket: '实时连接', network: 'Claude 官方服务' } as Record<string, string>)[name] || name
}

function exportJSON(report: Report) {
  download('claude-env-check-web.json', JSON.stringify(report, null, 2), 'application/json;charset=utf-8')
}

function exportHTML(report: Report) {
  const rows = report.checks.map(c => '<tr><td>' + esc(c.category) + '</td><td>' + esc(c.title) + '</td><td>' + esc(c.status) + '</td><td>' + esc(c.summary) + '</td></tr>').join('')
  const html = '<!doctype html><meta charset="utf-8"><title>Claude Environment Check Web Report</title><h1>Claude Environment Check Web Report</h1><p>顺利使用可能性：' + report.compatibility_score + '%</p><p>大陆环境暴露可能性：' + report.region_exposure_score + '%</p><p>检测完整度：' + report.coverage + '%</p><table border="1" cellspacing="0" cellpadding="6"><tr><th>分类</th><th>项目</th><th>状态</th><th>说明</th></tr>' + rows + '</table>'
  download('claude-env-check-web.html', html, 'text/html;charset=utf-8')
}

function download(name: string, body: string, type: string) {
  const blob = new Blob([body], { type })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  document.body.appendChild(a)
  a.click()
  a.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}

function esc(s: string) {
  return s.replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch] || ch))
}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>)
