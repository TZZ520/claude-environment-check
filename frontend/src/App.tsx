import {useMemo,useState,type Dispatch,type SetStateAction} from 'react'
import {Activity,ArrowRight,ChevronDown,ChevronRight,Download,Globe2,HelpCircle,Languages,Moon,Network,Play,RotateCcw,Server,Settings,ShieldAlert,Sun,Terminal,Wifi} from 'lucide-react'
import {api} from './api'
import {dict,type Language} from './i18n'
import type{Check,Evidence,Report,Route,ScanOptions,Status}from'./types'

const initial:ScanOptions={profile:'all',probe_url:'',timeout_seconds:8,public_fallback:true,authenticated:false,api_key:'',model_request:false,run_doctor:false,language:'zh'}
type Copy = ReturnType<typeof dict>

const services = [
  'api.anthropic.com',
  'api64.ipify.org',
  'checkip.amazonaws.com',
  'icanhazip.com',
  'ifconfig.me',
  'ipwho.is',
  'cloudflare-dns.com',
  'dns.google',
  'dns.quad9.net',
  'ws.postman-echo.com',
  'echo.websocket.events',
]

export default function App(){
 const detected=(navigator.language||'en').toLowerCase().startsWith('zh')?'zh':'en'
 const[lang,setLang]=useState<Language>((localStorage.getItem('cec-language')as Language)||detected)
 const[theme,setTheme]=useState(localStorage.getItem('cec-theme')||'dark')
 const[expert,setExpert]=useState(false)
 const[settings,setSettings]=useState(false)
 const[running,setRunning]=useState(false)
 const[report,setReport]=useState<Report|null>(null)
 const[error,setError]=useState('')
 const[opts,setOpts]=useState<ScanOptions>({...initial,language:lang})
 const[consent,setConsent]=useState(localStorage.getItem('cec-privacy')==='accepted')
 const t=dict(lang)

 const setLanguage=(v:Language)=>{setLang(v);localStorage.setItem('cec-language',v);setOpts(o=>({...o,language:v}))}
 const setColor=(v:string)=>{setTheme(v);localStorage.setItem('cec-theme',v)}
 const run=async()=>{
  if(!consent)return
  setRunning(true);setError('')
  try{
   const limit=((Number(opts.timeout_seconds)||8)*3+15)*1000
   const timeoutMessage=lang==='zh'
    ? '检测超过 '+Math.round(limit/1000)+' 秒。可以在设置里改成“只检查直连”后重试。'
    : 'Scan exceeded '+Math.round(limit/1000)+' seconds. Retry with direct-only mode in settings.'
   const watchdog=new Promise<never>((_,reject)=>setTimeout(()=>reject(new Error(timeoutMessage)),limit))
   const raw=await Promise.race([api.scan({...opts,api_key:opts.authenticated?opts.api_key:''}),watchdog])
   setReport(normalizeReport(raw))
  }catch(e){
   const msg=e instanceof Error?e.message:String(e)
   setError(msg);void api.logError(msg)
  }finally{
   setRunning(false);setOpts(o=>({...o,api_key:''}))
  }
 }
 const accept=()=>{localStorage.setItem('cec-privacy','accepted');setConsent(true)}
 return <div className={'app '+theme}>
  <header>
   <div className="brand"><div className="logo"><Activity size={22}/></div><div><strong>{t.app}</strong><span>{t.unofficial}</span></div></div>
   <div className="header-actions">
    <button className="icon" title={t.language} onClick={()=>setLanguage(lang==='zh'?'en':'zh')}><Languages size={18}/><span>{t.language}</span></button>
    <button className="icon compact" title={t.theme} onClick={()=>setColor(theme==='dark'?'light':'dark')}>{theme==='dark'?<Sun size={18}/>:<Moon size={18}/>}</button>
    <button className="icon compact" title={t.settings} onClick={()=>setSettings(!settings)}><Settings size={18}/></button>
   </div>
  </header>
  <main>
   <section className="hero">
    <div><div className="eyebrow"><ShieldAlert size={14}/>{t.unofficial}</div><h1>{t.tag}</h1><p>{t.disclaimer}</p></div>
    <button className="primary" disabled={running} onClick={run}>{running?<><span className="spinner"/>{t.running}</>:report?<><RotateCcw size={18}/>{t.rerun}</>:<><Play size={18}/>{t.start}</>}</button>
   </section>
   {error&&<div className="error">{friendlyError(error,lang)}</div>}
   {report?<Dashboard report={report} expert={expert} setExpert={setExpert} t={t} lang={lang}/>:<Empty running={running} t={t}/>}
  </main>
  {settings&&<SettingsPanel opts={opts} setOpts={setOpts} close={()=>setSettings(false)} t={t}/>}
  {!consent&&<PrivacyModal accept={accept} t={t}/>}
  <footer><span>v0.1.0 · rules {report?.rules_version||'2026.07.04-1'}</span><span>{t.disclaimer}</span></footer>
 </div>
}

function normalizeReport(raw:Report):Report{
 const r:any=raw||{}
 return {
  schema_version:String(r.schema_version||'unknown'),
  tool_version:String(r.tool_version||'unknown'),
  rules_version:String(r.rules_version||'unknown'),
  generated_at:String(r.generated_at||new Date().toISOString()),
  duration_ms:toNumber(r.duration_ms,0),
  platform:(r.platform&&typeof r.platform==='object')?r.platform:{},
  routes:array<Route>(r.routes).map(x=>({...x,websocket:normalizeStatus((x as any).websocket)})),
  checks:array<Check>(r.checks).map(x=>({...x,status:normalizeStatus((x as any).status),category:String((x as any).category||'system'),id:String((x as any).id||'unknown')})),
  compatibility_score:clampScore(r.compatibility_score),
  region_exposure_score:clampScore(r.region_exposure_score),
  coverage:clampScore(r.coverage),
  evidence:array<Evidence>(r.evidence),
  recommendations:array<string>(r.recommendations).map(String),
  privacy_redactions:array<string>(r.privacy_redactions).map(String),
  metadata:(r.metadata&&typeof r.metadata==='object')?r.metadata:undefined,
 }
}
function array<T>(v:unknown):T[]{return Array.isArray(v)?v as T[]:[]}
function toNumber(v:unknown,fallback:number){const n=Number(v);return Number.isFinite(n)?n:fallback}
function clampScore(v:unknown){return Math.max(0,Math.min(100,Math.round(toNumber(v,0))))}
function normalizeStatus(v:unknown):Status{return v==='pass'||v==='warn'||v==='fail'||v==='unknown'?v:'unknown'}

function Dashboard({report,expert,setExpert,t,lang}:{report:Report;expert:boolean;setExpert:(v:boolean)=>void;t:Copy;lang:Language}){
 const[guide,setGuide]=useState(false)
 const checks=array<Check>(report.checks)
 const routes=array<Route>(report.routes)
 const evidence=array<Evidence>(report.evidence)
 const recommendations=array<string>(report.recommendations)
 const groups=useMemo(()=>{const grouped:Record<string,Check[]>={};for(const c of checks)(grouped[c.category||'system']||=[]).push(c);return Object.entries(grouped).sort(([a],[b])=>categoryRank(a)-categoryRank(b)||a.localeCompare(b))},[checks])
 return <>
  <section className="score-grid">
   <Score value={report.compatibility_score} label={t.compatibility} hint={t.compatibilityHint} tone="good" t={t}/>
   <Score value={report.region_exposure_score} label={t.risk} hint={t.riskHint} tone="risk" t={t}/>
   <Score value={report.coverage} label={t.coverage} hint={t.coverageHint} tone="coverage" t={t}/>
   <div className="summary-card"><div className="summary-head"><Globe2 size={19}/><span>{safeDate(report.generated_at)}</span></div><b>{overall(report,t)}</b><p>{format(t.scanStats,{duration:(toNumber(report.duration_ms,0)/1000).toFixed(1),routes:routes.length,checks:checks.length})}</p><div className="legend"><i className="dot pass"/>{t.pass}<i className="dot warn"/>{t.warn}<i className="dot fail"/>{t.fail}<i className="dot unknown"/>{t.unknown}</div></div>
  </section>
  <section className="panel guide-panel"><button className="plain-help" onClick={()=>setGuide(!guide)}><HelpCircle size={17}/>{guide?t.hideExplain:t.explainScores}{guide?<ChevronDown size={16}/>:<ChevronRight size={16}/>}</button>{guide&&<div className="guide-text"><b>{t.scoreGuideTitle}</b><p>{t.scoreGuide}</p></div>}</section>
  <DeviceProfile report={report} t={t} lang={lang}/>
  <section className="panel"><div className="panel-title"><div><Network size={19}/><h2>{t.path}</h2></div></div><RouteFlow report={report} t={t}/></section>
  <section className="panel"><div className="panel-title"><div><Terminal size={19}/><h2>{t.checks}</h2></div><div className="segmented"><button className={!expert?'active':''} onClick={()=>setExpert(false)}>{t.basic}</button><button className={expert?'active':''} onClick={()=>setExpert(true)}>{t.expert}</button></div></div>
   <div className="check-groups">{groups.length?groups.map(([name,items])=><CheckGroup key={name} name={friendlyCategory(name,lang)} checks={items} expert={expert} t={t} lang={lang}/>):<div className="empty-inline">{t.unknown}</div>}</div>
  </section>
  {(evidence.length>0||recommendations.length>0)&&<section className="two-column">
   <div className="panel"><div className="panel-title"><div><ShieldAlert size={19}/><h2>{t.evidence}</h2></div></div><div className="evidence-list">{evidence.map((e,i)=><div className="evidence" key={i}><span className={'confidence '+String(e.confidence||'low')}>{friendlyConfidence(String(e.confidence||'low'),lang)}</span><p>{friendlyEvidence(String(e.message||''),lang)}</p><b>+{toNumber(e.impact,0)}</b></div>)}</div></div>
   <div className="panel"><div className="panel-title"><div><Activity size={19}/><h2>{t.recommendations}</h2></div></div><ul className="recommendations">{recommendations.map((x,i)=><li key={i}>{friendlyRecommendation(String(x),lang)}</li>)}</ul></div>
  </section>}
  <section className="export-row"><button onClick={()=>api.exportJSON(report)}><Download size={16}/>{t.exportJSON}</button><button onClick={()=>api.exportHTML(report)}><Download size={16}/>{t.exportHTML}</button></section>
 </>
}

function DeviceProfile({report,t,lang}:{report:Report;t:Copy;lang:Language}){
 const p=report.platform||{}
 const system=array<Check>(report.checks).find(c=>c.id==='system.readiness')
 const proxyEnv=p.proxy_env&&typeof p.proxy_env==='object'?Object.keys(p.proxy_env as Record<string,unknown>):[]
 const dns=array<string>((p as any).dns_servers)
 const userLang=array<string>((p as any).user_languages)
 const format=(p as any).format_settings&&typeof (p as any).format_settings==='object'?(p as any).format_settings as Record<string,unknown>:{}
 const title=lang==='zh'?'电脑地区环境匹配情况':'Device target-region match'
 const hint=lang==='zh'?'先看这台电脑自己的地区信号：时区、语言、文字格式、代码页、DNS、代理痕迹和 Claude Code 安装情况。只要出现明显中国大陆相关信号，就会直接标记为不符合目标环境；美国/非大陆信号越一致，匹配度越高。':'First check this device\'s region-like signals: timezone, language, text format, code page, DNS, proxy traces, and Claude Code installation. Clear Mainland China signals are treated as target-profile mismatches.'
 const tech=lang==='zh'?'这是怎么检测的？':'How was this checked?'
 const techBody=lang==='zh'?'读取操作系统公开设置、环境变量、系统 DNS、代理配置，并查找 claude 可执行文件。这里不读取私人文件，也不会把 API Key 或代理密码写入报告。':'Reads public OS settings, environment variables, system DNS, proxy config, and looks for the claude executable. It does not read private files or write API keys/proxy passwords to reports.'
 const signals=[
  {label:lang==='zh'?'系统和处理器':'OS and CPU',value:joinKnown([p.os,p.architecture||p.arch]),note:lang==='zh'?'判断程序能不能正常运行':'Whether the app can run here'},
  {label:lang==='zh'?'时区和时间偏移':'Timezone and clock zone',value:joinKnown([p.timezone,p.utc_offset]),note:lang==='zh'?'目标环境一致性的重要信号；+08:00 会被视为中国大陆相关信号':'Important target-profile signal; +08:00 is treated as Mainland-like'},
  {label:lang==='zh'?'系统语言':'System language',value:joinKnown([p.locale,(p as any).system_locale,...userLang]),note:lang==='zh'?'出现 zh-CN / zh-Hans-CN 会被视为中国大陆相关信号':'zh-CN / zh-Hans-CN is treated as Mainland-like'},
  {label:lang==='zh'?'文字和符号格式':'Text and symbol format',value:textFormatValue(format,(p as any).code_page,lang),note:lang==='zh'?'代码页 936 等会被视为中国大陆使用习惯信号':'Code page 936 is treated as a Mainland-like usage signal'},
  {label:lang==='zh'?'代理设置痕迹':'Proxy setting traces',value:proxyEnv.length?proxyEnv.join(' / '):(p.system_proxy?lang==='zh'?'发现系统代理信息':'System proxy info found':lang==='zh'?'未发现代理环境变量':'No proxy env vars found'),note:lang==='zh'?'只显示变量名或脱敏后的代理信息':'Shows names or redacted proxy info only'},
  {label:lang==='zh'?'DNS 服务器':'DNS servers',value:dns.length?dns.slice(0,3).join(' / ')+(dns.length>3?' …':''):(lang==='zh'?'未读取到':'Not read'),note:lang==='zh'?'电脑用来查询网址的服务器':'Servers used for website lookup'},
  {label:'Claude Code',value:p.claude_version||p.claude_path||(lang==='zh'?'没有找到 claude 程序':'claude executable not found'),note:lang==='zh'?'只检查是否安装和版本，不运行登录操作':'Checks install/version only'}
 ]
 return <section className="panel device-panel"><div className="panel-title"><div><Terminal size={19}/><h2>{title}</h2></div><StatusBadge value={system?.status||'unknown'} t={t}/></div><p className="panel-hint">{hint}</p><div className="device-grid">{signals.map((s,i)=><div className="device-signal" key={i}><b>{s.label}</b><span title={String(s.value)}>{String(s.value||'—')}</span><small>{s.note}</small></div>)}</div><details className="tech-expander"><summary><HelpCircle size={15}/>{tech}</summary><p>{techBody}</p></details></section>
}

function Score({value,label,hint,tone,t}:{value:number;label:string;hint:string;tone:string;t:Copy}){
 const v=clampScore(value)
 const level=tone==='risk'?(v>=70?'red':v>=50?'yellow':'green'):(v<65?'red':v<80?'yellow':'green')
 const text=tone==='risk'?(v>=70?t.riskHigh:v>=50?t.riskMid:t.riskLow):(v>=80?t.friendlyStatusStrong:v>=65?t.friendlyStatusModerate:t.friendlyStatusWeak)
 return <div className={'score-card '+tone+' '+level}><div className="ring" style={{'--value':v*3.6+'deg'} as any}><div><b>{v}</b><span>%</span></div></div><div><span>{label}</span><small>{text}</small><em>{hint}</em></div></div>
}

function RouteFlow({report,t}:{report:Report;t:Copy}){
 const routes=array<Route>(report.routes)
 const route=routes.find(r=>r.name==='environment')||routes[0]
 const platform=report.platform||{}
 const os=String(platform.os||'')
 const arch=String(platform.architecture||platform.arch||'')
 const checks=array<Check>(report.checks)
 return <div className="route-flow"><Node icon={<Wifi/>} label={t.device} detail={(os||'?')+' / '+(arch||'?')}/><ArrowRight/><Node icon={<Network/>} label={t.dnsProxy} detail={route?.proxy?maskShort(String(route.proxy)):t.routeDirect}/><ArrowRight/><Node icon={<Globe2/>} label={t.egress} detail={route?.public_ip?String(route.public_ip)+' · '+String(route.country_code||'?'):t.routeUnknown}/><ArrowRight/><Node icon={<Server/>} label={t.anthropic} detail={statusText(checks.find(c=>c.id==='anthropic.access')?.status||'unknown',t)}/></div>
}
function Node({icon,label,detail}:{icon:any;label:string;detail:string}){return <div className="route-node"><div>{icon}</div><b>{label}</b><span title={detail}>{detail}</span></div>}

function CheckGroup({name,checks,expert,t,lang}:{name:string;checks:Check[];expert:boolean;t:Copy;lang:Language}){
 const[open,setOpen]=useState(true)
 const items=array<Check>(checks)
 const worst=items.some(c=>c.status==='fail')?'fail':items.some(c=>c.status==='warn')?'warn':items.some(c=>c.status==='unknown')?'unknown':'pass'
 return <div className="check-group"><button className="group-head" onClick={()=>setOpen(!open)}>{open?<ChevronDown/>:<ChevronRight/>}<b>{name}</b><StatusBadge value={worst} t={t}/><span>{items.length}</span></button>{open&&<div>{items.map((c,i)=><CheckRow key={c.id||i} check={c} expert={expert} t={t} lang={lang}/>)}</div>}</div>
}
function CheckRow({check,expert,t,lang}:{check:Check;expert:boolean;t:Copy;lang:Language}){
 const[open,setOpen]=useState(false)
 const details=expert||open
 const h=humanCheck(check,lang)
 const status=normalizeStatus(check.status)
 return <div className="check-row"><button className="check-main" onClick={()=>setOpen(!open)}><StatusBadge value={status} t={t}/><div><b>{h.title}</b><p>{h.summary}</p></div><span className="meta">{check.duration_ms?check.duration_ms+' ms':''}</span>{open?<ChevronDown/>:<ChevronRight/>}</button>{details&&<div className="check-detail"><div className="tech-note"><b>{t.howItWorks}</b><p>{h.tech}</p></div>{check.source&&<p><b>{t.source}:</b> {friendlySource(String(check.source),lang)}</p>}{check.summary&&<p><b>{t.rawResult}:</b> {friendlyRawSummary(String(check.summary),lang)}</p>}{check.remediation&&<p>{friendlyRecommendation(String(check.remediation),lang)}</p>}{check.evidence!==undefined&&<details><summary>{t.rawEvidence}</summary><pre>{JSON.stringify(check.evidence,null,2)}</pre></details>}</div>}</div>
}
function StatusBadge({value,t}:{value:Status;t:Copy}){const v=normalizeStatus(value);return <span className={'status '+v}><i/>{statusText(v,t)}</span>}
function statusText(value:Status,t:Copy){return t[normalizeStatus(value)]}
function Empty({running,t}:{running:boolean;t:Copy}){return <section className="empty"><div className={running?'pulse-orbit active':'pulse-orbit'}><Globe2 size={42}/><i/><i/><i/></div><h2>{running?t.running:t.noReport}</h2><p>{t.disclaimer}</p></section>}

function SettingsPanel({opts,setOpts,close,t}:{opts:ScanOptions;setOpts:Dispatch<SetStateAction<ScanOptions>>;close:()=>void;t:Copy}){
 const patch=(v:Partial<ScanOptions>)=>setOpts(o=>({...o,...v}))
 return <div className="drawer-backdrop" onMouseDown={e=>{if(e.target===e.currentTarget)close()}}><aside className="drawer"><div className="drawer-head"><h2>{t.settings}</h2><button aria-label={t.close} onClick={close}>×</button></div><label>{t.profile}<select value={opts.profile} onChange={e=>patch({profile:e.target.value})}><option value="all">{t.all}</option><option value="direct">{t.direct}</option><option value="system-proxy">{t.proxy}</option></select></label><label>{t.probe}<input value={opts.probe_url} placeholder="https://probe.example.com" onChange={e=>patch({probe_url:e.target.value})}/></label><label>{t.timeout}<input type="number" min="3" max="30" value={opts.timeout_seconds} onChange={e=>patch({timeout_seconds:Number(e.target.value)})}/></label><Toggle label={t.fallback} checked={opts.public_fallback} change={v=>patch({public_fallback:v})}/><Toggle label={t.auth} checked={opts.authenticated} change={v=>patch({authenticated:v,model_request:v?opts.model_request:false})}/>{opts.authenticated&&<><label>{t.key}<input type="password" autoComplete="off" value={opts.api_key} onChange={e=>patch({api_key:e.target.value})}/></label><Toggle label={t.modelRequest} checked={opts.model_request} change={v=>patch({model_request:v})}/></>}<Toggle label={t.doctor} checked={opts.run_doctor} change={v=>patch({run_doctor:v})}/><button className="primary full" onClick={close}>{t.agree}</button></aside></div>
}
function Toggle({label,checked,change}:{label:string;checked:boolean;change:(v:boolean)=>void}){return <label className="toggle"><span>{label}</span><input type="checkbox" checked={checked} onChange={e=>change(e.target.checked)}/><i/></label>}
function PrivacyModal({accept,t}:{accept:()=>void;t:Copy}){return <div className="modal-backdrop"><div className="modal"><div className="modal-icon"><ShieldAlert/></div><h2>{t.privacyTitle}</h2><p>{t.privacy}</p><b className="service-title">{t.servicesMayContact}</b><div className="service-list">{services.map(s=><span key={s}>{s}</span>)}</div><button className="primary full" onClick={accept}>{t.agree}</button></div></div>}

function overall(r:Report,t:Copy){if(r.compatibility_score>=80&&r.region_exposure_score<35)return t.ready;if(r.compatibility_score>=60)return t.review;return t.attention}
function safeDate(s:string){const d=new Date(s);return Number.isNaN(d.getTime())?s:d.toLocaleString()}
function format(tpl:string,v:Record<string,string|number>){return tpl.replace(/\{(\w+)\}/g,(_,k)=>String(v[k]??''))}
function maskShort(s:string){return s.length>42?s.slice(0,39)+'…':s}
function categoryRank(name:string){const order:Record<string,number>={system:0,proxy:1,dns:2,network:3,tls:4,websocket:5};return order[name]??99}
function joinKnown(values:unknown[]){const out=values.map(v=>String(v||'').trim()).filter(Boolean);return out.length?out.join(' / '):'—'}
function textFormatValue(format:Record<string,unknown>,codePage:unknown,lang:Language){const parts=[format.decimal&&('decimal '+format.decimal),format.list&&('list '+format.list),format.date&&('date '+format.date),format.time&&('time '+format.time),codePage&&('codepage '+codePage)].filter(Boolean).map(String);return parts.length?parts.join(' / '):(lang==='zh'?'未读取到独立格式信息':'No separate format info read')}
function friendlyCategory(name:string,lang:Language){const zh:Record<string,string>={network:'能不能连到 Claude 服务',tls:'加密连接是否正常',proxy:'代理是否按预期工作',dns:'网址解析是否正常',system:'电脑地区环境匹配',websocket:'实时连接能力'};const en:Record<string,string>={network:'Can reach Claude services',tls:'Encrypted connection health',proxy:'Proxy path behavior',dns:'Website lookup health',system:'Device target-region match',websocket:'Realtime connection support'};return (lang==='zh'?zh:en)[name]||name}
function humanCheck(c:Check,lang:Language){
 const z=lang==='zh'
 const table:{match:(id:string)=>boolean;zh:[string,string,string];en:[string,string,string]}[]=[
  {match:id=>id==='anthropic.access'||id.startsWith('anthropic.access.'),zh:['Claude 官方服务能不能打开','检查当前网络是否能碰到 Claude 官方接口；未登录导致的 401/404 不算网络失败。','向 api.anthropic.com 的多个低风险地址发起请求，记录网址解析、连接、加密握手和 HTTP 状态；451 或明确地区含义的 403 会被视为高风险。'],en:['Can open Claude official service','Checks whether this network can reach Claude endpoints; unauthenticated 401/404 is not a network failure.','Sends low-risk requests to several api.anthropic.com paths and records DNS/TCP/TLS/HTTP status.']},
  {match:id=>id==='tls.integrity'||id.startsWith('tls.integrity.'),zh:['加密连接有没有异常','检查访问 Claude 时的加密证书和连接参数是否正常。','读取 TLS 版本、加密套件、ALPN、证书颁发者和证书指纹，用来发现证书替换、企业网关或代理终止 TLS 等现象。'],en:['Encrypted connection looks normal','Checks whether certificates and encrypted connection parameters look healthy.','Reads TLS version, cipher, ALPN, issuer, and certificate fingerprint to spot certificate replacement or TLS termination.']},
  {match:id=>id==='route.consistency',zh:['现在的流量从哪里出去','观察直连和当前代理下看到的公网出口是否一致。','分别使用多个公开观察服务检查公网 IP，并测试代理端口和 HTTP CONNECT 能否连到 Claude。'],en:['Where traffic exits','Observes whether direct and proxy paths use the same public exit.','Uses multiple public IP observers and proxy reachability checks.']},
  {match:id=>id==='egress.ip_type',zh:['当前代理/VPN 出口像不像住宅静态 IP','只把住宅运营商、静态倾向的出口判为通过；公用、共享、机房、云服务器、VPN、代理或无法确认的出口都判为威胁。','根据当前实际出口 IP 的 ASN、运营商名称、国家、代理路径和公开观测来源做启发式分类；不修改网络，也不证明 IP 一定是静态，只做保守判断。'],en:['Current proxy/VPN exit IP type','Only residential/static-leaning ISP exits pass; public, shared, datacenter, cloud, VPN, proxy, or unconfirmed exits are treated as threat.','Classifies the effective egress using ASN, organization, country, route, and observation source. It is conservative and does not prove static assignment.']},
  {match:id=>id==='dns.consistency',zh:['网址解析是否靠谱','检查电脑把 Claude 网址解析成地址时是否正常。','对比系统自带解析与 Cloudflare、Google、Quad9 的独立解析结果；部分来源失败不会直接判定整项失败。'],en:['Website lookup is reliable','Checks whether this device resolves Claude hostnames normally.','Compares system DNS with Cloudflare, Google, and Quad9 DoH answers.']},
  {match:id=>id==='system.readiness',zh:['电脑地区环境是否匹配','检查这台电脑的时区、语言、代码页、DNS、代理痕迹和 Claude Code 安装状态是否符合目标环境。','读取操作系统、架构、时区、语言、DNS 服务器、代理环境变量、文字格式和代码页，并查找 claude 可执行文件和版本；不会修改系统设置。'],en:['Device target-region match','Checks whether this device\'s timezone, language, code page, DNS, proxy traces, and Claude Code installation match the target profile.','Reads OS, architecture, timezone, locale, DNS servers, proxy env vars, text format, code page, and Claude executable/version; it does not modify system settings.']},
  {match:id=>id==='websocket.access'||id.startsWith('websocket.access.'),zh:['实时连接能不能建立','检查代理或网络是否支持常见的长连接。','尝试连接多个公开 WSS 回显服务，记录握手状态和错误；这不代表 Claude Code 内部协议，只是诊断网络能力。'],en:['Realtime connection can be established','Checks whether the network or proxy supports common long-lived connections.','Attempts WSS handshakes against multiple public echo services.']},
  {match:id=>id==='anthropic.authenticated',zh:['API Key 是否真的可用','在你主动开启时，验证密钥能否访问官方接口。','调用低风险的 models 端点；只有你再次允许时才发起最小模型请求。密钥只在内存中使用。'],en:['API key actually works','When enabled, verifies whether your key can access official endpoints.','Calls the low-risk models endpoint; sends a minimal model request only if you allow it. Key is memory-only.']},
  {match:id=>id==='claude.doctor',zh:['Claude 自带检查结果','运行 Claude Code 自己的 doctor 命令并脱敏展示摘要。','执行 claude doctor，截取并脱敏输出，不保存凭据。'],en:['Claude built-in doctor result','Runs Claude Code doctor and shows a redacted summary.','Executes claude doctor and redacts/truncates output.']},
 ]
 const row=table.find(x=>x.match(c.id||''))
 const status=z?friendlyStatusSummaryZH(c):friendlyStatusSummaryEN(c)
 if(!row)return {title:c.title||c.id||'Unknown check',summary:status||c.summary,tech:z?'展开后可查看这个检查项返回的原始证据。':'Open to view raw evidence returned by this check.'}
 const [title,,tech]=z?row.zh:row.en
 return {title,summary:status,tech}
}
function friendlyStatusSummaryZH(c:Check){const raw=String(c.summary||'');if(c.id==='system.readiness'&&raw.includes('Device-side signals match Mainland China'))return '电脑侧的时区、语言、代码页、DNS 或地区设置明显像中国大陆环境，不符合目标环境。';if(c.id==='system.readiness'&&raw.includes('Target-like device signals'))return '电脑侧地区信号暂未发现明显中国大陆特征，目标环境匹配度较好。';if(c.id==='egress.ip_type'&&raw.includes('Residential/static-leaning'))return '当前出口看起来像住宅运营商/静态倾向 IP，本项通过。';if(c.id==='egress.ip_type'&&raw.includes('Threat'))return '当前出口无法确认是住宅静态 IP，或更像公用/共享/机房/VPN/代理出口，判定为威胁。';const s=normalizeStatus(c.status);if(s==='pass')return '结果正常，当前项目没有发现明显问题。';if(s==='warn')return '能测到结果，但有一处需要留意。';if(s==='fail')return '这里检测到问题，可能会影响使用。';return '这项没有测完整，通常是超时、服务不可达或被网络拦截。'}
function friendlyStatusSummaryEN(c:Check){const raw=String(c.summary||'');if(c.id==='system.readiness'&&raw.includes('Device-side signals match Mainland China'))return 'Device-side timezone, language, code page, DNS, or region settings look Mainland-like, so the target profile is not met.';if(c.id==='system.readiness'&&raw.includes('Target-like device signals'))return 'No obvious Mainland-like device signal was found; target-profile match looks better.';if(c.id==='egress.ip_type'&&raw.includes('Residential/static-leaning'))return 'The current exit looks like a residential/static-leaning ISP IP, so this item passes.';if(c.id==='egress.ip_type'&&raw.includes('Threat'))return 'The current exit is not confirmed as residential/static, or looks public/shared/datacenter/VPN/proxy-like, so it is treated as threat.';const s=normalizeStatus(c.status);if(s==='pass')return 'Looks normal. No obvious issue found here.';if(s==='warn')return 'Measured, but something is worth checking.';if(s==='fail')return 'A problem was detected here and may affect usage.';return 'This check did not complete, usually due to timeout, unreachable service, or blocking.'}
function friendlyRawSummary(s:string,lang:Language){if(lang!=='zh')return s;return s.replace('Device-side signals match Mainland China','电脑侧信号匹配中国大陆环境').replace('target profile not met','不符合目标环境').replace('Target-like device signals; Claude Code executable was not found','电脑侧地区信号较符合目标环境，但没有找到 Claude Code 程序').replace('Target-like device signals and Claude Code executable found','电脑侧地区信号较符合目标环境，并且找到了 Claude Code 程序').replace('Endpoint reachable','官方接口可以连上').replace('No checks were run','没有运行检查').replace('System DNS works; DoH comparison unavailable','系统网址解析可用，但无法完成独立对比').replace('Supported OS; Claude Code executable was not found','系统支持，但没有找到 Claude Code 程序').replace('Supported OS and Claude Code executable found','系统支持，并且找到了 Claude Code 程序').replace('WebSocket handshake succeeded','实时连接握手成功').replace('All WebSocket handshake methods failed','所有实时连接测试方法都失败').replace('Direct and environment routes use different egress IPs','直连和代理使用了不同公网出口')}
function friendlyEvidence(s:string,lang:Language){if(lang!=='zh')return s;const map:Record<string,string>={'Current egress IP is not confirmed as residential/static':'当前出口 IP 没有被确认是住宅静态倾向。','Effective egress geolocates to Mainland China':'当前实际公网出口被识别为中国大陆。','Direct egress is in Mainland China while the routed egress differs':'直连出口在中国大陆，但代理/环境路径显示为另一个出口。','Anthropic endpoint returned an explicit region-related denial':'Claude 官方接口返回了明确和地区有关的拒绝。','Device-side signals match Mainland China target-risk profile':'电脑侧公开设置明显匹配中国大陆环境。','System timezone or UTC offset matches Mainland China common setting':'系统时区或时间偏移匹配中国大陆常见设置。','System language or region contains a Mainland Chinese marker':'系统语言或地区设置包含中国大陆标记。','System code page is 936 for Simplified Chinese/GBK':'系统代码页为 936，常见于简体中文/GBK 环境。','System timezone is commonly used in Mainland China':'系统时区常见于中国大陆。','System locale contains a Mainland Chinese marker':'系统语言设置包含中国大陆标记。'};return map[s]||s}
function friendlyRecommendation(s:string,lang:Language){if(lang!=='zh')return s;return s.replace('Review failed endpoint, DNS, certificate, proxy, and device-region checks before using Claude Code.','使用 Claude Code 前，建议先处理红色/黄色的连接、网址解析、证书、代理或电脑地区环境问题。').replace('Review failed endpoint, DNS, certificate, and proxy checks before using Claude Code.','使用 Claude Code 前，建议先处理红色/黄色的连接、网址解析、证书或代理问题。').replace("Review Anthropic's supported-location policy and keep device region, timezone, language, DNS, and proxy configuration consistent with your permitted environment.",'建议查看 Anthropic 官方支持地区政策，并保持电脑地区、时区、语言、DNS 和代理配置与你被允许的使用环境一致。').replace("Review Anthropic's supported-location policy and use only organization-approved network configurations.",'建议查看 Anthropic 官方支持地区政策，并只使用你所在组织允许的网络配置。').replace("Install Claude Code using Anthropic's official instructions.",'请按 Anthropic 官方说明安装 Claude Code。')}
function friendlySource(s:string,lang:Language){if(lang!=='zh')return s;return s.replace('system resolver + Cloudflare/Google/Quad9 DoH','系统自带网址解析 + 多个独立解析服务').replace('api.anthropic.com','Claude 官方接口').replace('ws.postman-echo.com + echo.websocket.events','多个公开实时连接测试服务')}
function friendlyConfidence(s:string,lang:Language){if(lang!=='zh')return s;return s==='high'?'可信度高':s==='medium'?'可信度中':s==='low'?'可信度低':s}
function friendlyError(e:string,lang:Language){if(lang!=='zh')return e;return e.replace('Error:','错误：').replace('Wails bridge is unavailable. Run the desktop application, not the source HTML directly.','桌面程序连接未就绪，请运行打包后的应用，不要直接打开网页源码。')}
