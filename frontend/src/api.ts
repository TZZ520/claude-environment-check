import type { Report, ScanOptions } from './types'
declare global { interface Window { go?: { main?: { App?: { Scan:(o:ScanOptions)=>Promise<Report>; ExportJSON:(r:Report)=>Promise<string>; ExportHTML:(r:Report)=>Promise<string>; OpenURL:(u:string)=>Promise<void>; LogFrontendError:(m:string)=>Promise<void> } } } } }
function app(){const a=window.go?.main?.App;if(!a)throw new Error('Wails bridge is unavailable. Run the desktop application, not the source HTML directly.');return a}
export const api={scan:(o:ScanOptions)=>app().Scan(o),exportJSON:(r:Report)=>app().ExportJSON(r),exportHTML:(r:Report)=>app().ExportHTML(r),openURL:(u:string)=>app().OpenURL(u),logError:(m:string)=>window.go?.main?.App?.LogFrontendError(m)}

