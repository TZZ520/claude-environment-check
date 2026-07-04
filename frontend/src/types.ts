export type Status = 'pass'|'warn'|'fail'|'unknown'
export interface TLSInfo { version?:string; cipher?:string; alpn?:string; issuer?:string; subject?:string; dns_names?:string[]; ja3?:string; ja3_hash?:string; diagnostic_fingerprint?:string }
export interface Route { name:string; proxy?:string; public_ip?:string; country?:string; country_code?:string; asn?:string; organization?:string; source?:string; http_status?:number; latency_ms?:number; tls?:TLSInfo; websocket:Status; websocket_ip?:string; error?:string }
export interface Check { id:string; category:string; status:Status; title:string; summary:string; evidence?:Record<string,unknown>; duration_ms?:number; source?:string; weight:number; observed:boolean; remediation?:string }
export interface Evidence { kind:string; message:string; impact:number; confidence:string; check_id?:string }
export interface Report { schema_version:string; tool_version:string; rules_version:string; generated_at:string; duration_ms:number; platform:Record<string,unknown>; routes:Route[]; checks:Check[]; compatibility_score:number; region_exposure_score:number; coverage:number; evidence:Evidence[]; recommendations:string[]; privacy_redactions:string[]; metadata?:Record<string,unknown> }
export interface ScanOptions { profile:string; probe_url:string; timeout_seconds:number; public_fallback:boolean; authenticated:boolean; api_key:string; model_request:boolean; run_doctor:boolean; language:string }

