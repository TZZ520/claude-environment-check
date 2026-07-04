export namespace model {
	
	export class Check {
	    id: string;
	    category: string;
	    status: string;
	    title: string;
	    summary: string;
	    evidence?: Record<string, any>;
	    duration_ms?: number;
	    source?: string;
	    weight: number;
	    observed: boolean;
	    remediation?: string;
	
	    static createFrom(source: any = {}) {
	        return new Check(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.category = source["category"];
	        this.status = source["status"];
	        this.title = source["title"];
	        this.summary = source["summary"];
	        this.evidence = source["evidence"];
	        this.duration_ms = source["duration_ms"];
	        this.source = source["source"];
	        this.weight = source["weight"];
	        this.observed = source["observed"];
	        this.remediation = source["remediation"];
	    }
	}
	export class Evidence {
	    kind: string;
	    message: string;
	    impact: number;
	    confidence: string;
	    check_id?: string;
	
	    static createFrom(source: any = {}) {
	        return new Evidence(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.kind = source["kind"];
	        this.message = source["message"];
	        this.impact = source["impact"];
	        this.confidence = source["confidence"];
	        this.check_id = source["check_id"];
	    }
	}
	export class Platform {
	    os: string;
	    architecture: string;
	    hostname?: string;
	    timezone: string;
	    utc_offset: string;
	    locale?: string;
	    system_locale?: string;
	    user_languages?: string[];
	    format_settings?: Record<string, string>;
	    code_page?: string;
	    proxy_env?: Record<string, string>;
	    system_proxy?: string;
	    dns_servers?: string[];
	    claude_path?: string;
	    claude_version?: string;
	
	    static createFrom(source: any = {}) {
	        return new Platform(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.os = source["os"];
	        this.architecture = source["architecture"];
	        this.hostname = source["hostname"];
	        this.timezone = source["timezone"];
	        this.utc_offset = source["utc_offset"];
	        this.locale = source["locale"];
	        this.system_locale = source["system_locale"];
	        this.user_languages = source["user_languages"];
	        this.format_settings = source["format_settings"];
	        this.code_page = source["code_page"];
	        this.proxy_env = source["proxy_env"];
	        this.system_proxy = source["system_proxy"];
	        this.dns_servers = source["dns_servers"];
	        this.claude_path = source["claude_path"];
	        this.claude_version = source["claude_version"];
	    }
	}
	export class TLSInfo {
	    version?: string;
	    cipher?: string;
	    alpn?: string;
	    issuer?: string;
	    subject?: string;
	    dns_names?: string[];
	    ja3?: string;
	    ja3_hash?: string;
	    diagnostic_fingerprint?: string;
	
	    static createFrom(source: any = {}) {
	        return new TLSInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.version = source["version"];
	        this.cipher = source["cipher"];
	        this.alpn = source["alpn"];
	        this.issuer = source["issuer"];
	        this.subject = source["subject"];
	        this.dns_names = source["dns_names"];
	        this.ja3 = source["ja3"];
	        this.ja3_hash = source["ja3_hash"];
	        this.diagnostic_fingerprint = source["diagnostic_fingerprint"];
	    }
	}
	export class Route {
	    name: string;
	    proxy?: string;
	    public_ip?: string;
	    country?: string;
	    country_code?: string;
	    asn?: string;
	    organization?: string;
	    source?: string;
	    http_status?: number;
	    latency_ms?: number;
	    tls?: TLSInfo;
	    websocket: string;
	    websocket_ip?: string;
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new Route(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.proxy = source["proxy"];
	        this.public_ip = source["public_ip"];
	        this.country = source["country"];
	        this.country_code = source["country_code"];
	        this.asn = source["asn"];
	        this.organization = source["organization"];
	        this.source = source["source"];
	        this.http_status = source["http_status"];
	        this.latency_ms = source["latency_ms"];
	        this.tls = this.convertValues(source["tls"], TLSInfo);
	        this.websocket = source["websocket"];
	        this.websocket_ip = source["websocket_ip"];
	        this.error = source["error"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Report {
	    schema_version: string;
	    tool_version: string;
	    rules_version: string;
	    // Go type: time
	    generated_at: any;
	    duration_ms: number;
	    platform: Platform;
	    routes: Route[];
	    checks: Check[];
	    compatibility_score: number;
	    region_exposure_score: number;
	    coverage: number;
	    evidence: Evidence[];
	    recommendations: string[];
	    privacy_redactions: string[];
	    metadata?: Record<string, any>;
	
	    static createFrom(source: any = {}) {
	        return new Report(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.schema_version = source["schema_version"];
	        this.tool_version = source["tool_version"];
	        this.rules_version = source["rules_version"];
	        this.generated_at = this.convertValues(source["generated_at"], null);
	        this.duration_ms = source["duration_ms"];
	        this.platform = this.convertValues(source["platform"], Platform);
	        this.routes = this.convertValues(source["routes"], Route);
	        this.checks = this.convertValues(source["checks"], Check);
	        this.compatibility_score = source["compatibility_score"];
	        this.region_exposure_score = source["region_exposure_score"];
	        this.coverage = source["coverage"];
	        this.evidence = this.convertValues(source["evidence"], Evidence);
	        this.recommendations = source["recommendations"];
	        this.privacy_redactions = source["privacy_redactions"];
	        this.metadata = source["metadata"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class ScanOptions {
	    profile: string;
	    probe_url: string;
	    timeout_seconds: number;
	    public_fallback: boolean;
	    authenticated: boolean;
	    api_key?: string;
	    model_request: boolean;
	    run_doctor: boolean;
	    language: string;
	
	    static createFrom(source: any = {}) {
	        return new ScanOptions(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.profile = source["profile"];
	        this.probe_url = source["probe_url"];
	        this.timeout_seconds = source["timeout_seconds"];
	        this.public_fallback = source["public_fallback"];
	        this.authenticated = source["authenticated"];
	        this.api_key = source["api_key"];
	        this.model_request = source["model_request"];
	        this.run_doctor = source["run_doctor"];
	        this.language = source["language"];
	    }
	}

}

