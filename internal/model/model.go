package model

import "time"

const (
	SchemaVersion = "1.0.0"
	ToolVersion   = "0.1.0"
	RulesVersion  = "2026.07.04-1"
)

type Status string

const (
	Pass    Status = "pass"
	Warn    Status = "warn"
	Fail    Status = "fail"
	Unknown Status = "unknown"
)

type TLSInfo struct {
	Version     string   `json:"version,omitempty"`
	Cipher      string   `json:"cipher,omitempty"`
	ALPN        string   `json:"alpn,omitempty"`
	Issuer      string   `json:"issuer,omitempty"`
	Subject     string   `json:"subject,omitempty"`
	DNSNames    []string `json:"dns_names,omitempty"`
	JA3         string   `json:"ja3,omitempty"`
	JA3Hash     string   `json:"ja3_hash,omitempty"`
	Fingerprint string   `json:"diagnostic_fingerprint,omitempty"`
}

type Route struct {
	Name             string         `json:"name"`
	Proxy            string         `json:"proxy,omitempty"`
	PublicIP         string         `json:"public_ip,omitempty"`
	Country          string         `json:"country,omitempty"`
	CountryCode      string         `json:"country_code,omitempty"`
	ASN              string         `json:"asn,omitempty"`
	Organization     string         `json:"organization,omitempty"`
	Source           string         `json:"source,omitempty"`
	HTTPStatus       int            `json:"http_status,omitempty"`
	LatencyMS        int64          `json:"latency_ms,omitempty"`
	TLS              TLSInfo        `json:"tls,omitempty"`
	WebSocket        Status         `json:"websocket"`
	WebSocketIP      string         `json:"websocket_ip,omitempty"`
	Error            string         `json:"error,omitempty"`
	ProxyDiagnostics map[string]any `json:"-"`
}

type Check struct {
	ID          string         `json:"id"`
	Category    string         `json:"category"`
	Status      Status         `json:"status"`
	Title       string         `json:"title"`
	Summary     string         `json:"summary"`
	Evidence    map[string]any `json:"evidence,omitempty"`
	DurationMS  int64          `json:"duration_ms,omitempty"`
	Source      string         `json:"source,omitempty"`
	Weight      int            `json:"weight"`
	Observed    bool           `json:"observed"`
	Remediation string         `json:"remediation,omitempty"`
}

type Evidence struct {
	Kind       string `json:"kind"`
	Message    string `json:"message"`
	Impact     int    `json:"impact"`
	Confidence string `json:"confidence"`
	CheckID    string `json:"check_id,omitempty"`
}

type Platform struct {
	OS             string            `json:"os"`
	Architecture   string            `json:"architecture"`
	Hostname       string            `json:"hostname,omitempty"`
	Timezone       string            `json:"timezone"`
	UTCOffset      string            `json:"utc_offset"`
	Locale         string            `json:"locale,omitempty"`
	SystemLocale   string            `json:"system_locale,omitempty"`
	UserLanguages  []string          `json:"user_languages,omitempty"`
	FormatSettings map[string]string `json:"format_settings,omitempty"`
	CodePage       string            `json:"code_page,omitempty"`
	ProxyEnv       map[string]string `json:"proxy_env,omitempty"`
	SystemProxy    string            `json:"system_proxy,omitempty"`
	DNSServers     []string          `json:"dns_servers,omitempty"`
	ClaudePath     string            `json:"claude_path,omitempty"`
	ClaudeVersion  string            `json:"claude_version,omitempty"`
}

type Report struct {
	SchemaVersion       string         `json:"schema_version"`
	ToolVersion         string         `json:"tool_version"`
	RulesVersion        string         `json:"rules_version"`
	GeneratedAt         time.Time      `json:"generated_at"`
	DurationMS          int64          `json:"duration_ms"`
	Platform            Platform       `json:"platform"`
	Routes              []Route        `json:"routes"`
	Checks              []Check        `json:"checks"`
	CompatibilityScore  int            `json:"compatibility_score"`
	RegionExposureScore int            `json:"region_exposure_score"`
	Coverage            int            `json:"coverage"`
	Evidence            []Evidence     `json:"evidence"`
	Recommendations     []string       `json:"recommendations"`
	PrivacyRedactions   []string       `json:"privacy_redactions"`
	Metadata            map[string]any `json:"metadata,omitempty"`
}

type ScanOptions struct {
	Profile        string `json:"profile"`
	ProbeURL       string `json:"probe_url"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	PublicFallback bool   `json:"public_fallback"`
	Authenticated  bool   `json:"authenticated"`
	APIKey         string `json:"api_key,omitempty"`
	ModelRequest   bool   `json:"model_request"`
	RunDoctor      bool   `json:"run_doctor"`
	Language       string `json:"language"`
}
