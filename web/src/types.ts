export type Status = 'pass' | 'warn' | 'fail' | 'unknown'

export interface Check {
  id: string
  category: string
  title: string
  status: Status
  summary: string
  weight: number
  observed: boolean
  source?: string
  duration_ms?: number
  evidence?: Record<string, unknown>
}

export interface Route {
  name: string
  public_ip?: string
  country?: string
  country_code?: string
  asn?: string
  organization?: string
  source?: string
  websocket: Status
  websocket_ip?: string
  tls?: Record<string, unknown>
}

export interface Evidence {
  kind: string
  message: string
  impact: number
  confidence: string
  check_id?: string
}

export interface Report {
  schema_version: string
  tool_version: string
  rules_version: string
  generated_at: string
  duration_ms: number
  platform: Record<string, unknown>
  routes: Route[]
  checks: Check[]
  compatibility_score: number
  region_exposure_score: number
  coverage: number
  evidence: Evidence[]
  recommendations: string[]
  privacy_redactions: string[]
  metadata: Record<string, unknown>
}

export interface ScanOptions {
  probe_url: string
  timeout_seconds: number
  public_fallback: boolean
}
