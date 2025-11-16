export interface TrustScore {
  score: number
  risk_level: string
  confidence: number
  rationale?: string
  factors: Record<string, number>
}

export interface CVESummary {
  total_cves: number
  critical_count: number
  high_count: number
  cisa_kev_count: number
  detected_version?: string
  version_specific_cves?: number
  version_specific_critical?: number
  version_specific_high?: number
  recent_cves?: CVE[]
}

export interface CVE {
  id: string
  severity: string
  base_score?: number
  published?: string
  description?: string
}

export interface Citation {
  source_type: string
  source: string
  claim: string
  is_vendor_stated?: boolean
}

export interface SecurityPosture {
  summary?: string
  description: string
  usage: string
  vendor_reputation: string
  data_handling: string
  deployment_controls?: string
  incidents_abuse?: string
  cve_summary: CVESummary
  citations: Citation[]
}

export interface Alternative {
  name: string
  vendor: string
  rationale: string
}

export interface AssessmentResponse {
  entity_name: string
  vendor_name: string
  category: string
  trust_score: TrustScore
  suggestion: string
  security_posture: SecurityPosture
  alternatives: Alternative[]
  is_cached?: boolean
  cached_at?: string
  cache_expires_at?: string
  assessment_timestamp?: string
}

