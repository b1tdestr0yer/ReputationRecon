import { AssessmentResponse } from '../types'

const API_BASE = '/api'

export interface CacheSearchParams {
  product_name?: string
  vendor_name?: string
  hash?: string
  min_trust_score?: number
  max_trust_score?: number
  limit?: number
}

export interface CacheSearchResponse {
  results: Array<{
    cache_key: string
    entity_name: string
    vendor_name: string
    trust_score: number
    risk_level: string
    category: string
    total_cves: number
    critical_cves: number
    cisa_kev_count: number
    created_at: string
    updated_at: string
    is_cached: boolean
    hash?: string
    pro_mode?: boolean
  }>
  count: number
}

export const searchCache = async (params: CacheSearchParams): Promise<CacheSearchResponse> => {
  const queryParams = new URLSearchParams()
  
  if (params.product_name) queryParams.append('product_name', params.product_name)
  if (params.vendor_name) queryParams.append('vendor_name', params.vendor_name)
  if (params.hash) queryParams.append('hash', params.hash)
  if (params.min_trust_score !== undefined) queryParams.append('min_trust_score', params.min_trust_score.toString())
  if (params.max_trust_score !== undefined) queryParams.append('max_trust_score', params.max_trust_score.toString())
  if (params.limit) queryParams.append('limit', params.limit.toString())

  const url = `${API_BASE}/cache/search?${queryParams.toString()}`
  const response = await fetch(url, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
    },
  })

  if (!response.ok) {
    const errorText = await response.text()
    throw new Error(`Server error: ${response.status} - ${errorText}`)
  }

  return response.json()
}

export const assessApplication = async (
  productName: string | null,
  vendorName: string | null,
  hash: string | null,
  forceRefresh = false,
  proMode = false
): Promise<AssessmentResponse> => {
  const url = `${API_BASE}/assess${forceRefresh ? '?force_refresh=true' : ''}`
  
  // Normalize values: trim whitespace and convert empty strings to null
  // This ensures cache key generation matches the original HTML version
  const normalizeValue = (value: string | null | undefined): string | null => {
    if (!value) return null
    const trimmed = value.trim()
    return trimmed === '' ? null : trimmed
  }
  
  const normalizedProduct = normalizeValue(productName)
  const normalizedVendor = normalizeValue(vendorName)
  const normalizedHash = normalizeValue(hash)
  
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      product_name: normalizedProduct,
      vendor_name: normalizedVendor,
      url: null,
      hash: normalizedHash,
      pro_mode: proMode,
    }),
  })

  if (!response.ok) {
    const errorText = await response.text()
    throw new Error(`Server error: ${response.status} - ${errorText}`)
  }

  return response.json()
}

export const exportReport = async (
  format: 'markdown' | 'pdf',
  data: AssessmentResponse
): Promise<Blob> => {
  const response = await fetch(`${API_BASE}/export/${format}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(data),
  })

  if (!response.ok) {
    throw new Error('Export failed')
  }

  return response.blob()
}

