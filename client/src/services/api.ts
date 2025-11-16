import { AssessmentResponse, CompareRequest, CompareResponse } from '../types'

const API_BASE = '/api'

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

export const compareApplications = async (
  requests: CompareRequest[]
): Promise<CompareResponse> => {
  const response = await fetch(`${API_BASE}/compare`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(requests),
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

