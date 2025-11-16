import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { searchCache } from '../services/api'
import './CacheBrowser.css'

interface CacheResult {
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
}

interface CacheBrowserProps {
  onSelectAssessment?: (cacheKey: string) => void
}

const CacheBrowser = ({ onSelectAssessment }: CacheBrowserProps) => {
  const navigate = useNavigate()
  const [productName, setProductName] = useState('')
  const [vendorName, setVendorName] = useState('')
  const [hash, setHash] = useState('')
  const [trustScoreFilter, setTrustScoreFilter] = useState<'all' | 'good' | 'bad'>('all')
  const [results, setResults] = useState<CacheResult[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Debounce search using ref
  const timeoutRef = useRef<NodeJS.Timeout | null>(null)

  const performSearch = async (product: string, vendor: string, hashValue: string, filter: string) => {
    setLoading(true)
    setError(null)

    try {
      const minScore = filter === 'bad' ? 0 : filter === 'good' ? 70 : undefined
      const maxScore = filter === 'bad' ? 69 : undefined

      const searchParams: any = {
        limit: 100,
      }
      
      if (product && product.trim()) {
        searchParams.product_name = product.trim()
      }
      if (vendor && vendor.trim()) {
        searchParams.vendor_name = vendor.trim()
      }
      if (hashValue && hashValue.trim()) {
        searchParams.hash = hashValue.trim()
      }
      if (minScore !== undefined) {
        searchParams.min_trust_score = minScore
      }
      if (maxScore !== undefined) {
        searchParams.max_trust_score = maxScore
      }

      console.log('[CacheBrowser] Searching with params:', searchParams)
      const response = await searchCache(searchParams)
      console.log('[CacheBrowser] Search response:', response)
      console.log('[CacheBrowser] First result hash:', response.results?.[0]?.hash)
      console.log('[CacheBrowser] All results with hashes:', response.results?.map(r => ({ name: r.entity_name, hash: r.hash })))

      setResults(response.results || [])
    } catch (err) {
      console.error('[CacheBrowser] Search error:', err)
      const errorMessage = err instanceof Error ? err.message : 'Error searching cache'
      setError(errorMessage)
      setResults([])
      
      // If it's a 404, suggest restarting the server
      if (errorMessage.includes('404') || errorMessage.includes('Not Found')) {
        setError('Endpoint not found. Please restart the server to register the new /api/cache/search endpoint.')
      }
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    // Clear existing timeout
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current)
    }

    // Debounce search
    timeoutRef.current = setTimeout(() => {
      performSearch(productName, vendorName, hash, trustScoreFilter)
    }, 300)

    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current)
      }
    }
  }, [productName, vendorName, hash, trustScoreFilter])

  const getRiskBadgeClass = (score: number, riskLevel: string) => {
    if (score >= 70) return 'risk-low'
    if (score >= 50) return 'risk-medium'
    if (score >= 30) return 'risk-high'
    return 'risk-critical'
  }

  const getRiskIcon = (score: number, riskLevel: string) => {
    if (score >= 70) return 'fas fa-check-circle'
    if (score >= 50) return 'fas fa-exclamation-circle'
    if (score >= 30) return 'fas fa-exclamation-triangle'
    return 'fas fa-times-circle'
  }

  const getRiskColor = (score: number) => {
    if (score >= 70) return '#4caf50'
    if (score >= 50) return '#ffc107'
    if (score >= 30) return '#ff6f00'
    return '#f44336'
  }

  const formatDate = (dateString: string) => {
    try {
      const date = new Date(dateString)
      return date.toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      })
    } catch {
      return dateString
    }
  }

  return (
    <div className="container cache-browser-page">
      <div className="cache-browser-header">
        <div className="cache-browser-header-content">
          <h2>
            <i className="fas fa-database"></i> Cache Browser
          </h2>
          <button className="back-btn" onClick={() => navigate('/')}>
            <i className="fas fa-arrow-left"></i>
            <span>Back to Home</span>
          </button>
        </div>
      </div>

        <div className="cache-browser-filters">
          <div className="filter-row">
            <div className="filter-group">
              <label>
                <i className="fas fa-box"></i> Product Name
              </label>
              <input
                type="text"
                placeholder="Search by product name..."
                value={productName}
                onChange={(e) => setProductName(e.target.value)}
              />
            </div>
            <div className="filter-group">
              <label>
                <i className="fas fa-building"></i> Vendor Name
              </label>
              <input
                type="text"
                placeholder="Search by vendor name..."
                value={vendorName}
                onChange={(e) => setVendorName(e.target.value)}
              />
            </div>
            <div className="filter-group">
              <label>
                <i className="fas fa-fingerprint"></i> Hash
              </label>
              <input
                type="text"
                placeholder="Search by hash (MD5, SHA1, SHA256)..."
                value={hash}
                onChange={(e) => setHash(e.target.value)}
              />
            </div>
          </div>

          <div className="filter-row">
            <div className="filter-group">
              <label>
                <i className="fas fa-shield-alt"></i> Trust Score Filter
              </label>
              <div className="filter-buttons">
                <button
                  className={trustScoreFilter === 'all' ? 'active' : ''}
                  onClick={() => setTrustScoreFilter('all')}
                >
                  All
                </button>
                <button
                  className={trustScoreFilter === 'good' ? 'active' : ''}
                  onClick={() => setTrustScoreFilter('good')}
                >
                  <i className="fas fa-check-circle"></i> Good (≥70)
                </button>
                <button
                  className={trustScoreFilter === 'bad' ? 'active' : ''}
                  onClick={() => setTrustScoreFilter('bad')}
                >
                  <i className="fas fa-times-circle"></i> Bad ({'<'}70)
                </button>
              </div>
            </div>
          </div>
        </div>

        {loading && (
          <div className="cache-browser-loading">
            <div className="loading-spinner-small">
              <div className="spinner-ring"></div>
            </div>
            <span>Searching cache...</span>
          </div>
        )}

        {error && (
          <div className="cache-browser-error">
            <i className="fas fa-exclamation-circle"></i> {error}
          </div>
        )}

        <div className="cache-browser-results">
          <div className="results-header">
            <h3>
              <i className="fas fa-list"></i> Results ({results.length})
            </h3>
          </div>

          {results.length === 0 && !loading && (
            <div className="no-results">
              <i className="fas fa-search"></i>
              <p>No assessments found matching your criteria</p>
            </div>
          )}

          <div className="results-grid">
            {results.map((result) => (
              <div
                key={result.cache_key}
                className="result-card"
                onClick={() => {
                  onSelectAssessment?.(result.cache_key)
                  // Extract hash - handle null, undefined, and empty string
                  // Make sure we get the hash even if it's stored as null/undefined
                  let hashValue = null
                  if (result.hash) {
                    if (typeof result.hash === 'string' && result.hash.trim()) {
                      hashValue = result.hash.trim()
                    } else if (result.hash !== null && result.hash !== undefined) {
                      hashValue = String(result.hash).trim()
                    }
                  }
                  
                  console.log('[CacheBrowser] Clicking result:', {
                    entity_name: result.entity_name,
                    vendor_name: result.vendor_name,
                    hash_original: result.hash,
                    hash_type: typeof result.hash,
                    hashValue: hashValue,
                    full_result: result
                  })
                  
                  navigate('/', {
                    state: {
                      productName: result.entity_name,
                      vendorName: result.vendor_name,
                      hash: hashValue,
                    },
                  })
                }}
              >
                <div className="result-header">
                  <div className="result-icon" style={{ color: getRiskColor(result.trust_score) }}>
                    <i className={getRiskIcon(result.trust_score, result.risk_level)}></i>
                  </div>
                  <div className="result-title">
                    <h4>{result.entity_name}</h4>
                    <p>{result.vendor_name}</p>
                  </div>
                  <div className="result-score" style={{ color: getRiskColor(result.trust_score) }}>
                    {result.trust_score}
                  </div>
                </div>

                <div className="result-badge">
                  <span className={`risk-badge ${getRiskBadgeClass(result.trust_score, result.risk_level)}`}>
                    {result.risk_level}
                  </span>
                  <span className="category-badge">{result.category}</span>
                </div>

                <div className="result-stats">
                  <div className="stat-item">
                    <i className="fas fa-bug"></i>
                    <span>{result.total_cves} CVEs</span>
                    {result.critical_cves > 0 && (
                      <span className="stat-critical">{result.critical_cves} Critical</span>
                    )}
                  </div>
                  {result.cisa_kev_count > 0 && (
                    <div className="stat-item stat-warning">
                      <i className="fas fa-exclamation-triangle"></i>
                      <span>{result.cisa_kev_count} CISA KEV</span>
                    </div>
                  )}
                  <div className="stat-item">
                    <i className="fas fa-fingerprint"></i>
                    {result.hash && result.hash.trim() ? (
                      <span style={{ fontFamily: 'monospace', fontSize: '0.85em' }}>
                        Hash: {result.hash.length > 32 ? `${result.hash.substring(0, 32)}...` : result.hash}
                      </span>
                    ) : (
                      <span style={{ fontSize: '0.85em', fontStyle: 'italic', color: 'var(--text-muted)' }}>
                        Hash: Not in cache
                      </span>
                    )}
                  </div>
                </div>

                <div className="result-footer">
                  <span>
                    <i className="fas fa-clock"></i> {formatDate(result.updated_at)}
                  </span>
                  {result.is_cached && (
                    <span className="cached-badge">
                      <i className="fas fa-database"></i> Cached
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
    </div>
  )
}

export default CacheBrowser

