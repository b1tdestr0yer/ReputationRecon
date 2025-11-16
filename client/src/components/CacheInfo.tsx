import { AssessmentResponse } from '../types'

interface CacheInfoProps {
  data: AssessmentResponse
  onRefresh: () => void
  isRefreshing: boolean
}

const CacheInfo = ({ data, onRefresh, isRefreshing }: CacheInfoProps) => {
  const isCached = data.is_cached || false
  const cachedAt = data.cached_at || null
  const cacheExpiresAt = data.cache_expires_at || null
  const assessmentTimestamp = data.assessment_timestamp || new Date().toISOString()
  // Explicitly check for pro_mode - it can be true, false, or undefined
  // Use strict check: if pro_mode exists and is true, use true; otherwise false
  const proMode = data.pro_mode === true
  
  // Debug logging
  console.log('[CacheInfo] pro_mode from data:', data.pro_mode, 'type:', typeof data.pro_mode, 'final proMode:', proMode)

  const formatDate = (dateString: string) => {
    const date = new Date(dateString)
    return date.toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  }

  const getRelativeTime = (dateString: string) => {
    const date = new Date(dateString)
    const now = new Date()
    const diff = now.getTime() - date.getTime()
    const seconds = Math.floor(diff / 1000)
    const minutes = Math.floor(seconds / 60)
    const hours = Math.floor(minutes / 60)
    const days = Math.floor(hours / 24)

    if (days > 0) return `${days} day${days !== 1 ? 's' : ''} ago`
    if (hours > 0) return `${hours} hour${hours !== 1 ? 's' : ''} ago`
    if (minutes > 0) return `${minutes} minute${minutes !== 1 ? 's' : ''} ago`
    return 'just now'
  }

  const formattedDate = formatDate(assessmentTimestamp)
  const relativeTime = getRelativeTime(assessmentTimestamp)

  let expiresInfo = ''
  let expiresBadge: JSX.Element | null = null
  if (cacheExpiresAt) {
    const expiresDate = new Date(cacheExpiresAt)
    const now = new Date()
    const timeUntilExpiry = expiresDate.getTime() - now.getTime()
    const daysUntilExpiry = Math.ceil(timeUntilExpiry / (1000 * 60 * 60 * 24))
    const hoursUntilExpiry = Math.ceil(timeUntilExpiry / (1000 * 60 * 60))

    const formattedExpiresDate = formatDate(cacheExpiresAt)

    if (daysUntilExpiry > 0) {
      expiresInfo = `Expires: ${formattedExpiresDate} (in ${daysUntilExpiry} day${daysUntilExpiry !== 1 ? 's' : ''})`
      expiresBadge = (
        <span
          style={{
            background: 'var(--card-bg)',
            color: '#856404',
            border: '1px solid #ffc107',
            padding: '4px 10px',
            borderRadius: '12px',
            fontSize: '0.8em',
            fontWeight: 500,
            marginLeft: '8px',
          }}
        >
          Valid for {daysUntilExpiry} day{daysUntilExpiry !== 1 ? 's' : ''}
        </span>
      )
    } else if (hoursUntilExpiry > 0) {
      expiresInfo = `Expires: ${formattedExpiresDate} (in ${hoursUntilExpiry} hour${hoursUntilExpiry !== 1 ? 's' : ''})`
      expiresBadge = (
        <span
          style={{
            background: 'var(--card-bg)',
            color: '#856404',
            border: '1px solid #ffc107',
            padding: '4px 10px',
            borderRadius: '12px',
            fontSize: '0.8em',
            fontWeight: 500,
            marginLeft: '8px',
          }}
        >
          Expires soon
        </span>
      )
    } else {
      expiresInfo = `Expired: ${formattedExpiresDate}`
      expiresBadge = (
        <span
          style={{
            background: 'var(--card-bg)',
            color: '#721c24',
            border: '1px solid #dc3545',
            padding: '4px 10px',
            borderRadius: '12px',
            fontSize: '0.8em',
            fontWeight: 500,
            marginLeft: '8px',
          }}
        >
          Expired
        </span>
      )
    }
  }

  return (
    <div className="section" style={{ marginTop: '40px' }}>
      <div
        style={{
          background: 'var(--section-bg)',
          padding: '20px',
          borderRadius: '12px',
          borderLeft: '4px solid #667eea',
          boxShadow: '0 2px 8px rgba(0,0,0,0.08)',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '20px',
          }}
        >
          <div style={{ flex: 1, minWidth: '250px' }}>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
                marginBottom: '12px',
              }}
            >
              <i className="fas fa-clock" style={{ color: '#667eea', fontSize: '1.3em' }}></i>
              <div>
                <div style={{ fontSize: '0.85em', color: 'var(--text-secondary)', marginBottom: '2px' }}>
                  Assessment Performed
                </div>
                <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '1em' }}>
                  {formattedDate}
                </div>
                <div style={{ fontSize: '0.85em', color: 'var(--text-muted)', marginTop: '2px' }}>
                  {relativeTime}
                </div>
              </div>
            </div>

            {isCached && cachedAt ? (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px',
                  marginBottom: '12px',
                }}
              >
                <i className="fas fa-database" style={{ color: '#ffc107', fontSize: '1.3em' }}></i>
                <div style={{ flex: 1 }}>
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      flexWrap: 'wrap',
                      gap: '8px',
                    }}
                  >
                    <div style={{ fontSize: '0.85em', color: 'var(--text-secondary)', marginBottom: '2px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span>Retrieved from Cache</span>
                      {proMode ? (
                        <span style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '4px',
                          padding: '2px 8px',
                          background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                          color: 'white',
                          borderRadius: '12px',
                          fontSize: '0.75em',
                          fontWeight: 'bold',
                          textTransform: 'uppercase',
                          letterSpacing: '0.5px'
                        }} title="PRO Mode">
                          <i className="fas fa-star"></i> PRO
                        </span>
                      ) : (
                        <span style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '4px',
                          padding: '2px 8px',
                          background: 'var(--section-bg)',
                          color: 'var(--text-secondary)',
                          borderRadius: '12px',
                          fontSize: '0.75em',
                          fontStyle: 'italic',
                          border: '1px solid var(--border-color)'
                        }} title="Classic Mode">
                          <i className="fas fa-circle"></i> Classic
                        </span>
                      )}
                    </div>
                    {expiresBadge}
                  </div>
                                        <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '1em' }}>
                      {formatDate(cachedAt)}
                    </div>
                    <div style={{ fontSize: '0.85em', color: 'var(--text-muted)', marginTop: '2px' }}>
                      Cached {getRelativeTime(cachedAt)}
                    </div>
                    {expiresInfo && (
                      <div style={{ fontSize: '0.85em', color: 'var(--text-secondary)', marginTop: '4px' }}>
                        <i className="fas fa-hourglass-half" style={{ marginRight: '4px' }}></i>
                        {expiresInfo}
                      </div>
                    )}
                    <div style={{ fontSize: '0.85em', color: 'var(--text-secondary)', marginTop: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span>Analysis Mode:</span>
                      {proMode ? (
                        <span style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '4px',
                          padding: '2px 8px',
                          background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                          color: 'white',
                          borderRadius: '12px',
                          fontSize: '0.8em',
                          fontWeight: 'bold',
                          textTransform: 'uppercase',
                          letterSpacing: '0.5px'
                        }}>
                          <i className="fas fa-star"></i> PRO Mode
                        </span>
                      ) : (
                        <span style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '4px',
                          padding: '2px 8px',
                          background: 'var(--section-bg)',
                          color: 'var(--text-secondary)',
                          borderRadius: '12px',
                          fontSize: '0.8em',
                          fontStyle: 'italic',
                          border: '1px solid var(--border-color)'
                        }}>
                          <i className="fas fa-circle"></i> Classic Mode
                        </span>
                      )}
                    </div>
                </div>
              </div>
            ) : (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px',
                }}
              >
                <i className="fas fa-sync-alt" style={{ color: '#28a745', fontSize: '1.3em' }}></i>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: '0.85em', color: 'var(--text-secondary)', marginBottom: '2px' }}>
                    Cache Status
                  </div>
                  <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '1em' }}>
                    Fresh Assessment
                  </div>
                  <div style={{ fontSize: '0.85em', color: 'var(--text-muted)', marginTop: '2px' }}>
                    Generated just now
                  </div>
                  <div style={{ fontSize: '0.85em', color: 'var(--text-secondary)', marginTop: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span>Analysis Mode:</span>
                    {proMode ? (
                      <span style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '4px',
                        padding: '2px 8px',
                        background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                        color: 'white',
                        borderRadius: '12px',
                        fontSize: '0.8em',
                        fontWeight: 'bold',
                        textTransform: 'uppercase',
                        letterSpacing: '0.5px'
                      }}>
                        <i className="fas fa-star"></i> PRO Mode
                      </span>
                    ) : (
                      <span style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '4px',
                        padding: '2px 8px',
                        background: 'var(--section-bg)',
                        color: 'var(--text-secondary)',
                        borderRadius: '12px',
                        fontSize: '0.8em',
                        fontStyle: 'italic',
                        border: '1px solid var(--border-color)'
                      }}>
                        <i className="fas fa-circle"></i> Classic Mode
                      </span>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>

          {isCached && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
              <button
                onClick={onRefresh}
                disabled={isRefreshing}
                style={{
                  background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                  color: 'white',
                  border: 'none',
                  padding: '12px 24px',
                  borderRadius: '8px',
                  fontSize: '0.95em',
                  fontWeight: 600,
                  cursor: isRefreshing ? 'not-allowed' : 'pointer',
                  boxShadow: '0 4px 12px rgba(102, 126, 234, 0.3)',
                  transition: 'all 0.3s ease',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '8px',
                  position: 'relative',
                  overflow: 'hidden',
                  opacity: isRefreshing ? 0.7 : 1,
                }}
                onMouseOver={(e) => {
                  if (!isRefreshing) {
                    e.currentTarget.style.transform = 'translateY(-2px)'
                    e.currentTarget.style.boxShadow = '0 6px 16px rgba(102, 126, 234, 0.4)'
                  }
                }}
                onMouseOut={(e) => {
                  e.currentTarget.style.transform = 'translateY(0)'
                  e.currentTarget.style.boxShadow = '0 4px 12px rgba(102, 126, 234, 0.3)'
                }}
              >
                <i
                  className={`fas fa-sync-alt ${isRefreshing ? 'spinning' : ''}`}
                  style={{
                    animation: isRefreshing ? 'spin 1s linear infinite' : 'none',
                  }}
                ></i>
                <span>Update Assessment</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default CacheInfo

