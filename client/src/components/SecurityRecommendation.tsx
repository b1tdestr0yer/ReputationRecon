import { SecurityPosture, TrustScore } from '../types'

interface SecurityRecommendationProps {
  suggestion: string
  trustScore: number
  riskLevel: string
  securityPosture: SecurityPosture
}

const SecurityRecommendation = ({
  suggestion,
  trustScore,
  riskLevel,
  securityPosture,
}: SecurityRecommendationProps) => {
  // Parse recommendation status from AI text
  let cleanSuggestion = suggestion || 'No recommendation available.'

  // Remove markdown asterisks
  cleanSuggestion = cleanSuggestion.replace(/\*\*([^*]+)\*\*/g, '$1')
  cleanSuggestion = cleanSuggestion.replace(/\*([^*]+)\*/g, '$1')
  cleanSuggestion = cleanSuggestion.replace(/_([^_]+)_/g, '$1')

  // Extract recommendation status from text
  let recStatus: string
  let recColor: string
  let recBgGradient: string
  let recBorderColor: string
  let recIcon: string
  let recTitle: string
  let recSubtitle: string

  const suggestionUpper = cleanSuggestion.toUpperCase()
  const suggestionLower = cleanSuggestion.toLowerCase()

  // Check for explicit status markers first (from AI)
  if (
    suggestionUpper.includes('NOT RECOMMENDED') ||
    suggestionLower.includes('do not allow') ||
    suggestionLower.includes('not recommended') ||
    suggestionLower.includes('should not be allowed') ||
    suggestionLower.includes('unsuitable for company laptops') ||
    (suggestionLower.includes('significant security risks') && suggestionLower.includes('not'))
  ) {
    recStatus = 'not-recommended'
    recColor = '#dc3545'
    recBgGradient = 'linear-gradient(135deg, #fff5f5 0%, #ffe5e5 100%)'
    recBorderColor = '#dc3545'
    recIcon = 'fas fa-times-circle'
    recTitle = 'Not Recommended'
    recSubtitle = 'Significant security risks identified'
  } else if (
    suggestionUpper.includes('USE WITH CAUTION') ||
    suggestionLower.includes('use with caution') ||
    suggestionLower.includes('exercise caution') ||
    suggestionLower.includes('elevated security concerns') ||
    suggestionLower.includes('requires additional controls')
  ) {
    recStatus = 'caution'
    recColor = '#ff9800'
    recBgGradient = 'linear-gradient(135deg, #fff8f0 0%, #ffe8d0 100%)'
    recBorderColor = '#ff9800'
    recIcon = 'fas fa-exclamation-triangle'
    recTitle = 'Use with Caution'
    recSubtitle = 'Elevated security concerns require additional controls'
  } else if (
    suggestionUpper.includes('CONDITIONALLY APPROVED') ||
    suggestionLower.includes('conditionally approved') ||
    suggestionLower.includes('may be acceptable') ||
    suggestionLower.includes('acceptable with') ||
    suggestionLower.includes('moderate security')
  ) {
    recStatus = 'conditional'
    recColor = '#ffc107'
    recBgGradient = 'linear-gradient(135deg, #fffbf0 0%, #fff5e0 100%)'
    recBorderColor = '#ffc107'
    recIcon = 'fas fa-check-circle'
    recTitle = 'Conditionally Approved'
    recSubtitle = 'Acceptable with standard security controls'
  } else if (
    suggestionUpper.includes('RECOMMENDED') ||
    suggestionLower.includes('suitable for deployment') ||
    suggestionLower.includes('appears suitable') ||
    suggestionLower.includes('relatively good security')
  ) {
    recStatus = 'recommended'
    recColor = '#28a745'
    recBgGradient = 'linear-gradient(135deg, #f0fff4 0%, #e0ffe0 100%)'
    recBorderColor = '#28a745'
    recIcon = 'fas fa-check-circle'
    recTitle = 'Recommended'
    recSubtitle = 'Suitable for deployment with standard controls'
  } else {
    // Fallback to trust score if no clear status in text
    const hasNegativeIndicators =
      suggestionLower.includes('do not') ||
      suggestionLower.includes('not allow') ||
      suggestionLower.includes('significant risks') ||
      suggestionLower.includes('active exploitation')

    const cisaKev = securityPosture?.cve_summary?.cisa_kev_count || 0
    const criticalCves = securityPosture?.cve_summary?.critical_count || 0

    if (hasNegativeIndicators || cisaKev > 0 || trustScore < 35 || riskLevel === 'Critical') {
      recStatus = 'not-recommended'
      recColor = '#dc3545'
      recBgGradient = 'linear-gradient(135deg, #fff5f5 0%, #ffe5e5 100%)'
      recBorderColor = '#dc3545'
      recIcon = 'fas fa-times-circle'
      recTitle = 'Not Recommended'
      recSubtitle = 'Significant security risks identified'
    } else if (trustScore < 55 || riskLevel === 'High' || criticalCves > 3) {
      recStatus = 'caution'
      recColor = '#ff9800'
      recBgGradient = 'linear-gradient(135deg, #fff8f0 0%, #ffe8d0 100%)'
      recBorderColor = '#ff9800'
      recIcon = 'fas fa-exclamation-triangle'
      recTitle = 'Use with Caution'
      recSubtitle = 'Elevated security concerns require additional controls'
    } else if (trustScore < 75 || riskLevel === 'Medium') {
      recStatus = 'conditional'
      recColor = '#ffc107'
      recBgGradient = 'linear-gradient(135deg, #fffbf0 0%, #fff5e0 100%)'
      recBorderColor = '#ffc107'
      recIcon = 'fas fa-check-circle'
      recTitle = 'Conditionally Approved'
      recSubtitle = 'Acceptable with standard security controls'
    } else {
      recStatus = 'recommended'
      recColor = '#28a745'
      recBgGradient = 'linear-gradient(135deg, #f0fff4 0%, #e0ffe0 100%)'
      recBorderColor = '#28a745'
      recIcon = 'fas fa-check-circle'
      recTitle = 'Recommended'
      recSubtitle = 'Suitable for deployment with standard controls'
    }
  }

  // Remove status line from text if present
  cleanSuggestion = cleanSuggestion.replace(
    /^(NOT RECOMMENDED|USE WITH CAUTION|CONDITIONALLY APPROVED|RECOMMENDED)\s*\n?/i,
    ''
  )

  // Split into paragraphs
  const paragraphs = cleanSuggestion.split('\n').filter((p) => p.trim())

  const shouldShowSecurityConsiderations =
    trustScore < 55 || recStatus === 'not-recommended' || recStatus === 'caution'

  return (
    <div className="section">
      <h3>
        <i className="fas fa-clipboard-check"></i> Security Recommendation
      </h3>
      <div
        className={`recommendation-card ${recStatus}`}
        style={{
          background: recBgGradient,
          borderLeft: `5px solid ${recBorderColor}`,
          borderRadius: '12px',
          padding: '25px',
          boxShadow: '0 4px 12px rgba(0,0,0,0.1)',
          marginBottom: '20px',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '15px',
            marginBottom: '20px',
            paddingBottom: '15px',
            borderBottom: '2px solid rgba(0,0,0,0.1)',
          }}
        >
          <div
            style={{
              width: '60px',
              height: '60px',
              borderRadius: '50%',
              background: recColor,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 4px 8px rgba(0,0,0,0.2)',
            }}
          >
            <i className={recIcon} style={{ fontSize: '2em', color: 'white' }}></i>
          </div>
          <div>
            <h4 style={{ margin: 0, color: recColor, fontSize: '1.5em', fontWeight: 700 }}>
              {recTitle}
            </h4>
            <p style={{ margin: '5px 0 0 0', color: '#666', fontSize: '0.95em' }}>
              {recSubtitle}
            </p>
          </div>
        </div>
        <div style={{ lineHeight: 1.8, color: '#333' }}>
          {paragraphs.map((para, index) => {
            // Check if paragraph contains "Recommendation:" to make it stand out
            if (para.toLowerCase().includes('recommendation:')) {
              const parts = para.split(/recommendation:/i)
              return (
                <p key={index} style={{ margin: '12px 0' }}>
                  <strong style={{ color: recColor }}>Recommendation:</strong>{' '}
                  {parts[1]?.trim() || ''}
                </p>
              )
            }
            // Check for key phrases to emphasize
            if (
              para.toLowerCase().includes('do not') ||
              para.toLowerCase().includes('not recommended') ||
              para.toLowerCase().includes('significant risks')
            ) {
              return (
                <p key={index} style={{ margin: '12px 0', color: recColor, fontWeight: 600 }}>
                  {para.trim()}
                </p>
              )
            }
            return (
              <p key={index} style={{ margin: '12px 0' }}>
                {para.trim()}
              </p>
            )
          })}
        </div>
        {shouldShowSecurityConsiderations && (
          <div
            style={{
              marginTop: '20px',
              padding: '15px',
              background: 'rgba(255,255,255,0.7)',
              borderRadius: '8px',
              borderLeft: `3px solid ${recColor}`,
            }}
          >
            <p style={{ margin: 0, fontWeight: 600, color: recColor }}>
              <i className="fas fa-shield-alt"></i> Security Considerations:
            </p>
            <ul style={{ margin: '10px 0 0 20px', paddingLeft: '10px', color: '#555' }}>
              {securityPosture?.cve_summary?.cisa_kev_count > 0 && (
                <li>
                  {securityPosture.cve_summary.cisa_kev_count} vulnerability(ies) actively
                  exploited (CISA KEV)
                </li>
              )}
              {securityPosture?.cve_summary?.critical_count > 0 && (
                <li>
                  {securityPosture.cve_summary.critical_count} critical CVE(s) identified
                </li>
              )}
              {(securityPosture?.cve_summary?.total_cves || 0) > 10 && (
                <li>
                  High number of CVEs ({securityPosture.cve_summary.total_cves}) indicates
                  ongoing security concerns
                </li>
              )}
              <li>Ensure latest version is deployed and monitored</li>
              <li>Obtain management approval before deployment</li>
            </ul>
          </div>
        )}
      </div>
    </div>
  )
}

export default SecurityRecommendation

