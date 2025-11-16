import { TrustScore } from '../types'

interface TrustScoreGaugeProps {
  trustScore: TrustScore
}

const TrustScoreGauge = ({ trustScore }: TrustScoreGaugeProps) => {
  const score = trustScore.score || 0
  const confidence = ((trustScore.confidence || 0) * 100).toFixed(0)

  // Determine colors based on score
  let gaugeColor: string
  let riskClass: string
  let riskText: string

  if (score >= 70) {
    gaugeColor = '#4caf50'
    riskClass = 'risk-low'
    riskText = 'Low Risk'
  } else if (score >= 50) {
    gaugeColor = '#ffc107'
    riskClass = 'risk-medium'
    riskText = 'Medium Risk'
  } else if (score >= 30) {
    gaugeColor = '#ff6f00'
    riskClass = 'risk-high'
    riskText = 'High Risk'
  } else {
    gaugeColor = '#f44336'
    riskClass = 'risk-critical'
    riskText = 'Critical Risk'
  }

  // Build factors HTML
  const factors = trustScore.factors || {}
  const sortedFactors = Object.entries(factors)
    .sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]))
    .slice(0, 8)

  return (
    <div className="trust-score-container">
      <div className="gauge-wrapper">
        <div
          className="gauge-circle"
          style={{
            ['--score' as string]: score,
            ['--gauge-color' as string]: gaugeColor,
          } as React.CSSProperties}
        >
          <div className="gauge-inner">
            <div className="gauge-score" style={{ color: gaugeColor }}>
              {score}
            </div>
            <div className="gauge-label">/ 100</div>
          </div>
        </div>
      </div>
      <div className="trust-score-info">
        <div>
          <span className={`risk-badge ${riskClass}`}>{riskText}</span>
        </div>
        <div className="confidence-meter">
          <span style={{ fontWeight: 600, minWidth: '120px' }}>Confidence:</span>
          <div className="confidence-bar">
            <div className="confidence-fill" style={{ width: `${confidence}%` }}></div>
          </div>
          <span style={{ fontWeight: 600 }}>{confidence}%</span>
        </div>
        <div>
          <p style={{ color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            {trustScore.rationale || 'No rationale provided'}
          </p>
        </div>
        <div>
          <h4 style={{ marginBottom: '15px', color: 'var(--text-primary)' }}>
            <i className="fas fa-chart-line"></i> Key Factors
          </h4>
          <div className="factors-grid">
            {sortedFactors.map(([key, value]) => {
              const isPositive = value > 0
              const displayValue = isPositive ? `+${value}` : value.toString()
              return (
                <div key={key} className={`factor-card ${isPositive ? 'positive' : 'negative'}`}>
                  <div className="factor-label">{key.replace(/_/g, ' ')}</div>
                  <div className={`factor-value ${isPositive ? 'positive' : 'negative'}`}>
                    {displayValue}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}

export default TrustScoreGauge

