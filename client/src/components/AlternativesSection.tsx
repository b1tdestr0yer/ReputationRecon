import { Alternative } from '../types'

interface AlternativesSectionProps {
  alternatives: Alternative[]
}

const AlternativesSection = ({ alternatives }: AlternativesSectionProps) => {
  return (
    <div className="section">
      <h3>
        <i className="fas fa-lightbulb"></i> Safer Alternatives
      </h3>
      <div className="security-cards">
        {alternatives.map((alt, index) => (
          <div
            key={index}
            className="security-card"
            style={{ borderTopColor: '#4caf50' }}
          >
            <div className="card-header">
              <i className="fas fa-check-circle card-icon" style={{ color: '#4caf50' }}></i>
              <div className="card-title">{alt.name}</div>
            </div>
            <div style={{ color: '#666', marginBottom: '10px' }}>
              <strong>Vendor:</strong> {alt.vendor}
            </div>
            <div className="card-content">{alt.rationale}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

export default AlternativesSection

