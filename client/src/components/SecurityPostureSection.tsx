import { useState } from 'react'
import { SecurityPosture } from '../types'

interface SecurityPostureSectionProps {
  securityPosture: SecurityPosture
}

const SecurityPostureSection = ({ securityPosture }: SecurityPostureSectionProps) => {
  const [expandedCard, setExpandedCard] = useState<string | null>(null)

  const toggleCard = (cardId: string) => {
    setExpandedCard(expandedCard === cardId ? null : cardId)
  }

  return (
    <div className="section">
      <h3>
        <i className="fas fa-shield-alt"></i> Security Posture
      </h3>
      {securityPosture.summary && (
        <div
          style={{
            background: 'var(--loading-bg)',
            padding: '20px',
            borderRadius: '10px',
            marginBottom: '20px',
            borderLeft: '5px solid #2196F3',
          }}
        >
          <p style={{ margin: 0, fontWeight: 600, color: '#1976D2', fontSize: '1.1em' }}>
            Executive Summary
          </p>
          <p style={{ margin: '10px 0 0 0', lineHeight: 1.6, color: 'var(--text-primary)' }}>{securityPosture.summary}</p>
        </div>
      )}

      <div className="security-cards">
        <div className={`security-card description ${expandedCard === 'description' ? 'expanded' : ''}`}>
          <div
            className="security-card-header"
            onClick={() => toggleCard('description')}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <i className="fas fa-info-circle card-icon" style={{ color: '#2196F3', fontSize: '1.8em' }}></i>
              <div className="card-title">Description</div>
            </div>
            <i className={`fas fa-chevron-down security-card-toggle ${expandedCard === 'description' ? 'rotated' : ''}`}></i>
          </div>
          <div className="security-card-content">{securityPosture.description}</div>
        </div>

        <div className={`security-card usage ${expandedCard === 'usage' ? 'expanded' : ''}`}>
          <div className="security-card-header" onClick={() => toggleCard('usage')}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <i className="fas fa-tasks card-icon" style={{ color: '#9C27B0', fontSize: '1.8em' }}></i>
              <div className="card-title">Usage</div>
            </div>
            <i className={`fas fa-chevron-down security-card-toggle ${expandedCard === 'usage' ? 'rotated' : ''}`}></i>
          </div>
          <div className="security-card-content">{securityPosture.usage}</div>
        </div>

        <div className={`security-card reputation ${expandedCard === 'reputation' ? 'expanded' : ''}`}>
          <div className="security-card-header" onClick={() => toggleCard('reputation')}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <i className="fas fa-star card-icon" style={{ color: '#FF9800', fontSize: '1.8em' }}></i>
              <div className="card-title">Vendor Reputation</div>
            </div>
            <i className={`fas fa-chevron-down security-card-toggle ${expandedCard === 'reputation' ? 'rotated' : ''}`}></i>
          </div>
          <div className="security-card-content">{securityPosture.vendor_reputation}</div>
        </div>

        <div className={`security-card data ${expandedCard === 'data' ? 'expanded' : ''}`}>
          <div className="security-card-header" onClick={() => toggleCard('data')}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <i className="fas fa-database card-icon" style={{ color: '#4CAF50', fontSize: '1.8em' }}></i>
              <div className="card-title">Data Handling</div>
            </div>
            <i className={`fas fa-chevron-down security-card-toggle ${expandedCard === 'data' ? 'rotated' : ''}`}></i>
          </div>
          <div className="security-card-content">{securityPosture.data_handling}</div>
        </div>

        <div className={`security-card deployment ${expandedCard === 'deployment' ? 'expanded' : ''}`}>
          <div className="security-card-header" onClick={() => toggleCard('deployment')}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <i className="fas fa-cog card-icon" style={{ color: '#00BCD4', fontSize: '1.8em' }}></i>
              <div className="card-title">Deployment Controls</div>
            </div>
            <i className={`fas fa-chevron-down security-card-toggle ${expandedCard === 'deployment' ? 'rotated' : ''}`}></i>
          </div>
          <div className="security-card-content">
            {securityPosture.deployment_controls || 'No deployment controls information available.'}
          </div>
        </div>

        <div className={`security-card incidents ${expandedCard === 'incidents' ? 'expanded' : ''}`}>
          <div className="security-card-header" onClick={() => toggleCard('incidents')}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <i className="fas fa-exclamation-triangle card-icon" style={{ color: '#F44336', fontSize: '1.8em' }}></i>
              <div className="card-title">Incidents & Abuse</div>
            </div>
            <i className={`fas fa-chevron-down security-card-toggle ${expandedCard === 'incidents' ? 'rotated' : ''}`}></i>
          </div>
          <div className="security-card-content">
            {securityPosture.incidents_abuse || 'No significant incidents reported.'}
          </div>
        </div>
      </div>
    </div>
  )
}

export default SecurityPostureSection

