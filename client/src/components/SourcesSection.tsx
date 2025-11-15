import { SecurityPosture, Citation } from '../types'

interface SourcesSectionProps {
  citations: Citation[]
  securityPosture: SecurityPosture
}

const SourcesSection = ({ citations, securityPosture }: SourcesSectionProps) => {
  const bugBountyCitations = citations.filter(
    (c) => c.source_type === 'HackerOne' || c.source_type === 'Bugcrowd'
  )

  const otherCitations = citations.filter(
    (c) => c.source_type !== 'HackerOne' && c.source_type !== 'Bugcrowd'
  )

  return (
    <>
      {bugBountyCitations.length > 0 && (
        <div className="section">
          <h3>
            <i className="fas fa-shield-alt"></i> Bug Bounty Reports
          </h3>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
              gap: '15px',
              marginBottom: '20px',
            }}
          >
            <div
              style={{
                background: 'var(--card-bg)',
                padding: '15px',
                borderRadius: '8px',
                textAlign: 'center',
                borderTop: '4px solid #ff5722',
              }}
            >
              <div style={{ fontSize: '2em', fontWeight: 'bold', color: '#ff5722' }}>
                {bugBountyCitations.length}
              </div>
              <div style={{ color: 'var(--text-secondary)', marginTop: '5px' }}>Total Reports</div>
            </div>
            <div
              style={{
                background: 'var(--card-bg)',
                padding: '15px',
                borderRadius: '8px',
                textAlign: 'center',
                borderTop: '4px solid #ff9800',
              }}
            >
              <div style={{ fontSize: '2em', fontWeight: 'bold', color: '#ff9800' }}>
                {bugBountyCitations.filter((c) => c.source_type === 'HackerOne').length}
              </div>
              <div style={{ color: 'var(--text-secondary)', marginTop: '5px' }}>HackerOne</div>
            </div>
            <div
              style={{
                background: 'var(--card-bg)',
                padding: '15px',
                borderRadius: '8px',
                textAlign: 'center',
                borderTop: '4px solid #9c27b0',
              }}
            >
              <div style={{ fontSize: '2em', fontWeight: 'bold', color: '#9c27b0' }}>
                {bugBountyCitations.filter((c) => c.source_type === 'Bugcrowd').length}
              </div>
              <div style={{ color: 'var(--text-secondary)', marginTop: '5px' }}>Bugcrowd</div>
            </div>
          </div>
          <h4 style={{ marginTop: '20px', marginBottom: '15px' }}>Public Bug Bounty Reports</h4>
          <div className="sources-list">
            {bugBountyCitations.map((citation, index) => {
              const isUrl = citation.source && citation.source.startsWith('http')
              return (
                <div key={index} className="source-item independent">
                  <strong>{citation.source_type}</strong>{' '}
                  <span style={{ color: '#ffc107' }}>(Independent)</span>
                  <br />
                  {isUrl ? (
                    <a
                      href={citation.source}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{ color: '#667eea' }}
                    >
                      {citation.source}
                    </a>
                  ) : (
                    <span>{citation.source}</span>
                  )}
                  <br />
                  <em style={{ color: 'var(--text-secondary)' }}>{citation.claim}</em>
                </div>
              )
            })}
          </div>
        </div>
      )}

      <div className="section">
        <h3>
          <i className="fas fa-book"></i> Sources & Information
        </h3>
        <div className="sources-list">
          {otherCitations.length > 0 ? (
            otherCitations.map((citation, index) => {
              const sourceClass = citation.is_vendor_stated ? 'vendor' : 'independent'
              const isUrl = citation.source && citation.source.startsWith('http')
              const displayText = isUrl
                ? citation.source
                : `${citation.source_type}: ${citation.source}`
              return (
                <div key={index} className={`source-item ${sourceClass}`}>
                  <strong>{citation.source_type}</strong>{' '}
                  {citation.is_vendor_stated ? (
                    <span style={{ color: '#4caf50' }}>(Vendor-stated)</span>
                  ) : (
                    <span style={{ color: '#ffc107' }}>(Independent)</span>
                  )}
                  <br />
                  {isUrl ? (
                    <a
                      href={citation.source}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{ color: '#667eea' }}
                    >
                      {displayText}
                    </a>
                  ) : (
                    <span>{displayText}</span>
                  )}
                  <br />
                  <em style={{ color: 'var(--text-secondary)' }}>{citation.claim}</em>
                </div>
              )
            })
          ) : (
            <p>No sources available.</p>
          )}
        </div>
      </div>
    </>
  )
}

export default SourcesSection

