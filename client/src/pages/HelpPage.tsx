import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import Header from '../components/Header'

const HelpPage = () => {
  const navigate = useNavigate()
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['overview']))

  const toggleSection = (section: string) => {
    setExpandedSections(prev => {
      const newSet = new Set(prev)
      if (newSet.has(section)) {
        newSet.delete(section)
      } else {
        newSet.add(section)
      }
      return newSet
    })
  }

  const isExpanded = (section: string) => expandedSections.has(section)

  return (
    <div className="container">
      <Header />
      
      <div style={{ marginTop: '40px' }}>
        <button 
          onClick={() => navigate('/')} 
          className="btn-secondary"
          style={{ marginBottom: '30px' }}
        >
          <i className="fas fa-arrow-left"></i> Back to Home
        </button>

        <div style={{ marginBottom: '40px' }}>
          <h2 style={{ marginBottom: '20px', color: 'var(--text-primary)' }}>
            <i className="fas fa-info-circle"></i> How Trust/Risk Levels Are Calculated
          </h2>
          <p style={{ color: 'var(--text-secondary)', lineHeight: '1.6', marginBottom: '30px' }}>
            Secure Your App Health calculates trust scores (0-100) based on comprehensive security data analysis. 
            The score starts at <strong>60 (neutral)</strong> and adjusts based on positive and negative security factors.
          </p>

          {/* Visual Score Range */}
          <div style={{ 
            backgroundColor: 'var(--section-bg)', 
            padding: '30px', 
            borderRadius: '12px', 
            marginBottom: '30px',
            border: '1px solid var(--border-color)'
          }}>
            <h3 style={{ marginBottom: '25px', color: 'var(--text-primary)', textAlign: 'center' }}>
              Risk Level Thresholds
            </h3>
            <div style={{ position: 'relative', marginBottom: '30px' }}>
              {/* Score Bar */}
              <div style={{
                height: '50px',
                borderRadius: '25px',
                background: 'linear-gradient(to right, #f44336 0%, #f44336 35%, #ff6f00 35%, #ff6f00 55%, #ffc107 55%, #ffc107 75%, #4caf50 75%)',
                position: 'relative',
                boxShadow: 'inset 0 2px 4px rgba(0,0,0,0.1)'
              }}>
                <div style={{
                  position: 'absolute',
                  left: '60%',
                  top: '-10px',
                  width: '3px',
                  height: '70px',
                  background: 'var(--text-primary)',
                  opacity: 0.3
                }}></div>
              </div>
              
              {/* Labels */}
              <div style={{
                display: 'grid',
                gridTemplateColumns: '1fr 1fr 1fr 1fr',
                marginTop: '20px',
                gap: '10px'
              }}>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ color: '#f44336', fontWeight: 'bold', marginBottom: '5px' }}>Critical</div>
                  <div style={{ color: 'var(--text-secondary)', fontSize: '0.9em' }}>&lt; 35</div>
                </div>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ color: '#ff6f00', fontWeight: 'bold', marginBottom: '5px' }}>High</div>
                  <div style={{ color: 'var(--text-secondary)', fontSize: '0.9em' }}>35-54</div>
                </div>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ color: '#ffc107', fontWeight: 'bold', marginBottom: '5px' }}>Medium</div>
                  <div style={{ color: 'var(--text-secondary)', fontSize: '0.9em' }}>55-74</div>
                </div>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ color: '#4caf50', fontWeight: 'bold', marginBottom: '5px' }}>Low</div>
                  <div style={{ color: 'var(--text-secondary)', fontSize: '0.9em' }}>≥ 75</div>
                </div>
              </div>
            </div>

            {/* Starting Score Indicator */}
            <div style={{
              textAlign: 'center',
              padding: '15px',
              backgroundColor: 'var(--container-bg)',
              borderRadius: '8px',
              border: '2px dashed var(--border-color)'
            }}>
              <span style={{ color: 'var(--text-secondary)' }}>Starting Score: </span>
              <span style={{ fontSize: '1.5em', fontWeight: 'bold', color: 'var(--text-primary)' }}>60</span>
              <span style={{ color: 'var(--text-muted)', fontSize: '0.9em', display: 'block', marginTop: '5px' }}>
                (Neutral baseline)
              </span>
            </div>
          </div>
        </div>

        {/* Collapsible Sections */}
        <section style={{ marginBottom: '30px' }}>
          <div
            onClick={() => toggleSection('penalties')}
            style={{
              cursor: 'pointer',
              padding: '20px',
              backgroundColor: 'var(--section-bg)',
              borderRadius: '12px',
              border: '2px solid var(--border-color)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '20px',
              transition: 'all 0.3s ease'
            }}
          >
            <h3 style={{ 
              margin: 0,
              color: 'var(--text-primary)',
              display: 'flex',
              alignItems: 'center',
              gap: '10px'
            }}>
              <i className="fas fa-exclamation-triangle" style={{ color: '#f44336' }}></i>
              Negative Factors (Penalties)
            </h3>
            <i className={`fas fa-chevron-${isExpanded('penalties') ? 'up' : 'down'}`} style={{ color: 'var(--text-secondary)' }}></i>
          </div>

          {isExpanded('penalties') && (
          <div style={{ padding: '0 20px 20px 20px' }}>

          {/* CVE Penalties - Visual */}
          <div style={{ marginBottom: '40px' }}>
            <div style={{ 
              display: 'flex', 
              alignItems: 'center', 
              gap: '10px', 
              marginBottom: '20px' 
            }}>
              <i className="fas fa-bug" style={{ color: '#f44336', fontSize: '1.5em' }}></i>
              <h4 style={{ color: 'var(--text-primary)', margin: 0 }}>
                CVE Penalties
              </h4>
            </div>

            {/* Version-Specific CVEs Chart */}
            <div style={{ 
              backgroundColor: 'var(--container-bg)', 
              padding: '20px', 
              borderRadius: '10px',
              marginBottom: '20px',
              border: '1px solid var(--border-color)'
            }}>
              <h5 style={{ color: 'var(--text-primary)', marginBottom: '15px' }}>
                Version-Specific CVEs <span style={{ color: 'var(--text-muted)', fontSize: '0.8em' }}>(Weighted More Heavily)</span>
              </h5>
              <div style={{ display: 'grid', gap: '12px' }}>
                {[
                  { label: '>20 CVEs', penalty: 8, width: 80 },
                  { label: '>10 CVEs', penalty: 5, width: 63 },
                  { label: '>5 CVEs', penalty: 3, width: 38 },
                  { label: 'Any CVEs', penalty: 2, width: 25 },
                  { label: '>5 Critical', penalty: 6, width: 75 },
                  { label: 'Any Critical', penalty: 4, width: 50 },
                  { label: '>10 High', penalty: 4, width: 50 },
                  { label: 'Any High', penalty: 2, width: 25 }
                ].map((item, idx) => (
                  <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
                    <div style={{ minWidth: '120px', fontSize: '0.9em', color: 'var(--text-secondary)' }}>
                      {item.label}
                    </div>
                    <div style={{ 
                      flex: 1, 
                      height: '24px', 
                      backgroundColor: '#f5f5f5',
                      borderRadius: '12px',
                      overflow: 'hidden',
                      position: 'relative'
                    }}>
                      <div style={{
                        width: `${item.width}%`,
                        height: '100%',
                        background: 'linear-gradient(90deg, #ff5722 0%, #f44336 100%)'
                      }}>
                      </div>
                    </div>
                    <div style={{ minWidth: '60px', textAlign: 'right', fontWeight: 'bold', color: '#f44336' }}>
                      -{item.penalty}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Total CVEs Chart */}
            <div style={{ 
              backgroundColor: 'var(--container-bg)', 
              padding: '20px', 
              borderRadius: '10px',
              marginBottom: '20px',
              border: '1px solid var(--border-color)'
            }}>
              <h5 style={{ color: 'var(--text-primary)', marginBottom: '15px' }}>
                Total CVEs <span style={{ color: 'var(--text-muted)', fontSize: '0.8em' }}>(Less Weight)</span>
              </h5>
              <div style={{ display: 'grid', gap: '12px' }}>
                {[
                  { label: '>50 CVEs', penalty: 6, width: 75 },
                  { label: '>20 CVEs', penalty: 3, width: 38 },
                  { label: '>5 CVEs', penalty: 2, width: 25 },
                  { label: 'Any CVEs', penalty: 1, width: 13 },
                  { label: '>5 Critical', penalty: 4, width: 50 },
                  { label: 'Any Critical', penalty: 2, width: 25 }
                ].map((item, idx) => (
                  <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
                    <div style={{ minWidth: '120px', fontSize: '0.9em', color: 'var(--text-secondary)' }}>
                      {item.label}
                    </div>
                    <div style={{ 
                      flex: 1, 
                      height: '24px', 
                      backgroundColor: '#f5f5f5',
                      borderRadius: '12px',
                      overflow: 'hidden'
                    }}>
                      <div style={{
                        width: `${item.width}%`,
                        height: '100%',
                        background: 'linear-gradient(90deg, #ff9800 0%, #ff5722 100%)'
                      }}>
                      </div>
                    </div>
                    <div style={{ minWidth: '60px', textAlign: 'right', fontWeight: 'bold', color: '#ff5722' }}>
                      -{item.penalty}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* CISA KEV Highlight */}
            <div style={{ 
              background: 'linear-gradient(135deg, #fff3cd 0%, #ffe082 100%)',
              padding: '20px', 
              borderRadius: '12px',
              border: '2px solid #ffc107',
              display: 'flex',
              alignItems: 'center',
              gap: '15px'
            }}>
              <i className="fas fa-exclamation-circle" style={{ fontSize: '2em', color: '#f57c00' }}></i>
              <div>
                <div style={{ fontWeight: 'bold', color: '#856404', marginBottom: '5px', fontSize: '1.1em' }}>
                  CISA KEV: -10 points per entry
                </div>
                <div style={{ color: '#856404', fontSize: '0.9em' }}>
                  Known Exploited Vulnerabilities are actively being exploited in the wild
                </div>
              </div>
            </div>
          </div>

          {/* VirusTotal Analysis - Visual */}
          <div style={{ marginBottom: '30px' }}>
            <div style={{ 
              display: 'flex', 
              alignItems: 'center', 
              gap: '10px', 
              marginBottom: '20px' 
            }}>
              <i className="fas fa-shield-virus" style={{ color: '#2196f3', fontSize: '1.5em' }}></i>
              <h4 style={{ color: 'var(--text-primary)', margin: 0 }}>
                VirusTotal Analysis
              </h4>
              <span style={{ 
                fontSize: '0.8em', 
                color: 'var(--text-muted)', 
                backgroundColor: 'var(--section-bg)',
                padding: '4px 10px',
                borderRadius: '12px'
              }}>
                Confidence-Weighted
              </span>
            </div>

            {/* Flagged Files */}
            <div style={{ 
              backgroundColor: 'var(--container-bg)', 
              padding: '20px', 
              borderRadius: '10px',
              marginBottom: '20px',
              border: '1px solid var(--border-color)'
            }}>
              <h5 style={{ color: 'var(--text-primary)', marginBottom: '15px' }}>
                Flagged Files (Penalties by Detection Count)
              </h5>
              <div style={{ display: 'grid', gap: '10px' }}>
                {[
                  { label: '≥30 detections', penalty: 60 },
                  { label: '≥20 detections', penalty: 50 },
                  { label: '≥15 detections', penalty: 40 },
                  { label: '≥10 detections', penalty: 35 },
                  { label: '≥5 detections', penalty: 25 },
                  { label: '<5 detections', penalty: 15 }
                ].map((item, idx) => (
                  <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
                    <div style={{ minWidth: '140px', fontSize: '0.9em', color: 'var(--text-secondary)' }}>
                      {item.label}
                    </div>
                    <div style={{ 
                      flex: 1, 
                      height: '28px', 
                      backgroundColor: '#f5f5f5',
                      borderRadius: '14px',
                      overflow: 'hidden'
                    }}>
                      <div style={{
                        width: `${(item.penalty / 60) * 100}%`,
                        height: '100%',
                        background: `linear-gradient(90deg, #f44336 0%, #d32f2f 100%)`
                      }}>
                      </div>
                    </div>
                    <div style={{ minWidth: '70px', textAlign: 'right', fontWeight: 'bold', color: '#f44336' }}>
                      -{item.penalty}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Trusted vs Untrusted Comparison */}
            <div style={{ 
              display: 'grid',
              gridTemplateColumns: '1fr 1fr',
              gap: '20px',
              marginBottom: '20px'
            }}>
              {/* Trusted Vendors */}
              <div style={{ 
                backgroundColor: '#ffebee', 
                padding: '20px', 
                borderRadius: '10px',
                border: '2px solid #f44336',
                position: 'relative'
              }}>
                <h5 style={{ color: '#c62828', marginBottom: '15px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <i className="fas fa-user-shield"></i> Trusted Vendors
                  <div style={{ position: 'relative', display: 'inline-block' }}>
                    <i 
                      className="fas fa-info-circle" 
                      style={{ 
                        fontSize: '0.7em', 
                        color: '#c62828', 
                        cursor: 'help',
                        opacity: 0.7,
                        marginLeft: '5px'
                      }}
                      title="Bitdefender, BitdefenderFalx, ClamAV, CrowdStrike, Kaspersky, Microsoft, Fortinet, Google, WithSecure, Palo Alto Networks, Sentinel One"
                      onMouseEnter={(e) => {
                        const tooltip = e.currentTarget
                        tooltip.style.opacity = '1'
                      }}
                      onMouseLeave={(e) => {
                        const tooltip = e.currentTarget
                        tooltip.style.opacity = '0.7'
                      }}
                    ></i>
                  </div>
                </h5>
                <p style={{ fontSize: '0.9em', color: '#d32f2f', marginBottom: '15px' }}>
                  Bitdefender, Kaspersky, Microsoft, CrowdStrike, WithSecure, etc.
                </p>
                <div style={{ marginBottom: '10px' }}>
                  <div style={{ color: '#c62828', fontWeight: 'bold' }}>-8 points each</div>
                </div>
                <div style={{ fontSize: '0.85em', color: '#d32f2f' }}>
                  <div>• 3+ vendors: +30% multiplier</div>
                  <div>• 2+ vendors: +15% multiplier</div>
                </div>
              </div>

              {/* Untrusted Vendors */}
              <div style={{ 
                backgroundColor: '#fff3e0', 
                padding: '20px', 
                borderRadius: '10px',
                border: '2px solid #ff9800'
              }}>
                <h5 style={{ color: '#e65100', marginBottom: '15px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <i className="fas fa-question-circle"></i> Untrusted (Potential FPs)
                </h5>
                <p style={{ fontSize: '0.9em', color: '#f57c00', marginBottom: '15px' }}>
                  Less reliable vendors, may be false positives
                </p>
                <div style={{ marginBottom: '10px' }}>
                  <div style={{ color: '#e65100', fontWeight: 'bold' }}>70% penalty reduction</div>
                </div>
                <div style={{ fontSize: '0.85em', color: '#f57c00' }}>
                  <div>• 10+ detections: (count-10) × 1</div>
                  <div>• 5+ detections: (count-5) × 0.5</div>
                </div>
              </div>
            </div>

            {/* Reputation Penalties */}
            <div style={{ 
              backgroundColor: 'var(--container-bg)', 
              padding: '15px', 
              borderRadius: '10px',
              border: '1px solid var(--border-color)'
            }}>
              <h5 style={{ color: 'var(--text-primary)', marginBottom: '10px', fontSize: '0.95em' }}>
                Additional Reputation Penalties
              </h5>
              <div style={{ display: 'flex', gap: '20px', flexWrap: 'wrap' }}>
                {[
                  { label: 'Rep < -50', penalty: 10 },
                  { label: 'Rep < 0', penalty: 5 },
                  { label: 'Community flags', penalty: 8 }
                ].map((item, idx) => (
                  <div key={idx} style={{ 
                    flex: '1',
                    minWidth: '150px',
                    textAlign: 'center',
                    padding: '10px',
                    backgroundColor: 'var(--section-bg)',
                    borderRadius: '6px'
                  }}>
                    <div style={{ fontSize: '0.85em', color: 'var(--text-secondary)', marginBottom: '5px' }}>
                      {item.label}
                    </div>
                    <div style={{ fontWeight: 'bold', color: '#f44336' }}>
                      -{item.penalty}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
          </div>
          )}
        </section>

        <section style={{ marginBottom: '30px' }}>
          <div
            onClick={() => toggleSection('bonuses')}
            style={{
              cursor: 'pointer',
              padding: '20px',
              backgroundColor: 'var(--section-bg)',
              borderRadius: '12px',
              border: '2px solid var(--border-color)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '20px',
              transition: 'all 0.3s ease'
            }}
          >
            <h3 style={{ 
              margin: 0,
              color: 'var(--text-primary)',
              display: 'flex',
              alignItems: 'center',
              gap: '10px'
            }}>
              <i className="fas fa-check-circle" style={{ color: '#4caf50' }}></i>
              Positive Factors (Bonuses)
            </h3>
            <i className={`fas fa-chevron-${isExpanded('bonuses') ? 'up' : 'down'}`} style={{ color: 'var(--text-secondary)' }}></i>
          </div>

          {isExpanded('bonuses') && (
          <div style={{ padding: '0 20px 20px 20px' }}>

          {/* Bonuses Grid */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
            gap: '20px',
            marginBottom: '20px'
          }}>
            {/* Transparency */}
            <div style={{ 
              backgroundColor: '#e3f2fd', 
              padding: '20px', 
              borderRadius: '12px',
              border: '2px solid #2196f3'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '15px' }}>
                <i className="fas fa-eye" style={{ color: '#1976d2', fontSize: '1.5em' }}></i>
                <h5 style={{ color: '#1565c0', margin: 0 }}>Transparency</h5>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.9em', color: '#1565c0' }}>5+ citations</span>
                  <span style={{ fontWeight: 'bold', color: '#4caf50', fontSize: '1.1em' }}>+12</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.9em', color: '#1565c0' }}>3+ citations</span>
                  <span style={{ fontWeight: 'bold', color: '#4caf50' }}>+8</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.9em', color: '#1565c0' }}>1+ citation</span>
                  <span style={{ fontWeight: 'bold', color: '#4caf50' }}>+3</span>
                </div>
              </div>
            </div>

            {/* Compliance */}
            <div style={{ 
              backgroundColor: '#f3e5f5', 
              padding: '20px', 
              borderRadius: '12px',
              border: '2px solid #9c27b0'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '15px' }}>
                <i className="fas fa-certificate" style={{ color: '#7b1fa2', fontSize: '1.5em' }}></i>
                <h5 style={{ color: '#6a1b9a', margin: 0 }}>Compliance</h5>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.9em', color: '#6a1b9a' }}>GDPR/SOC 2/ISO</span>
                  <span style={{ fontWeight: 'bold', color: '#4caf50', fontSize: '1.1em' }}>+10</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.9em', color: '#6a1b9a' }}>Data handling info</span>
                  <span style={{ fontWeight: 'bold', color: '#4caf50' }}>+5</span>
                </div>
              </div>
            </div>

            {/* Deployment */}
            <div style={{ 
              backgroundColor: '#e0f2f1', 
              padding: '20px', 
              borderRadius: '12px',
              border: '2px solid #009688'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '15px' }}>
                <i className="fas fa-cogs" style={{ color: '#00695c', fontSize: '1.5em' }}></i>
                <h5 style={{ color: '#004d40', margin: 0 }}>Deployment</h5>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '0.9em', color: '#004d40' }}>Controls documented</span>
                <span style={{ fontWeight: 'bold', color: '#4caf50', fontSize: '1.1em' }}>+5</span>
              </div>
            </div>

            {/* No Issues */}
            <div style={{ 
              backgroundColor: '#e8f5e9', 
              padding: '20px', 
              borderRadius: '12px',
              border: '2px solid #4caf50'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '15px' }}>
                <i className="fas fa-check-double" style={{ color: '#2e7d32', fontSize: '1.5em' }}></i>
                <h5 style={{ color: '#1b5e20', margin: 0 }}>No CVEs</h5>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '0.9em', color: '#1b5e20' }}>Clean security record</span>
                <span style={{ fontWeight: 'bold', color: '#4caf50', fontSize: '1.1em' }}>+5</span>
              </div>
            </div>

            {/* VirusTotal Clean Scans */}
            <div style={{ 
              backgroundColor: '#e8f5e9', 
              padding: '20px', 
              borderRadius: '12px',
              border: '2px solid #4caf50'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '15px' }}>
                <i className="fas fa-shield-virus" style={{ color: '#2e7d32', fontSize: '1.5em' }}></i>
                <h5 style={{ color: '#1b5e20', margin: 0 }}>VirusTotal Clean Scans</h5>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.9em', color: '#1b5e20' }}>Reputation {'>'} 50</span>
                  <span style={{ fontWeight: 'bold', color: '#4caf50', fontSize: '1.1em' }}>+12</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.9em', color: '#1b5e20' }}>Reputation {'>'} 0</span>
                  <span style={{ fontWeight: 'bold', color: '#4caf50' }}>+8</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.9em', color: '#1b5e20' }}>Low/No Reputation</span>
                  <span style={{ fontWeight: 'bold', color: '#4caf50' }}>+5</span>
                </div>
              </div>
              <div style={{ 
                marginTop: '12px', 
                padding: '8px 12px', 
                backgroundColor: 'rgba(76, 175, 80, 0.1)',
                borderRadius: '6px',
                fontSize: '0.85em',
                color: '#2e7d32',
                fontStyle: 'italic'
              }}>
                <i className="fas fa-info-circle" style={{ marginRight: '6px' }}></i>
                For files with 0 detections on VirusTotal
              </div>
            </div>
          </div>

          {/* Established Vendor Bonus */}
          <div style={{ 
            background: 'linear-gradient(135deg, #fff9c4 0%, #fff59d 100%)',
            padding: '25px', 
            borderRadius: '12px',
            border: '2px solid #fbc02d',
            marginBottom: '20px'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '15px' }}>
              <i className="fas fa-building" style={{ color: '#f57f17', fontSize: '1.5em' }}></i>
              <h5 style={{ color: '#f57f17', margin: 0 }}>Established Vendor Bonus</h5>
            </div>
            <p style={{ color: '#f57f17', marginBottom: '15px', fontSize: '0.9em' }}>
              Well-known vendors (Microsoft, Google, Apple, etc.) get a boost <strong>if no serious issues</strong>:
            </p>
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
              gap: '15px'
            }}>
              {[
                { score: 'Score ≥ 60', boost: 'Up to +20', range: '→ 80-85' },
                { score: 'Score ≥ 50', boost: 'Up to +20', range: '→ 70-75' },
                { score: 'Score < 50', boost: 'Up to +10', range: '→ ~65' },
                { score: 'Serious issues', boost: 'Up to +5', range: 'Limited' }
              ].map((item, idx) => (
                <div key={idx} style={{
                  backgroundColor: 'white',
                  padding: '12px',
                  borderRadius: '8px',
                  textAlign: 'center'
                }}>
                  <div style={{ fontSize: '0.85em', color: '#f57f17', marginBottom: '5px' }}>
                    {item.score}
                  </div>
                  <div style={{ fontWeight: 'bold', color: '#4caf50', fontSize: '1.1em', marginBottom: '3px' }}>
                    {item.boost}
                  </div>
                  <div style={{ fontSize: '0.8em', color: '#f57f17' }}>
                    {item.range}
                  </div>
                </div>
              ))}
            </div>
            <p style={{ color: '#f57f17', marginTop: '15px', fontSize: '0.85em', fontStyle: 'italic' }}>
              ⚠️ Does not apply if CISA KEV exists, many critical CVEs, or high VT flags
            </p>
          </div>
          </div>
          )}
        </section>

        <section style={{ marginBottom: '30px' }}>
          <div
            onClick={() => toggleSection('confidence')}
            style={{
              cursor: 'pointer',
              padding: '20px',
              backgroundColor: 'var(--section-bg)',
              borderRadius: '12px',
              border: '2px solid var(--border-color)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '20px',
              transition: 'all 0.3s ease'
            }}
          >
            <h3 style={{ 
              margin: 0,
              color: 'var(--text-primary)',
              display: 'flex',
              alignItems: 'center',
              gap: '10px'
            }}>
              <i className="fas fa-chart-line" style={{ color: '#2196f3' }}></i>
              Confidence Score
            </h3>
            <i className={`fas fa-chevron-${isExpanded('confidence') ? 'up' : 'down'}`} style={{ color: 'var(--text-secondary)' }}></i>
          </div>

          {isExpanded('confidence') && (
          <div style={{ padding: '0 20px 20px 20px' }}>
            <p style={{ color: 'var(--text-secondary)', marginBottom: '25px' }}>
              Reflects assessment reliability based on data quality (0.0-1.0, clamped 0.2-1.0):
            </p>

            {/* Base Confidence Chart */}
            <div style={{ 
              backgroundColor: 'var(--container-bg)', 
              padding: '20px', 
              borderRadius: '10px',
              marginBottom: '20px',
              border: '1px solid var(--border-color)'
            }}>
              <h5 style={{ color: 'var(--text-primary)', marginBottom: '20px' }}>Base Confidence</h5>
              <div style={{ display: 'grid', gap: '15px' }}>
                {[
                  { label: '5+ citations + (VT or CVEs) + vendor', conf: 0.85, width: 85 },
                  { label: '3+ citations + (VT or CVEs)', conf: 0.70, width: 70 },
                  { label: '2+ citations', conf: 0.55, width: 55 },
                  { label: '1+ citation', conf: 0.40, width: 40 },
                  { label: 'No citations', conf: 0.25, width: 25 }
                ].map((item, idx) => (
                  <div key={idx}>
                    <div style={{ 
                      display: 'flex', 
                      justifyContent: 'space-between',
                      marginBottom: '8px',
                      fontSize: '0.9em'
                    }}>
                      <span style={{ color: 'var(--text-secondary)' }}>{item.label}</span>
                      <span style={{ fontWeight: 'bold', color: 'var(--text-primary)' }}>{item.conf}</span>
                    </div>
                    <div style={{
                      height: '20px',
                      backgroundColor: '#e0e0e0',
                      borderRadius: '10px',
                      overflow: 'hidden'
                    }}>
                      <div style={{
                        width: `${item.width}%`,
                        height: '100%',
                        background: `linear-gradient(90deg, #2196f3 0%, #1976d2 100%)`
                      }}>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Adjustments */}
            <div style={{ 
              backgroundColor: 'var(--container-bg)', 
              padding: '20px', 
              borderRadius: '10px',
              border: '1px solid var(--border-color)'
            }}>
              <h5 style={{ color: 'var(--text-primary)', marginBottom: '15px' }}>Confidence Adjustments</h5>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
                {[
                  { label: 'VT confidence > 0.8', adj: '+0.10', color: '#4caf50' },
                  { label: 'VT confidence < 0.5', adj: '-0.05', color: '#ff9800' },
                  { label: 'VT clean but CVEs exist', adj: '-0.10', color: '#ff5722' },
                  { label: 'False positive indicators', adj: '-0.05', color: '#ff9800' }
                ].map((item, idx) => (
                  <div key={idx} style={{
                    padding: '12px',
                    backgroundColor: 'var(--section-bg)',
                    borderRadius: '8px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center'
                  }}>
                    <span style={{ fontSize: '0.9em', color: 'var(--text-secondary)' }}>{item.label}</span>
                    <span style={{ fontWeight: 'bold', color: item.color, fontSize: '1.1em' }}>{item.adj}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
          )}
        </section>

        {/* Key Insights - Compact */}
        <section style={{ 
          backgroundColor: 'var(--section-bg)', 
          padding: '25px', 
          borderRadius: '12px',
          border: '1px solid var(--border-color)',
          marginBottom: '30px'
        }}>
          <h3 style={{ 
            marginBottom: '20px', 
            color: 'var(--text-primary)',
            display: 'flex',
            alignItems: 'center',
            gap: '10px'
          }}>
            <i className="fas fa-lightbulb" style={{ color: '#ffc107' }}></i> Key Insights
          </h3>
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
            gap: '15px'
          }}>
            {[
              { icon: 'fa-balance-scale', text: 'Version-specific CVEs weighted more heavily', color: '#2196f3' },
              { icon: 'fa-skull', text: 'CISA KEV: -10 points each (most serious)', color: '#f44336' },
              { icon: 'fa-user-shield', text: 'Trusted vendor detections: -8 each', color: '#ff5722' },
              { icon: 'fa-users', text: 'Multiple trusted vendors: up to +30% multiplier', color: '#f44336' },
              { icon: 'fa-building', text: 'Established vendors get bonus (if clean)', color: '#ffc107' },
              { icon: 'fa-chart-bar', text: 'Confidence reflects data quality reliability', color: '#2196f3' },
              { icon: 'fa-robot', text: 'Values fine-tuned by AI training on real datasets', color: '#9c27b0' }
            ].map((item, idx) => (
              <div key={idx} style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: '12px',
                padding: '12px',
                backgroundColor: 'var(--container-bg)',
                borderRadius: '8px'
              }}>
                <i className={`fas ${item.icon}`} style={{ color: item.color, fontSize: '1.2em', marginTop: '2px' }}></i>
                <span style={{ color: 'var(--text-secondary)', fontSize: '0.9em', lineHeight: '1.5' }}>
                  {item.text}
                </span>
              </div>
            ))}
          </div>
        </section>

        <div style={{ 
          textAlign: 'center', 
          paddingTop: '30px',
          borderTop: '1px solid var(--border-color)',
          marginTop: '40px'
        }}>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.9em' }}>
            For more information or questions about the scoring methodology, please refer to the source code or contact support.
          </p>
        </div>
      </div>
    </div>
  )
}

export default HelpPage

