import { useState, useEffect } from 'react'
import { CVESummary, CVE } from '../types'

interface CVEAnalysisSectionProps {
  cveSummary: CVESummary
}

const ITEMS_PER_PAGE = 10

const CVEAnalysisSection = ({ cveSummary }: CVEAnalysisSectionProps) => {
  const [currentPage, setCurrentPage] = useState(1)
  const allCVEs = cveSummary.recent_cves || []
  const totalPages = Math.ceil(allCVEs.length / ITEMS_PER_PAGE)

  const startIndex = (currentPage - 1) * ITEMS_PER_PAGE
  const endIndex = Math.min(startIndex + ITEMS_PER_PAGE, allCVEs.length)
  const pageCVEs = allCVEs.slice(startIndex, endIndex)

  const goToPage = (page: number) => {
    if (page >= 1 && page <= totalPages) {
      setCurrentPage(page)
    }
  }

  const renderPagination = () => {
    if (totalPages <= 1) return null

    const maxVisiblePages = 7
    let startPage = Math.max(1, currentPage - Math.floor(maxVisiblePages / 2))
    let endPage = Math.min(totalPages, startPage + maxVisiblePages - 1)

    if (endPage - startPage < maxVisiblePages - 1) {
      startPage = Math.max(1, endPage - maxVisiblePages + 1)
    }

    return (
      <div
        id="cvePagination"
        style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          gap: '10px',
          marginTop: '20px',
          flexWrap: 'wrap',
        }}
      >
        <button
          className="cve-pagination-btn"
          disabled={currentPage === 1}
          onClick={() => goToPage(currentPage - 1)}
          style={{
            background: currentPage === 1 ? '#e0e0e0' : 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
            color: currentPage === 1 ? '#999' : 'white',
            border: 'none',
            padding: '8px 16px',
            borderRadius: '6px',
            fontSize: '0.9em',
            fontWeight: 600,
            cursor: currentPage === 1 ? 'not-allowed' : 'pointer',
            transition: 'all 0.2s ease',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          <i className="fas fa-chevron-left"></i>
          Previous
        </button>

        {startPage > 1 && (
          <>
            <button
              className="cve-pagination-btn"
              onClick={() => goToPage(1)}
              style={{
                background: 'var(--card-bg)',
                color: '#667eea',
                border: '2px solid #667eea',
                padding: '8px 12px',
                borderRadius: '6px',
                fontSize: '0.9em',
                fontWeight: 600,
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
            >
              1
            </button>
            {startPage > 2 && <span style={{ color: 'var(--text-muted)', padding: '0 8px' }}>...</span>}
          </>
        )}

        {Array.from({ length: endPage - startPage + 1 }, (_, i) => startPage + i).map((page) => {
          const isActive = page === currentPage
          return (
            <button
              key={page}
              className="cve-pagination-btn"
              onClick={() => goToPage(page)}
              style={{
                background: isActive ? 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' : 'var(--card-bg)',
                color: isActive ? 'white' : '#667eea',
                border: `2px solid ${isActive ? 'transparent' : '#667eea'}`,
                padding: '8px 12px',
                borderRadius: '6px',
                fontSize: '0.9em',
                fontWeight: isActive ? 700 : 600,
                cursor: 'pointer',
                transition: 'all 0.2s ease',
                minWidth: '40px',
              }}
            >
              {page}
            </button>
          )
        })}

        {endPage < totalPages && (
          <>
            {endPage < totalPages - 1 && <span style={{ color: 'var(--text-muted)', padding: '0 8px' }}>...</span>}
            <button
              className="cve-pagination-btn"
              onClick={() => goToPage(totalPages)}
              style={{
                background: 'var(--card-bg)',
                color: '#667eea',
                border: '2px solid #667eea',
                padding: '8px 12px',
                borderRadius: '6px',
                fontSize: '0.9em',
                fontWeight: 600,
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
            >
              {totalPages}
            </button>
          </>
        )}

        <button
          className="cve-pagination-btn"
          disabled={currentPage === totalPages}
          onClick={() => goToPage(currentPage + 1)}
          style={{
            background: currentPage === totalPages ? '#e0e0e0' : 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
            color: currentPage === totalPages ? '#999' : 'white',
            border: 'none',
            padding: '8px 16px',
            borderRadius: '6px',
            fontSize: '0.9em',
            fontWeight: 600,
            cursor: currentPage === totalPages ? 'not-allowed' : 'pointer',
            transition: 'all 0.2s ease',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          Next
          <i className="fas fa-chevron-right"></i>
        </button>
      </div>
    )
  }

  if (!allCVEs || allCVEs.length === 0) {
    return (
      <div className="section">
        <h3>
          <i className="fas fa-bug"></i> CVE Analysis
        </h3>
        <p style={{ color: 'var(--text-secondary)', fontStyle: 'italic' }}>No CVEs found in the database.</p>
      </div>
    )
  }

  return (
    <div className="section">
      <h3>
        <i className="fas fa-bug"></i> CVE Analysis
      </h3>
      {cveSummary.detected_version && (
        <div
          style={{
            background: 'var(--section-bg)',
            padding: '15px',
            borderRadius: '8px',
            marginBottom: '20px',
          }}
        >
          <p style={{ margin: '5px 0' }}>
            <strong>Detected Version:</strong> {cveSummary.detected_version}
          </p>
          <p style={{ margin: '5px 0' }}>
            <strong>Version-Specific CVEs:</strong> {cveSummary.version_specific_cves || 0} (Critical:{' '}
            {cveSummary.version_specific_critical || 0}, High: {cveSummary.version_specific_high || 0})
          </p>
        </div>
      )}

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
            borderTop: '4px solid #667eea',
          }}
        >
          <div style={{ fontSize: '2em', fontWeight: 'bold', color: '#667eea' }}>
            {cveSummary.total_cves}
          </div>
          <div style={{ color: 'var(--text-secondary)', marginTop: '5px' }}>Total CVEs</div>
        </div>
        <div
          style={{
            background: 'var(--card-bg)',
            padding: '15px',
            borderRadius: '8px',
            textAlign: 'center',
            borderTop: '4px solid #f44336',
          }}
        >
          <div style={{ fontSize: '2em', fontWeight: 'bold', color: '#f44336' }}>
            {cveSummary.critical_count}
          </div>
          <div style={{ color: 'var(--text-secondary)', marginTop: '5px' }}>Critical</div>
        </div>
        <div
          style={{
            background: 'var(--card-bg)',
            padding: '15px',
            borderRadius: '8px',
            textAlign: 'center',
            borderTop: '4px solid #ff6f00',
          }}
        >
          <div style={{ fontSize: '2em', fontWeight: 'bold', color: '#ff6f00' }}>
            {cveSummary.high_count}
          </div>
          <div style={{ color: 'var(--text-secondary)', marginTop: '5px' }}>High</div>
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
            {cveSummary.cisa_kev_count}
          </div>
          <div style={{ color: 'var(--text-secondary)', marginTop: '5px' }}>CISA KEV</div>
        </div>
      </div>

      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginTop: '20px',
          marginBottom: '15px',
          flexWrap: 'wrap',
          gap: '10px',
        }}
      >
        <h4 style={{ margin: 0 }}>
          Detailed CVE List{' '}
          {allCVEs.length < cveSummary.total_cves
            ? `(Showing ${allCVEs.length} of ${cveSummary.total_cves} total)`
            : `(${allCVEs.length} total)`}
        </h4>
        <div id="cvePaginationInfo" style={{ color: 'var(--text-secondary)', fontSize: '0.9em', fontWeight: 500 }}>
          Showing {startIndex + 1}-{endIndex} of {allCVEs.length}
        </div>
      </div>

      <div id="cveTableContainer">
        <table className="cve-table" id="cveTable">
          <thead>
            <tr>
              <th>CVE ID</th>
              <th>Severity</th>
              <th>CVSS Score</th>
              <th>Published</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody id="cveTableBody">
            {pageCVEs.map((cve, index) => {
              const severityClass =
                cve.severity === 'critical'
                  ? 'cve-critical'
                  : cve.severity === 'high'
                  ? 'cve-high'
                  : ''
              const description = cve.description
                ? cve.description.length > 150
                  ? cve.description.substring(0, 150) + '...'
                  : cve.description
                : 'N/A'
              const publishedDate = cve.published
                ? new Date(cve.published).toLocaleDateString()
                : 'N/A'

              return (
                <tr key={index}>
                  <td>
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{ color: '#667eea', textDecoration: 'none' }}
                    >
                      {cve.id}
                    </a>
                  </td>
                  <td className={severityClass}>{cve.severity.toUpperCase()}</td>
                  <td>{cve.base_score || 'N/A'}</td>
                  <td>{publishedDate}</td>
                  <td>{description}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {renderPagination()}

      {allCVEs.length < cveSummary.total_cves && (
        <p style={{ color: 'var(--text-secondary)', fontStyle: 'italic', marginTop: '10px' }}>
          Note: Only the most recent {allCVEs.length} CVEs are shown.
        </p>
      )}
    </div>
  )
}

export default CVEAnalysisSection

