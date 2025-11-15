import { AssessmentResponse } from '../types'
import { exportReport } from '../services/api'

interface ExportButtonsProps {
  assessmentData: AssessmentResponse
}

const ExportButtons = ({ assessmentData }: ExportButtonsProps) => {
  const handleExport = async (format: 'markdown' | 'pdf') => {
    try {
      const blob = await exportReport(format, assessmentData)
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url

      const filename = `${assessmentData.entity_name || 'report'}.${format === 'markdown' ? 'md' : 'html'}`
      a.download = filename
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch (error) {
      alert('Error exporting report: ' + (error instanceof Error ? error.message : 'Unknown error'))
    }
  }

  return (
    <div className="export-buttons">
      <button className="export-btn" onClick={() => handleExport('markdown')}>
        <i className="fas fa-file-alt"></i> Export as Markdown
      </button>
      <button className="export-btn" onClick={() => handleExport('pdf')}>
        <i className="fas fa-file-pdf"></i> Export as PDF/HTML
      </button>
    </div>
  )
}

export default ExportButtons

