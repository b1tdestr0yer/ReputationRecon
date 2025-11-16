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

  const handlePDFExport = async () => {
    try {
      const blob = await exportReport('pdf', assessmentData)
      const url = window.URL.createObjectURL(blob)
      // Open in new window for printing (user can print manually)
      const newWindow = window.open(url, '_blank')
      if (!newWindow) {
        // Fallback to download if popup blocked
        const a = document.createElement('a')
        a.href = url
        a.download = `${assessmentData.entity_name || 'report'}.html`
        document.body.appendChild(a)
        a.click()
        window.URL.revokeObjectURL(url)
        document.body.removeChild(a)
        alert('PDF export downloaded. Open the file and use your browser\'s Print function (Ctrl+P) and select "Save as PDF" to save.')
      }
    } catch (error) {
      alert('Error exporting PDF: ' + (error instanceof Error ? error.message : 'Unknown error'))
    }
  }

  return (
    <div className="export-buttons">
      <button className="export-btn" onClick={() => handleExport('markdown')}>
        <i className="fas fa-file-alt"></i> Export as Markdown
      </button>
      <button className="export-btn" onClick={handlePDFExport}>
        <i className="fas fa-file-pdf"></i> Export as PDF
      </button>
    </div>
  )
}

export default ExportButtons

