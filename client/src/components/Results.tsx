import { useState, useEffect } from 'react'
import { AssessmentResponse } from '../types'
import { assessApplication } from '../services/api'
import TrustScoreGauge from './TrustScoreGauge'
import SecurityRecommendation from './SecurityRecommendation'
import SecurityPostureSection from './SecurityPostureSection'
import CVEAnalysisSection from './CVEAnalysisSection'
import SpiderChart from './SpiderChart'
import SourcesSection from './SourcesSection'
import AlternativesSection from './AlternativesSection'
import ExportButtons from './ExportButtons'
import CacheInfo from './CacheInfo'
import Chatbot from './Chatbot'

interface AssessmentParams {
  productName: string | null
  vendorName: string | null
  hash: string | null
  proMode: boolean
}

interface ResultsProps {
  data: AssessmentResponse
  assessmentParams: AssessmentParams
  onRefresh?: (newData: AssessmentResponse) => void
}

const Results = ({ data, assessmentParams, onRefresh }: ResultsProps) => {
  const [currentData, setCurrentData] = useState<AssessmentResponse>(data)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [isChatbotOpen, setIsChatbotOpen] = useState(false)

  useEffect(() => {
    setCurrentData(data)
  }, [data])

  const handleRefresh = async () => {
    setIsRefreshing(true)
    try {
      // Use the original assessment parameters (including hash and proMode) for refresh
      const refreshedData = await assessApplication(
        assessmentParams.productName,
        assessmentParams.vendorName,
        assessmentParams.hash,
        true, // force refresh
        assessmentParams.proMode // preserve PRO mode
      )
      setCurrentData(refreshedData)
      if (onRefresh) {
        onRefresh(refreshedData)
      }
    } catch (error) {
      alert('Error refreshing assessment: ' + (error instanceof Error ? error.message : 'Unknown error'))
    } finally {
      setIsRefreshing(false)
    }
  }

  if (!currentData.trust_score) {
    return <div>Error: Trust score data is missing from the assessment response</div>
  }

  const detectedVersion = currentData.security_posture?.cve_summary?.detected_version
  const versionInfo = detectedVersion ? ` | <strong>Version:</strong> ${detectedVersion}` : ''

  return (
    <div className="results show">
      <h2 style={{ marginBottom: '10px' }}>
        <i className="fas fa-shield-alt"></i> Security Assessment: {currentData.entity_name}
      </h2>
      <p
        style={{ marginBottom: '30px', color: 'var(--text-secondary)' }}
        dangerouslySetInnerHTML={{
          __html: `<strong>Vendor:</strong> ${currentData.vendor_name} | <strong>Category:</strong> ${currentData.category}${versionInfo}`,
        }}
      />

      <SecurityRecommendation
        suggestion={currentData.suggestion}
        trustScore={currentData.trust_score.score}
        riskLevel={currentData.trust_score.risk_level}
        securityPosture={currentData.security_posture}
        assessmentData={currentData}
        onOpenChatbot={() => setIsChatbotOpen(true)}
      />

      <Chatbot
        assessmentData={currentData}
        isOpen={isChatbotOpen}
        onClose={() => setIsChatbotOpen(false)}
      />

      <div className="section">
        <h3>
          <i className="fas fa-chart-line"></i> Assessment Results
        </h3>
        <TrustScoreGauge trustScore={currentData.trust_score} />
      </div>

      <SpiderChart data={currentData} />

      <SecurityPostureSection securityPosture={currentData.security_posture} />

      <CVEAnalysisSection cveSummary={currentData.security_posture.cve_summary} />

      <SourcesSection
        citations={currentData.security_posture.citations}
        securityPosture={currentData.security_posture}
      />

      {currentData.alternatives.length > 0 && (
        <AlternativesSection alternatives={currentData.alternatives} />
      )}

      <ExportButtons assessmentData={currentData} />

      <CacheInfo
        data={currentData}
        onRefresh={handleRefresh}
        isRefreshing={isRefreshing}
      />
    </div>
  )
}

export default Results

