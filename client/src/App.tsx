import { useState } from 'react'
import { ThemeProvider } from './contexts/ThemeContext'
import TopBar from './components/TopBar'
import Header from './components/Header'
import SingleAssessmentForm from './components/SingleAssessmentForm'
import CompareModeForm from './components/CompareModeForm'
import LoadingIndicator from './components/LoadingIndicator'
import Results from './components/Results'
import { AssessmentResponse } from './types'

interface AssessmentParams {
  productName: string | null
  vendorName: string | null
  hash: string | null
  proMode: boolean
}

function App() {
  const [isCompareMode, setIsCompareMode] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [assessmentData, setAssessmentData] = useState<AssessmentResponse | null>(null)
  const [assessmentParams, setAssessmentParams] = useState<AssessmentParams | null>(null)

  const toggleMode = () => {
    setIsCompareMode(!isCompareMode)
    setAssessmentData(null)
    setAssessmentParams(null)
  }

  const handleAssessmentComplete = (
    data: AssessmentResponse,
    params: AssessmentParams
  ) => {
    setAssessmentData(data)
    setAssessmentParams(params)
    setIsLoading(false)
  }

  const handleLoadingStart = () => {
    setIsLoading(true)
    setAssessmentData(null)
    setAssessmentParams(null)
  }

  return (
    <ThemeProvider>
      <TopBar />
      <div className="container">
        <Header />
        
        <div className="form-group">
          <button onClick={toggleMode} className="btn-secondary">
            {isCompareMode ? 'Switch to Single Mode' : 'Switch to Compare Mode'}
          </button>
        </div>

      {!isCompareMode ? (
        <SingleAssessmentForm
          onLoadingStart={handleLoadingStart}
          onAssessmentComplete={handleAssessmentComplete}
        />
      ) : (
        <CompareModeForm
          onLoadingStart={handleLoadingStart}
          onAssessmentComplete={handleAssessmentComplete}
        />
      )}

        <LoadingIndicator isVisible={isLoading} />
        {assessmentData && assessmentParams && (
          <Results
            data={assessmentData}
            assessmentParams={assessmentParams}
            onRefresh={(newData) => setAssessmentData(newData)}
          />
        )}
      </div>
    </ThemeProvider>
  )
}

export default App

