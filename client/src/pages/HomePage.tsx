import { useState, useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import Header from '../components/Header'
import SingleAssessmentForm from '../components/SingleAssessmentForm'
import LoadingIndicator from '../components/LoadingIndicator'
import Results from '../components/Results'
import { AssessmentResponse } from '../types'

interface AssessmentParams {
  productName: string | null
  vendorName: string | null
  hash: string | null
  proMode: boolean
}

interface CacheBrowserState {
  productName?: string
  vendorName?: string
  hash?: string | null
  proMode?: boolean
}

const HomePage = () => {
  const location = useLocation()
  const [isLoading, setIsLoading] = useState(false)
  const [assessmentData, setAssessmentData] = useState<AssessmentResponse | null>(null)
  const [assessmentParams, setAssessmentParams] = useState<AssessmentParams | null>(null)
  const [initialValues, setInitialValues] = useState<CacheBrowserState | null>(null)

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

  // Handle navigation from cache browser
  useEffect(() => {
    const state = location.state as CacheBrowserState | null
    if (state && (state.productName || state.vendorName)) {
      console.log('[HomePage] Received navigation state:', state)
      setInitialValues(state)
      // Clear location state after reading to prevent re-triggering
      window.history.replaceState({}, document.title)
    }
  }, [location])

  return (
    <div className="container">
      <Header />
      
      <SingleAssessmentForm
        onLoadingStart={handleLoadingStart}
        onAssessmentComplete={handleAssessmentComplete}
        initialValues={initialValues}
        onInitialValuesUsed={() => setInitialValues(null)}
      />

      <LoadingIndicator isVisible={isLoading} />
      {assessmentData && assessmentParams && (
        <Results
          data={assessmentData}
          assessmentParams={assessmentParams}
          onRefresh={(newData) => setAssessmentData(newData)}
        />
      )}
    </div>
  )
}

export default HomePage

