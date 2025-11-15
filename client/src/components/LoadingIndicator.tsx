import { useEffect, useState } from 'react'

interface LoadingIndicatorProps {
  isVisible: boolean
}

const LoadingIndicator = ({ isVisible }: LoadingIndicatorProps) => {
  const [currentStep, setCurrentStep] = useState(0)

  const steps = [
    { icon: 'fas fa-search', text: 'Scanning threat intelligence databases...' },
    { icon: 'fas fa-shield-alt', text: 'Analyzing security posture...' },
    { icon: 'fas fa-chart-line', text: 'Calculating risk assessment...' },
    { icon: 'fas fa-file-alt', text: 'Generating security brief...' },
  ]

  useEffect(() => {
    if (!isVisible) {
      setCurrentStep(0)
      return
    }

    const interval = setInterval(() => {
      setCurrentStep((prev) => (prev + 1) % steps.length)
    }, 2000)

    return () => clearInterval(interval)
  }, [isVisible])

  if (!isVisible) return null

  return (
    <div className={`loading ${isVisible ? 'show' : ''}`}>
      <div className="loading-content">
        <div className="loading-spinner">
          <div className="spinner-ring"></div>
          <div className="spinner-ring"></div>
          <div className="spinner-ring"></div>
        </div>
        <h3 style={{ color: 'var(--text-primary)', marginBottom: '20px', fontSize: '1.5em' }}>
          Security Assessment in Progress
        </h3>
        <div className="loading-steps">
          {steps.map((step, index) => (
            <div
              key={index}
              className={`loading-step ${index === currentStep ? 'active' : ''}`}
            >
              <i className={step.icon}></i>
              <span className="loading-step-text">{step.text}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default LoadingIndicator

