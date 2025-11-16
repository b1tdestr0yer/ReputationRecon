import { useState, useEffect } from 'react'
import { assessApplication } from '../services/api'
import { AssessmentResponse } from '../types'

interface AssessmentParams {
  productName: string | null
  vendorName: string | null
  hash: string | null
  proMode: boolean
}

interface InitialValues {
  productName?: string
  vendorName?: string
  hash?: string | null
  proMode?: boolean
}

interface SingleAssessmentFormProps {
  onLoadingStart: () => void
  onAssessmentComplete: (data: AssessmentResponse, params: AssessmentParams) => void
  initialValues?: InitialValues | null
  onInitialValuesUsed?: () => void
}

const SingleAssessmentForm = ({ 
  onLoadingStart, 
  onAssessmentComplete,
  initialValues,
  onInitialValuesUsed
}: SingleAssessmentFormProps) => {
  const [product, setProduct] = useState('')
  const [vendor, setVendor] = useState('')
  const [hash, setHash] = useState('')
  const [proMode, setProMode] = useState(false)

  const handleAssess = async (
    productValue?: string | null,
    vendorValue?: string | null,
    hashValue?: string | null,
    proModeValue?: boolean
  ) => {
    // Use provided values or current state values
    const productToUse = productValue !== undefined ? productValue : product.trim() || null
    const vendorToUse = vendorValue !== undefined ? vendorValue : vendor.trim() || null
    const hashToUse = hashValue !== undefined ? hashValue : hash.trim() || null
    // Use provided proMode or current state value
    const proModeToUse = proModeValue !== undefined ? proModeValue : proMode

    // Normalize inputs exactly like the HTML version
    // Trim and convert empty strings to null for consistent cache key generation
    const productTrimmed = productToUse ? (typeof productToUse === 'string' ? productToUse.trim() : productToUse) || null : null
    const vendorTrimmed = vendorToUse ? (typeof vendorToUse === 'string' ? vendorToUse.trim() : vendorToUse) || null : null
    const hashTrimmed = hashToUse ? (typeof hashToUse === 'string' ? hashToUse.trim() : hashToUse) || null : null

    // Validate input lengths (only check if not null)
    if (productTrimmed && typeof productTrimmed === 'string' && productTrimmed.length > 128) {
      alert('Product name must be 128 characters or less')
      return
    }
    if (vendorTrimmed && typeof vendorTrimmed === 'string' && vendorTrimmed.length > 128) {
      alert('Vendor name must be 128 characters or less')
      return
    }
    if (hashTrimmed && typeof hashTrimmed === 'string' && hashTrimmed.length > 128) {
      alert('Hash must be 128 characters or less')
      return
    }

    if (!productTrimmed && !vendorTrimmed) {
      alert('Please provide at least one of: product name or vendor name')
      return
    }

    onLoadingStart()

    try {
      console.log('[SingleAssessmentForm] Calling assessApplication with pro_mode:', proModeToUse)
      const data = await assessApplication(
        productTrimmed,
        vendorTrimmed,
        hashTrimmed,
        false,
        proModeToUse
      )
      onAssessmentComplete(data, {
        productName: productTrimmed,
        vendorName: vendorTrimmed,
        hash: hashTrimmed,
        proMode: proModeToUse,
      })
    } catch (error) {
      alert('Error: ' + (error instanceof Error ? error.message : 'Unknown error'))
      onLoadingStart() // Reset loading state on error
    }
  }

  const handleButtonClick = () => {
    handleAssess()
  }

  // Handle initial values from cache browser
  useEffect(() => {
    if (initialValues) {
      const productName = initialValues.productName || ''
      const vendorName = initialValues.vendorName || ''
      // Handle hash: if it's null/undefined/empty, use empty string for form, but pass null to API
      // Make sure we handle string values correctly
      const hashValue = (initialValues.hash && typeof initialValues.hash === 'string' && initialValues.hash.trim()) 
        ? initialValues.hash.trim() 
        : ''
      // Set pro_mode from initial values
      const proModeValue = initialValues.proMode || false
      
      console.log('[SingleAssessmentForm] Setting initial values:', {
        productName,
        vendorName,
        hash: initialValues.hash,
        hashValue,
        proMode: proModeValue,
        initialValuesFull: initialValues
      })
      
      setProduct(productName)
      setVendor(vendorName)
      setHash(hashValue) // Set hash in form (empty string if null, otherwise the hash value)
      setProMode(proModeValue) // Set pro_mode checkbox
      
      // Force a render to show the hash value
      console.log('[SingleAssessmentForm] Hash state set to:', hashValue)
      console.log('[SingleAssessmentForm] PRO mode set to:', proModeValue)
      
      // Auto-trigger assessment after setting values
      // Use a small delay to ensure state is updated
      const timer = setTimeout(() => {
        // Pass null if hash is empty string, otherwise pass the hash
        const hashForApi = hashValue && hashValue.trim() ? hashValue.trim() : null
        console.log('[SingleAssessmentForm] Triggering assessment with:', {
          productName,
          vendorName,
          hashForApi,
          proMode: proModeValue
        })
        // IMPORTANT: Pass proModeValue explicitly to ensure cache lookup uses correct mode
        handleAssess(
          productName || null, 
          vendorName || null, 
          hashForApi,
          proModeValue  // Pass pro_mode explicitly for proper cache lookup
        )
        onInitialValuesUsed?.()
      }, 100)
      return () => clearTimeout(timer)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialValues])

  return (
    <div id="single-form">
      <div className="form-row">
        <div className="form-group">
          <label htmlFor="product">Product Name</label>
          <input
            type="text"
            id="product"
            placeholder="e.g., Slack"
            maxLength={128}
            value={product}
            onChange={(e) => setProduct(e.target.value)}
          />
        </div>
        <div className="form-group">
          <label htmlFor="vendor">Vendor Name</label>
          <input
            type="text"
            id="vendor"
            placeholder="e.g., Salesforce"
            maxLength={128}
            value={vendor}
            onChange={(e) => setVendor(e.target.value)}
          />
        </div>
      </div>

      <div className="form-group">
        <label htmlFor="hash">Hash (optional)</label>
        <input
          type="text"
          id="hash"
          placeholder="MD5, SHA1, or SHA256"
          maxLength={128}
          value={hash}
          onChange={(e) => setHash(e.target.value)}
        />
      </div>

      <div className="form-group">
        <div style={{
          padding: '20px',
          background: 'linear-gradient(135deg, rgba(102, 126, 234, 0.05) 0%, rgba(118, 75, 162, 0.05) 100%)',
          border: '2px solid rgba(102, 126, 234, 0.2)',
          borderRadius: '12px',
          transition: 'all 0.3s ease',
          position: 'relative',
          overflow: 'hidden'
        }}>
          {/* Animated background glow when checked */}
          {proMode && (
            <div style={{
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              background: 'linear-gradient(135deg, rgba(102, 126, 234, 0.1) 0%, rgba(118, 75, 162, 0.1) 100%)',
              animation: 'fadeIn 0.3s ease',
              pointerEvents: 'none'
            }}></div>
          )}
          
          <label 
            htmlFor="pro-mode" 
            style={{ 
              display: 'flex', 
              alignItems: 'center', 
              gap: '16px', 
              cursor: 'pointer',
              position: 'relative',
              zIndex: 1
            }}
          >
            {/* Custom checkbox */}
            <div style={{
              position: 'relative',
              width: '28px',
              height: '28px',
              flexShrink: 0
            }}>
              <input
                type="checkbox"
                id="pro-mode"
                checked={proMode}
                onChange={(e) => setProMode(e.target.checked)}
                style={{
                  position: 'absolute',
                  opacity: 0,
                  width: '100%',
                  height: '100%',
                  cursor: 'pointer',
                  zIndex: 2
                }}
              />
              <div
                className="custom-checkbox"
                style={{
                  width: '28px',
                  height: '28px',
                  borderRadius: '8px',
                  border: `3px solid ${proMode ? '#667eea' : 'var(--border-color)'}`,
                  background: proMode 
                    ? 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)'
                    : 'var(--input-bg)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
                  position: 'relative',
                  boxShadow: proMode 
                    ? '0 4px 12px rgba(102, 126, 234, 0.4), 0 2px 6px rgba(118, 75, 162, 0.3), inset 0 1px 2px rgba(255, 255, 255, 0.3)'
                    : '0 2px 4px rgba(0, 0, 0, 0.1)',
                  transform: proMode ? 'scale(1.05)' : 'scale(1)'
                }}
              >
                {proMode && (
                  <i 
                    className="fas fa-check" 
                    style={{
                      color: 'white',
                      fontSize: '14px',
                      fontWeight: 'bold',
                      animation: 'checkMarkIn 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
                      textShadow: '0 1px 2px rgba(0, 0, 0, 0.2)'
                    }}
                  ></i>
                )}
                
                {/* Glowing ring when checked */}
                {proMode && (
                  <div style={{
                    position: 'absolute',
                    inset: '-4px',
                    borderRadius: '12px',
                    border: '2px solid rgba(102, 126, 234, 0.5)',
                    animation: 'pulse-ring 2s ease-in-out infinite',
                    pointerEvents: 'none'
                  }}></div>
                )}
              </div>
            </div>
            
            <div style={{ flex: 1 }}>
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                marginBottom: '4px'
              }}>
                <span style={{
                  fontSize: '16px',
                  fontWeight: '700',
                  color: proMode ? '#667eea' : 'var(--text-primary)',
                  transition: 'color 0.3s ease',
                  letterSpacing: '0.3px'
                }}>
                  PRO Mode
                </span>
                {proMode && (
                  <span style={{
                    padding: '2px 8px',
                    background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                    color: 'white',
                    borderRadius: '12px',
                    fontSize: '10px',
                    fontWeight: 'bold',
                    textTransform: 'uppercase',
                    letterSpacing: '0.5px',
                    animation: 'fadeIn 0.3s ease',
                    boxShadow: '0 2px 4px rgba(102, 126, 234, 0.3)'
                  }}>
                    Active
                  </span>
                )}
              </div>
              <span style={{
                fontSize: '14px',
                color: 'var(--text-secondary)',
                lineHeight: '1.5'
              }}>
                Use gemini-2.5-pro for all AI operations <span style={{ fontStyle: 'italic', color: 'var(--text-muted)' }}>(higher quality, slower)</span>
              </span>
            </div>
          </label>
          
          {/* Elegant note */}
          <div style={{
            marginTop: '16px',
            padding: '14px 18px',
            background: proMode 
              ? 'linear-gradient(135deg, rgba(102, 126, 234, 0.12) 0%, rgba(118, 75, 162, 0.12) 100%)'
              : 'linear-gradient(135deg, rgba(102, 126, 234, 0.08) 0%, rgba(118, 75, 162, 0.08) 100%)',
            borderLeft: '3px solid #667eea',
            borderRadius: '8px',
            display: 'flex',
            alignItems: 'flex-start',
            gap: '12px',
            transition: 'all 0.3s ease',
            position: 'relative',
            zIndex: 1,
            marginLeft: '44px'
          }}>
            <i 
              className="fas fa-info-circle" 
              style={{ 
                color: '#667eea',
                fontSize: '16px',
                marginTop: '2px',
                flexShrink: 0,
                filter: 'drop-shadow(0 1px 2px rgba(102, 126, 234, 0.3))'
              }}
            ></i>
            <span style={{ 
              color: 'var(--text-secondary)',
              fontSize: '13px',
              lineHeight: '1.6',
              fontStyle: 'italic'
            }}>
              <strong style={{ color: 'var(--text-primary)', fontStyle: 'normal' }}>Note:</strong> Security Recommendation always uses PRO model regardless of this setting
            </span>
          </div>
        </div>
      </div>

      <button type="button" onClick={handleButtonClick}>
        <i className="fas fa-search"></i> Assess Application
      </button>
    </div>
  )
}

export default SingleAssessmentForm

