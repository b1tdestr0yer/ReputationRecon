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
    hashValue?: string | null
  ) => {
    // Use provided values or current state values
    const productToUse = productValue !== undefined ? productValue : product.trim() || null
    const vendorToUse = vendorValue !== undefined ? vendorValue : vendor.trim() || null
    const hashToUse = hashValue !== undefined ? hashValue : hash.trim() || null

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
      const data = await assessApplication(
        productTrimmed,
        vendorTrimmed,
        hashTrimmed,
        false,
        proMode
      )
      onAssessmentComplete(data, {
        productName: productTrimmed,
        vendorName: vendorTrimmed,
        hash: hashTrimmed,
        proMode: proMode,
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
      
      console.log('[SingleAssessmentForm] Setting initial values:', {
        productName,
        vendorName,
        hash: initialValues.hash,
        hashValue,
        initialValuesFull: initialValues
      })
      
      setProduct(productName)
      setVendor(vendorName)
      setHash(hashValue) // Set hash in form (empty string if null, otherwise the hash value)
      
      // Force a render to show the hash value
      console.log('[SingleAssessmentForm] Hash state set to:', hashValue)
      
      // Auto-trigger assessment after setting values
      // Use a small delay to ensure state is updated
      const timer = setTimeout(() => {
        // Pass null if hash is empty string, otherwise pass the hash
        const hashForApi = hashValue && hashValue.trim() ? hashValue.trim() : null
        console.log('[SingleAssessmentForm] Triggering assessment with:', {
          productName,
          vendorName,
          hashForApi
        })
        handleAssess(
          productName || null, 
          vendorName || null, 
          hashForApi
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
        <label htmlFor="pro-mode" style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
          <input
            type="checkbox"
            id="pro-mode"
            checked={proMode}
            onChange={(e) => setProMode(e.target.checked)}
            style={{ cursor: 'pointer' }}
          />
          <span>
            <strong>PRO Mode</strong> - Use gemini-2.5-pro for all AI operations (higher quality, slower)
          </span>
        </label>
        <small style={{ display: 'block', marginTop: '4px', color: '#666', marginLeft: '24px' }}>
          Note: Security Recommendation always uses PRO model regardless of this setting
        </small>
      </div>

      <button type="button" onClick={handleButtonClick}>
        <i className="fas fa-search"></i> Assess Application
      </button>
    </div>
  )
}

export default SingleAssessmentForm

