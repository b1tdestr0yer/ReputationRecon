import { useState } from 'react'
import { assessApplication } from '../services/api'
import { AssessmentResponse } from '../types'

interface AssessmentParams {
  productName: string | null
  vendorName: string | null
  hash: string | null
  proMode: boolean
}

interface SingleAssessmentFormProps {
  onLoadingStart: () => void
  onAssessmentComplete: (data: AssessmentResponse, params: AssessmentParams) => void
}

const SingleAssessmentForm = ({ onLoadingStart, onAssessmentComplete }: SingleAssessmentFormProps) => {
  const [product, setProduct] = useState('')
  const [vendor, setVendor] = useState('')
  const [hash, setHash] = useState('')
  const [proMode, setProMode] = useState(false)

  const handleAssess = async () => {
    // Normalize inputs exactly like the HTML version
    // Trim and convert empty strings to null for consistent cache key generation
    const productTrimmed = product.trim() || null
    const vendorTrimmed = vendor.trim() || null
    const hashTrimmed = hash.trim() || null

    // Validate input lengths (only check if not null)
    if (productTrimmed && productTrimmed.length > 128) {
      alert('Product name must be 128 characters or less')
      return
    }
    if (vendorTrimmed && vendorTrimmed.length > 128) {
      alert('Vendor name must be 128 characters or less')
      return
    }
    if (hashTrimmed && hashTrimmed.length > 128) {
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

      <button type="button" onClick={handleAssess}>
        <i className="fas fa-search"></i> Assess Application
      </button>
    </div>
  )
}

export default SingleAssessmentForm

