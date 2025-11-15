import { useState } from 'react'
import { compareApplications } from '../services/api'
import { AssessmentResponse, CompareRequest } from '../types'

interface AssessmentParams {
  productName: string | null
  vendorName: string | null
  hash: string | null
}

interface CompareModeFormProps {
  onLoadingStart: () => void
  onAssessmentComplete: (data: AssessmentResponse, params: AssessmentParams) => void
}

interface CompareItem {
  product: string
  vendor: string
}

const CompareModeForm = ({ onLoadingStart, onAssessmentComplete }: CompareModeFormProps) => {
  const [items, setItems] = useState<CompareItem[]>([
    { product: '', vendor: '' },
    { product: '', vendor: '' },
  ])

  const addCompareItem = () => {
    setItems([...items, { product: '', vendor: '' }])
  }

  const updateItem = (index: number, field: 'product' | 'vendor', value: string) => {
    const newItems = [...items]
    newItems[index][field] = value
    setItems(newItems)
  }

  const handleCompare = async () => {
    const requests: CompareRequest[] = []

      for (const item of items) {
        // Normalize inputs exactly like the HTML version
        // Trim and convert empty strings to null for consistent cache key generation
        const productTrimmed = item.product.trim() || null
        const vendorTrimmed = item.vendor.trim() || null

        // Validate input lengths (only check if not null)
        if (productTrimmed && productTrimmed.length > 128) {
          alert('Product name must be 128 characters or less')
          return
        }
        if (vendorTrimmed && vendorTrimmed.length > 128) {
          alert('Vendor name must be 128 characters or less')
          return
        }

        if (productTrimmed || vendorTrimmed) {
          requests.push({
            product_name: productTrimmed,
            vendor_name: vendorTrimmed,
          })
        }
      }

    if (requests.length < 2) {
      alert('Please provide at least 2 applications to compare')
      return
    }

    onLoadingStart()

    try {
      const data = await compareApplications(requests)
      // For comparison, we'll display the first assessment
      // You might want to create a dedicated comparison view component
      if (data.assessments && data.assessments.length > 0) {
        // Use the first request's parameters for refresh
        const firstRequest = requests[0]
        onAssessmentComplete(data.assessments[0], {
          productName: firstRequest.product_name,
          vendorName: firstRequest.vendor_name,
          hash: null, // Compare mode doesn't support hash
        })
      }
    } catch (error) {
      alert('Error: ' + (error instanceof Error ? error.message : 'Unknown error'))
      onLoadingStart() // Reset loading state on error
    }
  }

  return (
    <div id="compare-form" className="compare-mode show">
      <h2>Compare Applications</h2>
      <div id="compare-inputs">
        {items.map((item, index) => (
          <div key={index} className="form-row compare-item">
            <div className="form-group">
              <label>Product {index + 1}</label>
              <input
                type="text"
                className="compare-product"
                placeholder="Product name"
                maxLength={128}
                value={item.product}
                onChange={(e) => updateItem(index, 'product', e.target.value)}
              />
            </div>
            <div className="form-group">
              <label>Vendor {index + 1}</label>
              <input
                type="text"
                className="compare-vendor"
                placeholder="Vendor name"
                maxLength={128}
                value={item.vendor}
                onChange={(e) => updateItem(index, 'vendor', e.target.value)}
              />
            </div>
          </div>
        ))}
      </div>
      <button onClick={addCompareItem}>+ Add Another</button>
      <button onClick={handleCompare}>Compare Applications</button>
    </div>
  )
}

export default CompareModeForm

