import { useEffect, useRef } from 'react'
import { Chart, ChartConfiguration, registerables } from 'chart.js'
import { AssessmentResponse } from '../types'

Chart.register(...registerables)

interface SpiderChartProps {
  data: AssessmentResponse
}

const SpiderChart = ({ data }: SpiderChartProps) => {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const chartInstanceRef = useRef<Chart | null>(null)

  useEffect(() => {
    if (!canvasRef.current) return

    const scores = calculateSpiderChartScores(data)

    // Destroy previous chart if exists
    if (chartInstanceRef.current) {
      chartInstanceRef.current.destroy()
    }

    const scoreValues = [
      scores.virustotal,
      scores.cves,
      scores.aiScan,
      scores.vendorTrust,
      scores.informationQuantity,
    ]

    const getColorForScore = (score: number) => {
      if (score >= 70) {
        return { bg: 'rgba(40, 167, 69, 0.2)', border: 'rgba(40, 167, 69, 1)', point: 'rgba(40, 167, 69, 1)' }
      } else if (score >= 50) {
        return { bg: 'rgba(255, 193, 7, 0.2)', border: 'rgba(255, 193, 7, 1)', point: 'rgba(255, 193, 7, 1)' }
      } else {
        return { bg: 'rgba(220, 53, 69, 0.2)', border: 'rgba(220, 53, 69, 1)', point: 'rgba(220, 53, 69, 1)' }
      }
    }

    const colors = scoreValues.map((score) => getColorForScore(score))

    const config: ChartConfiguration = {
      type: 'radar',
      data: {
        labels: ['VirusTotal', 'CVEs', 'AI Scan', 'Vendor Trust', 'Information Quantity'],
        datasets: [
          {
            label: 'Score',
            data: scoreValues,
            backgroundColor: 'rgba(102, 126, 234, 0.15)',
            borderColor: 'rgba(102, 126, 234, 0.8)',
            borderWidth: 2,
            pointBackgroundColor: colors.map((c) => c.point),
            pointBorderColor: '#fff',
            pointHoverBackgroundColor: '#fff',
            pointHoverBorderColor: colors.map((c) => c.border),
            pointRadius: 5,
            pointHoverRadius: 7,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        scales: {
          r: {
            beginAtZero: true,
            max: 100,
            min: 0,
            ticks: {
              stepSize: 20,
              font: {
                size: 11,
              },
            },
            pointLabels: {
              font: {
                size: 13,
                weight: 'bold',
              },
            },
            grid: {
              color: 'rgba(0, 0, 0, 0.1)',
            },
          },
        },
        plugins: {
          legend: {
            display: false,
          },
          tooltip: {
            callbacks: {
              label: function (context) {
                const label = context.dataset.label || ''
                const value = context.parsed.r.toFixed(0)
                return label + ': ' + value + '/100'
              },
            },
          },
        },
        elements: {
          line: {
            borderWidth: 2,
          },
        },
      },
    }

    const ctx = canvasRef.current.getContext('2d')
    if (ctx) {
      chartInstanceRef.current = new Chart(ctx, config)
    }

    return () => {
      if (chartInstanceRef.current) {
        chartInstanceRef.current.destroy()
        chartInstanceRef.current = null
      }
    }
  }, [data])

  const calculateSpiderChartScores = (data: AssessmentResponse) => {
    let virustotalScore = 50
    const citations = data.security_posture?.citations || []
    const factors = data.trust_score?.factors || {}
    const vtCitation = citations.find((c) => {
      const claim = c.claim || ''
      return (
        (c.source_type === 'independent' || (c.source && c.source.includes('virustotal'))) &&
        claim.toLowerCase().includes('virustotal')
      )
    })

    // Trusted vendors list (same as backend)
    const trustedVendors = [
      'bitdefender',
      'bitdefenderfalx',
      'clamav',
      'crowdstrike',
      'crowstrike',
      'kaspersky',
      'microsoft',
      'fortinet',
      'google',
      'withsecure',
      'palo alto networks',
      'paloalto',
      'sentinel one',
      'sentinelone',
    ]

    let positives = 0
    let total = 0
    let trustedDetections = 0

    // Extract positives/total from citation
    if (vtCitation && vtCitation.claim) {
      const patterns = [/(\d+)\/(\d+)\s+vendors?\s+flagged/i, /(\d+)\s*\/\s*(\d+)/, /(\d+)\s+of\s+(\d+)/i]

      for (const pattern of patterns) {
        const match = vtCitation.claim.match(pattern)
        if (match) {
          positives = parseInt(match[1])
          total = parseInt(match[2])
          break
        }
      }
    }

    // Check for trusted vendor detections in factors
    for (const [key, value] of Object.entries(factors)) {
      if (key.startsWith('virustotal_trusted_vendors_')) {
        const match = key.match(/virustotal_trusted_vendors_(\d+)/)
        if (match) {
          trustedDetections = parseInt(match[1])
        }
      }
    }

    // Calculate score using new weighting logic
    if (positives === 0 && total > 0) {
      virustotalScore = 90
    } else if (positives > 0) {
      let basePenalty = 0
      if (positives >= 30) {
        basePenalty = 60
      } else if (positives >= 20) {
        basePenalty = 50
      } else if (positives >= 15) {
        basePenalty = 40
      } else if (positives >= 10) {
        basePenalty = 35
      } else if (positives >= 5) {
        basePenalty = 25
      } else {
        basePenalty = 15
      }

      const trustedPenalty = trustedDetections * 8
      const untrustedDetections = positives - trustedDetections
      let untrustedPenalty = 0
      if (untrustedDetections >= 10) {
        untrustedPenalty = (untrustedDetections - 10) * 1
      } else if (untrustedDetections >= 5) {
        untrustedPenalty = (untrustedDetections - 5) * 0.5
      }

      let totalPenalty = 0
      if (trustedDetections > 0) {
        totalPenalty = basePenalty + trustedPenalty + untrustedPenalty
        if (trustedDetections >= 3) {
          totalPenalty = totalPenalty * 1.3
        } else if (trustedDetections >= 2) {
          totalPenalty = totalPenalty * 1.15
        }
      } else {
        if (untrustedDetections > 0 && trustedDetections === 0) {
          totalPenalty = basePenalty * 0.3 + untrustedPenalty
        } else {
          totalPenalty = basePenalty + untrustedPenalty
        }
      }

      virustotalScore = Math.max(0, Math.min(100, 100 - totalPenalty))
    }

    let cvesScore = 50
    const cveSummary = data.security_posture?.cve_summary || {}
    const totalCves = cveSummary.total_cves || 0
    const criticalCount = cveSummary.critical_count || 0
    const highCount = cveSummary.high_count || 0
    const cisaKevCount = cveSummary.cisa_kev_count || 0

    if (totalCves === 0) {
      cvesScore = 100
    } else {
      let penalty = 0
      penalty += Math.min(30, totalCves * 2)
      penalty += criticalCount * 15
      penalty += highCount * 8
      penalty += cisaKevCount * 20
      cvesScore = Math.max(0, 100 - penalty)
    }

    let aiScanScore = 60
    const versionSpecificCves = cveSummary.version_specific_cves || 0
    const versionSpecificCritical = cveSummary.version_specific_critical || 0

    if (versionSpecificCves > 0) {
      if (versionSpecificCritical > 5) {
        aiScanScore -= 30
      } else if (versionSpecificCritical > 0) {
        aiScanScore -= 20
      } else if (versionSpecificCves > 10) {
        aiScanScore -= 15
      } else if (versionSpecificCves > 5) {
        aiScanScore -= 10
      } else {
        aiScanScore -= 5
      }
    } else if (totalCves > 0) {
      if (criticalCount > 5) {
        aiScanScore -= 20
      } else if (criticalCount > 0) {
        aiScanScore -= 12
      } else if (highCount > 10) {
        aiScanScore -= 10
      } else if (highCount > 0) {
        aiScanScore -= 5
      } else if (totalCves > 20) {
        aiScanScore -= 5
      }
    } else {
      aiScanScore += 10
    }

    if (cisaKevCount > 0) {
      aiScanScore -= cisaKevCount * 15
    }

    // Apply VirusTotal impact to AI Scan score
    if (positives > 0) {
      let vtPenalty = 0

      if (positives >= 30) {
        vtPenalty = 30
      } else if (positives >= 20) {
        vtPenalty = 25
      } else if (positives >= 15) {
        vtPenalty = 20
      } else if (positives >= 10) {
        vtPenalty = 18
      } else if (positives >= 5) {
        vtPenalty = 12
      } else {
        vtPenalty = 8
      }

      if (trustedDetections > 0) {
        vtPenalty += trustedDetections * 5
        if (trustedDetections >= 3) {
          vtPenalty = vtPenalty * 1.2
        } else if (trustedDetections >= 2) {
          vtPenalty = vtPenalty * 1.1
        }
      } else {
        const untrustedDetections = positives - trustedDetections
        if (untrustedDetections > 0 && trustedDetections === 0) {
          vtPenalty = vtPenalty * 0.4
        }
      }

      aiScanScore -= Math.min(40, vtPenalty)
    } else if (positives === 0 && total > 0) {
      aiScanScore += 5
    }

    let vendorReputation = data.security_posture?.vendor_reputation || ''
    const incidentsAbuse = data.security_posture?.incidents_abuse || ''

    const negativeKeywords = ['concern', 'incident', 'breach', 'vulnerability', 'exploit', 'malware', 'suspicious']
    const reputationLower = vendorReputation.toLowerCase()
    const incidentsLower = incidentsAbuse.toLowerCase()

    let negativeSignals = 0
    negativeKeywords.forEach((keyword) => {
      if (reputationLower.includes(keyword) || incidentsLower.includes(keyword)) {
        negativeSignals++
      }
    })

    if (negativeSignals > 3) {
      aiScanScore -= 15
    } else if (negativeSignals > 1) {
      aiScanScore -= 8
    } else if (negativeSignals > 0) {
      aiScanScore -= 3
    }

    const positiveKeywords = ['reputable', 'established', 'secure', 'compliance', 'certified', 'trusted']
    let positiveSignals = 0
    positiveKeywords.forEach((keyword) => {
      if (reputationLower.includes(keyword)) {
        positiveSignals++
      }
    })

    if (positiveSignals > 2) {
      aiScanScore += 10
    } else if (positiveSignals > 0) {
      aiScanScore += 5
    }

    const dataQuality = (data as any).data_quality || 'sufficient'
    const citationsCount = citations.length
    if (dataQuality === 'sufficient' && citationsCount >= 5) {
      aiScanScore += 5
    } else if (dataQuality === 'insufficient' || citationsCount < 2) {
      aiScanScore -= 5
    }

    aiScanScore = Math.max(0, Math.min(100, aiScanScore))

    let vendorTrustScore = data.trust_score?.score || 50

    const vendorReputationLower = (data.security_posture?.vendor_reputation || '').toLowerCase()
    const isEstablished = [
      'established',
      'reputable',
      'major',
      'leading',
      'well-known',
      'trusted',
      'recognized',
      'prominent',
      'large-scale',
      'enterprise',
    ].some((term) => vendorReputationLower.includes(term))

    if (isEstablished && vendorTrustScore < 85) {
      const hasSeriousIssues =
        (cveSummary.cisa_kev_count || 0) > 0 || (cveSummary.version_specific_critical || 0) > 5

      if (!hasSeriousIssues) {
        if (vendorTrustScore >= 60) {
          vendorTrustScore = Math.min(85, vendorTrustScore + Math.min(20, 85 - vendorTrustScore))
        } else if (vendorTrustScore >= 50) {
          vendorTrustScore = Math.min(75, vendorTrustScore + Math.min(20, 75 - vendorTrustScore))
        } else {
          vendorTrustScore = Math.min(65, vendorTrustScore + 10)
        }
      } else if (vendorTrustScore < 70) {
        vendorTrustScore = Math.min(70, vendorTrustScore + 5)
      }
    }

    let informationQuantityScore = 50
    if (citationsCount === 0) {
      informationQuantityScore = 0
    } else if (citationsCount <= 3) {
      informationQuantityScore = 30 + citationsCount * 10
    } else if (citationsCount <= 7) {
      informationQuantityScore = 60 + (citationsCount - 3) * 5
    } else {
      informationQuantityScore = Math.min(100, 80 + (citationsCount - 7) * 2)
    }

    if (dataQuality === 'insufficient') {
      informationQuantityScore = Math.max(0, informationQuantityScore - 30)
    } else if (dataQuality === 'limited') {
      informationQuantityScore = Math.max(0, informationQuantityScore - 15)
    }

    return {
      virustotal: Math.round(virustotalScore),
      cves: Math.round(cvesScore),
      aiScan: Math.round(aiScanScore),
      vendorTrust: Math.round(vendorTrustScore),
      informationQuantity: Math.round(informationQuantityScore),
    }
  }

  return (
    <div className="spider-chart-container">
      <h3>
        <i className="fas fa-spider"></i> Risk Assessment Breakdown
      </h3>
      <div className="spider-chart-wrapper">
        <canvas ref={canvasRef} id="spiderChart"></canvas>
      </div>
    </div>
  )
}

export default SpiderChart

