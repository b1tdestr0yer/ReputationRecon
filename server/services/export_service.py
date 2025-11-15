from typing import Dict, Any
from datetime import datetime


class ExportService:
    """Service for exporting assessments to various formats"""
    
    def export_to_markdown(self, assessment_data: Dict[str, Any]) -> str:
        """Export assessment to Markdown format"""
        trust = assessment_data.get("trust_score", {})
        posture = assessment_data.get("security_posture", {})
        cve_summary = posture.get("cve_summary", {})
        citations = posture.get("citations", [])
        alternatives = assessment_data.get("alternatives", [])
        
        md = f"""# Security Assessment Report: {assessment_data.get('entity_name', 'Unknown')}

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## Executive Summary

**Product:** {assessment_data.get('entity_name', 'Unknown')}  
**Vendor:** {assessment_data.get('vendor_name', 'Unknown')}  
**Category:** {assessment_data.get('category', 'Unknown')}  
**Trust Score:** {trust.get('score', 0)}/100 ({trust.get('risk_level', 'Unknown')} Risk)  
**Confidence:** {trust.get('confidence', 0):.1%}

### Trust Score Rationale
{trust.get('rationale', 'N/A')}

---

## Security Posture

### Description
{posture.get('description', 'N/A')}

### Usage
{posture.get('usage', 'N/A')}

### Vendor Reputation
{posture.get('vendor_reputation', 'N/A')}

### Data Handling & Compliance
{posture.get('data_handling', 'N/A')}

### Deployment & Admin Controls
{posture.get('deployment_controls', 'N/A')}

### Incidents & Abuse Signals
{posture.get('incidents_abuse', 'N/A')}

---

## Recommendation

{assessment_data.get('suggestion', 'No recommendation available.')}

---

## CVE Analysis

**Total CVEs:** {cve_summary.get('total_cves', 0)}  
**Critical CVEs:** {cve_summary.get('critical_count', 0)}  
**High CVEs:** {cve_summary.get('high_count', 0)}  
**CISA KEV Entries:** {cve_summary.get('cisa_kev_count', 0)}

### Recent CVEs
"""
        
        recent_cves = cve_summary.get('recent_cves', [])
        if recent_cves:
            md += "\n| CVE ID | Severity | CVSS Score | Description |\n"
            md += "|--------|----------|------------|-------------|\n"
            for cve in recent_cves[:10]:  # Top 10
                cve_id = cve.get('id', 'N/A')
                severity = cve.get('severity', 'unknown').upper()
                score = cve.get('base_score', 0)
                desc = cve.get('description', 'N/A')[:100] + "..." if len(cve.get('description', '')) > 100 else cve.get('description', 'N/A')
                md += f"| {cve_id} | {severity} | {score} | {desc} |\n"
        else:
            md += "\nNo recent CVEs found.\n"
        
        md += "\n---\n\n## Safer Alternatives\n\n"
        
        if alternatives:
            for i, alt in enumerate(alternatives, 1):
                md += f"### {i}. {alt.get('name', 'Unknown')} ({alt.get('vendor', 'Unknown')})\n"
                md += f"**Trust Score:** {alt.get('trust_score', 'N/A')}/100\n\n"
                md += f"{alt.get('rationale', 'N/A')}\n\n"
        else:
            md += "No alternatives suggested.\n"
        
        md += "\n---\n\n## Sources & Citations\n\n"
        
        if citations:
            vendor_citations = [c for c in citations if c.get('is_vendor_stated', False)]
            independent_citations = [c for c in citations if not c.get('is_vendor_stated', False)]
            
            if vendor_citations:
                md += "### Vendor-Stated Sources\n\n"
                for citation in vendor_citations:
                    md += f"- **{citation.get('source_type', 'Unknown')}**: [{citation.get('source', 'N/A')}]({citation.get('source', '#')})\n"
                    md += f"  - Claim: {citation.get('claim', 'N/A')}\n\n"
            
            if independent_citations:
                md += "### Independent Sources\n\n"
                for citation in independent_citations:
                    md += f"- **{citation.get('source_type', 'Unknown')}**: [{citation.get('source', 'N/A')}]({citation.get('source', '#')})\n"
                    md += f"  - Claim: {citation.get('claim', 'N/A')}\n\n"
        else:
            md += "No citations available.\n"
        
        md += f"\n---\n\n**Data Quality:** {assessment_data.get('data_quality', 'unknown')}  \n"
        md += f"**Assessment Timestamp:** {assessment_data.get('assessment_timestamp', 'N/A')}\n"
        
        return md
    
    def export_to_pdf_html(self, assessment_data: Dict[str, Any]) -> str:
        """Generate HTML for PDF export"""
        trust = assessment_data.get("trust_score", {})
        posture = assessment_data.get("security_posture", {})
        cve_summary = posture.get("cve_summary", {})
        citations = posture.get("citations", [])
        alternatives = assessment_data.get("alternatives", [])
        
        score = trust.get('score', 0)
        risk_color = "#28a745" if score >= 70 else "#ffc107" if score >= 50 else "#dc3545"
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Assessment: {assessment_data.get('entity_name', 'Unknown')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        h1 {{ color: #333; border-bottom: 3px solid {risk_color}; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; border-bottom: 2px solid #ddd; padding-bottom: 5px; }}
        h3 {{ color: #666; margin-top: 20px; }}
        .score-box {{ background: {risk_color}; color: white; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0; }}
        .score-value {{ font-size: 48px; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #f2f2f2; font-weight: bold; }}
        .citation {{ margin: 10px 0; padding: 10px; background: #f9f9f9; border-left: 4px solid #007bff; }}
        .vendor-citation {{ border-left-color: #28a745; }}
        .independent-citation {{ border-left-color: #ffc107; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <h1>Security Assessment Report</h1>
    <p><strong>Product:</strong> {assessment_data.get('entity_name', 'Unknown')}<br>
    <strong>Vendor:</strong> {assessment_data.get('vendor_name', 'Unknown')}<br>
    <strong>Category:</strong> {assessment_data.get('category', 'Unknown')}<br>
    <strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="score-box">
        <div class="score-value">{score}/100</div>
        <div style="font-size: 24px;">{trust.get('risk_level', 'Unknown')} Risk</div>
        <div>Confidence: {trust.get('confidence', 0):.1%}</div>
    </div>
    
    <h2>Executive Summary</h2>
    <p>{trust.get('rationale', 'N/A')}</p>
    
    <h2>Security Posture</h2>
    <h3>Description</h3>
    <p>{posture.get('description', 'N/A')}</p>
    
    <h3>Usage</h3>
    <p>{posture.get('usage', 'N/A')}</p>
    
    <h3>Vendor Reputation</h3>
    <p>{posture.get('vendor_reputation', 'N/A')}</p>
    
    <h3>Data Handling & Compliance</h3>
    <p>{posture.get('data_handling', 'N/A')}</p>
    
    <h3>Deployment & Admin Controls</h3>
    <p>{posture.get('deployment_controls', 'N/A')}</p>
    
    <h2>Recommendation</h2>
    <div style="background-color: #f0f7ff; padding: 20px; border-radius: 8px; border-left: 5px solid #007bff; margin: 20px 0;">
        <p style="white-space: pre-wrap;">{assessment_data.get('suggestion', 'No recommendation available.')}</p>
    </div>
    
    <h2>CVE Analysis</h2>
    <table>
        <tr>
            <th>Metric</th>
            <th>Value</th>
        </tr>
        <tr><td>Total CVEs</td><td>{cve_summary.get('total_cves', 0)}</td></tr>
        <tr><td>Critical CVEs</td><td>{cve_summary.get('critical_count', 0)}</td></tr>
        <tr><td>High CVEs</td><td>{cve_summary.get('high_count', 0)}</td></tr>
        <tr><td>CISA KEV Entries</td><td>{cve_summary.get('cisa_kev_count', 0)}</td></tr>
    </table>
"""
        
        recent_cves = cve_summary.get('recent_cves', [])
        if recent_cves:
            html += "<h3>Recent CVEs</h3><table><tr><th>CVE ID</th><th>Severity</th><th>CVSS Score</th><th>Description</th></tr>"
            for cve in recent_cves[:15]:
                cve_id = cve.get('id', 'N/A')
                severity = cve.get('severity', 'unknown').upper()
                score = cve.get('base_score', 0)
                desc = cve.get('description', 'N/A')[:150] + "..." if len(cve.get('description', '')) > 150 else cve.get('description', 'N/A')
                html += f"<tr><td>{cve_id}</td><td>{severity}</td><td>{score}</td><td>{desc}</td></tr>"
            html += "</table>"
        
        if alternatives:
            html += "<h2>Safer Alternatives</h2>"
            for i, alt in enumerate(alternatives, 1):
                html += f"<h3>{i}. {alt.get('name', 'Unknown')} ({alt.get('vendor', 'Unknown')})</h3>"
                html += f"<p><strong>Trust Score:</strong> {alt.get('trust_score', 'N/A')}/100</p>"
                html += f"<p>{alt.get('rationale', 'N/A')}</p>"
        
        if citations:
            html += "<h2>Sources & Citations</h2>"
            vendor_citations = [c for c in citations if c.get('is_vendor_stated', False)]
            independent_citations = [c for c in citations if not c.get('is_vendor_stated', False)]
            
            if vendor_citations:
                html += "<h3>Vendor-Stated Sources</h3>"
                for citation in vendor_citations:
                    html += f'<div class="citation vendor-citation">'
                    html += f'<strong>{citation.get("source_type", "Unknown")}</strong>: <a href="{citation.get("source", "#")}">{citation.get("source", "N/A")}</a><br>'
                    html += f'<em>{citation.get("claim", "N/A")}</em></div>'
            
            if independent_citations:
                html += "<h3>Independent Sources</h3>"
                for citation in independent_citations:
                    html += f'<div class="citation independent-citation">'
                    html += f'<strong>{citation.get("source_type", "Unknown")}</strong>: <a href="{citation.get("source", "#")}">{citation.get("source", "N/A")}</a><br>'
                    html += f'<em>{citation.get("claim", "N/A")}</em></div>'
        
        html += f"""
    <div class="footer">
        <p>Data Quality: {assessment_data.get('data_quality', 'unknown')}<br>
        Assessment Timestamp: {assessment_data.get('assessment_timestamp', 'N/A')}</p>
    </div>
</body>
</html>"""
        
        return html

