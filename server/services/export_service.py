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
        
        md = f"""# Security Assessment Report

## {assessment_data.get('entity_name', 'Unknown')}

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Data Quality:** {assessment_data.get('data_quality', 'unknown').upper()}

---

## Executive Summary

| Field | Value |
|-------|-------|
| **Product** | {assessment_data.get('entity_name', 'Unknown')} |
| **Vendor** | {assessment_data.get('vendor_name', 'Unknown')} |
| **Category** | {assessment_data.get('category', 'Unknown')} |
| **Trust Score** | **{trust.get('score', 0)}/100** ({trust.get('risk_level', 'Unknown')} Risk) |
| **Confidence** | {trust.get('confidence', 0):.1%} |

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

"""
        
        # Add version-specific CVE information
        detected_version = cve_summary.get('detected_version')
        if detected_version:
            md += f"**Detected Version:** {detected_version}\n"
            md += f"**Version-Specific CVEs:** {cve_summary.get('version_specific_cves', 0)}\n"
            md += f"**Version-Specific Critical:** {cve_summary.get('version_specific_critical', 0)}\n"
            md += f"**Version-Specific High:** {cve_summary.get('version_specific_high', 0)}\n\n"
        
        md += "### Recent CVEs\n\n"
        
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
        
        md += "\n---\n\n## VirusTotal Analysis\n\n"
        
        # Try to get VirusTotal data from multiple sources
        # First try collected_data (if included in export)
        collected_data = assessment_data.get('collected_data', {})
        vt = collected_data.get('virustotal') if collected_data else None
        
        # If not available, try to extract from citations
        if not vt:
            for citation in citations:
                if citation.get('source_type') == 'VirusTotal':
                    claim = citation.get('claim', '')
                    # Extract basic info from claim text
                    md += f"**VirusTotal Analysis:** {claim}\n\n"
                    break
        
        if vt and vt.get('response_code') == 1:
            positives = vt.get('positives', 0)
            total = vt.get('total', 0)
            malicious = vt.get('malicious', 0)
            suspicious = vt.get('suspicious', 0)
            reputation = vt.get('reputation', 0)
            risk_level = vt.get('risk_level', 'unknown')
            risk_confidence = vt.get('risk_confidence', 0.5)
            
            md += f"**Detection Rate:** {positives}/{total} engines flagged ({malicious} malicious, {suspicious} suspicious)\n"
            md += f"**Reputation Score:** {reputation}\n"
            md += f"**Risk Level:** {risk_level} ({int(risk_confidence*100)}% confidence)\n\n"
            
            # Executable name
            exe_name = vt.get('exe_name')
            if exe_name:
                md += f"**Executable Name:** {exe_name}\n"
            
            # Detected version
            detected_version = vt.get('detected_version')
            if detected_version:
                version_confidence = vt.get('version_confidence', 0.0)
                md += f"**Detected Version:** {detected_version} (confidence: {int(version_confidence*100)}%)\n"
            
            # Community notes
            community_notes = vt.get('community_notes', [])
            if community_notes:
                md += f"\n### Community Notes ({len(community_notes)} available)\n\n"
                for i, note in enumerate(community_notes[:10], 1):
                    note_text = note.get('text', '')
                    note_date = note.get('date', 0)
                    note_author = note.get('author', '')
                    if note_text:
                        md += f"**Note {i}:**\n"
                        if note_author:
                            md += f"*By: {note_author}*\n"
                        if note_date:
                            try:
                                date_str = datetime.fromtimestamp(note_date).strftime('%Y-%m-%d')
                                md += f"*Date: {date_str}*\n"
                            except:
                                pass
                        md += f"{note_text[:500]}{'...' if len(note_text) > 500 else ''}\n\n"
            
            # Submission history
            submission_history = vt.get('submission_history', [])
            if submission_history:
                md += f"\n### Submission History ({len(submission_history)} entries)\n\n"
                for i, submission in enumerate(submission_history[:5], 1):
                    sub_date = submission.get('date', 0)
                    sub_names = submission.get('submission_names', [])
                    if sub_names:
                        md += f"**Submission {i}:**\n"
                        if sub_date:
                            try:
                                date_str = datetime.fromtimestamp(sub_date).strftime('%Y-%m-%d')
                                md += f"*Date: {date_str}*\n"
                            except:
                                pass
                        md += f"*File names: {', '.join(sub_names[:5])}*\n\n"
            
            # File details
            file_details = vt.get('file_details', {})
            if file_details:
                md += "\n### File Details\n\n"
                pe_info = file_details.get('pe_info', {})
                if pe_info and isinstance(pe_info, dict):
                    version_info = pe_info.get('version_info', {})
                    if isinstance(version_info, dict):
                        product_name = version_info.get('ProductName') or version_info.get('product_name')
                        product_version = version_info.get('ProductVersion') or version_info.get('product_version')
                        if product_name:
                            md += f"**PE Product Name:** {product_name}\n"
                        if product_version:
                            md += f"**PE Product Version:** {product_version}\n"
                
                signature_info = file_details.get('signature_info', {})
                if signature_info:
                    md += "**Digital Signature:** Information available\n"
        else:
            md += "No VirusTotal data available.\n"
        
        md += "\n---\n\n## Trust Score Factors\n\n"
        
        # Add trust score factors
        factors = trust.get('factors', {})
        if factors:
            positive_factors = {k: v for k, v in factors.items() if v > 0}
            negative_factors = {k: v for k, v in factors.items() if v < 0}
            
            if positive_factors:
                md += "### Positive Factors\n\n"
                for factor, value in sorted(positive_factors.items(), key=lambda x: x[1], reverse=True):
                    md += f"- **{factor.replace('_', ' ').title()}:** +{value}\n"
                md += "\n"
            
            if negative_factors:
                md += "### Negative Factors\n\n"
                for factor, value in sorted(negative_factors.items(), key=lambda x: x[1]):
                    md += f"- **{factor.replace('_', ' ').title()}:** {value}\n"
                md += "\n"
        else:
            md += "No detailed factors available.\n"
        
        md += "\n---\n\n## Sources & Citations\n\n"
        
        if citations:
            vendor_citations = [c for c in citations if c.get('is_vendor_stated', False)]
            independent_citations = [c for c in citations if not c.get('is_vendor_stated', False)]
            
            if vendor_citations:
                md += "### Vendor-Stated Sources\n\n"
                for citation in vendor_citations:
                    md += f"- **{citation.get('source_type', 'Unknown')}**: [{citation.get('source', 'N/A')}]({citation.get('source', '#')})\n"
                    md += f"  - *{citation.get('claim', 'N/A')}*\n\n"
            
            if independent_citations:
                md += "### Independent Sources\n\n"
                for citation in independent_citations:
                    md += f"- **{citation.get('source_type', 'Unknown')}**: [{citation.get('source', 'N/A')}]({citation.get('source', '#')})\n"
                    md += f"  - *{citation.get('claim', 'N/A')}*\n\n"
        else:
            md += "No citations available.\n"
        
        md += f"\n---\n\n## Report Metadata\n\n"
        md += f"- **Assessment Timestamp:** {assessment_data.get('assessment_timestamp', 'N/A')}\n"
        md += f"- **Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        if assessment_data.get('cache_key'):
            md += f"- **Cache Key:** {assessment_data.get('cache_key')}\n"
        
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
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; line-height: 1.6; background: #f5f5f5; }}
        .container {{ background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid {risk_color}; padding-bottom: 10px; margin-top: 0; }}
        h2 {{ color: #555; margin-top: 30px; border-bottom: 2px solid #ddd; padding-bottom: 5px; }}
        h3 {{ color: #666; margin-top: 20px; }}
        .header-info {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .header-info table {{ margin: 0; }}
        .header-info td {{ border: none; padding: 5px 15px; }}
        .score-box {{ background: {risk_color}; color: white; padding: 30px; border-radius: 8px; text-align: center; margin: 20px 0; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .score-value {{ font-size: 56px; font-weight: bold; margin: 10px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #f2f2f2; font-weight: bold; }}
        .citation {{ margin: 10px 0; padding: 12px; background: #f9f9f9; border-left: 4px solid #007bff; border-radius: 4px; }}
        .vendor-citation {{ border-left-color: #28a745; }}
        .independent-citation {{ border-left-color: #ffc107; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }}
        .section-box {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0; }}
    </style>
</head>
<body>
    <div class="container">
    <h1>Security Assessment Report</h1>
    
    <div class="header-info">
        <table>
            <tr><td><strong>Product:</strong></td><td>{assessment_data.get('entity_name', 'Unknown')}</td></tr>
            <tr><td><strong>Vendor:</strong></td><td>{assessment_data.get('vendor_name', 'Unknown')}</td></tr>
            <tr><td><strong>Category:</strong></td><td>{assessment_data.get('category', 'Unknown')}</td></tr>
            <tr><td><strong>Data Quality:</strong></td><td>{assessment_data.get('data_quality', 'unknown').upper()}</td></tr>
            <tr><td><strong>Generated:</strong></td><td>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
        </table>
    </div>
    
    <div class="score-box">
        <div class="score-value">{score}/100</div>
        <div style="font-size: 28px; margin-top: 10px;">{trust.get('risk_level', 'Unknown')} Risk</div>
        <div style="font-size: 18px; margin-top: 10px; opacity: 0.9;">Confidence: {trust.get('confidence', 0):.1%}</div>
    </div>
    
    <h2>Executive Summary</h2>
    <div class="section-box">
        <p>{trust.get('rationale', 'N/A')}</p>
    </div>
    
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
"""
        
        # Add version-specific CVE information
        detected_version = cve_summary.get('detected_version')
        if detected_version:
            html += f"<tr><td>Detected Version</td><td>{detected_version}</td></tr>"
            html += f"<tr><td>Version-Specific CVEs</td><td>{cve_summary.get('version_specific_cves', 0)}</td></tr>"
            html += f"<tr><td>Version-Specific Critical</td><td>{cve_summary.get('version_specific_critical', 0)}</td></tr>"
            html += f"<tr><td>Version-Specific High</td><td>{cve_summary.get('version_specific_high', 0)}</td></tr>"
        
        html += """    </table>
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
        
        # Add VirusTotal Analysis section
        html += "<h2>VirusTotal Analysis</h2>"
        
        # Try to get VirusTotal data from multiple sources
        collected_data = assessment_data.get('collected_data', {})
        vt = collected_data.get('virustotal') if collected_data else None
        
        # If not available, try to extract from citations
        if not vt:
            for citation in citations:
                if citation.get('source_type') == 'VirusTotal':
                    claim = citation.get('claim', '')
                    html += f"<p><strong>VirusTotal Analysis:</strong> {claim}</p>"
                    break
        
        if vt and vt.get('response_code') == 1:
            positives = vt.get('positives', 0)
            total = vt.get('total', 0)
            malicious = vt.get('malicious', 0)
            suspicious = vt.get('suspicious', 0)
            reputation = vt.get('reputation', 0)
            risk_level = vt.get('risk_level', 'unknown')
            risk_confidence = vt.get('risk_confidence', 0.5)
            
            html += f"<p><strong>Detection Rate:</strong> {positives}/{total} engines flagged ({malicious} malicious, {suspicious} suspicious)<br>"
            html += f"<strong>Reputation Score:</strong> {reputation}<br>"
            html += f"<strong>Risk Level:</strong> {risk_level} ({int(risk_confidence*100)}% confidence)</p>"
            
            # Executable name
            exe_name = vt.get('exe_name')
            if exe_name:
                html += f"<p><strong>Executable Name:</strong> {exe_name}</p>"
            
            # Detected version
            detected_version = vt.get('detected_version')
            if detected_version:
                version_confidence = vt.get('version_confidence', 0.0)
                html += f"<p><strong>Detected Version:</strong> {detected_version} (confidence: {int(version_confidence*100)}%)</p>"
            
            # Community notes
            community_notes = vt.get('community_notes', [])
            if community_notes:
                html += f"<h3>Community Notes ({len(community_notes)} available)</h3>"
                for i, note in enumerate(community_notes[:10], 1):
                    note_text = note.get('text', '')
                    note_date = note.get('date', 0)
                    note_author = note.get('author', '')
                    if note_text:
                        html += f'<div class="citation" style="margin: 15px 0;">'
                        html += f'<strong>Note {i}</strong>'
                        if note_author:
                            html += f' <em>by {note_author}</em>'
                        if note_date:
                            try:
                                date_str = datetime.fromtimestamp(note_date).strftime('%Y-%m-%d')
                                html += f' <em>({date_str})</em>'
                            except:
                                pass
                        html += f'<br>{note_text[:500]}{"..." if len(note_text) > 500 else ""}</div>'
            
            # Submission history
            submission_history = vt.get('submission_history', [])
            if submission_history:
                html += f"<h3>Submission History ({len(submission_history)} entries)</h3>"
                html += "<table><tr><th>#</th><th>Date</th><th>File Names</th></tr>"
                for i, submission in enumerate(submission_history[:5], 1):
                    sub_date = submission.get('date', 0)
                    sub_names = submission.get('submission_names', [])
                    date_str = ""
                    if sub_date:
                        try:
                            date_str = datetime.fromtimestamp(sub_date).strftime('%Y-%m-%d')
                        except:
                            pass
                    names_str = ', '.join(sub_names[:5]) if sub_names else 'N/A'
                    html += f"<tr><td>{i}</td><td>{date_str}</td><td>{names_str}</td></tr>"
                html += "</table>"
            
            # File details
            file_details = vt.get('file_details', {})
            if file_details:
                html += "<h3>File Details</h3>"
                pe_info = file_details.get('pe_info', {})
                if pe_info and isinstance(pe_info, dict):
                    version_info = pe_info.get('version_info', {})
                    if isinstance(version_info, dict):
                        product_name = version_info.get('ProductName') or version_info.get('product_name')
                        product_version = version_info.get('ProductVersion') or version_info.get('product_version')
                        if product_name or product_version:
                            html += "<p>"
                            if product_name:
                                html += f"<strong>PE Product Name:</strong> {product_name}<br>"
                            if product_version:
                                html += f"<strong>PE Product Version:</strong> {product_version}<br>"
                            html += "</p>"
                
                signature_info = file_details.get('signature_info', {})
                if signature_info:
                    html += "<p><strong>Digital Signature:</strong> Information available</p>"
        else:
            html += "<p>No VirusTotal data available.</p>"
        
        # Add Trust Score Factors
        html += "<h2>Trust Score Factors</h2>"
        factors = trust.get('factors', {})
        if factors:
            positive_factors = {k: v for k, v in factors.items() if v > 0}
            negative_factors = {k: v for k, v in factors.items() if v < 0}
            
            if positive_factors:
                html += "<h3>Positive Factors</h3><ul>"
                for factor, value in sorted(positive_factors.items(), key=lambda x: x[1], reverse=True):
                    html += f"<li><strong>{factor.replace('_', ' ').title()}:</strong> +{value}</li>"
                html += "</ul>"
            
            if negative_factors:
                html += "<h3>Negative Factors</h3><ul>"
                for factor, value in sorted(negative_factors.items(), key=lambda x: x[1]):
                    html += f"<li><strong>{factor.replace('_', ' ').title()}:</strong> {value}</li>"
                html += "</ul>"
        else:
            html += "<p>No detailed factors available.</p>"
        
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
        <h3>Report Metadata</h3>
        <p><strong>Assessment Timestamp:</strong> {assessment_data.get('assessment_timestamp', 'N/A')}<br>
        <strong>Report Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>"""
        
        if assessment_data.get('cache_key'):
            html += f"<strong>Cache Key:</strong> {assessment_data.get('cache_key')}<br>"
        
        html += """</p>
    </div>
    </div>
</body>
</html>"""
        
        return html

