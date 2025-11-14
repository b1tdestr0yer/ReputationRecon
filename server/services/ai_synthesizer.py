import os
from typing import Dict, List, Optional, Any
from datetime import datetime
from server.dtos.AssessmentResponse import (
    SecurityPosture, Citation, CVESummary, TrustScore, Alternative, SoftwareCategory
)


class AISynthesizer:
    """AI-powered synthesis engine with citation tracking"""
    
    def __init__(self):
        # In production, you'd use OpenAI, Anthropic, or similar
        # For now, we'll create a structured synthesis
        self.openai_api_key = os.getenv("OPENAI_API_KEY")
        self.use_ai = bool(self.openai_api_key)
    
    async def synthesize_security_posture(
        self,
        entity_name: str,
        vendor_name: str,
        category: SoftwareCategory,
        collected_data: Dict[str, Any]
    ) -> SecurityPosture:
        """Synthesize security posture from collected data"""
        print(f"[AI Synthesizer] Synthesizing security posture for {entity_name} ({vendor_name})")
        
        # Extract information from collected data
        print(f"[AI Synthesizer] Extracting description...")
        description = self._extract_description(collected_data)
        print(f"[AI Synthesizer] Extracting usage...")
        usage = self._extract_usage(collected_data, category)
        print(f"[AI Synthesizer] Extracting vendor reputation...")
        vendor_reputation = self._extract_vendor_reputation(collected_data)
        print(f"[AI Synthesizer] Extracting CVE summary...")
        cve_summary = self._extract_cve_summary(collected_data)
        print(f"[AI Synthesizer] Extracting incidents...")
        incidents = self._extract_incidents(collected_data)
        print(f"[AI Synthesizer] Extracting data handling info...")
        data_handling = self._extract_data_handling(collected_data)
        print(f"[AI Synthesizer] Extracting deployment controls...")
        deployment = self._extract_deployment_controls(collected_data)
        print(f"[AI Synthesizer] Extracting citations...")
        citations = self._extract_citations(collected_data)
        print(f"[AI Synthesizer] ✓ Extracted {len(citations)} citations")
        
        return SecurityPosture(
            description=description,
            usage=usage,
            vendor_reputation=vendor_reputation,
            cve_summary=cve_summary,
            incidents_abuse=incidents,
            data_handling=data_handling,
            deployment_controls=deployment,
            citations=citations
        )
    
    def _extract_description(self, data: Dict) -> str:
        """Extract product description"""
        vendor_page = data.get("vendor_page")
        vt_data = data.get("virustotal")
        
        description_parts = []
        
        if vendor_page and vendor_page.get("content"):
            content = vendor_page["content"].lower()
            # Try to extract meaningful description
            if "about" in content or "product" in content or "solution" in content:
                description_parts.append("Product information available from vendor website.")
        
        if vt_data and vt_data.get("response_code") == 1:
            # VirusTotal has info about the file
            scan_date = vt_data.get("scan_date", "")
            positives = vt_data.get("positives", 0)
            total = vt_data.get("total", 0)
            if positives > 0:
                description_parts.append(f"File analysis: {positives}/{total} security vendors flagged this file as potentially malicious (scan date: {scan_date}).")
            else:
                description_parts.append(f"File analysis: No security vendors flagged this file (scan date: {scan_date}).")
        
        if not description_parts:
            return "Limited public information available. Consider providing a URL or hash for more detailed analysis."
        
        return " ".join(description_parts)
    
    def _extract_usage(self, data: Dict, category: SoftwareCategory) -> str:
        """Extract usage information"""
        return f"Primary use case: {category.value}. Additional usage details from vendor documentation."
    
    def _extract_vendor_reputation(self, data: Dict) -> str:
        """Extract vendor reputation"""
        incidents = data.get("incidents", [])
        cve_data = data.get("cves", {})
        cisa_kev = data.get("cisa_kev", [])
        vt_data = data.get("virustotal")
        
        info_parts = []
        
        # CVE information
        total_cves = cve_data.get("total_cves", 0)
        critical_cves = cve_data.get("critical_count", 0)
        if total_cves > 0:
            if critical_cves > 0:
                info_parts.append(f"Security posture: {total_cves} CVEs found, including {critical_cves} critical vulnerabilities.")
            else:
                info_parts.append(f"Security posture: {total_cves} CVEs documented.")
        
        # CISA KEV
        if len(cisa_kev) > 0:
            info_parts.append(f"CRITICAL: {len(cisa_kev)} vulnerabilities in CISA Known Exploited Vulnerabilities catalog.")
        
        # VirusTotal reputation
        if vt_data and vt_data.get("response_code") == 1:
            positives = vt_data.get("positives", 0)
            if positives > 0:
                info_parts.append(f"File reputation: Flagged by {positives} security vendors.")
        
        # Incidents
        if incidents:
            info_parts.append(f"{len(incidents)} documented security incidents found.")
        
        if not info_parts:
            return "Limited public information on vendor reputation. No significant security issues found in available sources."
        
        return " ".join(info_parts)
    
    def _extract_cve_summary(self, data: Dict) -> CVESummary:
        """Extract CVE summary"""
        cve_data = data.get("cves", {})
        cisa_kev = data.get("cisa_kev", [])
        
        return CVESummary(
            total_cves=cve_data.get("total_cves", 0),
            critical_count=cve_data.get("critical_count", 0),
            high_count=cve_data.get("high_count", 0),
            recent_trend="unknown",
            cisa_kev_count=len(cisa_kev),
            recent_cves=cve_data.get("recent_cves", [])
        )
    
    def _extract_incidents(self, data: Dict) -> str:
        """Extract incidents and abuse signals"""
        incidents = data.get("incidents", [])
        if incidents:
            return f"Found {len(incidents)} documented security incidents or abuse cases."
        return "No significant public incidents or abuse signals found in available sources."
    
    def _extract_data_handling(self, data: Dict) -> str:
        """Extract data handling and compliance information"""
        tos = data.get("terms_of_service")
        vendor_page = data.get("vendor_page")
        
        info_parts = []
        
        if tos and tos.get("content"):
            content = tos["content"].lower()
            compliance_info = []
            
            if "gdpr" in content or "general data protection" in content:
                compliance_info.append("GDPR")
            if "soc 2" in content or "soc2" in content:
                compliance_info.append("SOC 2")
            if "iso 27001" in content or "iso27001" in content:
                compliance_info.append("ISO 27001")
            if "hipaa" in content:
                compliance_info.append("HIPAA")
            if "data processing agreement" in content or "dpa" in content:
                compliance_info.append("DPA available")
            
            if compliance_info:
                info_parts.append(f"Compliance certifications mentioned: {', '.join(compliance_info)}.")
            else:
                info_parts.append("Terms of Service available for review.")
        
        if vendor_page and vendor_page.get("content"):
            content = vendor_page["content"].lower()
            if "encryption" in content:
                info_parts.append("Encryption mentioned in security documentation.")
            if "data residency" in content or "data location" in content:
                info_parts.append("Data residency/location information available.")
        
        if not info_parts:
            return "Data handling and compliance information not found in public sources. Contact vendor directly for details."
        
        return " ".join(info_parts)
    
    def _extract_deployment_controls(self, data: Dict) -> str:
        """Extract deployment and admin controls"""
        security_page = data.get("vendor_page")
        info_parts = []
        
        if security_page and security_page.get("content"):
            content = security_page["content"].lower()
            
            if "sso" in content or "single sign-on" in content:
                info_parts.append("SSO support mentioned.")
            if "mfa" in content or "multi-factor" in content or "2fa" in content:
                info_parts.append("Multi-factor authentication available.")
            if "role-based" in content or "rbac" in content:
                info_parts.append("Role-based access control mentioned.")
            if "api" in content and "key" in content:
                info_parts.append("API key management available.")
            if "audit log" in content or "auditing" in content:
                info_parts.append("Audit logging capabilities mentioned.")
        
        if info_parts:
            return " ".join(info_parts) + " Review vendor security documentation for complete details."
        
        return "Deployment and admin control details not found in public sources. Contact vendor for specific controls."
    
    def _extract_citations(self, data: Dict) -> List[Citation]:
        """Extract all citations from collected data"""
        citations = []
        
        if data.get("vendor_page"):
            citations.append(Citation(
                source=data["vendor_page"].get("url", ""),
                source_type="vendor",
                claim="Vendor security information",
                is_vendor_stated=True,
                timestamp=datetime.now()
            ))
        
        if data.get("terms_of_service"):
            citations.append(Citation(
                source=data["terms_of_service"].get("url", ""),
                source_type="vendor",
                claim="Terms of Service and data handling",
                is_vendor_stated=True,
                timestamp=datetime.now()
            ))
        
        cisa_kev = data.get("cisa_kev", [])
        for kev in cisa_kev:
            citations.append(Citation(
                source="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                source_type="CISA",
                claim=f"Known exploited vulnerability: {kev.get('cveID', '')}",
                is_vendor_stated=False,
                timestamp=datetime.now()
            ))
        
        return citations
    
    async def calculate_trust_score(
        self,
        security_posture: SecurityPosture,
        collected_data: Dict
    ) -> TrustScore:
        """Calculate trust score (0-100) with rationale"""
        print(f"[AI Synthesizer] Calculating trust score...")
        
        factors = {}
        score = 50  # Start at neutral
        print(f"[AI Synthesizer] Starting score: {score}/100")
        
        # Factor 1: CVE count (negative impact)
        cve_total = security_posture.cve_summary.total_cves
        if cve_total > 50:
            factors["cve_count"] = -20
            score -= 20
        elif cve_total > 20:
            factors["cve_count"] = -10
            score -= 10
        elif cve_total > 0:
            factors["cve_count"] = -5
            score -= 5
        
        # Factor 2: CISA KEV (critical negative)
        if security_posture.cve_summary.cisa_kev_count > 0:
            factors["cisa_kev"] = -30
            score -= 30
        
        # Factor 3: Critical CVEs
        if security_posture.cve_summary.critical_count > 5:
            factors["critical_cves"] = -15
            score -= 15
        elif security_posture.cve_summary.critical_count > 0:
            factors["critical_cves"] = -10
            score -= 10
        
        # Factor 4: Incidents
        if "incidents" in security_posture.incidents_abuse.lower():
            factors["incidents"] = -10
            score -= 10
        
        # Factor 5: Vendor transparency (positive)
        vendor_citations = [c for c in security_posture.citations if c.is_vendor_stated]
        if len(vendor_citations) >= 2:
            factors["vendor_transparency"] = 10
            score += 10
        
        # Factor 6: Data handling info available
        if "insufficient" not in security_posture.data_handling.lower():
            factors["data_handling"] = 5
            score += 5
        
        # Clamp score to 0-100
        score = max(0, min(100, score))
        
        # Determine risk level
        if score >= 80:
            risk_level = "Low"
        elif score >= 60:
            risk_level = "Medium"
        elif score >= 40:
            risk_level = "High"
        else:
            risk_level = "Critical"
        
        # Calculate confidence based on data quality
        citation_count = len(security_posture.citations)
        if citation_count >= 5:
            confidence = 0.9
        elif citation_count >= 3:
            confidence = 0.7
        elif citation_count >= 1:
            confidence = 0.5
        else:
            confidence = 0.3
        
        rationale = self._generate_rationale(score, risk_level, factors, security_posture)
        
        print(f"[AI Synthesizer] Trust score calculation complete:")
        print(f"  - Final score: {score}/100")
        print(f"  - Risk level: {risk_level}")
        print(f"  - Confidence: {confidence:.1%}")
        print(f"  - Factors: {len(factors)} contributing factors")
        
        return TrustScore(
            score=score,
            risk_level=risk_level,
            confidence=confidence,
            rationale=rationale,
            factors=factors
        )
    
    def _generate_rationale(self, score: int, risk_level: str, 
                           factors: Dict, posture: SecurityPosture) -> str:
        """Generate rationale for the trust score"""
        parts = [f"Trust Score: {score}/100 ({risk_level} Risk)"]
        
        if factors.get("cisa_kev", 0) < 0:
            parts.append(f"Critical: {posture.cve_summary.cisa_kev_count} CVE(s) in CISA KEV catalog.")
        
        if posture.cve_summary.critical_count > 0:
            parts.append(f"Found {posture.cve_summary.critical_count} critical CVEs.")
        
        if posture.cve_summary.total_cves > 0:
            parts.append(f"Total CVEs: {posture.cve_summary.total_cves}.")
        
        if factors.get("vendor_transparency", 0) > 0:
            parts.append("Vendor provides security documentation.")
        
        return " ".join(parts)
    
    async def suggest_alternatives(
        self,
        category: SoftwareCategory,
        entity_name: str
    ) -> List[Alternative]:
        """Suggest safer alternatives"""
        print(f"[AI Synthesizer] Suggesting alternatives for category: {category.value}")
        # Category-based alternatives (simplified)
        alternatives_map = {
            SoftwareCategory.FILE_SHARING: [
                Alternative(
                    name="Nextcloud",
                    vendor="Nextcloud GmbH",
                    rationale="Open-source, self-hostable alternative with strong security focus and regular security audits.",
                    trust_score=85
                )
            ],
            SoftwareCategory.COLLABORATION: [
                Alternative(
                    name="Element",
                    vendor="Element",
                    rationale="Open-source, end-to-end encrypted collaboration platform with self-hosting options.",
                    trust_score=80
                )
            ],
            SoftwareCategory.GENAI_TOOL: [
                Alternative(
                    name="Self-hosted LLM",
                    vendor="Various",
                    rationale="Self-hosted open-source LLM solutions provide better data control and privacy.",
                    trust_score=75
                )
            ]
        }
        
        alternatives = alternatives_map.get(category, [])
        print(f"[AI Synthesizer] ✓ Found {len(alternatives)} alternatives")
        return alternatives

