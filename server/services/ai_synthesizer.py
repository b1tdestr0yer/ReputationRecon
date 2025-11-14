import os
import json
import re
from datetime import datetime
from typing import Dict, List, Optional, Any

import google.generativeai as genai
from dotenv import load_dotenv

from server.dtos.AssessmentResponse import (
    SecurityPosture, Citation, CVESummary, TrustScore, Alternative, SoftwareCategory
)

load_dotenv()


class AISynthesizer:
    """Clean, deterministic, predictable Gemini-based synthesis."""

    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        if api_key:
            genai.configure(api_key=api_key)
            # Use gemini-2.5-flash (faster) or gemini-2.5-pro (more capable)
            try:
                self.model = genai.GenerativeModel('gemini-2.5-flash')
                self.use_ai = True
                print("[AI Synthesizer] ✓ Google Gemini configured for AI-powered synthesis (using gemini-2.5-flash)")
            except Exception as e:
                print(f"[AI Synthesizer] ⚠ Error initializing gemini-2.5-flash: {e}, trying gemini-2.5-pro")
                try:
                    self.model = genai.GenerativeModel('gemini-2.5-pro')
                    self.use_ai = True
                    print("[AI Synthesizer] ✓ Google Gemini configured (using gemini-2.5-pro)")
                except Exception as e2:
                    print(f"[AI Synthesizer] ✗ Error initializing Gemini models: {e2}, using basic synthesis")
                    self.model = None
                    self.use_ai = False
        else:
            self.model = None
            self.use_ai = False

    # -------------------------------------------------------------------------
    # MAIN SYNTHESIS METHOD
    # -------------------------------------------------------------------------
    async def synthesize_security_posture(
        self,
        entity_name: str,
        vendor_name: str,
        category: SoftwareCategory,
        collected_data: Dict[str, Any]
    ) -> SecurityPosture:
        """Synthesize security posture from collected data"""
        print(f"[AI Synthesizer] Synthesizing security posture for {entity_name} ({vendor_name})")
        
        # Add entity/vendor names to collected_data for use in extraction methods
        collected_data["entity_name"] = entity_name
        collected_data["vendor_name"] = vendor_name
        
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

    # -------------------------------------------------------------------------
    # DESCRIPTION
    # -------------------------------------------------------------------------
    def _extract_description(self, data: Dict) -> str:
        """Extract product description using AI with all available context"""
        entity_name = data.get("entity_name", "the product")
        vendor_name = data.get("vendor_name", "the vendor")
        vendor_page = data.get("vendor_page") or {}
        tos = data.get("terms_of_service") or {}
        content = ""
        
        if vendor_page and vendor_page.get("content"):
            content += f"Vendor page content:\n{vendor_page.get('content', '')[:3000]}\n\n"
        if tos and tos.get("content"):
            content += f"Terms of Service content:\n{tos.get('content', '')[:2000]}\n\n"
        
        # Use AI to generate description from available data
        if self.use_ai and self.model:
            try:
                prompt = f"""You are a security analyst writing a CISO-ready brief. Write a concise 2-3 sentence description of what this software product DOES based on available information.

Product: {entity_name}
Vendor: {vendor_name}

Available information:
{content if content else "Limited public information available."}

Rules:
- Focus on product functionality and primary use cases
- Use professional, security-assessment tone
- If information is limited, state that clearly
- Be factual and avoid speculation

Write the description:"""

                resp = self.model.generate_content(prompt)
                result = resp.text.strip()
                if result and len(result) > 20:  # Ensure we got a real response
                    print(f"[AI Synthesizer] ✓ Generated description using AI")
                    return result
            except Exception as e:
                print(f"[AI Synthesizer] ⚠ Error generating description with AI: {e}")

        # Fallback
        if content:
            return f"{entity_name} is a software product by {vendor_name}. Product description available from vendor documentation."
        return f"Insufficient public evidence for detailed description of {entity_name}."


    # -------------------------------------------------------------------------
    # USAGE
    # -------------------------------------------------------------------------
    def _extract_usage(self, data: Dict, category: SoftwareCategory) -> str:
        """Extract usage information using AI"""
        entity_name = data.get("entity_name", "the product")
        vendor_name = data.get("vendor_name", "the vendor")
        vendor_page = data.get("vendor_page") or {}
        content = vendor_page.get("content", "") if vendor_page else ""

        if self.use_ai and self.model:
            try:
                prompt = f"""You are a security analyst. Describe how this product is typically used, in 2-3 sentences.

Product: {entity_name}
Vendor: {vendor_name}
Category: {category.value}

Vendor information:
{content[:3000] if content else "Limited vendor information available."}

Focus on:
- Realistic usage patterns
- Typical deployment scenarios
- Primary use cases
- Target user base

If information is limited, state that clearly. Write the usage description:"""

                resp = self.model.generate_content(prompt)
                result = resp.text.strip()
                if result and len(result) > 20:
                    print(f"[AI Synthesizer] ✓ Generated usage description using AI")
                    return result
            except Exception as e:
                print(f"[AI Synthesizer] ⚠ Error generating usage with AI: {e}")

        # Fallback
        return (
            f"{entity_name} is classified as a '{category.value}' product. "
            "Insufficient public evidence for detailed usage patterns."
        )


    # -------------------------------------------------------------------------
    # VENDOR REPUTATION
    # -------------------------------------------------------------------------
    def _extract_vendor_reputation(self, data: Dict) -> str:
        """Extract vendor reputation using all available security signals"""
        entity_name = data.get("entity_name", "the product")
        vendor_name = data.get("vendor_name", "the vendor")
        cves = data.get("cves") or {}
        incidents = data.get("incidents") or []
        kev = data.get("cisa_kev") or []
        vt = data.get("virustotal")

        # Build comprehensive summary
        indicators = []
        total = cves.get("total_cves", 0) if cves else 0
        critical = cves.get("critical_count", 0) if cves else 0
        high = cves.get("high_count", 0) if cves else 0

        if total > 0:
            indicators.append(f"Total CVEs: {total} ({critical} critical, {high} high severity)")
        if kev and len(kev) > 0:
            indicators.append(f"CISA KEV entries: {len(kev)} (actively exploited vulnerabilities)")
        if incidents and len(incidents) > 0:
            indicators.append(f"Documented security incidents: {len(incidents)}")
        if vt:
            positives = vt.get("positives", 0)
            total_scans = vt.get("total", 0)
            if positives > 0:
                indicators.append(f"VirusTotal: {positives}/{total_scans} security vendors flagged this file")
            elif total_scans > 0:
                indicators.append(f"VirusTotal: 0/{total_scans} vendors flagged (clean scan)")

        if self.use_ai and self.model:
            try:
                prompt = f"""You are a security analyst writing a CISO-ready brief. Summarize vendor security reputation in 2-3 sentences based ONLY on factual security indicators.

Vendor: {vendor_name}
Product: {entity_name}

Security Indicators:
{chr(10).join(indicators) if indicators else "No security indicators found in public databases."}

Rules:
- Be factual and evidence-based
- If indicators are positive (few CVEs, no KEV entries, clean VirusTotal), note that
- If indicators are concerning (many CVEs, KEV entries, VirusTotal flags), state clearly
- If data is very limited, explicitly state "Insufficient public evidence"
- Do NOT overstate reputation without strong evidence
- Mention specific numbers when available

Write the vendor reputation summary:"""

                resp = self.model.generate_content(prompt)
                result = resp.text.strip()
                if result and len(result) > 30:
                    print(f"[AI Synthesizer] ✓ Generated vendor reputation using AI")
                    return result
            except Exception as e:
                print(f"[AI Synthesizer] ⚠ Error generating vendor reputation with AI: {e}")

        # Fallback
        if indicators:
            return f"Security indicators for {vendor_name}: {'; '.join(indicators)}"
        return f"Insufficient public evidence for comprehensive assessment of {vendor_name}'s security reputation."


    # -------------------------------------------------------------------------
    # CVE SUMMARY
    # -------------------------------------------------------------------------
    def _extract_cve_summary(self, data: Dict) -> CVESummary:
        cves = data.get("cves") or {}
        kev = data.get("cisa_kev") or []
        return CVESummary(
            total_cves=cves.get("total_cves", 0) if cves else 0,
            critical_count=cves.get("critical_count", 0) if cves else 0,
            high_count=cves.get("high_count", 0) if cves else 0,
            recent_trend="unknown",
            cisa_kev_count=len(kev) if kev else 0,
            recent_cves=cves.get("recent_cves", []) if cves else []
        )


    # -------------------------------------------------------------------------
    # INCIDENTS
    # -------------------------------------------------------------------------
    def _extract_incidents(self, data: Dict) -> str:
        incidents = data.get("incidents") or []
        kev = data.get("cisa_kev") or []
        cves = data.get("cves") or {}

        context = []
        if kev:
            context.append(f"{len(kev)} KEV vulnerabilities (active exploitation)")
        if incidents:
            context.append(f"{len(incidents)} public incidents")
        if cves and cves.get("critical_count", 0):
            context.append(f"{cves.get('critical_count')} critical CVEs")

        if self.use_ai and self.model and context:
            try:
                prompt = f"""
Write a **2–3 sentence** summary of security incidents & abuse signals.

Data:
{chr(10).join(context)}

Rules:
- If findings are severe, state it clearly.
- If limited, say visibility is limited.
"""
                resp = self.model.generate_content(prompt)
                return resp.text.strip()
            except Exception:
                pass

        if incidents:
            return f"{len(incidents)} documented security incidents."
        if kev:
            return f"{len(kev)} KEV vulnerabilities, indicating active exploitation."
        return "No significant public incident data found."


    # -------------------------------------------------------------------------
    # DATA HANDLING
    # -------------------------------------------------------------------------
    def _extract_data_handling(self, data: Dict) -> str:
        """Extract data handling and compliance information"""
        entity_name = data.get("entity_name", "the product")
        tos = data.get("terms_of_service") or {}
        vendor = data.get("vendor_page") or {}

        content = ""
        if tos and tos.get("content"):
            content += f"Terms of Service:\n{tos['content'][:3000]}\n\n"
        if vendor and vendor.get("content"):
            content += f"Vendor Security Page:\n{vendor['content'][:3000]}"

        if self.use_ai and self.model:
            try:
                prompt = f"""You are a security analyst. Extract data-handling & compliance information in 2-3 sentences.

Product: {entity_name}

Look for and mention:
- GDPR compliance
- SOC 2 Type II
- ISO 27001
- HIPAA
- Encryption standards
- Data residency/geographic restrictions
- Data Processing Agreements (DPAs)
- Privacy certifications

Vendor documentation:
{content if content else "No vendor documentation available."}

Rules:
- Only state compliance if explicitly mentioned
- If information is limited, state "Insufficient public evidence"
- Be specific about what certifications/standards are mentioned
- Use professional security-assessment tone

Write the data handling summary:"""

                resp = self.model.generate_content(prompt)
                result = resp.text.strip()
                if result and len(result) > 30:
                    print(f"[AI Synthesizer] ✓ Generated data handling info using AI")
                    return result
            except Exception as e:
                print(f"[AI Synthesizer] ⚠ Error generating data handling with AI: {e}")

        # Fallback keyword search
        if content:
            low = content.lower()
            mentions = []
            compliance_map = {
                "gdpr": "GDPR",
                "soc 2": "SOC 2",
                "iso 27001": "ISO 27001",
                "iso27001": "ISO 27001",
                "hipaa": "HIPAA",
                "encryption": "Encryption",
                "dpa": "Data Processing Agreement"
            }
            for keyword, label in compliance_map.items():
                if keyword in low:
                    mentions.append(label)
            
            if mentions:
                return f"Compliance-related mentions found: {', '.join(set(mentions))}. Insufficient public evidence for comprehensive data handling assessment."
        
        return f"Insufficient public evidence for data handling and compliance details for {entity_name}."


    # -------------------------------------------------------------------------
    # DEPLOYMENT CONTROLS
    # -------------------------------------------------------------------------
    def _extract_deployment_controls(self, data: Dict) -> str:
        page = data.get("vendor_page") or {}
        content = page.get("content") if page else None

        if self.use_ai and self.model and content:
            try:
                prompt = f"""
Extract deployment/admin controls in 2–3 sentences.

Look for:
- SSO, MFA/2FA
- RBAC
- API key management
- Audit logging

Vendor text:
{content[:4000]}
"""
                resp = self.model.generate_content(prompt)
                return resp.text.strip()
            except Exception:
                pass

        if not content:
            return "No deployment-control information found."

        low = content.lower() if content else ""
        out = []

        if "sso" in low or "single sign-on" in low:
            out.append("SSO supported.")
        if "mfa" in low or "2fa" in low or "multi-factor" in low:
            out.append("MFA available.")
        if "role-based" in low or "rbac" in low:
            out.append("RBAC supported.")
        if "api key" in low:
            out.append("API key management present.")
        if "audit" in low:
            out.append("Audit logging available.")

        return " ".join(out) if out else "No specific deployment-control claims found."


    # -------------------------------------------------------------------------
    # CITATIONS
    # -------------------------------------------------------------------------
    def _extract_citations(self, data: Dict) -> List[Citation]:
        """Extract all citations from collected data"""
        cites = []

        vendor_page = data.get("vendor_page")
        if vendor_page and vendor_page.get("url"):
            cites.append(Citation(
                source=vendor_page.get("url", ""),
                source_type="vendor",
                claim="Vendor security documentation",
                is_vendor_stated=True,
                timestamp=datetime.now()
            ))

        terms_of_service = data.get("terms_of_service")
        if terms_of_service and terms_of_service.get("url"):
            cites.append(Citation(
                source=terms_of_service.get("url", ""),
                source_type="vendor",
                claim="Terms of Service / Privacy Policy",
                is_vendor_stated=True,
                timestamp=datetime.now()
            ))

        # Add CVE citations
        cves = data.get("cves") or {}
        if cves and cves.get("total_cves", 0) > 0:
            cites.append(Citation(
                source="NVD (National Vulnerability Database)",
                source_type="CVE",
                claim=f"{cves.get('total_cves', 0)} CVE(s) found",
                is_vendor_stated=False,
                timestamp=datetime.now()
            ))

        # Add CISA KEV citations
        kev_list = data.get("cisa_kev") or []
        for kev in kev_list:
            if kev and kev.get("cveID"):
                cites.append(Citation(
                    source="CISA KEV (Known Exploited Vulnerabilities)",
                    source_type="CISA",
                    claim=f"KEV Entry: {kev.get('cveID', 'Unknown')}",
                    is_vendor_stated=False,
                    timestamp=datetime.now()
                ))

        # Add VirusTotal citation if available
        vt = data.get("virustotal")
        if vt and vt.get("response_code") == 1:
            positives = vt.get("positives", 0)
            total = vt.get("total", 0)
            cites.append(Citation(
                source="VirusTotal",
                source_type="independent",
                claim=f"File analysis: {positives}/{total} vendors flagged",
                is_vendor_stated=False,
                timestamp=datetime.now()
            ))

        return cites


    # -------------------------------------------------------------------------
    # TRUST SCORE (same logic, but cleaned)
    # -------------------------------------------------------------------------
    async def calculate_trust_score(
        self, security_posture: SecurityPosture, collected_data: Dict
    ) -> TrustScore:
        """Calculate trust score with more nuanced logic"""
        # Start with a neutral score that reflects limited data
        score = 60  # Start higher to account for "unknown" not being "bad"
        factors = {}

        cve = security_posture.cve_summary
        vt = collected_data.get("virustotal")

        # CVE impact (negative factors)
        if cve.total_cves > 50:
            score -= 25
            factors["high_cve_count"] = -25
        elif cve.total_cves > 20:
            score -= 15
            factors["moderate_cve_count"] = -15
        elif cve.total_cves > 5:
            score -= 8
            factors["some_cves"] = -8
        elif cve.total_cves > 0:
            score -= 3
            factors["few_cves"] = -3
        else:
            # No CVEs is actually positive (but don't over-weight it)
            factors["no_cves"] = +5
            score += 5

        # CISA KEV is very serious
        if cve.cisa_kev_count > 0:
            score -= 35
            factors["cisa_kev"] = -35

        # Critical CVEs are concerning
        if cve.critical_count > 5:
            score -= 20
            factors["many_critical_cves"] = -20
        elif cve.critical_count > 0:
            score -= 10
            factors["critical_cves"] = -10

        # VirusTotal analysis
        if vt and vt.get("response_code") == 1:
            positives = vt.get("positives", 0)
            total = vt.get("total", 0)
            if positives == 0 and total > 0:
                # Clean scan is positive
                score += 8
                factors["clean_virustotal"] = +8
            elif positives > 0:
                # Flagged by vendors is negative
                flag_ratio = positives / total if total > 0 else 0
                if flag_ratio > 0.1:  # More than 10% flagged
                    score -= 25
                    factors["virustotal_flagged"] = -25
                else:
                    score -= 10
                    factors["virustotal_suspicious"] = -10

        # Positive factors
        if len(security_posture.citations) >= 5:
            score += 12
            factors["high_transparency"] = +12
        elif len(security_posture.citations) >= 3:
            score += 8
            factors["good_transparency"] = +8
        elif len(security_posture.citations) >= 1:
            score += 3
            factors["some_transparency"] = +3

        # Data handling information available
        data_handling_lower = security_posture.data_handling.lower()
        if "insufficient" not in data_handling_lower and "no publicly available" not in data_handling_lower:
            if any(term in data_handling_lower for term in ["gdpr", "soc 2", "iso", "compliance"]):
                score += 10
                factors["compliance_info"] = +10
            else:
                score += 5
                factors["data_handling_info"] = +5

        # Deployment controls mentioned
        if "insufficient" not in security_posture.deployment_controls.lower() and len(security_posture.deployment_controls) > 50:
            score += 5
            factors["deployment_controls"] = +5

        # Clamp score
        score = max(0, min(100, score))

        # Risk level
        if score >= 75:
            level = "Low"
        elif score >= 55:
            level = "Medium"
        elif score >= 35:
            level = "High"
        else:
            level = "Critical"

        # Confidence based on data quality
        cites = len(security_posture.citations)
        has_vt = vt and vt.get("response_code") == 1
        has_cves = cve.total_cves > 0
        has_vendor_info = any("vendor" in c.source_type.lower() for c in security_posture.citations)
        
        if cites >= 5 and (has_vt or has_cves) and has_vendor_info:
            conf = 0.85
        elif cites >= 3 and (has_vt or has_cves):
            conf = 0.70
        elif cites >= 2:
            conf = 0.55
        elif cites >= 1:
            conf = 0.40
        else:
            conf = 0.25

        # Build rationale
        factor_summary = []
        for key, value in sorted(factors.items(), key=lambda x: abs(x[1]), reverse=True)[:5]:
            sign = "+" if value > 0 else ""
            factor_summary.append(f"{key}: {sign}{value}")
        
        rationale = f"Trust score: {score}/100 ({level} risk). Key factors: {', '.join(factor_summary)}. Confidence: {conf:.0%} based on {cites} data sources."

        return TrustScore(
            score=score,
            risk_level=level,
            confidence=conf,
            rationale=rationale,
            factors=factors
        )


    # -------------------------------------------------------------------------
    # ALTERNATIVES
    # -------------------------------------------------------------------------
    async def suggest_alternatives(self, category: SoftwareCategory, entity_name: str) -> List[Alternative]:
        if self.use_ai and self.model:
            try:
                prompt = f"""
Suggest **1–2 reputable alternatives** for:

Category: {category.value}
Product: {entity_name}

Return JSON with:
- name
- vendor
- rationale (security focused)
- trust_score (0-100)
"""
                resp = self.model.generate_content(prompt)
                t = resp.text

                # Extract JSON
                m = re.search(r"\{.*\}", t, re.DOTALL)
                if m:
                    data = json.loads(m.group(0))
                    out = []
                    for alt in data.get("alternatives", [])[:2]:
                        out.append(Alternative(
                            name=alt.get("name", "Unknown"),
                            vendor=alt.get("vendor", "Unknown"),
                            rationale=alt.get("rationale", ""),
                            trust_score=alt.get("trust_score", 60)
                        ))
                    return out
            except Exception:
                pass

        # fallback
        defaults = {
            SoftwareCategory.FILE_SHARING: [
                Alternative(
                    name="Nextcloud",
                    vendor="Nextcloud GmbH",
                    rationale="Open-source, self-hosted, strong security posture.",
                    trust_score=85
                )
            ],
            SoftwareCategory.COLLABORATION: [
                Alternative(
                    name="Element",
                    vendor="Element",
                    rationale="E2EE, open-source, can be self-hosted.",
                    trust_score=80
                )
            ]
        }
        return defaults.get(category, [])
