import os
import json
import re
from datetime import datetime
from typing import Dict, List, Optional, Any

import httpx
from dotenv import load_dotenv

from server.dtos.AssessmentResponse import (
    SecurityPosture, Citation, CVESummary, TrustScore, Alternative, SoftwareCategory
)

load_dotenv()


class AISynthesizer:
    """Clean, deterministic, predictable Gemini-based synthesis using Vertex AI REST API."""

    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        self.model_name = "gemini-2.5-flash-lite"  # Using flash-lite as shown in user's example
        self.base_url = "https://aiplatform.googleapis.com/v1/publishers/google/models"
        
        if self.api_key:
            self.use_ai = True
            print(f"[AI Synthesizer] ✓ Vertex AI configured for AI-powered synthesis (using {self.model_name})")
        else:
            self.use_ai = False
            print("[AI Synthesizer] ✗ No API key found, using basic synthesis")
    
    async def _call_vertex_ai(self, prompt: str) -> Optional[str]:
        """Call Vertex AI REST API and return the generated text.
        
        Uses the Vertex AI REST API endpoint as documented at:
        https://docs.cloud.google.com/vertex-ai/generative-ai/docs/model-reference/inference
        """
        if not self.use_ai or not self.api_key:
            return None
        
        try:
            # Use generateContent (non-streaming) endpoint
            # Format: https://aiplatform.googleapis.com/v1/publishers/google/models/{model}:generateContent
            url = f"{self.base_url}/{self.model_name}:generateContent"
            params = {"key": self.api_key}
            
            # Request payload format per Vertex AI documentation
            payload = {
                "contents": [
                    {
                        "role": "user",
                        "parts": [
                            {
                                "text": prompt
                            }
                        ]
                    }
                ]
            }
            
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(url, params=params, json=payload)
                response.raise_for_status()
                
                data = response.json()
                
                # Extract text from Vertex AI response structure
                # Response format: {"candidates": [{"content": {"parts": [{"text": "..."}]}}]}
                if "candidates" in data and len(data["candidates"]) > 0:
                    candidate = data["candidates"][0]
                    if "content" in candidate and "parts" in candidate["content"]:
                        parts = candidate["content"]["parts"]
                        if len(parts) > 0 and "text" in parts[0]:
                            return parts[0]["text"]
                
                # Fallback: try to find text anywhere in the response
                if "text" in str(data):
                    text_match = re.search(r'"text":\s*"([^"]+)"', json.dumps(data))
                    if text_match:
                        return text_match.group(1)
                
                print(f"[AI Synthesizer] ⚠ Unexpected response format: {json.dumps(data)[:200]}")
                return None
                
        except httpx.HTTPStatusError as e:
            error_text = e.response.text[:500] if hasattr(e.response, 'text') else str(e)
            print(f"[AI Synthesizer] ⚠ HTTP error calling Vertex AI: {e.response.status_code} - {error_text}")
            return None
        except Exception as e:
            print(f"[AI Synthesizer] ⚠ Error calling Vertex AI: {e}")
            return None

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
        
        # Add entity/vendor names and hash to collected_data for use in extraction methods
        collected_data["entity_name"] = entity_name
        collected_data["vendor_name"] = vendor_name
        # Store hash if available for building URLs
        if "hash" not in collected_data:
            # Try to get hash from request if available
            collected_data["hash"] = collected_data.get("hash", "")
        
        # Extract information from collected data
        print(f"[AI Synthesizer] Extracting description...")
        description = await self._extract_description(collected_data)
        print(f"[AI Synthesizer] Extracting usage...")
        usage = await self._extract_usage(collected_data, category)
        print(f"[AI Synthesizer] Extracting vendor reputation...")
        vendor_reputation = await self._extract_vendor_reputation(collected_data)
        print(f"[AI Synthesizer] Extracting CVE summary...")
        cve_summary = self._extract_cve_summary(collected_data)
        print(f"[AI Synthesizer] Extracting incidents...")
        incidents = await self._extract_incidents(collected_data)
        print(f"[AI Synthesizer] Extracting data handling info...")
        data_handling = await self._extract_data_handling(collected_data)
        print(f"[AI Synthesizer] Extracting deployment controls...")
        deployment = await self._extract_deployment_controls(collected_data)
        print(f"[AI Synthesizer] Extracting citations...")
        citations = self._extract_citations(collected_data)
        print(f"[AI Synthesizer] ✓ Extracted {len(citations)} citations")
        
        # Generate short summary after all data is extracted
        print(f"[AI Synthesizer] Generating security posture summary...")
        summary = await self._generate_security_posture_summary(
            entity_name, vendor_name, category,
            description, usage, vendor_reputation, cve_summary,
            incidents, data_handling, deployment
        )
        
        return SecurityPosture(
            summary=summary,
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
    async def _extract_description(self, data: Dict) -> str:
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
        if self.use_ai:
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

                result = await self._call_vertex_ai(prompt)
                if result and len(result.strip()) > 20:  # Ensure we got a real response
                    print(f"[AI Synthesizer] ✓ Generated description using AI")
                    return result.strip()
            except Exception as e:
                print(f"[AI Synthesizer] ⚠ Error generating description with AI: {e}")

        # Fallback
        if content:
            return f"{entity_name} is a software product by {vendor_name}. Product description available from vendor documentation."
        return f"Insufficient public evidence for detailed description of {entity_name}."


    # -------------------------------------------------------------------------
    # USAGE
    # -------------------------------------------------------------------------
    async def _extract_usage(self, data: Dict, category: SoftwareCategory) -> str:
        """Extract usage information using AI"""
        entity_name = data.get("entity_name", "the product")
        vendor_name = data.get("vendor_name", "the vendor")
        vendor_page = data.get("vendor_page") or {}
        content = vendor_page.get("content", "") if vendor_page else ""

        if self.use_ai:
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

                result = await self._call_vertex_ai(prompt)
                if result and len(result.strip()) > 20:
                    print(f"[AI Synthesizer] ✓ Generated usage description using AI")
                    return result.strip()
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
    async def _extract_vendor_reputation(self, data: Dict) -> str:
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
            malicious = vt.get("malicious", 0)
            suspicious = vt.get("suspicious", 0)
            reputation = vt.get("reputation", 0)
            risk_level = vt.get("risk_level", "unknown")
            risk_confidence = vt.get("risk_confidence", 0.5)
            risk_rationale = vt.get("risk_rationale", [])
            threat_names = vt.get("threat_names", [])
            risk_flags = vt.get("risk_flags", [])
            false_positive_indicators = vt.get("false_positive_indicators", [])
            comments = vt.get("comments", [])
            
            # Build comprehensive VirusTotal indicator with v3 data
            vt_indicator = f"VirusTotal: {positives}/{total_scans} flagged"
            if malicious > 0:
                vt_indicator += f" ({malicious} malicious"
                if suspicious > 0:
                    vt_indicator += f", {suspicious} suspicious"
                vt_indicator += ")"
            elif suspicious > 0:
                vt_indicator += f" ({suspicious} suspicious)"
            
            if reputation != 0:
                vt_indicator += f", reputation: {reputation}"
            
            if threat_names:
                threat_str = ", ".join(threat_names[:3])
                vt_indicator += f", threats: {threat_str}"
            
            if risk_level != "unknown":
                confidence_pct = int(risk_confidence * 100)
                vt_indicator += f", risk: {risk_level} ({confidence_pct}% confidence)"
            
            indicators.append(vt_indicator)
            
            # Add risk rationale (explains the assessment)
            if risk_rationale:
                for rationale in risk_rationale[:2]:
                    indicators.append(f"VirusTotal: {rationale}")
            
            # Add false positive indicators if present
            if false_positive_indicators:
                fp_str = ", ".join(false_positive_indicators)
                indicators.append(f"VirusTotal: False positive indicators detected ({fp_str})")
            
            # Add specific risk flags
            if "high_detection_rate" in risk_flags and "high_detection_rate_with_fp_indicators" not in risk_flags:
                indicators.append("VirusTotal: High detection rate (>30% of engines flagged) - high confidence threat")
            if "very_low_reputation" in risk_flags:
                indicators.append("VirusTotal: Very low reputation score")
            if "threat_classified" in risk_flags:
                indicators.append("VirusTotal: File classified as known threat")
            if "sandbox_analysis_available" in risk_flags:
                indicators.append("VirusTotal: Sandbox behavioral analysis available")
            
            # Add community comments if available
            if comments:
                indicators.append(f"VirusTotal: {len(comments)} community comments available")

        if self.use_ai:
            try:
                prompt = f"""You are a security analyst writing a CISO-ready brief. Summarize vendor security reputation in 2-3 sentences based ONLY on factual security indicators.

Vendor: {vendor_name}
Product: {entity_name}

Security Indicators:
{chr(10).join(indicators) if indicators else "No security indicators found in public databases."}

Rules:
- Be factual and evidence-based - only state what the data shows
- If indicators are positive (few CVEs, no KEV entries, clean VirusTotal), note that clearly
- If indicators are concerning (many CVEs, KEV entries, VirusTotal flags), state clearly but distinguish between high-confidence and low-confidence findings
- If VirusTotal shows false positive indicators, mention that the risk may be lower than detections suggest
- If data is very limited, explicitly state "Insufficient public evidence"
- Do NOT overstate reputation without strong evidence
- Mention specific numbers when available
- Be conservative - when confidence is low, state uncertainty clearly
- Cross-reference findings: if VirusTotal is clean but CVEs exist, note CVEs may be patched
- Use VirusTotal risk confidence levels to qualify statements

Write the vendor reputation summary:"""

                result = await self._call_vertex_ai(prompt)
                if result and len(result.strip()) > 30:
                    print(f"[AI Synthesizer] ✓ Generated vendor reputation using AI")
                    return result.strip()
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
        hashlookup = data.get("hashlookup") or {}
        # Get version from hashlookup (which may have been updated with vendor page version)
        detected_version = hashlookup.get("product_version") if hashlookup else None
        version_source = hashlookup.get("version_source", "unknown") if hashlookup else "unknown"
        if detected_version:
            print(f"[AI Synthesizer] Using version {detected_version} (source: {version_source})")
        
        return CVESummary(
            total_cves=cves.get("total_cves", 0) if cves else 0,
            critical_count=cves.get("critical_count", 0) if cves else 0,
            high_count=cves.get("high_count", 0) if cves else 0,
            recent_trend="unknown",
            cisa_kev_count=len(kev) if kev else 0,
            recent_cves=cves.get("recent_cves", []) if cves else [],
            version_specific_cves=cves.get("version_specific_cves", 0) if cves else 0,
            version_specific_critical=cves.get("version_specific_critical", 0) if cves else 0,
            version_specific_high=cves.get("version_specific_high", 0) if cves else 0,
            version_specific_recent=cves.get("version_specific_recent", []) if cves else [],
            detected_version=detected_version
        )


    # -------------------------------------------------------------------------
    # INCIDENTS
    # -------------------------------------------------------------------------
    async def _extract_incidents(self, data: Dict) -> str:
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

        if self.use_ai and context:
            try:
                prompt = f"""
Write a **2–3 sentence** summary of security incidents & abuse signals.

Data:
{chr(10).join(context)}

Rules:
- If findings are severe, state it clearly.
- If limited, say visibility is limited.
"""
                result = await self._call_vertex_ai(prompt)
                if result:
                    return result.strip()
            except Exception as e:
                print(f"[AI Synthesizer] ⚠ Error generating incidents summary: {e}")

        if incidents:
            return f"{len(incidents)} documented security incidents."
        if kev:
            return f"{len(kev)} KEV vulnerabilities, indicating active exploitation."
        return "No significant public incident data found."


    # -------------------------------------------------------------------------
    # DATA HANDLING
    # -------------------------------------------------------------------------
    async def _extract_data_handling(self, data: Dict) -> str:
        """Extract data handling and compliance information"""
        entity_name = data.get("entity_name", "the product")
        tos = data.get("terms_of_service") or {}
        vendor = data.get("vendor_page") or {}

        content = ""
        if tos and tos.get("content"):
            content += f"Terms of Service:\n{tos['content'][:3000]}\n\n"
        if vendor and vendor.get("content"):
            content += f"Vendor Security Page:\n{vendor['content'][:3000]}"

        if self.use_ai:
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

                result = await self._call_vertex_ai(prompt)
                if result and len(result.strip()) > 30:
                    print(f"[AI Synthesizer] ✓ Generated data handling info using AI")
                    return result.strip()
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
    async def _extract_deployment_controls(self, data: Dict) -> str:
        page = data.get("vendor_page") or {}
        content = page.get("content") if page else None

        if self.use_ai and content:
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
                result = await self._call_vertex_ai(prompt)
                if result:
                    return result.strip()
            except Exception as e:
                print(f"[AI Synthesizer] ⚠ Error generating deployment controls: {e}")

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

        # Add CVE citations with proper URLs
        cves = data.get("cves") or {}
        entity_name = data.get("entity_name", "")
        if cves and cves.get("total_cves", 0) > 0:
            # Build NVD search URL
            search_query = entity_name.replace(" ", "+") if entity_name else ""
            nvd_url = f"https://nvd.nist.gov/vuln/search/results?query={search_query}&results_type=overview" if search_query else "https://nvd.nist.gov/vuln/search"
            cites.append(Citation(
                source=nvd_url,
                source_type="CVE",
                claim=f"{cves.get('total_cves', 0)} CVE(s) found in NVD (National Vulnerability Database)",
                is_vendor_stated=False,
                timestamp=datetime.now()
            ))

        # Add CISA KEV citations with proper URLs
        kev_list = data.get("cisa_kev") or []
        for kev in kev_list:
            if kev and kev.get("cveID"):
                cve_id = kev.get("cveID", "")
                # Link to CISA KEV catalog and specific CVE in NVD
                cisa_url = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                nvd_cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                cites.append(Citation(
                    source=nvd_cve_url,
                    source_type="CISA",
                    claim=f"KEV Entry: {cve_id} (CISA Known Exploited Vulnerabilities)",
                    is_vendor_stated=False,
                    timestamp=datetime.now()
                ))

        # Add VirusTotal citation with proper URL and enhanced v3 information
        vt = data.get("virustotal")
        hash_value = data.get("hash", "")
        # Try to get hash from VirusTotal response if not in data
        if vt and not hash_value:
            hash_value = vt.get("sha256") or vt.get("sha1") or vt.get("md5") or ""
        
        if vt and vt.get("response_code") == 1:
            positives = vt.get("positives", 0)
            total = vt.get("total", 0)
            malicious = vt.get("malicious", 0)
            suspicious = vt.get("suspicious", 0)
            reputation = vt.get("reputation", 0)
            risk_level = vt.get("risk_level", "unknown")
            risk_confidence = vt.get("risk_confidence", 0.5)
            threat_names = vt.get("threat_names", [])
            false_positive_indicators = vt.get("false_positive_indicators", [])
            
            # Build VirusTotal report URL using the hash
            if hash_value:
                hash_upper = hash_value.upper().strip()
                if len(hash_upper) in [32, 40, 64]:
                    vt_url = f"https://www.virustotal.com/gui/file/{hash_upper}"
                else:
                    vt_url = "https://www.virustotal.com"
            else:
                vt_url = "https://www.virustotal.com"
            
            # Build comprehensive claim with v3 data including confidence
            claim_parts = [f"VirusTotal v3 analysis: {positives}/{total} engines flagged"]
            if malicious > 0:
                claim_parts.append(f"{malicious} malicious")
            if suspicious > 0:
                claim_parts.append(f"{suspicious} suspicious")
            if reputation != 0:
                claim_parts.append(f"reputation: {reputation}")
            if risk_level != "unknown":
                confidence_pct = int(risk_confidence * 100)
                claim_parts.append(f"risk: {risk_level} ({confidence_pct}% confidence)")
            if threat_names:
                threat_str = ", ".join(threat_names[:2])
                claim_parts.append(f"threats: {threat_str}")
            if false_positive_indicators:
                claim_parts.append("false positive indicators detected")
            
            claim = ", ".join(claim_parts)
            
            cites.append(Citation(
                source=vt_url,
                source_type="VirusTotal",
                claim=claim,
                is_vendor_stated=False,
                timestamp=datetime.now()
            ))

        return cites

    async def _generate_security_posture_summary(
        self,
        entity_name: str,
        vendor_name: str,
        category: SoftwareCategory,
        description: str,
        usage: str,
        vendor_reputation: str,
        cve_summary: CVESummary,
        incidents: str,
        data_handling: str,
        deployment_controls: str
    ) -> str:
        """Generate a short AI summary of the security posture"""
        if not self.use_ai:
            # Fallback to a simple summary
            cve_info = f"{cve_summary.total_cves} CVEs" if cve_summary.total_cves > 0 else "no known CVEs"
            kev_info = f", {cve_summary.cisa_kev_count} in CISA KEV" if cve_summary.cisa_kev_count > 0 else ""
            return f"{entity_name} by {vendor_name} ({category.value}) has {cve_info}{kev_info}. {vendor_reputation[:100]}..."
        
        try:
            prompt = f"""Generate a very short, concise summary (2-3 sentences maximum, under 200 characters) of the security posture for this software.

Product: {entity_name}
Vendor: {vendor_name}
Category: {category.value}

Key Security Information:
- Description: {description[:200]}
- Usage: {usage[:200]}
- Vendor Reputation: {vendor_reputation[:200]}
- CVEs: {cve_summary.total_cves} total ({cve_summary.critical_count} critical, {cve_summary.high_count} high), {cve_summary.cisa_kev_count} in CISA KEV
- Incidents: {incidents[:150]}
- Data Handling: {data_handling[:150]}
- Deployment Controls: {deployment_controls[:150]}

Write a brief, executive-level summary that captures the overall security posture. Focus on the most critical aspects (CVEs, vendor reputation, data handling). Keep it under 200 characters.

Respond with ONLY the summary text, no labels or prefixes."""

            summary = await self._call_vertex_ai(prompt)
            if summary:
                summary = summary.strip()
                # Clean up any extra formatting
                summary = summary.replace('**', '').replace('*', '').strip()
                # Limit to 250 characters as a safety measure
                if len(summary) > 250:
                    summary = summary[:247] + "..."
                print(f"[AI Synthesizer] ✓ Generated security posture summary: {summary[:100]}...")
                return summary
        except Exception as e:
            print(f"[AI Synthesizer] ✗ Error generating summary: {e}, using fallback")
        
        # Fallback summary
        cve_info = f"{cve_summary.total_cves} CVEs" if cve_summary.total_cves > 0 else "no known CVEs"
        kev_info = f", {cve_summary.cisa_kev_count} in CISA KEV" if cve_summary.cisa_kev_count > 0 else ""
        return f"{entity_name} by {vendor_name} ({category.value}) has {cve_info}{kev_info}. {vendor_reputation[:100]}..."


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
        
        # Well-known, established companies that should get more lenient scoring
        # These are major tech companies with established security practices
        well_known_vendors = {
            "discord", "discord inc", "discordapp",
            "microsoft", "microsoft corporation",
            "google", "alphabet", "google llc",
            "apple", "apple inc",
            "salesforce", "salesforce.com",
            "adobe", "adobe inc", "adobe systems",
            "oracle", "oracle corporation",
            "ibm", "international business machines",
            "amazon", "amazon web services", "aws",
            "meta", "facebook", "meta platforms",
            "slack", "slack technologies",
            "zoom", "zoom video communications",
            "dropbox", "dropbox inc",
            "atlassian", "atlassian corporation",
            "github", "github inc", "microsoft github",
            "gitlab", "gitlab inc",
            "red hat", "redhat",
            "canonical", "ubuntu",
            "docker", "docker inc",
            "vmware", "vmware inc",
            "cisco", "cisco systems",
            "palo alto", "palo alto networks",
            "crowdstrike", "crowdstrike inc",
            "splunk", "splunk inc",
            "okta", "okta inc",
            "auth0",
            "twilio", "twilio inc",
            "stripe", "stripe inc",
            "paypal", "paypal holdings",
            "intel", "intel corporation",
            "nvidia", "nvidia corporation",
            "amd", "advanced micro devices"
        }
        
        # Check if vendor is well-known
        vendor_name = collected_data.get("vendor_name", "").lower().strip()
        entity_name = collected_data.get("entity_name", "").lower().strip()
        is_well_known = (
            vendor_name in well_known_vendors or
            entity_name in well_known_vendors or
            any(vendor in vendor_name or vendor in entity_name for vendor in well_known_vendors if len(vendor) > 5)
        )
        
        # Also check vendor reputation text for established/reputable indicators
        vendor_reputation_lower = security_posture.vendor_reputation.lower()
        is_established = any(term in vendor_reputation_lower for term in [
            "established", "reputable", "major", "leading", "well-known",
            "trusted", "recognized", "prominent", "large-scale", "enterprise"
        ])

        # Version-specific CVEs are weighted more heavily (more relevant to current version)
        if cve.detected_version and cve.version_specific_cves > 0:
            # Version-specific CVEs have higher impact
            if cve.version_specific_cves > 20:
                score -= 30
                factors["high_version_cve_count"] = -30
            elif cve.version_specific_cves > 10:
                score -= 20
                factors["moderate_version_cve_count"] = -20
            elif cve.version_specific_cves > 5:
                score -= 12
                factors["some_version_cves"] = -12
            else:
                score -= 6
                factors["few_version_cves"] = -6
            
            # Version-specific critical CVEs are very concerning
            if cve.version_specific_critical > 5:
                score -= 25
                factors["many_version_critical_cves"] = -25
            elif cve.version_specific_critical > 0:
                score -= 15
                factors["version_critical_cves"] = -15
            
            # Version-specific high CVEs
            if cve.version_specific_high > 10:
                score -= 15
                factors["many_version_high_cves"] = -15
            elif cve.version_specific_high > 0:
                score -= 8
                factors["version_high_cves"] = -8
        
        # Total CVE impact (less weight than version-specific, but still important)
        if cve.total_cves > 50:
            score -= 20
            factors["high_cve_count"] = -20
        elif cve.total_cves > 20:
            score -= 12
            factors["moderate_cve_count"] = -12
        elif cve.total_cves > 5:
            score -= 6
            factors["some_cves"] = -6
        elif cve.total_cves > 0:
            score -= 2
            factors["few_cves"] = -2
        else:
            # No CVEs is actually positive (but don't over-weight it)
            if not (cve.detected_version and cve.version_specific_cves > 0):
                factors["no_cves"] = +5
                score += 5

        # CISA KEV is very serious
        if cve.cisa_kev_count > 0:
            score -= 35
            factors["cisa_kev"] = -35

        # Total critical CVEs (less weight if we have version-specific data)
        if cve.critical_count > 5:
            if not (cve.detected_version and cve.version_specific_critical > 0):
                score -= 15
                factors["many_critical_cves"] = -15
        elif cve.critical_count > 0:
            if not (cve.detected_version and cve.version_specific_critical > 0):
                score -= 8
                factors["critical_cves"] = -8

        # VirusTotal analysis (enhanced with v3 data and confidence scoring)
        if vt and vt.get("response_code") == 1:
            positives = vt.get("positives", 0)
            total = vt.get("total", 0)
            malicious = vt.get("malicious", 0)
            suspicious = vt.get("suspicious", 0)
            reputation = vt.get("reputation", 0)
            risk_level = vt.get("risk_level", "unknown")
            risk_confidence = vt.get("risk_confidence", 0.5)
            threat_names = vt.get("threat_names", [])
            risk_flags = vt.get("risk_flags", [])
            false_positive_indicators = vt.get("false_positive_indicators", [])
            community_malicious = vt.get("community_malicious", 0)
            community_harmless = vt.get("community_harmless", 0)
            
            # Apply confidence weighting to all VT-based score adjustments
            confidence_multiplier = risk_confidence
            
            if positives == 0 and total > 0:
                # Clean scan is positive, but check reputation and confidence
                if reputation > 50:
                    base_bonus = 12
                    score += int(base_bonus * confidence_multiplier)
                    factors["excellent_virustotal"] = +int(base_bonus * confidence_multiplier)
                elif reputation > 0:
                    base_bonus = 8
                    score += int(base_bonus * confidence_multiplier)
                    factors["clean_virustotal"] = +int(base_bonus * confidence_multiplier)
                else:
                    base_bonus = 5
                    score += int(base_bonus * confidence_multiplier)
                    factors["clean_virustotal_low_rep"] = +int(base_bonus * confidence_multiplier)
            elif positives > 0:
                # Flagged by vendors is negative - use enhanced risk assessment with confidence
                flag_ratio = positives / total if total > 0 else 0
                
                # Check for false positive indicators - reduce penalty if present
                fp_reduction = 0.5 if false_positive_indicators else 1.0
                
                # Critical risk: high detection rate or known threats
                if risk_level == "critical":
                    base_penalty = 35
                    adjusted_penalty = int(base_penalty * confidence_multiplier * fp_reduction)
                    score -= adjusted_penalty
                    factors["virustotal_critical"] = -adjusted_penalty
                elif risk_level == "high":
                    # High risk: >10% flagged or primarily malicious
                    if malicious > suspicious * 2:
                        base_penalty = 30
                    else:
                        base_penalty = 20
                    adjusted_penalty = int(base_penalty * confidence_multiplier * fp_reduction)
                    score -= adjusted_penalty
                    if malicious > suspicious * 2:
                        factors["virustotal_malicious"] = -adjusted_penalty
                    else:
                        factors["virustotal_flagged"] = -adjusted_penalty
                elif risk_level == "medium":
                    # Medium risk: some detections but not overwhelming
                    if threat_names:
                        base_penalty = 18
                    else:
                        base_penalty = 12
                    adjusted_penalty = int(base_penalty * confidence_multiplier * fp_reduction)
                    score -= adjusted_penalty
                    if threat_names:
                        factors["virustotal_threat_classified"] = -adjusted_penalty
                    else:
                        factors["virustotal_suspicious"] = -adjusted_penalty
                else:
                    # Low risk: few detections
                    base_penalty = 8
                    adjusted_penalty = int(base_penalty * confidence_multiplier * fp_reduction)
                    score -= adjusted_penalty
                    factors["virustotal_low_risk"] = -adjusted_penalty
                
                # Additional penalties for reputation (only if high confidence)
                if reputation < -50 and risk_confidence > 0.7:
                    score -= 10
                    factors["very_low_reputation"] = -10
                elif reputation < 0 and risk_confidence > 0.6:
                    score -= 5
                    factors["negative_reputation"] = -5
                
                # Community votes matter (weighted by confidence)
                if community_malicious > community_harmless * 3 and risk_confidence > 0.6:
                    score -= int(8 * confidence_multiplier)
                    factors["community_flagged_malicious"] = -int(8 * confidence_multiplier)

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

        # Well-known/established company bonus (more lenient scoring)
        # Apply this after calculating penalties but before final clamping
        if is_well_known or is_established:
            # Calculate how much we need to boost to get to a reasonable level
            # For well-known companies, we want them to score at least 75-85 if they're generally clean
            # But we don't want to completely ignore security issues
            
            # Only apply bonus if there are no serious red flags
            has_serious_issues = (
                cve.cisa_kev_count > 0 or  # CISA KEV is always serious
                (cve.version_specific_critical > 5) or  # Many critical CVEs
                (vt and vt.get("response_code") == 1 and 
                 vt.get("positives", 0) > 0 and 
                 (vt.get("positives", 0) / max(vt.get("total", 1), 1)) > 0.1)  # High VirusTotal flags
            )
            
            if not has_serious_issues:
                # Apply a boost, but scale it based on current score
                # If score is already decent (60+), give a bigger boost
                # If score is low due to minor issues, give a moderate boost
                if score >= 60:
                    # Already decent, boost to 80-85 range
                    boost = min(20, 85 - score)
                    score += boost
                    factors["established_vendor_bonus"] = +boost
                elif score >= 50:
                    # Moderate issues, boost to 70-75 range
                    boost = min(20, 75 - score)
                    score += boost
                    factors["established_vendor_bonus"] = +boost
                else:
                    # More significant issues, but still give some benefit
                    boost = min(10, 65 - score)
                    if boost > 0:
                        score += boost
                        factors["established_vendor_bonus"] = +boost
            else:
                # Has serious issues, but still give a small benefit for transparency
                if score < 70:
                    boost = min(5, 70 - score)
                    if boost > 0:
                        score += boost
                        factors["established_vendor_partial_bonus"] = +boost

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

        # Enhanced confidence calculation based on data quality and risk confidence
        cites = len(security_posture.citations)
        has_vt = vt and vt.get("response_code") == 1
        has_cves = cve.total_cves > 0
        has_vendor_info = any("vendor" in c.source_type.lower() for c in security_posture.citations)
        
        # Base confidence from data sources
        if cites >= 5 and (has_vt or has_cves) and has_vendor_info:
            base_conf = 0.85
        elif cites >= 3 and (has_vt or has_cves):
            base_conf = 0.70
        elif cites >= 2:
            base_conf = 0.55
        elif cites >= 1:
            base_conf = 0.40
        else:
            base_conf = 0.25
        
        # Adjust confidence based on VirusTotal risk confidence if available
        if has_vt:
            vt_risk_confidence = vt.get("risk_confidence", 0.5)
            # Weight VT confidence: if VT has high confidence, boost overall confidence
            if vt_risk_confidence > 0.8:
                base_conf = min(1.0, base_conf + 0.10)  # High VT confidence boosts overall
            elif vt_risk_confidence < 0.5:
                base_conf = max(0.2, base_conf - 0.05)  # Low VT confidence slightly reduces
        
        # Adjust confidence based on CVE-VT cross-validation
        if has_vt and has_cves:
            vt_risk = vt.get("risk_level", "unknown")
            # If VT is clean but CVEs exist, confidence is lower (CVEs may be patched)
            if vt_risk == "clean" and cve.total_cves > 0:
                base_conf = max(0.3, base_conf - 0.10)
        
        # Adjust confidence based on false positive indicators
        if has_vt:
            fp_indicators = vt.get("false_positive_indicators", [])
            if fp_indicators:
                # False positive indicators suggest we should be more cautious
                base_conf = max(0.3, base_conf - 0.05)
        
        conf = base_conf

        # Build rationale
        factor_summary = []
        # Filter out non-numeric values (like string messages) before sorting
        numeric_factors = {k: v for k, v in factors.items() if isinstance(v, (int, float))}
        for key, value in sorted(numeric_factors.items(), key=lambda x: abs(x[1]), reverse=True)[:5]:
            sign = "+" if value > 0 else ""
            factor_summary.append(f"{key}: {sign}{value}")
        
        rationale = f"Trust score: {score}/100 ({level} risk). Key factors: {', '.join(factor_summary)}. Confidence: {conf:.0%} based on {cites} data sources."

        # Filter out any non-numeric values from factors before returning (Pydantic validation requires only numbers)
        numeric_factors_only = {k: v for k, v in factors.items() if isinstance(v, (int, float))}

        return TrustScore(
            score=score,
            risk_level=level,
            confidence=conf,
            rationale=rationale,
            factors=numeric_factors_only
        )


    # -------------------------------------------------------------------------
    # ALTERNATIVES
    # -------------------------------------------------------------------------
    async def suggest_alternatives(
        self, 
        category: SoftwareCategory, 
        entity_name: str,
        vendor_name: str,
        trust_score: TrustScore,
        security_posture: SecurityPosture,
        collected_data: Dict
    ) -> List[Alternative]:
        """
        Suggest safer alternatives only if trust score is below threshold (under 80 or not Low risk).
        Uses Gemini to generate context-aware suggestions based on app type and security issues found.
        """
        # Only suggest alternatives if trust score is low (under 80 or Medium/High/Critical risk)
        score = trust_score.score
        risk_level = trust_score.risk_level
        
        # Threshold: suggest if score < 80 OR risk level is not "Low"
        should_suggest = score < 80 or risk_level != "Low"
        
        if not should_suggest:
            print(f"[AI Synthesizer] Trust score {score}/100 ({risk_level} risk) is acceptable, skipping alternatives")
            return []
        
        print(f"[AI Synthesizer] Trust score {score}/100 ({risk_level} risk) is low, suggesting alternatives...")
        
        # Gather context about the application and its security issues
        description = security_posture.description[:200] if security_posture.description else "N/A"
        usage = security_posture.usage[:200] if security_posture.usage else "N/A"
        
        # Identify key security concerns
        cve = security_posture.cve_summary
        security_concerns = []
        if cve.total_cves > 0:
            security_concerns.append(f"{cve.total_cves} CVEs found ({cve.critical_count} critical, {cve.high_count} high)")
        if cve.cisa_kev_count > 0:
            security_concerns.append(f"{cve.cisa_kev_count} CISA KEV entries (actively exploited)")
        
        vt = collected_data.get("virustotal")
        if vt and vt.get("response_code") == 1:
            positives = vt.get("positives", 0)
            total = vt.get("total", 0)
            if positives > 0:
                security_concerns.append(f"VirusTotal: {positives}/{total} engines flagged")
        
        concerns_text = "; ".join(security_concerns) if security_concerns else "General security concerns identified"
        
        if self.use_ai:
            try:
                prompt = f"""You are a security analyst helping a CISO find safer alternatives to a software product.

Current Product Assessment:
- Product Name: {entity_name}
- Vendor: {vendor_name}
- Category: {category.value}
- Trust Score: {score}/100 ({risk_level} risk)
- Description: {description}
- Primary Usage: {usage}
- Security Concerns: {concerns_text}

Task: Suggest 2-3 reputable, security-focused alternatives that:
1. Serve the same or similar purpose (same category: {category.value})
2. Have better security posture than the current product
3. Are well-established and trusted in the industry
4. Address the specific security concerns identified

For each alternative, provide:
- name: The product name
- vendor: The vendor/company name
- rationale: A brief 1-2 sentence explanation of why this is a safer alternative, focusing on security benefits
- trust_score: An estimated trust score (0-100) - be realistic, typically 75-90 for good alternatives

Return ONLY valid JSON in this exact format (no markdown, no code blocks):
{{
  "alternatives": [
    {{
      "name": "Product Name",
      "vendor": "Vendor Name",
      "rationale": "Why this is safer (1-2 sentences focusing on security)",
      "trust_score": 85
    }},
    {{
      "name": "Product Name 2",
      "vendor": "Vendor Name 2",
      "rationale": "Why this is safer (1-2 sentences focusing on security)",
      "trust_score": 82
    }}
  ]
}}

Important:
- Return 2-3 alternatives (not more, not less)
- Focus on security benefits in rationale
- Be specific about what makes them safer
- Trust scores should be realistic (typically 75-90 for good alternatives)
- Only suggest well-known, established products
- Ensure alternatives are actually in the same category: {category.value}"""
                
                t = await self._call_vertex_ai(prompt)
                if not t:
                    raise Exception("Empty response from Vertex AI")
                
                # Clean up the response - remove markdown code blocks if present
                t = re.sub(r'```json\s*', '', t)
                t = re.sub(r'```\s*', '', t)
                t = t.strip()
                
                # Extract JSON
                m = re.search(r'\{[^{}]*"alternatives"\s*:\s*\[.*?\]\s*\}', t, re.DOTALL)
                if not m:
                    # Try broader pattern
                    m = re.search(r'\{.*"alternatives".*\}', t, re.DOTALL)
                
                if m:
                    json_str = m.group(0)
                    data = json.loads(json_str)
                    out = []
                    
                    alternatives_list = data.get("alternatives", [])
                    if not isinstance(alternatives_list, list):
                        alternatives_list = []
                    
                    for alt in alternatives_list[:3]:  # Take up to 3
                        if not isinstance(alt, dict):
                            continue
                            
                        name = alt.get("name", "").strip()
                        vendor = alt.get("vendor", "").strip()
                        rationale = alt.get("rationale", "").strip()
                        trust_score_alt = alt.get("trust_score", 75)
                        
                        # Validate and clamp trust_score
                        try:
                            trust_score_alt = int(trust_score_alt)
                            trust_score_alt = max(0, min(100, trust_score_alt))
                        except (ValueError, TypeError):
                            trust_score_alt = 75
                        
                        if name and vendor and rationale:
                            out.append(Alternative(
                                name=name,
                                vendor=vendor,
                                rationale=rationale,
                                trust_score=trust_score_alt
                            ))
                    
                    if out:
                        print(f"[AI Synthesizer] ✓ Generated {len(out)} alternatives using AI")
                        return out
                    else:
                        print(f"[AI Synthesizer] ⚠ AI returned alternatives but none were valid, using fallback")
                else:
                    print(f"[AI Synthesizer] ⚠ Could not parse JSON from AI response, using fallback")
                    print(f"[AI Synthesizer] Response preview: {t[:200]}")
                    
            except json.JSONDecodeError as e:
                print(f"[AI Synthesizer] ⚠ JSON decode error: {e}, using fallback")
            except Exception as e:
                print(f"[AI Synthesizer] ⚠ Error generating alternatives with AI: {e}, using fallback")
                import traceback
                traceback.print_exc()

        # Fallback: category-based defaults (only if AI failed)
        print(f"[AI Synthesizer] Using fallback alternatives for category: {category.value}")
        defaults = {
            SoftwareCategory.FILE_SHARING: [
                Alternative(
                    name="Nextcloud",
                    vendor="Nextcloud GmbH",
                    rationale="Open-source, self-hosted solution with strong security posture, GDPR compliant, and full data control.",
                    trust_score=85
                ),
                Alternative(
                    name="Seafile",
                    vendor="Seafile Ltd",
                    rationale="Open-source file sync and sharing with end-to-end encryption and self-hosting options.",
                    trust_score=80
                )
            ],
            SoftwareCategory.COLLABORATION: [
                Alternative(
                    name="Element",
                    vendor="Element",
                    rationale="End-to-end encrypted, open-source collaboration platform based on Matrix protocol. Can be self-hosted.",
                    trust_score=82
                ),
                Alternative(
                    name="Mattermost",
                    vendor="Mattermost Inc",
                    rationale="Open-source, self-hostable team collaboration with enterprise security features and compliance certifications.",
                    trust_score=80
                )
            ],
            SoftwareCategory.COMMUNICATION: [
                Alternative(
                    name="Signal",
                    vendor="Signal Foundation",
                    rationale="End-to-end encrypted messaging with open-source client, minimal metadata collection, and strong privacy focus.",
                    trust_score=88
                ),
                Alternative(
                    name="Element",
                    vendor="Element",
                    rationale="E2EE messaging based on Matrix protocol, open-source, and supports self-hosting for complete control.",
                    trust_score=82
                )
            ],
            SoftwareCategory.CLOUD_STORAGE: [
                Alternative(
                    name="Nextcloud",
                    vendor="Nextcloud GmbH",
                    rationale="Self-hosted cloud storage with strong security, GDPR compliance, and full data sovereignty.",
                    trust_score=85
                ),
                Alternative(
                    name="Tresorit",
                    vendor="Tresorit",
                    rationale="Zero-knowledge encrypted cloud storage with end-to-end encryption and strong security certifications.",
                    trust_score=83
                )
            ],
            SoftwareCategory.SECURITY_TOOL: [
                Alternative(
                    name="Wazuh",
                    vendor="Wazuh Inc",
                    rationale="Open-source security monitoring platform with active threat detection and compliance management.",
                    trust_score=82
                )
            ],
            SoftwareCategory.DEVELOPMENT: [
                Alternative(
                    name="GitLab",
                    vendor="GitLab Inc",
                    rationale="Open-source DevOps platform with self-hosting options, strong security features, and compliance certifications.",
                    trust_score=83
                ),
                Alternative(
                    name="Gitea",
                    vendor="Gitea",
                    rationale="Lightweight, self-hosted Git service with minimal resource requirements and strong security focus.",
                    trust_score=80
                )
            ]
        }
        
        fallback_alternatives = defaults.get(category, [
            Alternative(
                name="Consider open-source alternatives",
                vendor="Various",
                rationale="For better security transparency and control, consider evaluating open-source alternatives in this category that allow self-hosting and security audits.",
                trust_score=75
            )
        ])
        
        return fallback_alternatives[:2]  # Return max 2 from fallback

    # -------------------------------------------------------------------------
    # SUGGESTION
    # -------------------------------------------------------------------------
    async def generate_suggestion(
        self,
        entity_name: str,
        vendor_name: str,
        category: SoftwareCategory,
        security_posture: SecurityPosture,
        trust_score: TrustScore,
        collected_data: Dict[str, Any]
    ) -> str:
        """Generate AI suggestion on whether to use this application on a company laptop"""
        if self.use_ai:
            try:
                # Build comprehensive data summary for the AI
                data_summary = []
                
                # Product information
                data_summary.append(f"Product: {entity_name}")
                data_summary.append(f"Vendor: {vendor_name}")
                data_summary.append(f"Category: {category.value}")
                data_summary.append("")
                
                # Security posture information
                data_summary.append("Security Posture Summary:")
                data_summary.append(f"- Description: {security_posture.description}")
                data_summary.append(f"- Usage: {security_posture.usage}")
                data_summary.append(f"- Vendor Reputation: {security_posture.vendor_reputation}")
                data_summary.append(f"- Incidents/Abuse: {security_posture.incidents_abuse}")
                data_summary.append(f"- Data Handling: {security_posture.data_handling}")
                data_summary.append(f"- Deployment Controls: {security_posture.deployment_controls}")
                data_summary.append("")
                
                # CVE information
                cve = security_posture.cve_summary
                data_summary.append("CVE Information:")
                data_summary.append(f"- Total CVEs: {cve.total_cves}")
                data_summary.append(f"- Critical CVEs: {cve.critical_count}")
                data_summary.append(f"- High CVEs: {cve.high_count}")
                data_summary.append(f"- CISA KEV entries: {cve.cisa_kev_count}")
                if cve.detected_version:
                    data_summary.append(f"- Detected Version: {cve.detected_version}")
                    data_summary.append(f"- Version-specific CVEs: {cve.version_specific_cves}")
                    data_summary.append(f"- Version-specific Critical: {cve.version_specific_critical}")
                    data_summary.append(f"- Version-specific High: {cve.version_specific_high}")
                data_summary.append("")
                
                # Trust score
                data_summary.append("Trust Score:")
                data_summary.append(f"- Score: {trust_score.score}/100")
                data_summary.append(f"- Risk Level: {trust_score.risk_level}")
                data_summary.append(f"- Confidence: {trust_score.confidence:.1%}")
                data_summary.append(f"- Rationale: {trust_score.rationale}")
                data_summary.append("")
                
                # VirusTotal data
                vt = collected_data.get("virustotal")
                if vt and vt.get("response_code") == 1:
                    data_summary.append("VirusTotal Analysis:")
                    positives = vt.get("positives", 0)
                    total = vt.get("total", 0)
                    malicious = vt.get("malicious", 0)
                    suspicious = vt.get("suspicious", 0)
                    reputation = vt.get("reputation", 0)
                    risk_level = vt.get("risk_level", "unknown")
                    risk_confidence = vt.get("risk_confidence", 0.5)
                    threat_names = vt.get("threat_names", [])
                    false_positive_indicators = vt.get("false_positive_indicators", [])
                    
                    data_summary.append(f"- Detection: {positives}/{total} engines flagged")
                    if malicious > 0:
                        data_summary.append(f"- Malicious detections: {malicious}")
                    if suspicious > 0:
                        data_summary.append(f"- Suspicious detections: {suspicious}")
                    if reputation != 0:
                        data_summary.append(f"- Reputation score: {reputation}")
                    if risk_level != "unknown":
                        data_summary.append(f"- Risk level: {risk_level} ({risk_confidence:.1%} confidence)")
                    if threat_names:
                        data_summary.append(f"- Threat names: {', '.join(threat_names[:5])}")
                    if false_positive_indicators:
                        data_summary.append(f"- False positive indicators: {', '.join(false_positive_indicators)}")
                    data_summary.append("")
                
                # Vendor page content (truncated)
                vendor_page = collected_data.get("vendor_page")
                if vendor_page and vendor_page.get("content"):
                    content_preview = vendor_page.get("content", "")[:2000]
                    data_summary.append("Vendor Documentation (excerpt):")
                    data_summary.append(content_preview)
                    data_summary.append("")
                
                # Terms of service content (truncated)
                tos = collected_data.get("terms_of_service")
                if tos and tos.get("content"):
                    tos_preview = tos.get("content", "")[:1500]
                    data_summary.append("Terms of Service (excerpt):")
                    data_summary.append(tos_preview)
                    data_summary.append("")
                
                # Incidents
                incidents = collected_data.get("incidents", [])
                if incidents:
                    data_summary.append(f"Security Incidents: {len(incidents)} documented incidents found")
                    data_summary.append("")
                
                # Citations count
                data_summary.append(f"Data Sources: {len(security_posture.citations)} citations available")
                
                # Build the prompt
                prompt = f"""You are an experienced Cyber Security/System Administrator with over 20+ years of experience and have the task of assessing if this application should be used and ran on a company laptop or not. Keep the suggestion small and concise.

Based on all the collected data below, provide a recommendation on whether this application should be allowed on company laptops. Consider:

- Security posture and trust score
- CVE history and active vulnerabilities
- Vendor reputation and track record
- Data handling and compliance
- Deployment controls available
- VirusTotal analysis results
- Any documented security incidents

Provide a clear, professional recommendation that balances security concerns with business needs.

Collected Data:
{chr(10).join(data_summary)}

Write your recommendation:"""

                result = await self._call_vertex_ai(prompt)
                if result and len(result.strip()) > 50:  # Ensure we got a substantial response
                    print(f"[AI Synthesizer] ✓ Generated suggestion using AI")
                    return result.strip()
            except Exception as e:
                print(f"[AI Synthesizer] ⚠ Error generating suggestion with AI: {e}")
        
        # Fallback suggestion based on trust score
        risk_level = trust_score.risk_level
        score = trust_score.score
        
        if risk_level == "Critical" or score < 35:
            return f"Based on the security assessment, {entity_name} by {vendor_name} presents significant security risks (Trust Score: {score}/100, Risk Level: {risk_level}). The application has {security_posture.cve_summary.total_cves} CVEs, including {security_posture.cve_summary.critical_count} critical vulnerabilities. {security_posture.cve_summary.cisa_kev_count} vulnerabilities are listed in CISA KEV, indicating active exploitation. Recommendation: Do not allow this application on company laptops without additional security controls and management approval."
        elif risk_level == "High" or score < 55:
            return f"Based on the security assessment, {entity_name} by {vendor_name} presents elevated security concerns (Trust Score: {score}/100, Risk Level: {risk_level}). The application has {security_posture.cve_summary.total_cves} CVEs, including {security_posture.cve_summary.critical_count} critical vulnerabilities. Recommendation: Exercise caution when deploying this application on company laptops. Consider implementing additional security controls, ensuring the latest version is used, and obtaining management approval before deployment."
        elif risk_level == "Medium" or score < 75:
            return f"Based on the security assessment, {entity_name} by {vendor_name} has a moderate security posture (Trust Score: {score}/100, Risk Level: {risk_level}). The application has {security_posture.cve_summary.total_cves} CVEs. Recommendation: This application may be acceptable for company laptops with standard security controls in place. Ensure the application is kept up to date and monitor for new security advisories."
        else:
            return f"Based on the security assessment, {entity_name} by {vendor_name} demonstrates a relatively good security posture (Trust Score: {score}/100, Risk Level: {risk_level}). The application has {security_posture.cve_summary.total_cves} CVEs. Recommendation: This application appears suitable for deployment on company laptops with standard security controls and regular updates."