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
        vt = data.get("virustotal")
        content = ""
        
        if vendor_page and vendor_page.get("content"):
            content += f"Vendor page content:\n{vendor_page.get('content', '')[:3000]}\n\n"
        if tos and tos.get("content"):
            content += f"Terms of Service content:\n{tos.get('content', '')[:2000]}\n\n"
        
        # Add VirusTotal file information if available
        if vt and vt.get("response_code") == 1:
            exe_name = vt.get("exe_name")
            meaningful_name = vt.get("meaningful_name")
            type_description = vt.get("type_description")
            file_details = vt.get("file_details", {})
            
            if exe_name or meaningful_name or type_description:
                content += "File Information:\n"
                if exe_name:
                    content += f"Executable name: {exe_name}\n"
                if meaningful_name:
                    content += f"Meaningful name: {meaningful_name}\n"
                if type_description:
                    content += f"File type: {type_description}\n"
                
                # Add PE info if available
                pe_info = file_details.get("pe_info", {})
                if pe_info and isinstance(pe_info, dict):
                    version_info = pe_info.get("version_info", {})
                    if isinstance(version_info, dict):
                        product_name = version_info.get("ProductName") or version_info.get("product_name")
                        product_version = version_info.get("ProductVersion") or version_info.get("product_version")
                        if product_name:
                            content += f"PE Product Name: {product_name}\n"
                        if product_version:
                            content += f"PE Product Version: {product_version}\n"
                content += "\n"
        
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
            
            # Add community notes (more detailed than comments)
            community_notes = vt.get("community_notes", [])
            if community_notes:
                indicators.append(f"VirusTotal: {len(community_notes)} community notes available")
            
            # Add submission history information
            submission_history = vt.get("submission_history", [])
            if submission_history:
                indicators.append(f"VirusTotal: {len(submission_history)} submission history entries")
            
            # Add executable name if available
            exe_name = vt.get("exe_name")
            if exe_name:
                indicators.append(f"VirusTotal: Executable name: {exe_name}")
            
            # Add file details if available (PE info, etc.)
            file_details = vt.get("file_details", {})
            if file_details:
                pe_info = file_details.get("pe_info", {})
                if pe_info:
                    indicators.append("VirusTotal: PE (Portable Executable) file information available")
                signature_info = file_details.get("signature_info", {})
                if signature_info:
                    indicators.append("VirusTotal: Digital signature information available")

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
        vt = data.get("virustotal")
        
        # Get version from multiple sources (priority: hashlookup > VT > vendor page)
        # hashlookup may have been updated with vendor page or VT version
        detected_version = hashlookup.get("product_version") if hashlookup else None
        version_source = hashlookup.get("version_source", "unknown") if hashlookup else "unknown"
        
        # If no version from hashlookup, try VirusTotal
        if not detected_version and vt and vt.get("response_code") == 1:
            vt_version = vt.get("detected_version")
            if vt_version and vt_version.strip():
                detected_version = vt_version.strip()
                version_source = "virustotal"
                version_confidence = vt.get("version_confidence", 0.0)
                print(f"[AI Synthesizer] Using version {detected_version} from VirusTotal (confidence: {int(version_confidence*100)}%)")
        
        if detected_version and version_source != "virustotal":
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
        bug_bounties = data.get("bug_bounties") or {}

        context = []
        if kev:
            context.append(f"{len(kev)} KEV vulnerabilities (active exploitation)")
        if incidents:
            context.append(f"{len(incidents)} public incidents")
        if cves and cves.get("critical_count", 0):
            context.append(f"{cves.get('critical_count')} critical CVEs")
        if bug_bounties and bug_bounties.get("total_reports", 0) > 0:
            total = bug_bounties.get("total_reports", 0)
            h1_count = bug_bounties.get("hackerone_count", 0)
            bc_count = bug_bounties.get("bugcrowd_count", 0)
            context.append(f"{total} public bug bounty reports ({h1_count} HackerOne, {bc_count} Bugcrowd)")

        if self.use_ai and context:
            try:
                prompt = f"""
Write a **2–3 sentence** summary of security incidents & abuse signals.

Data:
{chr(10).join(context)}

Rules:
- If findings are severe, state it clearly.
- If limited, say visibility is limited.
- Mention bug bounty reports if available as they indicate active security research.
"""
                result = await self._call_vertex_ai(prompt)
                if result:
                    return result.strip()
            except Exception as e:
                print(f"[AI Synthesizer] ⚠ Error generating incidents summary: {e}")

        if bug_bounties and bug_bounties.get("total_reports", 0) > 0:
            total = bug_bounties.get("total_reports", 0)
            return f"{total} public bug bounty reports found, indicating active security research and potential vulnerabilities."
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
            
            # Add executable name if available
            exe_name = vt.get("exe_name")
            if exe_name:
                claim_parts.append(f"file: {exe_name}")
            
            # Add version if detected from VT
            detected_version = vt.get("detected_version")
            if detected_version:
                version_confidence = vt.get("version_confidence", 0.0)
                claim_parts.append(f"version: {detected_version} ({int(version_confidence*100)}% confidence)")
            
            # Add community notes count
            community_notes = vt.get("community_notes", [])
            if community_notes:
                claim_parts.append(f"{len(community_notes)} community notes")
            
            claim = ", ".join(claim_parts)
            
            cites.append(Citation(
                source=vt_url,
                source_type="VirusTotal",
                claim=claim,
                is_vendor_stated=False,
                timestamp=datetime.now()
            ))

        # Add bug bounty citations
        bug_bounties = data.get("bug_bounties") or {}
        if bug_bounties and bug_bounties.get("reports"):
            reports = bug_bounties.get("reports", [])
            for report in reports[:5]:  # Limit to 5 citations
                platform = report.get("platform", "Bug Bounty")
                title = report.get("title", "Bug Report")
                url = report.get("url", "")
                if url:
                    cites.append(Citation(
                        source=url,
                        source_type=platform,
                        claim=f"Public bug bounty report: {title}",
                        is_vendor_stated=False,
                        timestamp=datetime.now()
                    ))
            # Add summary citation if there are more reports
            total = bug_bounties.get("total_reports", 0)
            if total > 5:
                h1_count = bug_bounties.get("hackerone_count", 0)
                bc_count = bug_bounties.get("bugcrowd_count", 0)
                if h1_count > 0:
                    cites.append(Citation(
                        source="https://hackerone.com/hacktivity",
                        source_type="HackerOne",
                        claim=f"{h1_count} additional HackerOne reports found",
                        is_vendor_stated=False,
                        timestamp=datetime.now()
                    ))
                if bc_count > 0:
                    cites.append(Citation(
                        source="https://bugcrowd.com/disclosures",
                        source_type="Bugcrowd",
                        claim=f"{bc_count} additional Bugcrowd reports found",
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
            # Get bug bounty info from incidents (already included) but also check collected_data
            bug_bounty_info = ""
            # The incidents string should already include bug bounty info, but we can verify
            
            prompt = f"""Generate a very short, concise summary (2-3 sentences maximum, under 200 characters) of the security posture for this software.

Product: {entity_name}
Vendor: {vendor_name}
Category: {category.value}

Key Security Information:
- Description: {description[:200]}
- Usage: {usage[:200]}
- Vendor Reputation: {vendor_reputation[:200]}
- CVEs: {cve_summary.total_cves} total ({cve_summary.critical_count} critical, {cve_summary.high_count} high), {cve_summary.cisa_kev_count} in CISA KEV
- Incidents & Bug Bounties: {incidents[:150]}
- Data Handling: {data_handling[:150]}
- Deployment Controls: {deployment_controls[:150]}

Write a brief, executive-level summary that captures the overall security posture. Focus on the most critical aspects (CVEs, vendor reputation, data handling, bug bounty reports if mentioned). Keep it under 200 characters.

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

        # Group all CVE-related penalties together
        cve_penalty = 0
        cve_details = []
        
        # Version-specific CVEs are weighted more heavily (more relevant to current version)
        if cve.detected_version and cve.version_specific_cves > 0:
            # Version-specific CVEs have higher impact (reduced penalties)
            if cve.version_specific_cves > 20:
                cve_penalty += 8
                cve_details.append(f"{cve.version_specific_cves} version-specific CVEs")
            elif cve.version_specific_cves > 10:
                cve_penalty += 5
                cve_details.append(f"{cve.version_specific_cves} version-specific CVEs")
            elif cve.version_specific_cves > 5:
                cve_penalty += 3
                cve_details.append(f"{cve.version_specific_cves} version-specific CVEs")
            else:
                cve_penalty += 2
                cve_details.append(f"{cve.version_specific_cves} version-specific CVEs")
            
            # Version-specific critical CVEs are very concerning (reduced penalties)
            if cve.version_specific_critical > 5:
                cve_penalty += 6
                cve_details.append(f"{cve.version_specific_critical} critical")
            elif cve.version_specific_critical > 0:
                cve_penalty += 4
                cve_details.append(f"{cve.version_specific_critical} critical")
            
            # Version-specific high CVEs (reduced penalties)
            if cve.version_specific_high > 10:
                cve_penalty += 4
                cve_details.append(f"{cve.version_specific_high} high")
            elif cve.version_specific_high > 0:
                cve_penalty += 2
                cve_details.append(f"{cve.version_specific_high} high")
        else:
            # Total CVE impact (less weight than version-specific, but still important)
            if cve.total_cves > 50:
                cve_penalty += 6
                cve_details.append(f"{cve.total_cves} total CVEs")
            elif cve.total_cves > 20:
                cve_penalty += 3
                cve_details.append(f"{cve.total_cves} total CVEs")
            elif cve.total_cves > 5:
                cve_penalty += 2
                cve_details.append(f"{cve.total_cves} total CVEs")
            elif cve.total_cves > 0:
                cve_penalty += 1
                cve_details.append(f"{cve.total_cves} total CVEs")
            
            # Total critical CVEs (less weight if we have version-specific data)
            if cve.critical_count > 5:
                if not (cve.detected_version and cve.version_specific_critical > 0):
                    cve_penalty += 4
                    cve_details.append(f"{cve.critical_count} critical")
            elif cve.critical_count > 0:
                if not (cve.detected_version and cve.version_specific_critical > 0):
                    cve_penalty += 2
                    cve_details.append(f"{cve.critical_count} critical")

        # CISA KEV is very serious (reduced penalty)
        if cve.cisa_kev_count > 0:
            cve_penalty += 10
            cve_details.append(f"{cve.cisa_kev_count} CISA KEV")
        
        # Apply grouped CVE penalty
        if cve_penalty > 0:
            score -= cve_penalty
            cve_label = "CVE Issues"
            if cve_details:
                cve_label += f" ({', '.join(cve_details[:3])})"  # Show first 3 details
            factors[cve_label] = -cve_penalty
        elif cve.total_cves == 0:
            # No CVEs is actually positive (but don't over-weight it)
            if not (cve.detected_version and cve.version_specific_cves > 0):
                factors["no_cves"] = +5
                score += 5

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
            last_analysis_results = vt.get("last_analysis_results", {})
            
            # Trusted vendors that are considered reliable indicators of true positives
            trusted_vendors = {
                "bitdefender", "bitdefenderfalx", "clamav", "crowdstrike", "crowstrike",
                "kaspersky", "microsoft", "fortinet", "google", "withsecure",
                "palo alto networks", "paloalto", "sentinel one", "sentinelone"
            }
            
            # Count trusted vs untrusted vendor detections
            trusted_detections = 0
            untrusted_detections = 0
            trusted_vendor_names = []
            
            if last_analysis_results and isinstance(last_analysis_results, dict):
                for vendor_name, result_data in last_analysis_results.items():
                    if isinstance(result_data, dict):
                        category = result_data.get("category", "").lower()
                        # Check if vendor detected as malicious or suspicious
                        if category in ["malicious", "suspicious"]:
                            vendor_lower = vendor_name.lower().strip()
                            # Check if vendor is in trusted list (case-insensitive, handle variations)
                            # Match if vendor name contains trusted vendor name or vice versa
                            # Also handle multi-word vendor names like "Palo Alto Networks"
                            is_trusted = False
                            for trusted in trusted_vendors:
                                # Exact match or contains as whole word
                                if (trusted == vendor_lower or 
                                    trusted in vendor_lower or 
                                    vendor_lower in trusted or
                                    # Handle spaces: "palo alto" matches "paloalto"
                                    trusted.replace(" ", "") == vendor_lower.replace(" ", "") or
                                    vendor_lower.replace(" ", "") == trusted.replace(" ", "")):
                                    is_trusted = True
                                    break
                            
                            if is_trusted:
                                trusted_detections += 1
                                trusted_vendor_names.append(vendor_name)
                            else:
                                untrusted_detections += 1
            
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
                
                # Calculate base penalty based on total positives (much more weight for many positives)
                # Scale penalty significantly with number of positives
                if positives >= 30:
                    base_penalty = 60  # Very high penalty for many detections
                elif positives >= 20:
                    base_penalty = 50
                elif positives >= 15:
                    base_penalty = 40
                elif positives >= 10:
                    base_penalty = 35
                elif positives >= 5:
                    base_penalty = 25
                else:
                    base_penalty = 15
                
                # Trusted vendor detections are weighted much more heavily
                # Each trusted vendor detection adds significant penalty
                trusted_penalty = trusted_detections * 8  # 8 points per trusted vendor detection
                
                # Untrusted detections are treated as potential false positives (reduced weight)
                # Only count untrusted detections if there are many of them
                untrusted_penalty = 0
                if untrusted_detections >= 10:
                    untrusted_penalty = (untrusted_detections - 10) * 1  # Minimal weight
                elif untrusted_detections >= 5:
                    untrusted_penalty = (untrusted_detections - 5) * 0.5  # Very minimal weight
                
                # If we have trusted vendor detections, they override the base penalty logic
                if trusted_detections > 0:
                    # Trusted detections are the primary factor
                    total_penalty = base_penalty + trusted_penalty + int(untrusted_penalty)
                    # Additional multiplier if multiple trusted vendors agree
                    if trusted_detections >= 3:
                        total_penalty = int(total_penalty * 1.3)  # 30% more if 3+ trusted vendors
                    elif trusted_detections >= 2:
                        total_penalty = int(total_penalty * 1.15)  # 15% more if 2+ trusted vendors
                else:
                    # No trusted detections - treat as potential false positives
                    # Reduce penalty significantly if only untrusted detections
                    if untrusted_detections > 0 and trusted_detections == 0:
                        total_penalty = int(base_penalty * 0.3) + int(untrusted_penalty)  # 70% reduction
                    else:
                        total_penalty = base_penalty + int(untrusted_penalty)
                
                # Apply confidence multiplier
                adjusted_penalty = int(total_penalty * confidence_multiplier)
                score -= adjusted_penalty
                
                # Record factors
                if trusted_detections > 0:
                    factors[f"virustotal_trusted_vendors_{trusted_detections}"] = -adjusted_penalty
                    if trusted_detections >= 3:
                        factors["multiple_trusted_vendors"] = "high_confidence"
                else:
                    if positives >= 30:
                        factors["virustotal_many_detections"] = -adjusted_penalty
                    elif positives >= 15:
                        factors["virustotal_moderate_detections"] = -adjusted_penalty
                    else:
                        factors["virustotal_few_detections"] = -adjusted_penalty
                
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
                    
                    # Add new VirusTotal data
                    exe_name = vt.get("exe_name")
                    if exe_name:
                        data_summary.append(f"- Executable name: {exe_name}")
                    
                    detected_version = vt.get("detected_version")
                    if detected_version:
                        version_confidence = vt.get("version_confidence", 0.0)
                        data_summary.append(f"- Detected version: {detected_version} (confidence: {int(version_confidence*100)}%)")
                    
                    community_notes = vt.get("community_notes", [])
                    if community_notes:
                        data_summary.append(f"- Community notes: {len(community_notes)} available")
                        # Include first few community notes for context
                        for i, note in enumerate(community_notes[:3], 1):
                            note_text = note.get("text", "")[:200]
                            if note_text:
                                data_summary.append(f"  Note {i}: {note_text}...")
                    
                    submission_history = vt.get("submission_history", [])
                    if submission_history:
                        data_summary.append(f"- Submission history: {len(submission_history)} entries")
                        # Include submission names from first entry
                        first_submission = submission_history[0]
                        submission_names = first_submission.get("submission_names", [])
                        if submission_names:
                            data_summary.append(f"  Sample submission names: {', '.join(submission_names[:3])}")
                    
                    file_details = vt.get("file_details", {})
                    if file_details:
                        pe_info = file_details.get("pe_info", {})
                        if pe_info and isinstance(pe_info, dict):
                            version_info = pe_info.get("version_info", {})
                            if isinstance(version_info, dict):
                                product_name = version_info.get("ProductName") or version_info.get("product_name")
                                product_version = version_info.get("ProductVersion") or version_info.get("product_version")
                                if product_name:
                                    data_summary.append(f"- PE Product Name: {product_name}")
                                if product_version:
                                    data_summary.append(f"- PE Product Version: {product_version}")
                        
                        signature_info = file_details.get("signature_info", {})
                        if signature_info:
                            data_summary.append("- Digital signature information available")
                    
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
                
                # Bug bounty reports
                bug_bounties = collected_data.get("bug_bounties", {})
                if bug_bounties and bug_bounties.get("total_reports", 0) > 0:
                    data_summary.append("Bug Bounty Reports:")
                    total = bug_bounties.get("total_reports", 0)
                    h1_count = bug_bounties.get("hackerone_count", 0)
                    bc_count = bug_bounties.get("bugcrowd_count", 0)
                    data_summary.append(f"- Total public reports: {total}")
                    data_summary.append(f"- HackerOne: {h1_count} reports")
                    data_summary.append(f"- Bugcrowd: {bc_count} reports")
                    # Include report titles for context
                    reports = bug_bounties.get("reports", [])
                    if reports:
                        data_summary.append("- Sample reports:")
                        for i, report in enumerate(reports[:5], 1):
                            title = report.get("title", "Bug Report")
                            platform = report.get("platform", "Unknown")
                            data_summary.append(f"  {i}. [{platform}] {title}")
                    data_summary.append("")
                
                # Citations count
                data_summary.append(f"Data Sources: {len(security_posture.citations)} citations available")
                
                # Build the prompt
                prompt = f"""You are an experienced Cyber Security Manager/CISO with over 20+ years of experience. Your task is to provide a clear, actionable recommendation on whether this application should be allowed on company laptops.

IMPORTANT: Start your response with ONE of these recommendation statuses on its own line:
- "NOT RECOMMENDED" - if the application should NOT be allowed due to significant security risks
- "USE WITH CAUTION" - if the application has elevated security concerns requiring additional controls
- "CONDITIONALLY APPROVED" - if the application is acceptable with standard security controls
- "RECOMMENDED" - if the application is suitable for deployment

After the status, provide 2-3 sentences explaining your recommendation based on ALL available data.

Consider these factors (in order of importance for security managers):
1. CISA KEV entries (actively exploited vulnerabilities) - HIGHEST PRIORITY
2. Critical and high-severity CVEs, especially version-specific ones
3. VirusTotal detection rates and threat classifications
4. Bug bounty reports (indicate active security research and potential vulnerabilities)
5. Vendor reputation and security track record
6. Data handling and compliance (SOC 2, ISO 27001, GDPR)
7. Security incidents and abuse signals
8. Trust score (use as one factor, not the sole determinant)

CRITICAL: If the text says "not recommended" or "do not allow" or similar, the status MUST be "NOT RECOMMENDED" regardless of trust score.

Collected Data:
{chr(10).join(data_summary)}

Format your response as:
[STATUS]
[2-3 sentence explanation with specific security concerns or positive factors]

Example:
NOT RECOMMENDED
This application has 3 CISA KEV entries indicating active exploitation, along with 5 critical CVEs. VirusTotal shows 77% detection rate with threat classification as hacktool. The combination of actively exploited vulnerabilities and high detection rates makes this application unsuitable for company laptops without exceptional business justification and additional security controls.

Write your recommendation:"""

                result = await self._call_vertex_ai(prompt)
                if result and len(result.strip()) > 50:  # Ensure we got a substantial response
                    print(f"[AI Synthesizer] ✓ Generated suggestion using AI")
                    return result.strip()
            except Exception as e:
                print(f"[AI Synthesizer] ⚠ Error generating suggestion with AI: {e}")
        
        # Fallback suggestion based on multiple factors (not just trust score)
        risk_level = trust_score.risk_level
        score = trust_score.score
        cve_summary = security_posture.cve_summary
        cisa_kev_count = cve_summary.cisa_kev_count
        critical_count = cve_summary.critical_count
        
        # Consider multiple factors for recommendation
        # CISA KEV is highest priority - if present, likely not recommended
        if cisa_kev_count > 0 or risk_level == "Critical" or score < 35:
            return f"NOT RECOMMENDED\nBased on the security assessment, {entity_name} by {vendor_name} presents significant security risks (Trust Score: {score}/100, Risk Level: {risk_level}). The application has {cve_summary.total_cves} CVEs, including {critical_count} critical vulnerabilities. {cisa_kev_count} vulnerabilities are listed in CISA KEV, indicating active exploitation. This application should not be allowed on company laptops without exceptional business justification, additional security controls, and management approval."
        elif critical_count > 3 or risk_level == "High" or score < 55:
            return f"USE WITH CAUTION\nBased on the security assessment, {entity_name} by {vendor_name} presents elevated security concerns (Trust Score: {score}/100, Risk Level: {risk_level}). The application has {cve_summary.total_cves} CVEs, including {critical_count} critical vulnerabilities. Exercise caution when deploying this application on company laptops. Consider implementing additional security controls, ensuring the latest version is used, and obtaining management approval before deployment."
        elif risk_level == "Medium" or score < 75:
            return f"CONDITIONALLY APPROVED\nBased on the security assessment, {entity_name} by {vendor_name} has a moderate security posture (Trust Score: {score}/100, Risk Level: {risk_level}). The application has {cve_summary.total_cves} CVEs. This application may be acceptable for company laptops with standard security controls in place. Ensure the application is kept up to date and monitor for new security advisories."
        else:
            return f"RECOMMENDED\nBased on the security assessment, {entity_name} by {vendor_name} demonstrates a relatively good security posture (Trust Score: {score}/100, Risk Level: {risk_level}). The application has {cve_summary.total_cves} CVEs. This application appears suitable for deployment on company laptops with standard security controls and regular updates."