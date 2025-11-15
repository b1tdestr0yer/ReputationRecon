from typing import Optional, Dict, Any
from server.dtos.AssessmentRequest import AssessmentRequest
from server.dtos.AssessmentResponse import AssessmentResponse, SoftwareCategory
from server.services.cache import AssessmentCache
from server.services.data_collectors import (
    CVECollector, VendorPageCollector, VirusTotalCollector,
    WebSearchCollector, EntityResolver, CIRCLHashlookupCollector,
    BugBountyCollector
)
from server.services.classifier import SoftwareClassifier
from server.services.ai_synthesizer import AISynthesizer
import asyncio


class AssessmentService:
    """Main service for conducting security assessments"""
    
    def __init__(self):
        self.cache = AssessmentCache()
        self.cve_collector = CVECollector()
        self.vendor_collector = VendorPageCollector()
        self.vt_collector = VirusTotalCollector()
        self.hashlookup_collector = CIRCLHashlookupCollector()
        self.web_collector = WebSearchCollector()
        self.bugbounty_collector = BugBountyCollector()
        self.entity_resolver = EntityResolver()
        self.classifier = SoftwareClassifier()
        self.synthesizer = AISynthesizer()
    
    async def assess(self, request: AssessmentRequest) -> AssessmentResponse:
        """Perform complete security assessment"""
        print("\n" + "="*60)
        print("[Assessment Service] Starting new assessment")
        print(f"[Assessment Service] Request: product={request.product_name}, vendor={request.vendor_name}, url={request.url}, hash={'***' if request.hash else None}")
        print("="*60)
        
        # Check cache first
        print("[Assessment Service] Checking cache...")
        cached = self.cache.get(
            product_name=request.product_name,
            vendor_name=request.vendor_name,
            url=request.url,
            hash=request.hash
        )
        
        if cached:
            print("[Assessment Service] ⚠ Cache hit found, but generating fresh assessment")
            # Return cached result (would need to reconstruct AssessmentResponse)
            # For now, continue to generate fresh assessment
            pass
        else:
            print("[Assessment Service] No cache entry found")
        
        # Step 1: Resolve entity and vendor (including URL via Gemini if not provided)
        print("\n[Assessment Service] Step 1: Resolving entity and vendor...")
        resolved = await self.entity_resolver.resolve(
            product_name=request.product_name,
            vendor_name=request.vendor_name,
            url=request.url
        )
        
        entity_name = resolved["entity_name"]
        vendor_name = resolved["vendor_name"]
        resolved_url = resolved["resolved_url"]  # This may be Gemini-resolved if not provided
        print(f"[Assessment Service] ✓ Resolved: {entity_name} by {vendor_name}")
        if resolved_url:
            print(f"  → URL: {resolved_url}")
        else:
            print(f"  → No URL available (neither provided nor resolved)")
        
        # Step 2: Classify software
        print(f"\n[Assessment Service] Step 2: Classifying software...")
        category = self.classifier.classify(
            product_name=entity_name,
            vendor_name=vendor_name,
            url=resolved_url
        )
        print(f"[Assessment Service] ✓ Classified as: {category.value}")
        
        # Step 3: Collect data from all sources (parallel)
        print(f"\n[Assessment Service] Step 3: Collecting data from all sources...")
        collected_data = await self._collect_all_data(
            entity_name=entity_name,
            vendor_name=vendor_name,
            url=resolved_url,
            hash=request.hash
        )
        print(f"[Assessment Service] ✓ Data collection complete")
        cve_data = collected_data.get('cves', {})
        print(f"  - CVEs: {cve_data.get('total_cves', 0)} (version-specific: {cve_data.get('version_specific_cves', 0)})")
        print(f"  - CISA KEV: {len(collected_data.get('cisa_kev', []))}")
        print(f"  - Vendor page: {'✓' if collected_data.get('vendor_page') else '✗'}")
        print(f"  - Terms of Service: {'✓' if collected_data.get('terms_of_service') else '✗'}")
        vt_report = collected_data.get('virustotal')
        if vt_report and vt_report.get('response_code') == 1:
            exe_name = vt_report.get('exe_name')
            exe_info = f" (EXE: {exe_name})" if exe_name else ""
            print(f"  - VirusTotal: ✓{exe_info}")
        else:
            print(f"  - VirusTotal: ✗")
        bug_bounties = collected_data.get('bug_bounties', {})
        if bug_bounties and bug_bounties.get('total_reports', 0) > 0:
            print(f"  - Bug Bounties: ✓ ({bug_bounties.get('total_reports', 0)} reports: {bug_bounties.get('hackerone_count', 0)} HackerOne, {bug_bounties.get('bugcrowd_count', 0)} Bugcrowd)")
        else:
            print(f"  - Bug Bounties: ✗")
        hashlookup_info = collected_data.get('hashlookup')
        if hashlookup_info and hashlookup_info.get('found'):
            version = hashlookup_info.get('product_version', '') or 'unknown'
            if version and version != 'unknown':
                print(f"  - CIRCL Hashlookup: ✓ (Version: {version})")
            else:
                print(f"  - CIRCL Hashlookup: ✓ (Version information not available)")
        else:
            print(f"  - CIRCL Hashlookup: ✗")
        
        # Step 4: Synthesize security posture
        print(f"\n[Assessment Service] Step 4: Synthesizing security posture...")
        security_posture = await self.synthesizer.synthesize_security_posture(
            entity_name=entity_name,
            vendor_name=vendor_name,
            category=category,
            collected_data=collected_data
        )
        print(f"[Assessment Service] ✓ Security posture synthesized ({len(security_posture.citations)} citations)")
        
        # Step 5: Calculate trust score
        print(f"\n[Assessment Service] Step 5: Calculating trust score...")
        trust_score = await self.synthesizer.calculate_trust_score(
            security_posture=security_posture,
            collected_data=collected_data
        )
        print(f"[Assessment Service] ✓ Trust score: {trust_score.score}/100 ({trust_score.risk_level} risk, {trust_score.confidence:.1%} confidence)")
        
        # Step 6: Suggest alternatives (only if trust score is low)
        print(f"\n[Assessment Service] Step 6: Suggesting alternatives...")
        alternatives = await self.synthesizer.suggest_alternatives(
            category=category,
            entity_name=entity_name,
            vendor_name=vendor_name,
            trust_score=trust_score,
            security_posture=security_posture,
            collected_data=collected_data
        )
        print(f"[Assessment Service] ✓ Found {len(alternatives)} alternatives")
        
        # Step 7: Generate suggestion
        print(f"\n[Assessment Service] Step 7: Generating suggestion...")
        suggestion = await self.synthesizer.generate_suggestion(
            entity_name=entity_name,
            vendor_name=vendor_name,
            category=category,
            security_posture=security_posture,
            trust_score=trust_score,
            collected_data=collected_data
        )
        print(f"[Assessment Service] ✓ Generated suggestion ({len(suggestion)} characters)")
        
        # Step 8: Determine data quality
        citation_count = len(security_posture.citations)
        if citation_count >= 5:
            data_quality = "sufficient"
        elif citation_count >= 2:
            data_quality = "limited"
        else:
            data_quality = "insufficient"
        print(f"[Assessment Service] Data quality: {data_quality} ({citation_count} citations)")
        
        # Create response
        print(f"\n[Assessment Service] Step 8: Creating assessment response...")
        response = AssessmentResponse(
            entity_name=entity_name,
            vendor_name=vendor_name,
            category=category,
            security_posture=security_posture,
            trust_score=trust_score,
            alternatives=alternatives,
            suggestion=suggestion,
            data_quality=data_quality
        )
        
        # Cache the result
        print(f"[Assessment Service] Caching assessment result...")
        cache_data = response.model_dump()
        self.cache.set(
            product_name=request.product_name,
            vendor_name=request.vendor_name,
            url=request.url,
            hash=request.hash,
            assessment_data=cache_data
        )
        
        # Set cache key in response
        response.cache_key = self.cache._generate_key(
            request.product_name,
            request.vendor_name,
            request.url,
            request.hash
        )
        
        print(f"[Assessment Service] ✓ Assessment complete!")
        print("="*60 + "\n")
        return response
    
    async def _collect_all_data(
        self,
        entity_name: str,
        vendor_name: str,
        url: Optional[str],
        hash: Optional[str]
    ) -> Dict[str, Any]:
        """Collect data from all sources in parallel"""
        print(f"[Assessment Service] Starting parallel data collection...")
        tasks = []
        
        # CVE data
        print(f"  → Queueing CVE search...")
        tasks.append(self.cve_collector.search_cves(entity_name, vendor_name))
        
        # CISA KEV
        print(f"  → Queueing CISA KEV lookup...")
        tasks.append(self.cve_collector.get_cisa_kev(entity_name))
        
        # Vendor pages - use resolved URL (which may have been resolved by Gemini)
        async def noop():
            return None
        
        vendor_url = url  # This is the resolved_url from EntityResolver, which may be Gemini-resolved
        if vendor_url:
            print(f"  → Queueing vendor page fetch...")
            tasks.append(self.vendor_collector.fetch_security_page(vendor_url))
            print(f"  → Queueing Terms of Service fetch...")
            tasks.append(self.vendor_collector.fetch_terms_of_service(vendor_url))
        else:
            print(f"  → Skipping vendor pages (no URL available)")
            tasks.append(noop())
            tasks.append(noop())
        
        # VirusTotal (if hash provided)
        if hash:
            print(f"  → Queueing VirusTotal lookup...")
            tasks.append(self.vt_collector.get_file_report(hash))
        else:
            print(f"  → Skipping VirusTotal (no hash provided)")
            tasks.append(noop())
        
        # CIRCL Hashlookup (if hash provided) - for version detection
        if hash:
            print(f"  → Queueing CIRCL Hashlookup lookup...")
            tasks.append(self.hashlookup_collector.get_file_info(hash))
        else:
            print(f"  → Skipping CIRCL Hashlookup (no hash provided)")
            tasks.append(noop())
        
        # Web search for incidents
        print(f"  → Queueing incident search...")
        tasks.append(self.web_collector.search_incidents(entity_name, vendor_name))
        
        # Bug bounty reports
        print(f"  → Queueing bug bounty search...")
        tasks.append(self.bugbounty_collector.search_bug_bounties(entity_name, vendor_name))
        
        # Execute all tasks
        print(f"[Assessment Service] Executing {len(tasks)} data collection tasks in parallel...")
        results = await asyncio.gather(*tasks, return_exceptions=True)
        print(f"[Assessment Service] All data collection tasks completed")
        
        # Organize results
        cve_data = results[0] if not isinstance(results[0], Exception) else {}
        cisa_kev = results[1] if not isinstance(results[1], Exception) else []
        vendor_page = results[2] if not isinstance(results[2], Exception) else None
        tos = results[3] if not isinstance(results[3], Exception) else None
        vt_report = results[4] if not isinstance(results[4], Exception) else None
        hashlookup_info = results[5] if not isinstance(results[5], Exception) else None
        incidents = results[6] if not isinstance(results[6], Exception) else []
        bug_bounties = results[7] if not isinstance(results[7], Exception) else {}
        
        # Extract latest version from vendor page if available (prefer this as it's the "latest" version)
        product_version = None
        version_source = None
        version_confidence = 0.0
        
        # First, try to get version from VirusTotal (from file details, history, comments)
        if vt_report and vt_report.get("response_code") == 1:
            vt_version = vt_report.get("detected_version")
            vt_confidence = vt_report.get("version_confidence", 0.0)
            if vt_version and vt_version.strip():
                product_version = vt_version.strip()
                version_source = "virustotal"
                version_confidence = vt_confidence
                print(f"[Assessment Service] ✓ Detected product version from VirusTotal: {product_version} (confidence: {int(vt_confidence*100)}%)")
        
        # Then, try to get version from hashlookup (fallback)
        if not product_version and hashlookup_info and hashlookup_info.get("found"):
            hashlookup_version = hashlookup_info.get("product_version")
            # Check if version exists and is not empty
            if hashlookup_version and hashlookup_version.strip():
                product_version = hashlookup_version.strip()
                version_source = "hashlookup"
                version_confidence = 0.7  # Medium confidence for hashlookup
                print(f"[Assessment Service] ✓ Detected product version from hashlookup: {product_version}")
        
        # Finally, try to get latest version from vendor page (this takes precedence as it's the "latest")
        if vendor_page and vendor_page.get("content") and vendor_page.get("url"):
            print(f"[Assessment Service] Attempting to extract latest version from vendor page...")
            latest_version = await self.vendor_collector.extract_latest_version(
                vendor_page.get("content", ""),
                entity_name,
                vendor_name,
                vendor_page.get("url", "")
            )
            if latest_version:
                print(f"[Assessment Service] ✓ Extracted latest version from vendor page: {latest_version}")
                product_version = latest_version  # Prefer vendor page version as it's the "latest"
                version_source = "vendor_page"
                version_confidence = 0.8  # High confidence for vendor page
            else:
                print(f"[Assessment Service] Could not extract version from vendor page")
        
        # If we have a version (from hashlookup or vendor page), search for version-specific CVEs
        if product_version:
            print(f"[Assessment Service] Searching for version-specific CVEs for version: {product_version}...")
            version_cve_data = await self.cve_collector.search_cves(
                entity_name, vendor_name, product_version
            )
            # Merge version-specific data into CVE results
            cve_data.update(version_cve_data)
        
        # Update hashlookup_info with the version we're using (for backward compatibility)
        # The version_source indicates where it came from (vendor_page > virustotal > hashlookup)
        if product_version and hashlookup_info:
            hashlookup_info["product_version"] = product_version
            hashlookup_info["version_source"] = version_source or "unknown"
            hashlookup_info["version_confidence"] = version_confidence
        elif product_version and not hashlookup_info:
            # Create hashlookup_info dict if it doesn't exist but we have a version
            hashlookup_info = {
                "found": True,
                "product_version": product_version,
                "version_source": version_source or "unknown",
                "version_confidence": version_confidence
            }
        
        # Extract exe_name from VirusTotal if available
        exe_name = None
        if vt_report and vt_report.get("response_code") == 1:
            exe_name = vt_report.get("exe_name")
        
        return {
            "cves": cve_data,
            "cisa_kev": cisa_kev,
            "vendor_page": vendor_page,
            "terms_of_service": tos,
            "virustotal": vt_report,
            "hashlookup": hashlookup_info,
            "incidents": incidents,
            "bug_bounties": bug_bounties,
            "hash": hash,  # Store hash for building URLs in citations
            "exe_name": exe_name  # Executable name from VirusTotal
        }
    
    async def compare(self, requests: list[AssessmentRequest]) -> Dict[str, Any]:
        """Compare multiple assessments"""
        print(f"\n[Assessment Service] Starting comparison of {len(requests)} applications")
        assessments = []
        for i, request in enumerate(requests, 1):
            print(f"\n[Assessment Service] Processing application {i}/{len(requests)}")
            assessment = await self.assess(request)
            assessments.append(assessment.model_dump())
        
        print(f"\n[Assessment Service] Comparison complete - analyzing results...")
        
        # Safely get trust scores for comparison
        def get_trust_score(x):
            return (x.get("trust_score") or {}).get("score", 0)
        
        if assessments:
            highest_trust = max(assessments, key=get_trust_score)
            lowest_trust = min(assessments, key=get_trust_score)
        else:
            highest_trust = None
            lowest_trust = None
        
        result = {
            "assessments": assessments,
            "comparison": {
                "count": len(assessments),
                "highest_trust": highest_trust,
                "lowest_trust": lowest_trust
            }
        }
        
        if highest_trust and lowest_trust:
            highest_score = get_trust_score(highest_trust)
            lowest_score = get_trust_score(lowest_trust)
            print(f"[Assessment Service] Highest trust: {highest_trust.get('entity_name', 'Unknown')} ({highest_score}/100)")
            print(f"[Assessment Service] Lowest trust: {lowest_trust.get('entity_name', 'Unknown')} ({lowest_score}/100)")
        return result

