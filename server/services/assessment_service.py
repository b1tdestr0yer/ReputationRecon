from typing import Optional, Dict, Any
from server.dtos.AssessmentRequest import AssessmentRequest
from server.dtos.AssessmentResponse import AssessmentResponse, SoftwareCategory
from server.services.cache import AssessmentCache
from server.services.data_collectors import (
    CVECollector, VendorPageCollector, VirusTotalCollector,
    WebSearchCollector, EntityResolver, CIRCLHashlookupCollector
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
        
        # Step 1: Resolve entity and vendor
        print("\n[Assessment Service] Step 1: Resolving entity and vendor...")
        resolved = await self.entity_resolver.resolve(
            product_name=request.product_name,
            vendor_name=request.vendor_name,
            url=request.url
        )
        
        entity_name = resolved["entity_name"]
        vendor_name = resolved["vendor_name"]
        resolved_url = resolved["resolved_url"]
        
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
        print(f"  - VirusTotal: {'✓' if collected_data.get('virustotal') else '✗'}")
        hashlookup_info = collected_data.get('hashlookup')
        if hashlookup_info and hashlookup_info.get('found'):
            version = hashlookup_info.get('product_version', 'unknown')
            print(f"  - CIRCL Hashlookup: ✓ (Version: {version})")
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
        
        # Step 6: Suggest alternatives
        print(f"\n[Assessment Service] Step 6: Suggesting alternatives...")
        alternatives = await self.synthesizer.suggest_alternatives(
            category=category,
            entity_name=entity_name
        )
        print(f"[Assessment Service] ✓ Found {len(alternatives)} alternatives")
        
        # Step 7: Determine data quality
        citation_count = len(security_posture.citations)
        if citation_count >= 5:
            data_quality = "sufficient"
        elif citation_count >= 2:
            data_quality = "limited"
        else:
            data_quality = "insufficient"
        print(f"[Assessment Service] Data quality: {data_quality} ({citation_count} citations)")
        
        # Create response
        print(f"\n[Assessment Service] Step 7: Creating assessment response...")
        response = AssessmentResponse(
            entity_name=entity_name,
            vendor_name=vendor_name,
            category=category,
            security_posture=security_posture,
            trust_score=trust_score,
            alternatives=alternatives,
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
        
        # Vendor pages - try to find even without explicit URL
        async def noop():
            return None
        
        vendor_url = url
        if not vendor_url and vendor_name and vendor_name.lower() not in ["unknown vendor", "unknown"]:
            # Try to construct a URL from vendor name
            vendor_domain = vendor_name.lower().replace(" ", "").replace(".", "")
            vendor_url = f"https://{vendor_domain}.com"
            print(f"  → Attempting to find vendor pages using constructed URL: {vendor_url}")
        
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
        
        # If hashlookup found version info, search for version-specific CVEs
        product_version = None
        if hashlookup_info and hashlookup_info.get("found"):
            product_version = hashlookup_info.get("product_version")
            if product_version:
                print(f"[Assessment Service] ✓ Detected product version from hashlookup: {product_version}")
                print(f"[Assessment Service] Searching for version-specific CVEs...")
                version_cve_data = await self.cve_collector.search_cves(
                    entity_name, vendor_name, product_version
                )
                # Merge version-specific data into CVE results
                cve_data.update(version_cve_data)
        
        return {
            "cves": cve_data,
            "cisa_kev": cisa_kev,
            "vendor_page": vendor_page,
            "terms_of_service": tos,
            "virustotal": vt_report,
            "hashlookup": hashlookup_info,
            "incidents": incidents,
            "hash": hash  # Store hash for building URLs in citations
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

