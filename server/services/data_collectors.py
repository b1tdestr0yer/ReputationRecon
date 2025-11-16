import httpx
import os
import re
from typing import Dict, List, Optional, Any
from datetime import datetime
import asyncio
from dotenv import load_dotenv
import json

from server.utils.sanitize import remove_double_stars

# Load environment variables
load_dotenv()


class DataCollector:
    """Base class for data collectors"""
    
    def __init__(self):
        self.timeout = 30.0
        self.headers = {
            "User-Agent": "ReputationRecon/1.0 (Security Assessment Tool)"
        }
    
    async def fetch(self, url: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """Generic HTTP fetch"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout, headers=self.headers) as client:
                response = await client.get(url, params=params)
                if response.status_code == 200:
                    return response.json()
        except Exception as e:
            print(f"Error fetching {url}: {e}")
        return None


class CVECollector(DataCollector):
    """Collect CVE data from various sources"""
    
    async def search_cves(self, product_name: str, vendor_name: str, product_version: Optional[str] = None) -> Dict[str, Any]:
        """Search for CVEs related to the product using NVD API"""
        print(f"[CVE Collector] Searching CVEs for product: {product_name}, vendor: {vendor_name}, version: {product_version or 'all versions'}")
        results = {
            "total_cves": 0,
            "critical_count": 0,
            "high_count": 0,
            "recent_cves": [],
            "cisa_kev_count": 0,
            "version_specific_cves": 0,
            "version_specific_critical": 0,
            "version_specific_high": 0,
            "version_specific_recent": []
        }
        
        try:
            # Use NVD API v2 (free, no API key required)
            # Search by keyword (product name or vendor)
            search_terms = [product_name, vendor_name]
            all_cves = []
            seen_cve_ids = set()  # Track CVE IDs to avoid duplicates (normalized, case-insensitive)
            
            for term in search_terms:
                if not term or term.lower() in ["unknown", "unknown product", "unknown vendor"]:
                    print(f"[CVE Collector] Skipping invalid search term: {term}")
                    continue
                
                print(f"[CVE Collector] Searching NVD API for: {term}")
                    
                # NVD API endpoint
                url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
                params = {
                    "keywordSearch": term,
                    "resultsPerPage": 20  # Limit to recent/important ones
                }
                
                data = await self.fetch(url, params)
                if data and "vulnerabilities" in data:
                    print(f"[CVE Collector] Found {len(data['vulnerabilities'])} vulnerabilities for term: {term}")
                    for vuln in data["vulnerabilities"]:
                        cve_item = vuln.get("cve", {})
                        cve_id = cve_item.get("id", "").strip().upper()  # Normalize CVE ID
                        
                        if not cve_id:
                            continue
                        
                        # Skip if we've already seen this CVE
                        if cve_id in seen_cve_ids:
                            print(f"[CVE Collector] Skipping duplicate CVE: {cve_id}")
                            continue
                        seen_cve_ids.add(cve_id)
                        
                        # Get CVSS score
                        metrics = cve_item.get("metrics", {})
                        cvss_v3 = metrics.get("cvssMetricV31", [])
                        if not cvss_v3:
                            cvss_v3 = metrics.get("cvssMetricV30", [])
                        if not cvss_v3:
                            cvss_v3 = metrics.get("cvssMetricV2", [])
                        
                        base_score = 0.0
                        if cvss_v3:
                            base_score = float(cvss_v3[0].get("cvssData", {}).get("baseScore", 0))
                        
                        severity = "unknown"
                        if base_score >= 9.0:
                            severity = "critical"
                        elif base_score >= 7.0:
                            severity = "high"
                        
                        all_cves.append({
                            "id": cve_id,
                            "description": cve_item.get("descriptions", [{}])[0].get("value", ""),
                            "base_score": base_score,
                            "severity": severity,
                            "published": cve_item.get("published", "")
                        })
            
            # If version provided, search for version-specific CVEs
            version_specific_cve_ids = set()  # Track version-specific CVE IDs
            if product_version:
                print(f"[CVE Collector] Searching for version-specific CVEs: {product_version}")
                version_search_terms = [
                    f"{product_name} {product_version}",
                    f"{vendor_name} {product_name} {product_version}",
                    product_version
                ]
                
                for term in version_search_terms:
                    if not term or term.lower() in ["unknown", "unknown product", "unknown vendor"]:
                        continue
                    
                    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
                    params = {
                        "keywordSearch": term,
                        "resultsPerPage": 20
                    }
                    
                    version_data = await self.fetch(url, params)
                    if version_data and "vulnerabilities" in version_data:
                        for vuln in version_data["vulnerabilities"]:
                            cve_item = vuln.get("cve", {})
                            cve_id = cve_item.get("id", "").strip().upper()  # Normalize CVE ID
                            
                            if not cve_id:
                                continue
                            
                            # Mark as version-specific
                            version_specific_cve_ids.add(cve_id)
                            
                            # Get CVSS score
                            metrics = cve_item.get("metrics", {})
                            cvss_v3 = metrics.get("cvssMetricV31", [])
                            if not cvss_v3:
                                cvss_v3 = metrics.get("cvssMetricV30", [])
                            if not cvss_v3:
                                cvss_v3 = metrics.get("cvssMetricV2", [])
                            
                            base_score = 0.0
                            if cvss_v3:
                                base_score = float(cvss_v3[0].get("cvssData", {}).get("baseScore", 0))
                            
                            severity = "unknown"
                            if base_score >= 9.0:
                                severity = "critical"
                            elif base_score >= 7.0:
                                severity = "high"
                            
                            # Add to all_cves if not already present
                            if cve_id not in seen_cve_ids:
                                seen_cve_ids.add(cve_id)
                                all_cves.append({
                                    "id": cve_id,
                                    "description": cve_item.get("descriptions", [{}])[0].get("value", ""),
                                    "base_score": base_score,
                                    "severity": severity,
                                    "published": cve_item.get("published", "")
                                })
                            else:
                                print(f"[CVE Collector] Version-specific CVE {cve_id} already in main list")
            
            # Final deduplication pass (in case of any edge cases)
            # Create a dict keyed by CVE ID to ensure uniqueness
            cve_dict = {}
            for cve in all_cves:
                cve_id = cve.get("id", "").strip().upper()
                if cve_id and cve_id not in cve_dict:
                    cve_dict[cve_id] = cve
            
            unique_cves = list(cve_dict.values())
            version_specific_cves = []
            
            # Reset counts and count from unique CVEs only
            results["critical_count"] = 0
            results["high_count"] = 0
            results["version_specific_critical"] = 0
            results["version_specific_high"] = 0
            
            for cve in unique_cves:
                cve_id = cve.get("id", "").strip().upper()
                severity = cve.get("severity", "unknown")
                
                # Count critical and high
                if severity == "critical":
                    results["critical_count"] += 1
                elif severity == "high":
                    results["high_count"] += 1
                
                # Check if this CVE is version-specific
                if cve_id in version_specific_cve_ids:
                    version_specific_cves.append(cve)
                    if severity == "critical":
                        results["version_specific_critical"] += 1
                    elif severity == "high":
                        results["version_specific_high"] += 1
            
            results["total_cves"] = len(unique_cves)
            results["recent_cves"] = sorted(unique_cves, key=lambda x: x.get("published", ""), reverse=True)[:10]
            results["version_specific_cves"] = len(version_specific_cves)
            results["version_specific_recent"] = sorted(version_specific_cves, key=lambda x: x.get("published", ""), reverse=True)[:10]
            
            # verify counts are consistent
            if results["critical_count"] > results["total_cves"] or results["high_count"] > results["total_cves"]:
                print(f"[CVE Collector] ⚠ WARNING: Count mismatch detected! Total: {results['total_cves']}, Critical: {results['critical_count']}, High: {results['high_count']}")
                print(f"[CVE Collector] Debug - Unique CVE IDs: {[c.get('id') for c in unique_cves]}")
            
            print(f"[CVE Collector] CVE search complete: {results['total_cves']} total CVEs ({results['version_specific_cves']} version-specific), {results['critical_count']} critical ({results['version_specific_critical']} version-specific), {results['high_count']} high ({results['version_specific_high']} version-specific)")
            
        except Exception as e:
            print(f"[CVE Collector] ERROR searching CVEs: {e}")
        
        return results
    
    async def get_cisa_kev(self, product_name: str) -> List[Dict]:
        """Get CISA KEV entries for the product"""
        print(f"[CVE Collector] Fetching CISA KEV entries for: {product_name}")
        # CISA KEV API endpoint
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        data = await self.fetch(url, params=None)
        
        if data and "vulnerabilities" in data:
            print(f"[CVE Collector] CISA KEV catalog contains {len(data['vulnerabilities'])} total entries")
            # Filter by product name (simplified matching)
            product_lower = product_name.lower()
            matching = [
                v for v in data["vulnerabilities"]
                if product_lower in v.get("vulnerable_product", "").lower() or
                   product_lower in v.get("product", "").lower()
            ]
            print(f"[CVE Collector] Found {len(matching)} CISA KEV entries matching: {product_name}")
            return matching
        
        print(f"[CVE Collector] No CISA KEV data retrieved")
        return []


class VendorPageCollector(DataCollector):
    """Collect data from vendor security pages"""
    
    def __init__(self):
        """Initialize VendorPageCollector with optional Gemini AI support"""
        super().__init__()
        api_key = os.getenv("GEMINI_API_KEY")
        self.api_key = api_key
        if api_key:
            try:
                genai.configure(api_key=api_key)
                self.use_ai = True
                self.default_model_name = "gemini-2.5-flash-lite"
                self.pro_model_name = "gemini-2.5-pro"
                # Initialize both models
                try:
                    self.default_model = genai.GenerativeModel(self.default_model_name)
                    self.pro_model = genai.GenerativeModel(self.pro_model_name)
                    print(f"[Vendor Collector] ✓ Google Gemini configured (default: {self.default_model_name}, PRO: {self.pro_model_name})")
                except Exception as e:
                    print(f"[Vendor Collector] ✗ Error initializing Gemini models: {e}, using fallback")
                    self.default_model = None
                    self.pro_model = None
                    self.use_ai = False
            except Exception as e:
                print(f"[Vendor Collector] ✗ Error configuring Gemini: {e}, using fallback")
                self.default_model = None
                self.pro_model = None
                self.use_ai = False
        else:
            self.default_model = None
            self.pro_model = None
            self.use_ai = False
    
    def _get_model(self, pro_mode: bool = False):
        """Get the appropriate model based on mode."""
        if not self.use_ai:
            return None
        return self.pro_model if pro_mode else self.default_model
    
    async def extract_latest_version(self, vendor_page_content: str, product_name: str, vendor_name: str, vendor_url: str, pro_mode: bool = False) -> Optional[str]:
        """Extract the latest version of the software from vendor page content using Gemini"""
        model = self._get_model(pro_mode=pro_mode)
        if not self.use_ai or not model:
            print("[Vendor Collector] Gemini not available, skipping AI-based version extraction")
            return None
        
        if not vendor_page_content or not product_name:
            print("[Vendor Collector] Insufficient data for version extraction")
            return None
        
        try:
            print(f"[Vendor Collector] Using Gemini to extract latest version for: {product_name} by {vendor_name}")
            # Clean HTML content - remove script and style tags
            import re
            cleaned_content = re.sub(r'<script[^>]*>.*?</script>', '', vendor_page_content, flags=re.DOTALL | re.IGNORECASE)
            cleaned_content = re.sub(r'<style[^>]*>.*?</style>', '', cleaned_content, flags=re.DOTALL | re.IGNORECASE)
            # Remove HTML tags but keep text
            cleaned_content = re.sub(r'<[^>]+>', ' ', cleaned_content)
            # Clean up whitespace
            cleaned_content = ' '.join(cleaned_content.split())
            # Limit content length for API
            cleaned_content = cleaned_content[:15000]  # Limit to 15k chars
            
            prompt = f"""Analyze the following vendor page content and extract the latest/current version number for the software product.

Product Name: {product_name}
Vendor Name: {vendor_name}
Vendor URL: {vendor_url}

Page Content (first 15000 characters):
{cleaned_content}

Please identify the latest/current version number of {product_name}. Look for:
- Version numbers (e.g., 1.2.3, 2.0, v3.1.4, 2024.1)
- Release announcements mentioning "latest version" or "current version"
- Download pages showing version numbers
- Release notes or changelog entries

Return ONLY the version number in JSON format:
{{"version": "1.2.3"}}

If you cannot find a clear version number, return:
{{"version": null}}

Respond with ONLY valid JSON, no additional text or explanation."""

            response = model.generate_content(prompt)
            response_text = remove_double_stars(response.text.strip())
            
            # Try to extract JSON from response
            # Remove markdown code blocks if present
            if "```json" in response_text:
                response_text = response_text.split("```json")[1].split("```")[0].strip()
            elif "```" in response_text:
                response_text = response_text.split("```")[1].split("```")[0].strip()
            
            # Parse JSON
            try:
                result = json.loads(response_text)
                version = result.get("version")
                if version and version.lower() not in ["null", "none", "unknown", ""]:
                    # Clean up version string (remove "v" prefix, extra spaces, etc.)
                    version = version.strip().lstrip("vV").strip()
                    print(f"[Vendor Collector] ✓ Gemini extracted latest version: {version}")
                    return version
                else:
                    print(f"[Vendor Collector] ✗ Gemini could not find version information")
                    return None
            except json.JSONDecodeError as e:
                print(f"[Vendor Collector] ✗ Failed to parse Gemini JSON response: {e}")
                print(f"[Vendor Collector] Response was: {response_text[:200]}")
                return None
                
        except Exception as e:
            print(f"[Vendor Collector] ✗ Error using Gemini for version extraction: {e}")
            return None
    
    async def fetch_security_page(self, vendor_url: str) -> Optional[Dict]:
        """Try to find and fetch vendor security/PSIRT page"""
        print(f"[Vendor Collector] Searching for security page at: {vendor_url}")
        # Common security page paths
        security_paths = [
            "/security",
            "/security/overview",
            "/trust",
            "/compliance",
            "/security/psirt",
            "/security/advisories",
            "/about/security",
            "/security-center"
        ]
        
        base_url = vendor_url.rstrip('/')
        for path in security_paths:
            url = base_url + path
            try:
                async with httpx.AsyncClient(timeout=self.timeout, headers=self.headers, follow_redirects=True) as client:
                    response = await client.get(url)
                    if response.status_code == 200:
                        content = response.text[:20000]  # First 20k chars
                        print(f"[Vendor Collector] ✓ Found security page: {url}")
                        return {
                            "url": url,
                            "content": content,
                            "found": True,
                            "status_code": response.status_code
                        }
                    else:
                        print(f"[Vendor Collector] Security page not found at {url} (status: {response.status_code})")
            except Exception as e:
                print(f"[Vendor Collector] Error checking {url}: {e}")
                continue
        
        # Try fetching main page and look for security links
        try:
            async with httpx.AsyncClient(timeout=self.timeout, headers=self.headers, follow_redirects=True) as client:
                response = await client.get(base_url)
                if response.status_code == 200:
                    content = response.text[:20000]
                    # Look for security-related keywords
                    if any(keyword in content.lower() for keyword in ["security", "trust", "compliance", "soc2", "iso"]):
                        print(f"[Vendor Collector] ✓ Found security info on main page: {base_url}")
                        return {
                            "url": base_url,
                            "content": content,
                            "found": True,
                            "status_code": response.status_code
                        }
        except Exception as e:
            print(f"[Vendor Collector] Error checking main page: {e}")
        
        print(f"[Vendor Collector] ✗ No security page found for: {vendor_url}")
        return None
    
    async def fetch_terms_of_service(self, vendor_url: str) -> Optional[Dict]:
        """Try to fetch Terms of Service or Data Processing Agreement"""
        print(f"[Vendor Collector] Searching for Terms of Service at: {vendor_url}")
        tos_paths = [
            "/terms",
            "/terms-of-service",
            "/legal/terms",
            "/privacy",
            "/data-processing-agreement",
            "/legal/privacy",
            "/privacy-policy",
            "/terms-and-conditions",
            "/legal"
        ]
        
        base_url = vendor_url.rstrip('/')
        for path in tos_paths:
            url = base_url + path
            try:
                async with httpx.AsyncClient(timeout=self.timeout, headers=self.headers, follow_redirects=True) as client:
                    response = await client.get(url)
                    if response.status_code == 200:
                        content = response.text[:20000]
                        print(f"[Vendor Collector] ✓ Found Terms of Service: {url}")
                        return {
                            "url": url,
                            "content": content,
                            "found": True,
                            "status_code": response.status_code
                        }
                    else:
                        print(f"[Vendor Collector] Terms not found at {url} (status: {response.status_code})")
            except Exception as e:
                print(f"[Vendor Collector] Error checking {url}: {e}")
                continue
        
        print(f"[Vendor Collector] ✗ No Terms of Service found for: {vendor_url}")
        return None


class VirusTotalCollector(DataCollector):
    """Collect comprehensive data from VirusTotal using v3 API"""
    
    async def _fetch_v3(self, endpoint: str, api_key: str) -> Optional[Dict]:
        """Helper method to fetch from VirusTotal v3 API"""
        url = f"https://www.virustotal.com/api/v3{endpoint}"
        headers = {
            **self.headers,
            "x-apikey": api_key
        }
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout, headers=headers) as client:
                response = await client.get(url)
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 404:
                    return None
                elif response.status_code == 429:
                    print(f"[VirusTotal Collector] ⚠ Rate limit exceeded")
                    return None
                else:
                    print(f"[VirusTotal Collector] ⚠ API returned status {response.status_code} for {endpoint}")
                    return None
        except Exception as e:
            print(f"[VirusTotal Collector] ✗ Error fetching {endpoint}: {e}")
            return None
    
    async def get_file_report(self, hash: str) -> Optional[Dict]:
        """Get comprehensive VirusTotal file report using v3 API with multiple endpoints"""
        print(f"[VirusTotal Collector] Fetching v3 report for hash: {hash[:16]}...")
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not api_key:
            print("[VirusTotal Collector] ✗ VIRUSTOTAL_API_KEY not configured, skipping")
            return None
        
        # Fetch main file report
        file_data = await self._fetch_v3(f"/files/{hash}", api_key)
        if not file_data:
            print(f"[VirusTotal Collector] Hash not found in VirusTotal database")
            return {"response_code": 0, "message": "Hash not found"}
        
        # Extract attributes from v3 response
        attributes = file_data.get("data", {}).get("attributes", {})
        
        # Get analysis stats
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        malicious = last_analysis_stats.get("malicious", 0)
        suspicious = last_analysis_stats.get("suspicious", 0)
        harmless = last_analysis_stats.get("harmless", 0)
        undetected = last_analysis_stats.get("undetected", 0)
        total_engines = malicious + suspicious + harmless + undetected
        positives = malicious + suspicious
        
        # Get reputation
        reputation = attributes.get("reputation", 0)
        
        # Get threat classification
        threat_names = []
        popular_threat = attributes.get("popular_threat_classification", {})
        if popular_threat:
            threat_label = popular_threat.get("suggested_threat_label", "")
            if threat_label:
                threat_names = [threat_label] if isinstance(threat_label, str) else threat_label
        
        # Get community votes
        community_votes = attributes.get("community_votes", {})
        community_harmless = community_votes.get("harmless", 0)
        community_malicious = community_votes.get("malicious", 0)
        
        # Get file metadata
        type_description = attributes.get("type_description", "")
        type_extension = attributes.get("type_extension", "")
        meaningful_name = attributes.get("meaningful_name", "")
        size = attributes.get("size", 0)
        tags = attributes.get("tags", [])
        names = attributes.get("names", [])
        first_submission = attributes.get("first_submission_date", 0)
        
        # Get last analysis results (detailed engine results)
        last_analysis_results = attributes.get("last_analysis_results", {})
        
        # Get sandbox verdicts
        sandbox_verdicts = attributes.get("sandbox_verdicts", {})
        
        # Get behavior data
        sigma_analysis_stats = attributes.get("sigma_analysis_stats", {})
        crowdsourced_yara_results = attributes.get("crowdsourced_yara_results", [])
        
        # Fetch additional data from other v3 endpoints
        comments_data = await self._fetch_v3(f"/files/{hash}/comments", api_key)
        comments = []
        community_notes = []
        if comments_data and "data" in comments_data:
            all_comments = comments_data.get("data", [])
            comments = all_comments[:5]  # Limit to 5 most recent for backward compatibility
            # Extract community notes (all comments with text)
            community_notes = [
                {
                    "text": c.get("attributes", {}).get("text", ""),
                    "date": c.get("attributes", {}).get("date", 0),
                    "votes": c.get("attributes", {}).get("votes", {}),
                    "author": c.get("attributes", {}).get("author", "")
                }
                for c in all_comments[:20]  # Get up to 20 community notes
                if c.get("attributes", {}).get("text", "").strip()
            ]
        
        # Fetch relationships (related files, URLs, etc.)
        relationships_data = await self._fetch_v3(f"/files/{hash}/relationships", api_key)
        relationships = {}
        if relationships_data and "data" in relationships_data:
            relationships = relationships_data.get("data", {})
        
        # Fetch submission history (if endpoint exists)
        submission_history = []
        try:
            history_data = await self._fetch_v3(f"/files/{hash}/history", api_key)
            if history_data and "data" in history_data:
                history_items = history_data.get("data", [])
                submission_history = [
                    {
                        "date": item.get("attributes", {}).get("date", 0),
                        "submission_names": item.get("attributes", {}).get("submission_names", []),
                        "submission_names_count": item.get("attributes", {}).get("submission_names_count", 0),
                        "submission_id": item.get("id", "")
                    }
                    for item in history_items[:10]  # Get up to 10 most recent submissions
                ]
        except Exception as e:
            # History endpoint might not be available or might fail
            # We'll use names from attributes as fallback
            pass
        
        # If no history from endpoint, use names from attributes as submission history
        if not submission_history and names:
            submission_history = [
                {
                    "date": first_submission if first_submission > 0 else attributes.get("last_submission_date", 0),
                    "submission_names": names[:10],
                    "submission_names_count": len(names),
                    "submission_id": ""
                }
            ]
        
        # Extract executable name from various sources
        exe_name = None
        # Try meaningful_name first (most reliable)
        if meaningful_name:
            exe_name = meaningful_name
        # Try names array (common file names)
        elif names and len(names) > 0:
            # Filter for .exe files or take the first one
            exe_names = [n for n in names if n.lower().endswith('.exe')]
            if exe_names:
                exe_name = exe_names[0]
            else:
                exe_name = names[0]
        # Try from submission history
        if not exe_name and submission_history:
            for hist_item in submission_history:
                submission_names = hist_item.get("submission_names", [])
                if submission_names:
                    exe_names = [n for n in submission_names if n.lower().endswith('.exe')]
                    if exe_names:
                        exe_name = exe_names[0]
                        break
                    exe_name = submission_names[0]
                    break
        
        # Extract version information from VT data (details, history, comments)
        detected_version = None
        version_confidence = 0.0
        
        # Try to extract version from file names
        version_patterns = [
            r'[vV]?(\d+\.\d+\.\d+\.\d+)',  # 1.2.3.4
            r'[vV]?(\d+\.\d+\.\d+)',       # 1.2.3
            r'[vV]?(\d+\.\d+)',            # 1.2
            r'[vV](\d+)',                  # v1
        ]
        
        version_candidates = {}
        
        # Check meaningful_name
        if meaningful_name:
            for pattern in version_patterns:
                match = re.search(pattern, meaningful_name)
                if match:
                    version = match.group(1)
                    version_candidates[version] = version_candidates.get(version, 0) + 3  # High weight
                    break
        
        # Check names array
        for name in names[:10]:  # Check first 10 names
            for pattern in version_patterns:
                match = re.search(pattern, name)
                if match:
                    version = match.group(1)
                    version_candidates[version] = version_candidates.get(version, 0) + 2  # Medium weight
                    break
        
        # Check submission history names
        for hist_item in submission_history:
            submission_names = hist_item.get("submission_names", [])
            for name in submission_names[:5]:  # Check first 5 names per submission
                for pattern in version_patterns:
                    match = re.search(pattern, name)
                    if match:
                        version = match.group(1)
                        version_candidates[version] = version_candidates.get(version, 0) + 1  # Lower weight
                        break
        
        # Check community notes for version mentions
        for note in community_notes:
            note_text = note.get("text", "")
            for pattern in version_patterns:
                match = re.search(pattern, note_text)
                if match:
                    version = match.group(1)
                    version_candidates[version] = version_candidates.get(version, 0) + 1  # Lower weight
                    break
        
        # Select most common/weighted version
        if version_candidates:
            detected_version = max(version_candidates.items(), key=lambda x: x[1])[0]
            max_weight = max(version_candidates.values())
            # Calculate confidence based on weight and frequency
            if max_weight >= 3:
                version_confidence = 0.8  # High confidence from meaningful_name
            elif max_weight >= 2:
                version_confidence = 0.6  # Medium confidence from names
            else:
                version_confidence = 0.4  # Lower confidence from history/notes
            
            # Boost confidence if version appears multiple times
            if version_candidates[detected_version] > 1:
                version_confidence = min(0.95, version_confidence + 0.1)
        
        # Get additional file details
        file_details = {
            "exiftool": attributes.get("exiftool", {}),
            "pe_info": attributes.get("pe_info", {}),
            "trid": attributes.get("trid", []),
            "magic": attributes.get("magic", ""),
            "creation_date": attributes.get("creation_date", 0),
            "signature_info": attributes.get("signature_info", {}),
            "authentihash": attributes.get("authentihash", ""),
            "ssdeep": attributes.get("ssdeep", ""),
            "tlsh": attributes.get("tlsh", ""),
            "vhash": attributes.get("vhash", ""),
        }
        
        # Extract version from PE info if available
        if not detected_version and file_details.get("pe_info"):
            pe_info = file_details["pe_info"]
            # Try to get version from PE version info
            if isinstance(pe_info, dict):
                version_info = pe_info.get("version_info", {})
                if isinstance(version_info, dict):
                    file_version = version_info.get("FileVersion") or version_info.get("ProductVersion")
                    if file_version:
                        # Clean up version string
                        version_match = re.search(r'(\d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+|\d+\.\d+)', str(file_version))
                        if version_match:
                            detected_version = version_match.group(1)
                            version_confidence = 0.9  # High confidence from PE info
        
        # Calculate detection metrics
        detection_consensus = positives / total_engines if total_engines > 0 else 0.0
        reputation_confidence = min(1.0, total_engines / 70.0)
        
        # Enhanced false positive detection
        false_positive_indicators = []
        if positives > 0:
            # Few detections with many engines = potential FP
            if positives <= 3 and total_engines > 50:
                false_positive_indicators.append("few_detections")
            # Mostly suspicious vs malicious = less certain
            if suspicious > malicious * 2:
                false_positive_indicators.append("mostly_suspicious")
            # High reputation but detections = potential FP
            if reputation > 50 and positives < 5:
                false_positive_indicators.append("high_rep_with_detections")
            # Community says harmless but engines flagged
            if community_harmless > community_malicious * 2 and positives < 10:
                false_positive_indicators.append("community_disagrees")
        
        # Enhanced risk assessment
        risk_level = "unknown"
        risk_confidence = 0.5
        risk_rationale = []
        risk_flags = []
        
        flag_ratio = detection_consensus
        has_fp_indicators = len(false_positive_indicators) > 0
        
        if positives == 0 and total_engines > 0:
            risk_level = "clean"
            risk_flags.append("no_detections")
            risk_confidence = 0.85 if total_engines > 50 else 0.65
            risk_rationale.append(f"Clean scan: 0/{total_engines} engines flagged")
            if reputation > 50:
                risk_confidence = 0.95
                risk_rationale.append(f"High reputation score ({reputation})")
        elif positives > 0:
            # High detection rate (>30%)
            if flag_ratio > 0.3:
                if not has_fp_indicators:
                    risk_level = "critical"
                    risk_confidence = 0.90
                    risk_flags.append("high_detection_rate")
                    risk_rationale.append(f"High detection rate: {positives}/{total_engines} ({flag_ratio:.1%}) engines flagged")
                else:
                    risk_level = "high"
                    risk_confidence = 0.70
                    risk_flags.append("high_detection_rate_with_fp_indicators")
                    risk_rationale.append(f"High detection rate ({flag_ratio:.1%}) but false positive indicators present")
            # Moderate detection rate (10-30%)
            elif flag_ratio > 0.1:
                if malicious > suspicious * 2:
                    risk_level = "high" if not has_fp_indicators else "medium"
                    risk_confidence = 0.80 if not has_fp_indicators else 0.60
                    risk_flags.append("moderate_detection_rate_malicious")
                    risk_rationale.append(f"Moderate detection rate ({flag_ratio:.1%}), primarily malicious ({malicious} malicious, {suspicious} suspicious)")
                else:
                    risk_level = "medium" if not has_fp_indicators else "low"
                    risk_confidence = 0.70 if not has_fp_indicators else 0.55
                    risk_flags.append("moderate_detection_rate")
                    risk_rationale.append(f"Moderate detection rate ({flag_ratio:.1%}), mostly suspicious detections")
            # Low detection rate (<10%)
            else:
                if has_fp_indicators:
                    risk_level = "low"
                    risk_confidence = 0.60
                    risk_flags.append("low_detection_rate_likely_fp")
                    risk_rationale.append(f"Low detection rate ({flag_ratio:.1%}) with false positive indicators - likely benign")
                elif malicious > 0:
                    risk_level = "low"
                    risk_confidence = 0.65
                    risk_flags.append("low_detection_rate_some_malicious")
                    risk_rationale.append(f"Low detection rate ({flag_ratio:.1%}) but includes {malicious} malicious detections")
                else:
                    risk_level = "low"
                    risk_confidence = 0.70
                    risk_flags.append("low_detection_rate_suspicious_only")
                    risk_rationale.append(f"Low detection rate ({flag_ratio:.1%}), only suspicious detections")
            
            if malicious > suspicious:
                risk_flags.append("primarily_malicious")
            else:
                risk_flags.append("primarily_suspicious")
        
        # Reputation impact
        if reputation < -50:
            risk_flags.append("very_low_reputation")
            if risk_level in ["clean", "low", "unknown"]:
                risk_level = "high"
                risk_confidence = max(risk_confidence, 0.75)
            risk_rationale.append(f"Very low reputation score ({reputation})")
        elif reputation < 0:
            risk_flags.append("negative_reputation")
            if risk_level == "clean":
                risk_level = "low"
                risk_confidence = 0.65
            risk_rationale.append(f"Negative reputation score ({reputation})")
        elif reputation > 50 and positives > 0:
            risk_confidence = max(0.5, risk_confidence - 0.15)
            risk_rationale.append(f"High reputation ({reputation}) conflicts with detections - possible false positive")
        
        # Threat classification impact
        if threat_names:
            risk_flags.append("threat_classified")
            if risk_level in ["clean", "low"]:
                risk_level = "medium"
                risk_confidence = 0.75
            risk_rationale.append(f"Threat classified: {', '.join(threat_names[:2])}")
        
        # Community votes impact
        total_community_votes = community_harmless + community_malicious
        if total_community_votes > 0:
            community_ratio = community_malicious / total_community_votes
            if community_ratio > 0.7:
                risk_flags.append("community_flagged_malicious")
                if risk_level in ["clean", "low"]:
                    risk_level = "medium"
                    risk_confidence = 0.70
                risk_rationale.append(f"Community votes: {community_malicious}/{total_community_votes} flagged as malicious")
            elif community_ratio < 0.3 and positives > 0:
                risk_confidence = max(0.5, risk_confidence - 0.10)
                risk_rationale.append(f"Community votes suggest harmless ({community_harmless}/{total_community_votes}) despite engine detections")
        
        # Sandbox verdicts boost confidence
        if sandbox_verdicts:
            risk_flags.append("sandbox_analysis_available")
            risk_confidence = min(1.0, risk_confidence + 0.10)
        
        # File age and history
        first_submission = attributes.get("first_submission_date", 0)
        if first_submission > 0 and total_engines > 60 and positives == 0:
            risk_confidence = min(1.0, risk_confidence + 0.05)
            risk_rationale.append("Well-scanned file with extensive history")
        
        # Build comprehensive response
        normalized_data = {
            "response_code": 1,
            "positives": positives,
            "total": total_engines,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "reputation": reputation,
            "reputation_confidence": reputation_confidence,
            "threat_names": threat_names,
            "community_harmless": community_harmless,
            "community_malicious": community_malicious,
            "type_description": type_description,
            "type_extension": type_extension,
            "meaningful_name": meaningful_name,
            "tags": tags,
            "names": names[:5],
            "size": size,
            "sandbox_verdicts": sandbox_verdicts,
            "last_analysis_results": last_analysis_results,
            "sigma_analysis_stats": sigma_analysis_stats,
            "crowdsourced_yara_results": crowdsourced_yara_results,
            "comments": comments,
            "community_notes": community_notes,
            "submission_history": submission_history,
            "relationships": relationships,
            "detection_consensus": detection_consensus,
            "false_positive_indicators": false_positive_indicators,
            "risk_level": risk_level,
            "risk_confidence": risk_confidence,
            "risk_rationale": risk_rationale,
            "risk_flags": risk_flags,
            "sha256": attributes.get("sha256", ""),
            "sha1": attributes.get("sha1", ""),
            "md5": attributes.get("md5", ""),
            "first_submission_date": first_submission,
            "last_submission_date": attributes.get("last_submission_date", 0),
            "last_analysis_date": attributes.get("last_analysis_date", 0),
            "exe_name": exe_name,
            "detected_version": detected_version,
            "version_confidence": version_confidence,
            "file_details": file_details,
            "v3_api": True
        }
        
        # Log additional information
        log_parts = [f"{positives}/{total_engines} flagged ({malicious} malicious, {suspicious} suspicious)"]
        log_parts.append(f"reputation: {reputation}")
        log_parts.append(f"risk: {risk_level} (confidence: {int(risk_confidence*100)}%)")
        if exe_name:
            log_parts.append(f"exe: {exe_name}")
        if detected_version:
            log_parts.append(f"version: {detected_version} (confidence: {int(version_confidence*100)}%)")
        if community_notes:
            log_parts.append(f"community notes: {len(community_notes)}")
        if submission_history:
            log_parts.append(f"submissions: {len(submission_history)}")
        
        print(f"[VirusTotal Collector] ✓ v3 Report: {', '.join(log_parts)}")
        
        return normalized_data
    
    async def search_file(self, query: str) -> Optional[Dict]:
        """Search VirusTotal for files using v3 API"""
        print(f"[VirusTotal Collector] Searching v3 for: {query[:50]}...")
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not api_key:
            print("[VirusTotal Collector] ✗ VIRUSTOTAL_API_KEY not configured, skipping")
            return None
        
        search_data = await self._fetch_v3(f"/search?query={query}&limit=10", api_key)
        if search_data and "data" in search_data:
            results = search_data.get("data", [])
            print(f"[VirusTotal Collector] ✓ Search found {len(results)} results")
            return {"results": results, "count": len(results)}
        
        return None


class CIRCLHashlookupCollector(DataCollector):
    """Collect version information from CIRCL hashlookup"""
    
    async def get_file_info(self, hash: str) -> Optional[Dict]:
        """Get file information including version from CIRCL hashlookup"""
        print(f"[CIRCL Hashlookup] Fetching file info for hash: {hash[:16]}...")
        
        # Determine hash type and normalize
        hash_upper = hash.upper().strip()
        hash_type = None
        
        if len(hash_upper) == 32:
            hash_type = "md5"
        elif len(hash_upper) == 40:
            hash_type = "sha1"
        elif len(hash_upper) == 64:
            hash_type = "sha256"
        else:
            print(f"[CIRCL Hashlookup] ✗ Unsupported hash length: {len(hash_upper)}")
            return None
        
        url = f"https://hashlookup.circl.lu/lookup/{hash_type}/{hash_upper}"
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout, headers=self.headers) as client:
                response = await client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    print(f"[CIRCL Hashlookup] ✓ File info retrieved")
                    
                    # Extract version information
                    version_info = {
                        "found": True,
                        "filename": data.get("FileName", ""),
                        "filesize": data.get("FileSize", ""),
                        "product_name": "",
                        "product_version": "",
                        "source": data.get("source", ""),
                        "trust": data.get("hashlookup:trust", 50)
                    }
                    
                    # Extract product information - try multiple possible structures
                    product_code = data.get("ProductCode")
                    if product_code:
                        # Handle ProductCode as a dictionary/object
                        if isinstance(product_code, dict):
                            version_info["product_name"] = (product_code.get("ProductName", "") or product_code.get("product_name", "")).strip()
                            version_info["product_version"] = (product_code.get("ProductVersion", "") or product_code.get("product_version", "")).strip()
                        # Handle ProductCode as a string (some APIs return it this way)
                        elif isinstance(product_code, str):
                            # Try to extract from string format if needed
                            version_info["product_name"] = product_code.strip()
                    
                    # Also check for direct fields in the response (some APIs structure differently)
                    if not version_info["product_version"]:
                        version_info["product_version"] = (
                            data.get("ProductVersion", "") or 
                            data.get("product_version", "") or
                            data.get("Version", "") or
                            data.get("version", "") or
                            data.get("FileVersion", "") or
                            data.get("file_version", "")
                        ).strip()
                    
                    if not version_info["product_name"]:
                        version_info["product_name"] = (
                            data.get("ProductName", "") or
                            data.get("product_name", "") or
                            data.get("Name", "") or
                            data.get("name", "")
                        ).strip()
                    
                    if version_info["product_name"] or version_info["product_version"]:
                        print(f"[CIRCL Hashlookup] ✓ Found product: {version_info['product_name']} version {version_info['product_version']}")
                    else:
                        print(f"[CIRCL Hashlookup] ⚠ No product version information found")
                        # Debug: print available keys to help diagnose
                        print(f"[CIRCL Hashlookup] Debug - Available keys in response: {list(data.keys())[:10]}")
                    
                    return version_info
                elif response.status_code == 404:
                    print(f"[CIRCL Hashlookup] Hash not found in database")
                    return None
                else:
                    print(f"[CIRCL Hashlookup] ✗ API returned status {response.status_code}")
                    return None
        except Exception as e:
            print(f"[CIRCL Hashlookup] ✗ Error fetching file info: {e}")
            return None


class WebSearchCollector(DataCollector):
    """Collect data from web searches (for incidents, news, etc.)"""
    
    async def search_incidents(self, product_name: str, vendor_name: str) -> List[Dict]:
        """Search for security incidents related to the product"""
        # In production, you'd use a search API like Google Custom Search, Bing, etc.
        # For now, return placeholder
        return []
    
    async def search_advisories(self, product_name: str) -> List[Dict]:
        """Search for security advisories"""
        # Would integrate with CERT databases, vendor advisories, etc.
        return []


class BugBountyCollector(DataCollector):
    """Collect public bug bounty reports from HackerOne and Bugcrowd"""
    
    async def search_hackerone(self, product_name: str, vendor_name: str) -> List[Dict]:
        """Search HackerOne public hacktivity for bug reports"""
        print(f"[Bug Bounty Collector] Searching HackerOne for: {product_name}, {vendor_name}")
        reports = []
        
        try:
            # HackerOne public hacktivity API endpoint
            # Search terms: product name and vendor name
            search_terms = [product_name, vendor_name]
            
            for term in search_terms:
                if not term or term.lower() in ["unknown", "unknown product", "unknown vendor"]:
                    continue
                
                # HackerOne hacktivity search (public endpoint)
                # Note: This is a simplified search - in production you might need API key for more results
                url = "https://hackerone.com/hacktivity"
                params = {
                    "querystring": term,
                    "type": "public"
                }
                
                # Use web search approach since HackerOne doesn't have a simple public API
                # We'll search for public reports via their hacktivity page
                search_url = f"https://hackerone.com/hacktivity?querystring={term.replace(' ', '+')}"
                
                try:
                    async with httpx.AsyncClient(timeout=self.timeout, headers=self.headers, follow_redirects=True) as client:
                        response = await client.get(search_url)
                        if response.status_code == 200:
                            content = response.text
                            
                            # Parse HTML to extract report information
                            # Look for report links and titles
                            # Find report links (simplified pattern)
                            report_pattern = r'href="(/reports/[^"]+)"'
                            title_pattern = r'<a[^>]*href="/reports/[^"]+"[^>]*>([^<]+)</a>'
                            
                            report_links = re.findall(report_pattern, content)
                            titles = re.findall(title_pattern, content)
                            
                            for i, link in enumerate(report_links[:10]):  # Limit to 10 reports
                                report_url = f"https://hackerone.com{link}"
                                title = titles[i] if i < len(titles) else "Bug Report"
                                
                                reports.append({
                                    "platform": "HackerOne",
                                    "title": title,
                                    "url": report_url,
                                    "product": term
                                })
                            
                            if report_links:
                                print(f"[Bug Bounty Collector] Found {len(report_links)} HackerOne reports for: {term}")
                except Exception as e:
                    print(f"[Bug Bounty Collector] Error searching HackerOne for {term}: {e}")
        
        except Exception as e:
            print(f"[Bug Bounty Collector] Error in HackerOne search: {e}")
        
        return reports
    
    async def search_bugcrowd(self, product_name: str, vendor_name: str) -> List[Dict]:
        """Search Bugcrowd public vulnerability disclosures"""
        print(f"[Bug Bounty Collector] Searching Bugcrowd for: {product_name}, {vendor_name}")
        reports = []
        
        try:
            search_terms = [product_name, vendor_name]
            
            for term in search_terms:
                if not term or term.lower() in ["unknown", "unknown product", "unknown vendor"]:
                    continue
                
                # Bugcrowd public vulnerability disclosure search
                search_url = f"https://bugcrowd.com/disclosures?q={term.replace(' ', '+')}"
                
                try:
                    async with httpx.AsyncClient(timeout=self.timeout, headers=self.headers, follow_redirects=True) as client:
                        response = await client.get(search_url)
                        if response.status_code == 200:
                            content = response.text
                            
                            # Parse HTML to extract disclosure information
                            # Find disclosure links
                            disclosure_pattern = r'href="(/[^"]+/disclosure/[^"]+)"'
                            title_pattern = r'<a[^>]*href="/[^"]+/disclosure/[^"]+"[^>]*>([^<]+)</a>'
                            
                            disclosure_links = re.findall(disclosure_pattern, content)
                            titles = re.findall(title_pattern, content)
                            
                            for i, link in enumerate(disclosure_links[:10]):  # Limit to 10 reports
                                report_url = f"https://bugcrowd.com{link}"
                                title = titles[i] if i < len(titles) else "Vulnerability Disclosure"
                                
                                reports.append({
                                    "platform": "Bugcrowd",
                                    "title": title,
                                    "url": report_url,
                                    "product": term
                                })
                            
                            if disclosure_links:
                                print(f"[Bug Bounty Collector] Found {len(disclosure_links)} Bugcrowd reports for: {term}")
                except Exception as e:
                    print(f"[Bug Bounty Collector] Error searching Bugcrowd for {term}: {e}")
        
        except Exception as e:
            print(f"[Bug Bounty Collector] Error in Bugcrowd search: {e}")
        
        return reports
    
    async def search_bug_bounties(self, product_name: str, vendor_name: str) -> Dict[str, Any]:
        """Search both HackerOne and Bugcrowd for public bug bounty reports"""
        print(f"[Bug Bounty Collector] Searching bug bounty platforms for: {product_name} ({vendor_name})")
        
        # Search both platforms in parallel
        hackerone_reports = await self.search_hackerone(product_name, vendor_name)
        bugcrowd_reports = await self.search_bugcrowd(product_name, vendor_name)
        
        all_reports = hackerone_reports + bugcrowd_reports
        
        # Remove duplicates based on URL
        seen_urls = set()
        unique_reports = []
        for report in all_reports:
            url = report.get("url", "")
            if url and url not in seen_urls:
                seen_urls.add(url)
                unique_reports.append(report)
        
        result = {
            "total_reports": len(unique_reports),
            "hackerone_count": len(hackerone_reports),
            "bugcrowd_count": len(bugcrowd_reports),
            "reports": unique_reports
        }
        
        print(f"[Bug Bounty Collector] ✓ Found {len(unique_reports)} total bug bounty reports ({len(hackerone_reports)} HackerOne, {len(bugcrowd_reports)} Bugcrowd)")
        
        return result


class EntityResolver:
    """Resolve entity and vendor identity from input"""
    
    def __init__(self):
        """Initialize EntityResolver with Vertex AI REST API support"""
        self.api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        self.default_model = "gemini-2.5-flash-lite"  # Default to flash-lite for speed
        self.pro_model = "gemini-2.5-pro"  # PRO model
        self.base_url = "https://aiplatform.googleapis.com/v1/publishers/google/models"
        
        if self.api_key:
            self.use_ai = True
            print(f"[Entity Resolver] ✓ Vertex AI configured for URL resolution (default: {self.default_model}, PRO: {self.pro_model})")
        else:
            self.use_ai = False
            print("[Entity Resolver] ✗ No API key found, using fallback resolution")
    
    def _get_model_name(self, pro_mode: bool = False) -> str:
        """Get the appropriate model name based on mode."""
        return self.pro_model if pro_mode else self.default_model
    
    async def _call_vertex_ai(self, prompt: str, model_name: Optional[str] = None) -> Optional[str]:
        """Call Vertex AI REST API and return the generated text.
        
        Uses the Vertex AI REST API endpoint as documented at:
        https://docs.cloud.google.com/vertex-ai/generative-ai/docs/model-reference/inference
        """
        if not self.use_ai or not self.api_key:
            return None
        
        try:
            # Use generateContent (non-streaming) endpoint
            # Format: https://aiplatform.googleapis.com/v1/publishers/google/models/{model}:generateContent
            model = model_name or self.default_model
            url = f"{self.base_url}/{model}:generateContent"
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
                
                print(f"[Entity Resolver] ⚠ Unexpected response format: {json.dumps(data)[:200]}")
                return None
                
        except httpx.HTTPStatusError as e:
            error_text = e.response.text[:500] if hasattr(e.response, 'text') else str(e)
            print(f"[Entity Resolver] ⚠ HTTP error calling Vertex AI: {e.response.status_code} - {error_text}")
            return None
        except Exception as e:
            print(f"[Entity Resolver] ⚠ Error calling Vertex AI: {e}")
            return None
    
    async def resolve_vendor_url_with_gemini(self, product_name: Optional[str], vendor_name: Optional[str], pro_mode: bool = False) -> Optional[str]:
        """Use Vertex AI to resolve the vendor's official website URL"""
        if not self.use_ai:
            print("[Entity Resolver] Vertex AI not available, skipping AI-based URL resolution")
            return None
        
        if not vendor_name or vendor_name.lower() in ["unknown vendor", "unknown", ""]:
            print("[Entity Resolver] No valid vendor name provided for AI resolution")
            return None
        
        try:
            print(f"[Entity Resolver] Using Vertex AI to resolve vendor URL for: {vendor_name} / {product_name}")
            prompt = f"""Given the following vendor and product information, provide the official website URL for the vendor.

Vendor Name: {vendor_name}
Product Name: {product_name or 'Not specified'}

Please provide ONLY the official website URL (e.g., https://www.company.com) in JSON format:
{{"url": "https://www.example.com"}}

If you cannot determine the URL with high confidence, return:
{{"url": null}}

Respond with ONLY valid JSON, no additional text or explanation."""

            model_name = self._get_model_name(pro_mode=pro_mode)
            response_text = await self._call_vertex_ai(prompt, model_name=model_name)
            if not response_text:
                print("[Entity Resolver] ✗ Empty response from Vertex AI")
                return None
            
            response_text = response_text.strip()
            
            # Try to extract JSON from response
            # Remove markdown code blocks if present
            if "```json" in response_text:
                response_text = response_text.split("```json")[1].split("```")[0].strip()
            elif "```" in response_text:
                response_text = response_text.split("```")[1].split("```")[0].strip()
            
            # Parse JSON
            try:
                result = json.loads(response_text)
                resolved_url = result.get("url")
                if resolved_url and resolved_url.startswith("http"):
                    print(f"[Entity Resolver] ✓ Vertex AI resolved vendor URL: {resolved_url}")
                    return resolved_url
                else:
                    print(f"[Entity Resolver] ✗ Vertex AI returned invalid URL: {resolved_url}")
                    return None
            except json.JSONDecodeError as e:
                print(f"[Entity Resolver] ✗ Failed to parse Vertex AI JSON response: {e}")
                print(f"[Entity Resolver] Response was: {response_text[:200]}")
                return None
                
        except Exception as e:
            print(f"[Entity Resolver] ✗ Error using Vertex AI for URL resolution: {e}")
            return None
    
    async def resolve(self, product_name: Optional[str] = None,
                     vendor_name: Optional[str] = None,
                     url: Optional[str] = None,
                     pro_mode: bool = False) -> Dict[str, str]:
        """Resolve entity and vendor names, and optionally resolve vendor URL using Vertex AI"""
        print(f"[Entity Resolver] Resolving entity - product: {product_name}, vendor: {vendor_name}, url: {url}")
        resolved_entity = product_name or ""
        resolved_vendor = vendor_name or ""
        resolved_url = url or ""
        
        # If no URL provided, try to resolve it using Vertex AI
        if not resolved_url and resolved_vendor and resolved_vendor.lower() not in ["unknown vendor", "unknown", ""]:
            print(f"[Entity Resolver] No URL provided, attempting to resolve using Vertex AI...")
            ai_url = await self.resolve_vendor_url_with_gemini(resolved_entity, resolved_vendor, pro_mode=pro_mode)
            if ai_url:
                resolved_url = ai_url
        
        # If URL provided, try to extract vendor/product info
        if resolved_url:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(resolved_url)
                domain = parsed.netloc or parsed.path.split('/')[0]
                domain = domain.replace("www.", "")
                
                # Extract company name from domain
                domain_parts = domain.split(".")
                if len(domain_parts) >= 2:
                    company_name = domain_parts[0].title()
                    
                    # Common domain mappings
                    domain_mappings = {
                        "slack": ("Slack", "Salesforce"),
                        "microsoft": ("Microsoft", "Microsoft"),
                        "google": ("Google", "Alphabet"),
                        "salesforce": ("Salesforce", "Salesforce"),
                        "adobe": ("Adobe", "Adobe"),
                        "oracle": ("Oracle", "Oracle"),
                        "ibm": ("IBM", "IBM"),
                        "amazon": ("AWS", "Amazon"),
                        "github": ("GitHub", "Microsoft"),
                    }
                    
                    domain_lower = domain_parts[0].lower()
                    if domain_lower in domain_mappings:
                        resolved_entity, resolved_vendor = domain_mappings[domain_lower]
                        print(f"[Entity Resolver] ✓ Mapped domain to known vendor: {resolved_entity} / {resolved_vendor}")
                    else:
                        if not resolved_vendor:
                            resolved_vendor = company_name
                        if not resolved_entity:
                            resolved_entity = company_name
                        print(f"[Entity Resolver] Extracted from domain: {resolved_entity} / {resolved_vendor}")
                
                if not resolved_vendor:
                    resolved_vendor = domain.split(".")[0].title()
                if not resolved_entity:
                    resolved_entity = resolved_vendor
                    
            except Exception as e:
                print(f"Error resolving entity from URL: {e}")
        
        # Fallback to defaults
        if not resolved_entity:
            resolved_entity = "Unknown Product"
        if not resolved_vendor:
            resolved_vendor = "Unknown Vendor"
        
        result = {
            "entity_name": resolved_entity,
            "vendor_name": resolved_vendor,
            "resolved_url": resolved_url
        }
        print(f"[Entity Resolver] ✓ Resolved to: {result['entity_name']} / {result['vendor_name']} (URL: {result['resolved_url'] or 'none'})")
        return result

