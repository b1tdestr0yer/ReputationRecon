import httpx
import os
import re
from typing import Dict, List, Optional, Any
from datetime import datetime
import asyncio
from dotenv import load_dotenv
import google.generativeai as genai
import json

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
                        cve_id = cve_item.get("id", "")
                        
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
                            results["critical_count"] += 1
                        elif base_score >= 7.0:
                            severity = "high"
                            results["high_count"] += 1
                        
                        all_cves.append({
                            "id": cve_id,
                            "description": cve_item.get("descriptions", [{}])[0].get("value", ""),
                            "base_score": base_score,
                            "severity": severity,
                            "published": cve_item.get("published", "")
                        })
            
            # If version provided, search for version-specific CVEs
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
                            cve_id = cve_item.get("id", "")
                            
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
                                results["version_specific_critical"] += 1
                            elif base_score >= 7.0:
                                severity = "high"
                                results["version_specific_high"] += 1
                            
                            # Add to version-specific list
                            version_cve = {
                                "id": cve_id,
                                "description": cve_item.get("descriptions", [{}])[0].get("value", ""),
                                "base_score": base_score,
                                "severity": severity,
                                "published": cve_item.get("published", "")
                            }
                            
                            # Check if already in all_cves (avoid double counting in totals)
                            if not any(c["id"] == cve_id for c in all_cves):
                                all_cves.append(version_cve)
                                if severity == "critical":
                                    results["critical_count"] += 1
                                elif severity == "high":
                                    results["high_count"] += 1
            
            # Remove duplicates
            seen = set()
            unique_cves = []
            version_specific_cves = []
            
            for cve in all_cves:
                if cve["id"] not in seen:
                    seen.add(cve["id"])
                    unique_cves.append(cve)
                    
                    # Check if this CVE is version-specific (appears in version search results)
                    if product_version:
                        cve_desc = cve.get("description", "").lower()
                        version_lower = product_version.lower()
                        # Check if version appears in description
                        if version_lower in cve_desc:
                            version_specific_cves.append(cve)
            
            results["total_cves"] = len(unique_cves)
            results["recent_cves"] = sorted(unique_cves, key=lambda x: x.get("published", ""), reverse=True)[:10]
            results["version_specific_cves"] = len(version_specific_cves)
            results["version_specific_recent"] = sorted(version_specific_cves, key=lambda x: x.get("published", ""), reverse=True)[:10]
            
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
    """Collect data from VirusTotal"""
    
    async def get_file_report(self, hash: str) -> Optional[Dict]:
        """Get VirusTotal file report"""
        print(f"[VirusTotal Collector] Fetching report for hash: {hash[:16]}...")
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not api_key:
            print("[VirusTotal Collector] ✗ VIRUSTOTAL_API_KEY not configured, skipping")
            return None
        
        url = "https://www.virustotal.com/vtapi/v2/file/report"
        params = {
            "apikey": api_key,
            "resource": hash
        }
        
        data = await self.fetch(url, params)
        if data:
            if data.get("response_code") == 1:
                positives = data.get("positives", 0)
                total = data.get("total", 0)
                print(f"[VirusTotal Collector] ✓ Report retrieved: {positives}/{total} vendors flagged")
            else:
                print(f"[VirusTotal Collector] Hash not found in VirusTotal database")
        else:
            print(f"[VirusTotal Collector] ✗ Failed to retrieve report")
        
        return data


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
                    
                    # Extract product information
                    product_code = data.get("ProductCode", {})
                    if product_code:
                        version_info["product_name"] = product_code.get("ProductName", "")
                        version_info["product_version"] = product_code.get("ProductVersion", "")
                    
                    if version_info["product_name"] or version_info["product_version"]:
                        print(f"[CIRCL Hashlookup] ✓ Found product: {version_info['product_name']} version {version_info['product_version']}")
                    else:
                        print(f"[CIRCL Hashlookup] ⚠ No product version information found")
                    
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


class EntityResolver:
    """Resolve entity and vendor identity from input"""
    
    def __init__(self):
        """Initialize EntityResolver with optional Gemini AI support"""
        api_key = os.getenv("GEMINI_API_KEY")
        if api_key:
            try:
                genai.configure(api_key=api_key)
                # Try gemini-2.5-flash first, fallback to gemini-2.5-pro
                try:
                    self.model = genai.GenerativeModel('gemini-2.5-flash')
                    self.use_ai = True
                    print("[Entity Resolver] ✓ Google Gemini configured for URL resolution (using gemini-2.5-flash)")
                except Exception as e:
                    print(f"[Entity Resolver] ⚠ Error initializing gemini-2.5-flash: {e}, trying gemini-2.5-pro")
                    try:
                        self.model = genai.GenerativeModel('gemini-2.5-pro')
                        self.use_ai = True
                        print("[Entity Resolver] ✓ Google Gemini configured (using gemini-2.5-pro)")
                    except Exception as e2:
                        print(f"[Entity Resolver] ✗ Error initializing Gemini models: {e2}, using fallback")
                        self.model = None
                        self.use_ai = False
            except Exception as e:
                print(f"[Entity Resolver] ✗ Error configuring Gemini: {e}, using fallback")
                self.model = None
                self.use_ai = False
        else:
            self.model = None
            self.use_ai = False
    
    async def resolve_vendor_url_with_gemini(self, product_name: Optional[str], vendor_name: Optional[str]) -> Optional[str]:
        """Use Gemini AI to resolve the vendor's official website URL"""
        if not self.use_ai or not self.model:
            print("[Entity Resolver] Gemini not available, skipping AI-based URL resolution")
            return None
        
        if not vendor_name or vendor_name.lower() in ["unknown vendor", "unknown", ""]:
            print("[Entity Resolver] No valid vendor name provided for AI resolution")
            return None
        
        try:
            print(f"[Entity Resolver] Using Gemini to resolve vendor URL for: {vendor_name} / {product_name}")
            prompt = f"""Given the following vendor and product information, provide the official website URL for the vendor.

Vendor Name: {vendor_name}
Product Name: {product_name or 'Not specified'}

Please provide ONLY the official website URL (e.g., https://www.company.com) in JSON format:
{{"url": "https://www.example.com"}}

If you cannot determine the URL with high confidence, return:
{{"url": null}}

Respond with ONLY valid JSON, no additional text or explanation."""

            response = self.model.generate_content(prompt)
            response_text = response.text.strip()
            
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
                    print(f"[Entity Resolver] ✓ Gemini resolved vendor URL: {resolved_url}")
                    return resolved_url
                else:
                    print(f"[Entity Resolver] ✗ Gemini returned invalid URL: {resolved_url}")
                    return None
            except json.JSONDecodeError as e:
                print(f"[Entity Resolver] ✗ Failed to parse Gemini JSON response: {e}")
                print(f"[Entity Resolver] Response was: {response_text[:200]}")
                return None
                
        except Exception as e:
            print(f"[Entity Resolver] ✗ Error using Gemini for URL resolution: {e}")
            return None
    
    async def resolve(self, product_name: Optional[str] = None,
                     vendor_name: Optional[str] = None,
                     url: Optional[str] = None) -> Dict[str, str]:
        """Resolve entity and vendor names, and optionally resolve vendor URL using Gemini"""
        print(f"[Entity Resolver] Resolving entity - product: {product_name}, vendor: {vendor_name}, url: {url}")
        resolved_entity = product_name or ""
        resolved_vendor = vendor_name or ""
        resolved_url = url or ""
        
        # If no URL provided, try to resolve it using Gemini
        if not resolved_url and resolved_vendor and resolved_vendor.lower() not in ["unknown vendor", "unknown", ""]:
            print(f"[Entity Resolver] No URL provided, attempting to resolve using Gemini...")
            gemini_url = await self.resolve_vendor_url_with_gemini(resolved_entity, resolved_vendor)
            if gemini_url:
                resolved_url = gemini_url
        
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

