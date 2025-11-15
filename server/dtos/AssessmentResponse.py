from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class SoftwareCategory(str, Enum):
    """Software taxonomy categories"""
    FILE_SHARING = "File Sharing"
    GENAI_TOOL = "GenAI Tool"
    SAAS_CRM = "SaaS CRM"
    ENDPOINT_AGENT = "Endpoint Agent"
    COLLABORATION = "Collaboration"
    SECURITY_TOOL = "Security Tool"
    DEVELOPMENT = "Development"
    CLOUD_STORAGE = "Cloud Storage"
    COMMUNICATION = "Communication"
    PROJECT_MANAGEMENT = "Project Management"
    GAMES = "Games"
    DEFAULT_WINDOWS_APP = "Default Windows App"
    BROWSER = "Browser"
    MEDIA_PLAYER = "Media Player"
    OFFICE_SUITE = "Office Suite"
    SYSTEM_UTILITY = "System Utility"
    NETWORKING = "Networking"
    DATABASE = "Database"
    OTHER = "Other"


class Citation(BaseModel):
    """Citation for a claim"""
    source: str = Field(..., description="Source URL or identifier")
    source_type: str = Field(..., description="Type of source (vendor, CVE, CISA, etc.)")
    claim: str = Field(..., description="The claim being made")
    is_vendor_stated: bool = Field(False, description="Whether this is a vendor-stated claim vs independent")
    timestamp: Optional[datetime] = Field(None, description="When the source was accessed")


class CVESummary(BaseModel):
    """CVE trend summary"""
    total_cves: int = Field(0, description="Total number of CVEs")
    critical_count: int = Field(0, description="Number of critical CVEs (CVSS >= 9.0)")
    high_count: int = Field(0, description="Number of high CVEs (CVSS 7.0-8.9)")
    recent_trend: str = Field("unknown", description="Trend: increasing, decreasing, stable")
    cisa_kev_count: int = Field(0, description="Number of CVEs in CISA KEV catalog")
    recent_cves: List[Dict[str, Any]] = Field(default_factory=list, description="Recent CVE details")
    version_specific_cves: int = Field(0, description="Number of CVEs specific to detected version")
    version_specific_critical: int = Field(0, description="Number of critical CVEs for detected version")
    version_specific_high: int = Field(0, description="Number of high CVEs for detected version")
    version_specific_recent: List[Dict[str, Any]] = Field(default_factory=list, description="Recent version-specific CVEs")
    detected_version: Optional[str] = Field(None, description="Product version detected from hash")


class TrustScore(BaseModel):
    """Trust/Risk score with rationale"""
    score: int = Field(..., ge=0, le=100, description="Trust score (0-100, higher is better)")
    risk_level: str = Field(..., description="Risk level: Low, Medium, High, Critical")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in the score (0.0-1.0)")
    rationale: str = Field(..., description="Explanation of the score")
    factors: Dict[str, float] = Field(default_factory=dict, description="Contributing factors and their weights")


class Alternative(BaseModel):
    """Safer alternative suggestion"""
    name: str = Field(..., description="Name of the alternative")
    vendor: str = Field(..., description="Vendor name")
    rationale: str = Field(..., description="Why this is a safer alternative")
    trust_score: Optional[int] = Field(None, ge=0, le=100, description="Trust score if available")


class SecurityPosture(BaseModel):
    """Security posture summary"""
    summary: str = Field(..., description="Short AI-generated summary of the security posture")
    description: str = Field(..., description="Product description")
    usage: str = Field(..., description="Primary use cases")
    vendor_reputation: str = Field(..., description="Vendor reputation summary")
    cve_summary: CVESummary = Field(..., description="CVE trend summary")
    incidents_abuse: str = Field(..., description="Incidents and abuse signals")
    data_handling: str = Field(..., description="Data handling and compliance information")
    deployment_controls: str = Field(..., description="Deployment and admin controls")
    citations: List[Citation] = Field(default_factory=list, description="All citations")


class AssessmentResponse(BaseModel):
    """Complete assessment response"""
    entity_name: str = Field(..., description="Resolved entity name")
    vendor_name: str = Field(..., description="Resolved vendor name")
    category: SoftwareCategory = Field(..., description="Software category")
    security_posture: SecurityPosture = Field(..., description="Security posture summary")
    trust_score: TrustScore = Field(..., description="Trust/risk score")
    alternatives: List[Alternative] = Field(default_factory=list, description="Safer alternatives")
    assessment_timestamp: datetime = Field(default_factory=datetime.now, description="When assessment was performed")
    data_quality: str = Field("sufficient", description="Data quality: sufficient, limited, insufficient")
    cache_key: Optional[str] = Field(None, description="Cache key for this assessment")

