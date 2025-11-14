"""
Configuration helper for ReputationRecon
Provides easy access to API keys and configuration settings
"""
import os
from dotenv import load_dotenv
from typing import Optional

# Load .env file if it exists
load_dotenv()


class Config:
    """Configuration class for API keys and settings"""
    
    # VirusTotal API Key
    VIRUSTOTAL_API_KEY: Optional[str] = os.getenv("VIRUSTOTAL_API_KEY")
    
    # Google Gemini API Key (required for AI-powered analysis)
    GEMINI_API_KEY: Optional[str] = os.getenv("GEMINI_API_KEY")
    
    # Cache settings
    CACHE_DB_PATH: str = os.getenv("CACHE_DB_PATH", "assessments_cache.db")
    CACHE_TTL_DAYS: int = int(os.getenv("CACHE_TTL_DAYS", "30"))
    
    # API rate limits
    ASSESSMENT_RATE_LIMIT: str = os.getenv("ASSESSMENT_RATE_LIMIT", "10/minute")
    COMPARE_RATE_LIMIT: str = os.getenv("COMPARE_RATE_LIMIT", "5/minute")
    VIRUSTOTAL_RATE_LIMIT: str = os.getenv("VIRUSTOTAL_RATE_LIMIT", "4/minute")
    
    @classmethod
    def is_virustotal_configured(cls) -> bool:
        """Check if VirusTotal API key is configured"""
        return cls.VIRUSTOTAL_API_KEY is not None and cls.VIRUSTOTAL_API_KEY.strip() != ""
    
    @classmethod
    def is_gemini_configured(cls) -> bool:
        """Check if Google Gemini API key is configured"""
        return cls.GEMINI_API_KEY is not None and cls.GEMINI_API_KEY.strip() != ""
    
    @classmethod
    def get_status(cls) -> dict:
        """Get configuration status"""
        return {
            "virustotal_configured": cls.is_virustotal_configured(),
            "gemini_configured": cls.is_gemini_configured(),
            "cache_db_path": cls.CACHE_DB_PATH,
            "cache_ttl_days": cls.CACHE_TTL_DAYS
        }

