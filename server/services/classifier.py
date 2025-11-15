from typing import Dict, Optional
from server.dtos.AssessmentResponse import SoftwareCategory
import google.generativeai as genai
import os
from dotenv import load_dotenv
from server.utils.sanitize import remove_double_stars

load_dotenv()


class SoftwareClassifier:
    """
    AI-augmented but deterministic software classifier.
    Uses Gemini when available, otherwise clean keyword fallback.
    """

    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        if api_key:
            genai.configure(api_key=api_key)
            # Use gemini-2.5-flash (faster) or gemini-2.5-pro (more capable)
            try:
                self.model = genai.GenerativeModel('gemini-2.5-flash')
                self.use_ai = True
                print("[Classifier] ✓ Google Gemini configured for AI-powered classification (using gemini-2.5-flash)")
            except Exception as e:
                print(f"[Classifier] ⚠ Error initializing gemini-2.5-flash: {e}, trying gemini-2.5-pro")
                try:
                    self.model = genai.GenerativeModel('gemini-2.5-pro')
                    self.use_ai = True
                    print("[Classifier] ✓ Google Gemini configured (using gemini-2.5-pro)")
                except Exception as e2:
                    print(f"[Classifier] ✗ Error initializing Gemini models: {e2}, using fallback")
                    self.model = None
                    self.use_ai = False
        else:
            self.model = None
            self.use_ai = False

        # Normalizat, extins, mult mai robust
        self.category_aliases = {
            # File Sharing & Storage
            "file sharing": SoftwareCategory.FILE_SHARING,
            "file storage": SoftwareCategory.FILE_SHARING,
            "cloud storage": SoftwareCategory.CLOUD_STORAGE,
            "dropbox": SoftwareCategory.CLOUD_STORAGE,
            "onedrive": SoftwareCategory.CLOUD_STORAGE,
            "google drive": SoftwareCategory.CLOUD_STORAGE,
            
            # AI Tools
            "genai": SoftwareCategory.GENAI_TOOL,
            "gen ai": SoftwareCategory.GENAI_TOOL,
            "ai tool": SoftwareCategory.GENAI_TOOL,
            "artificial intelligence": SoftwareCategory.GENAI_TOOL,
            "chatgpt": SoftwareCategory.GENAI_TOOL,
            "claude": SoftwareCategory.GENAI_TOOL,
            "copilot": SoftwareCategory.GENAI_TOOL,
            
            # CRM & Business
            "crm": SoftwareCategory.SAAS_CRM,
            "saas crm": SoftwareCategory.SAAS_CRM,
            "salesforce": SoftwareCategory.SAAS_CRM,
            "hubspot": SoftwareCategory.SAAS_CRM,
            
            # Project Management
            "project management": SoftwareCategory.PROJECT_MANAGEMENT,
            "jira": SoftwareCategory.PROJECT_MANAGEMENT,
            "trello": SoftwareCategory.PROJECT_MANAGEMENT,
            "asana": SoftwareCategory.PROJECT_MANAGEMENT,
            
            # Security & Endpoint
            "endpoint": SoftwareCategory.ENDPOINT_AGENT,
            "endpoint security": SoftwareCategory.ENDPOINT_AGENT,
            "antivirus": SoftwareCategory.SECURITY_TOOL,
            "security tool": SoftwareCategory.SECURITY_TOOL,
            "firewall": SoftwareCategory.SECURITY_TOOL,
            "vpn": SoftwareCategory.SECURITY_TOOL,
            "malware": SoftwareCategory.SECURITY_TOOL,
            
            # Collaboration & Communication
            "collaboration": SoftwareCategory.COLLABORATION,
            "slack": SoftwareCategory.COLLABORATION,
            "teams": SoftwareCategory.COLLABORATION,
            "communication": SoftwareCategory.COMMUNICATION,
            "messaging": SoftwareCategory.COMMUNICATION,
            "email": SoftwareCategory.COMMUNICATION,
            "zoom": SoftwareCategory.COMMUNICATION,
            "skype": SoftwareCategory.COMMUNICATION,
            
            # Development
            "development": SoftwareCategory.DEVELOPMENT,
            "ide": SoftwareCategory.DEVELOPMENT,
            "code editor": SoftwareCategory.DEVELOPMENT,
            "programming": SoftwareCategory.DEVELOPMENT,
            "git": SoftwareCategory.DEVELOPMENT,
            "github": SoftwareCategory.DEVELOPMENT,
            "visual studio": SoftwareCategory.DEVELOPMENT,
            "vscode": SoftwareCategory.DEVELOPMENT,
            "compiler": SoftwareCategory.DEVELOPMENT,
            "debugger": SoftwareCategory.DEVELOPMENT,
            
            # Games
            "game": SoftwareCategory.GAMES,
            "games": SoftwareCategory.GAMES,
            "gaming": SoftwareCategory.GAMES,
            "steam": SoftwareCategory.GAMES,
            "epic games": SoftwareCategory.GAMES,
            "gog": SoftwareCategory.GAMES,
            
            # Default Windows Apps
            "default windows app": SoftwareCategory.DEFAULT_WINDOWS_APP,
            "windows app": SoftwareCategory.DEFAULT_WINDOWS_APP,
            "microsoft store": SoftwareCategory.DEFAULT_WINDOWS_APP,
            "calculator": SoftwareCategory.DEFAULT_WINDOWS_APP,
            "notepad": SoftwareCategory.DEFAULT_WINDOWS_APP,
            "paint": SoftwareCategory.DEFAULT_WINDOWS_APP,
            "windows media": SoftwareCategory.DEFAULT_WINDOWS_APP,
            "windows defender": SoftwareCategory.DEFAULT_WINDOWS_APP,
            "windows update": SoftwareCategory.DEFAULT_WINDOWS_APP,
            
            # Browser
            "browser": SoftwareCategory.BROWSER,
            "web browser": SoftwareCategory.BROWSER,
            "chrome": SoftwareCategory.BROWSER,
            "firefox": SoftwareCategory.BROWSER,
            "edge": SoftwareCategory.BROWSER,
            "safari": SoftwareCategory.BROWSER,
            "opera": SoftwareCategory.BROWSER,
            "brave": SoftwareCategory.BROWSER,
            
            # Media Player
            "media player": SoftwareCategory.MEDIA_PLAYER,
            "video player": SoftwareCategory.MEDIA_PLAYER,
            "audio player": SoftwareCategory.MEDIA_PLAYER,
            "vlc": SoftwareCategory.MEDIA_PLAYER,
            "media player classic": SoftwareCategory.MEDIA_PLAYER,
            "itunes": SoftwareCategory.MEDIA_PLAYER,
            "spotify": SoftwareCategory.MEDIA_PLAYER,
            "winamp": SoftwareCategory.MEDIA_PLAYER,
            
            # Office Suite
            "office suite": SoftwareCategory.OFFICE_SUITE,
            "office": SoftwareCategory.OFFICE_SUITE,
            "microsoft office": SoftwareCategory.OFFICE_SUITE,
            "word": SoftwareCategory.OFFICE_SUITE,
            "excel": SoftwareCategory.OFFICE_SUITE,
            "powerpoint": SoftwareCategory.OFFICE_SUITE,
            "libreoffice": SoftwareCategory.OFFICE_SUITE,
            "openoffice": SoftwareCategory.OFFICE_SUITE,
            "google workspace": SoftwareCategory.OFFICE_SUITE,
            
            # System Utility
            "system utility": SoftwareCategory.SYSTEM_UTILITY,
            "utility": SoftwareCategory.SYSTEM_UTILITY,
            "system tool": SoftwareCategory.SYSTEM_UTILITY,
            "disk utility": SoftwareCategory.SYSTEM_UTILITY,
            "backup": SoftwareCategory.SYSTEM_UTILITY,
            "cleanup": SoftwareCategory.SYSTEM_UTILITY,
            "registry": SoftwareCategory.SYSTEM_UTILITY,
            "task manager": SoftwareCategory.SYSTEM_UTILITY,
            
            # Networking
            "networking": SoftwareCategory.NETWORKING,
            "network": SoftwareCategory.NETWORKING,
            "ftp": SoftwareCategory.NETWORKING,
            "ssh": SoftwareCategory.NETWORKING,
            "remote desktop": SoftwareCategory.NETWORKING,
            "teamviewer": SoftwareCategory.NETWORKING,
            "wireshark": SoftwareCategory.NETWORKING,
            
            # Database
            "database": SoftwareCategory.DATABASE,
            "sql": SoftwareCategory.DATABASE,
            "mysql": SoftwareCategory.DATABASE,
            "postgresql": SoftwareCategory.DATABASE,
            "mongodb": SoftwareCategory.DATABASE,
            "oracle": SoftwareCategory.DATABASE,
            "sqlite": SoftwareCategory.DATABASE,
        }

    def classify(
        self,
        product_name: str,
        vendor_name: str,
        description: Optional[str] = None,
        url: Optional[str] = None
    ) -> SoftwareCategory:

        text = " ".join([
            product_name or "",
            vendor_name or "",
            description or ""
        ]).lower()

        # If AI available
        if self.use_ai and self.model:
            try:
                prompt = f"""
Classify the following software into ONE of these categories:

- File Sharing
- GenAI Tool
- SaaS CRM
- Endpoint Agent
- Collaboration
- Security Tool
- Development
- Cloud Storage
- Communication
- Project Management
- Games
- Default Windows App
- Browser
- Media Player
- Office Suite
- System Utility
- Networking
- Database
- Other

Respond with *only the category name*, nothing else.

Product: {product_name}
Vendor: {vendor_name}
Description: {description or "none"}
URL: {url or "none"}
"""
                resp = self.model.generate_content(prompt)
                out = remove_double_stars(resp.text.strip().lower())
                for alias, cat in self.category_aliases.items():
                    if alias in out:
                        return cat
                return SoftwareCategory.OTHER

            except Exception:
                pass  # fallback below

        # Fallback deterministic keyword matching
        for alias, cat in self.category_aliases.items():
            if alias in text:
                return cat

        return SoftwareCategory.OTHER
