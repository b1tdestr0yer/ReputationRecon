from typing import Dict, Optional
from server.dtos.AssessmentResponse import SoftwareCategory
import google.generativeai as genai
import os
from dotenv import load_dotenv

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
            "file sharing": SoftwareCategory.FILE_SHARING,
            "file storage": SoftwareCategory.FILE_SHARING,
            "cloud storage": SoftwareCategory.CLOUD_STORAGE,
            "genai": SoftwareCategory.GENAI_TOOL,
            "gen ai": SoftwareCategory.GENAI_TOOL,
            "ai tool": SoftwareCategory.GENAI_TOOL,
            "crm": SoftwareCategory.SAAS_CRM,
            "saas crm": SoftwareCategory.SAAS_CRM,
            "project management": SoftwareCategory.PROJECT_MANAGEMENT,
            "endpoint": SoftwareCategory.ENDPOINT_AGENT,
            "endpoint security": SoftwareCategory.ENDPOINT_AGENT,
            "collaboration": SoftwareCategory.COLLABORATION,
            "communication": SoftwareCategory.COMMUNICATION,
            "security tool": SoftwareCategory.SECURITY_TOOL,
            "development": SoftwareCategory.DEVELOPMENT,
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
- Other

Respond with *only the category name*, nothing else.

Product: {product_name}
Vendor: {vendor_name}
Description: {description or "none"}
URL: {url or "none"}
"""
                resp = self.model.generate_content(prompt)
                out = resp.text.strip().lower()
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
