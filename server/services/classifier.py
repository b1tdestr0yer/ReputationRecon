from typing import Dict, Optional
from server.dtos.AssessmentResponse import SoftwareCategory


class SoftwareClassifier:
    """Classify software into taxonomy categories"""
    
    # Category keywords mapping
    CATEGORY_KEYWORDS = {
        SoftwareCategory.FILE_SHARING: [
            "file sharing", "file storage", "dropbox", "onedrive", "google drive",
            "file transfer", "file sync", "cloud storage"
        ],
        SoftwareCategory.GENAI_TOOL: [
            "ai", "artificial intelligence", "machine learning", "llm", "gpt",
            "generative", "chatbot", "openai", "claude", "bard"
        ],
        SoftwareCategory.SAAS_CRM: [
            "crm", "customer relationship", "salesforce", "hubspot", "sales",
            "customer management"
        ],
        SoftwareCategory.ENDPOINT_AGENT: [
            "endpoint", "edr", "antivirus", "security agent", "malware",
            "threat detection", "crowdstrike", "sentinelone"
        ],
        SoftwareCategory.COLLABORATION: [
            "collaboration", "slack", "teams", "workspace", "team chat",
            "communication platform"
        ],
        SoftwareCategory.SECURITY_TOOL: [
            "security", "vulnerability scanner", "penetration testing",
            "security assessment", "siem", "soar"
        ],
        SoftwareCategory.DEVELOPMENT: [
            "development", "ide", "code editor", "version control", "git",
            "ci/cd", "devops"
        ],
        SoftwareCategory.CLOUD_STORAGE: [
            "cloud storage", "s3", "azure storage", "cloud backup"
        ],
        SoftwareCategory.COMMUNICATION: [
            "email", "messaging", "voip", "video conferencing", "zoom",
            "skype", "whatsapp"
        ],
        SoftwareCategory.PROJECT_MANAGEMENT: [
            "project management", "jira", "asana", "trello", "task management"
        ]
    }
    
    def classify(self, product_name: str, vendor_name: str, 
                description: Optional[str] = None, url: Optional[str] = None) -> SoftwareCategory:
        """Classify software into a category"""
        print(f"[Classifier] Classifying: {product_name} / {vendor_name}")
        # Combine all text for analysis
        text = f"{product_name} {vendor_name}".lower()
        if description:
            text += f" {description.lower()}"
        if url:
            text += f" {url.lower()}"
        
        # Score each category
        scores = {}
        for category, keywords in self.CATEGORY_KEYWORDS.items():
            score = sum(1 for keyword in keywords if keyword in text)
            if score > 0:
                scores[category] = score
        
        # Return category with highest score, or OTHER if no match
        if scores:
            max_score = max(scores.values())
            if max_score > 0:
                best_category = max(scores, key=scores.get)
                print(f"[Classifier] ✓ Classified as: {best_category.value} (score: {max_score})")
                return best_category
        
        print(f"[Classifier] ✓ Classified as: {SoftwareCategory.OTHER.value} (no match found)")
        return SoftwareCategory.OTHER

