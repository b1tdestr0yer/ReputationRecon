from pydantic import BaseModel, Field
from typing import Optional


class AssessmentRequest(BaseModel):
    """Request model for application assessment"""
    product_name: Optional[str] = Field(None, description="Name of the product/application")
    vendor_name: Optional[str] = Field(None, description="Name of the vendor/company")
    url: Optional[str] = Field(None, description="URL of the product/vendor website")
    hash: Optional[str] = Field(None, description="Optional binary hash (MD5, SHA1, SHA256)")
    
    class Config:
        json_schema_extra = {
            "example": {
                "product_name": "Slack",
                "vendor_name": "Salesforce",
                "url": "https://slack.com"
            }
        }

