from pydantic import BaseModel, Field, field_validator
from typing import Optional


class AssessmentRequest(BaseModel):
    """Request model for application assessment"""
    product_name: Optional[str] = Field(None, max_length=128, description="Name of the product/application")
    vendor_name: Optional[str] = Field(None, max_length=128, description="Name of the vendor/company")
    url: Optional[str] = Field(None, max_length=128, description="URL of the product/vendor website")
    hash: Optional[str] = Field(None, max_length=128, description="Optional binary hash (MD5, SHA1, SHA256)")
    pro_mode: Optional[bool] = Field(False, description="Enable PRO mode - uses gemini-2.5-pro for all AI operations")
    
    @field_validator('product_name', 'vendor_name', 'url', 'hash')
    @classmethod
    def validate_length(cls, v):
        if v is not None and len(v) > 128:
            raise ValueError(f'Field must be 128 characters or less (got {len(v)} characters)')
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "product_name": "Slack",
                "vendor_name": "Salesforce",
                "url": "https://slack.com"
            }
        }

