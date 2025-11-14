from pydantic import BaseModel, Field, model_validator
from typing import Self, Optional


class AppDetails(BaseModel):
    company_name: str
    product_name: str
    sha1: str