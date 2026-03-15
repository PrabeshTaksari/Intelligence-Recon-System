"""Finding-related schemas."""
from typing import Optional
from datetime import datetime
from pydantic import BaseModel


class FindingResponse(BaseModel):
    """Response schema for finding."""
    id: int
    scan_id: int
    tool_name: str
    type: str
    severity: str
    owasp_category: Optional[str] = None
    location: str
    description: str
    evidence: Optional[str] = None
    created_at: datetime
    
    model_config = {"from_attributes": True}


class FindingSummary(BaseModel):
    """Summary of findings by severity and category."""
    by_severity: dict
    by_owasp: dict
    by_type: dict
    total: int


