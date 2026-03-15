"""Scan-related schemas."""
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, field_validator


class ScanCreate(BaseModel):
    """Request schema for creating a new scan."""
    target: str = Field(..., min_length=1, max_length=255, description="Target domain or host")
    owasp_category: str = Field(..., description="OWASP Top 10 category ID (e.g., A01:2021)")
    selected_tools: List[str] = Field(default_factory=list, description="List of tool names to run")
    
    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        """Validate and sanitize target."""
        v = v.strip().lower()
        # Remove protocol if present
        v = v.replace("http://", "").replace("https://", "")
        # Remove trailing slashes
        v = v.rstrip("/")
        if not v:
            raise ValueError("Target cannot be empty")
        return v
    
    @field_validator("owasp_category")
    @classmethod
    def validate_owasp(cls, v: str) -> str:
        """Validate OWASP category."""
        valid_categories = [
            "A01:2021", "A02:2021", "A03:2021", "A04:2021", "A05:2021",
            "A06:2021", "A07:2021", "A08:2021", "A09:2021", "A10:2021"
        ]
        if v not in valid_categories:
            raise ValueError(f"Invalid OWASP category. Must be one of: {', '.join(valid_categories)}")
        return v


class ScanResponse(BaseModel):
    """Response schema for scan creation."""
    scan_id: int
    status: str
    message: Optional[str] = None
    ai_decision_summary: Optional[Dict[str, Any]] = None
    
    model_config = {"from_attributes": True}


class ScanStatus(BaseModel):
    """Schema for scan status polling."""
    scan_id: int
    status: str
    target: str
    owasp_category: str
    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime] = None
    tools: List[Dict[str, Any]] = Field(default_factory=list)
    
    model_config = {"from_attributes": True}


class ScanListItem(BaseModel):
    """Schema for scan list item."""
    id: int
    target: str
    owasp_category: str
    owasp_category_name: Optional[str] = None
    status: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    highest_severity: Optional[str] = None
    finding_count: int = 0
    
    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    """Response schema for scan list."""
    scans: List[ScanListItem]
    total: int
    page: int
    page_size: int


class AIDecisionInfo(BaseModel):
    """AI decision information."""
    tools_to_run: List[str] = Field(default_factory=list)
    tools_skipped: List[Dict[str, str]] = Field(default_factory=list)
    raw_response: Optional[str] = None


class ScanDetailResponse(BaseModel):
    """Detailed scan response."""
    id: int
    target: str
    owasp_category: str
    owasp_category_name: Optional[str] = None
    status: str
    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime] = None
    user_selected_tools: List[str] = Field(default_factory=list)
    ai_decision: Optional[AIDecisionInfo] = None
    tool_runs: List[Dict[str, Any]] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    findings_summary: Dict[str, Any] = Field(default_factory=dict)
    error_summary: Optional[str] = None
    
    model_config = {"from_attributes": True}


