"""ToolRun-related schemas."""
from typing import Optional
from datetime import datetime
from pydantic import BaseModel


class ToolRunResponse(BaseModel):
    """Response schema for tool run."""
    id: int
    scan_id: int
    tool_name: str
    status: str
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    summary: Optional[str] = None
    error_message: Optional[str] = None
    
    model_config = {"from_attributes": True}


class ToolRunStatusResponse(BaseModel):
    """Minimal schema for status polling."""
    tool_name: str
    status: str
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    
    model_config = {"from_attributes": True}


