"""Scheduled scan schemas."""
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field, field_validator, model_validator

# All supported schedule frequencies (One-time, Daily, Weekly, Monthly)
FREQUENCY_CHOICES = ("once", "daily", "weekly", "monthly")


def _normalize_frequency(v: str) -> str:
    """Normalize frequency to one of once, daily, weekly, monthly."""
    if not v or not isinstance(v, str):
        return "weekly"
    v = v.strip().lower()
    # Map labels/variants to canonical values
    mapping = {
        "once": "once", "one-time": "once", "one time": "once",
        "daily": "daily", "weekly": "weekly", "monthly": "monthly",
    }
    return mapping.get(v) if v in mapping else (v if v in FREQUENCY_CHOICES else "")


class ScheduledScanCreate(BaseModel):
    """Request schema for creating a scheduled scan."""
    target: str = Field(..., min_length=1, max_length=255)
    owasp_category: str = Field(..., description="OWASP category ID e.g. A01:2021")
    selected_tools: List[str] = Field(default_factory=list, min_length=1)
    frequency: str = Field(default="weekly", description="once | daily | weekly | monthly")
    next_run_at: Optional[datetime] = Field(None, description="When to run next (UTC). Required when schedule is enabled.")

    @model_validator(mode="after")
    def one_time_requires_next_run(self):
        if self.frequency == "once" and self.next_run_at is None:
            raise ValueError("One-time schedule must have next_run_at set (date and time).")
        return self

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip().lower().replace("http://", "").replace("https://", "").rstrip("/")
        if not v:
            raise ValueError("Target cannot be empty")
        return v

    @field_validator("owasp_category")
    @classmethod
    def validate_owasp(cls, v: str) -> str:
        valid = ["A01:2021", "A02:2021", "A03:2021", "A04:2021", "A05:2021",
                 "A06:2021", "A07:2021", "A08:2021", "A09:2021", "A10:2021"]
        if v not in valid:
            raise ValueError(f"Invalid OWASP category. Must be one of: {', '.join(valid)}")
        return v

    @field_validator("frequency")
    @classmethod
    def validate_frequency(cls, v: str) -> str:
        canonical = _normalize_frequency(v)
        if canonical not in FREQUENCY_CHOICES:
            raise ValueError("Frequency must be 'once', 'daily', 'weekly', or 'monthly'.")
        return canonical


class ScheduledScanUpdate(BaseModel):
    """Request schema for updating a scheduled scan (partial)."""
    target: Optional[str] = Field(None, min_length=1, max_length=255)
    owasp_category: Optional[str] = None
    selected_tools: Optional[List[str]] = None
    frequency: Optional[str] = None
    enabled: Optional[bool] = None
    next_run_at: Optional[datetime] = None

    @field_validator("frequency")
    @classmethod
    def validate_frequency(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        canonical = _normalize_frequency(v)
        if canonical not in FREQUENCY_CHOICES:
            raise ValueError("Frequency must be 'once', 'daily', 'weekly', or 'monthly'.")
        return canonical


class ScheduledScanResponse(BaseModel):
    """Response schema for a scheduled scan."""
    id: int
    target: str
    owasp_category: str
    selected_tools: List[str]
    frequency: str
    enabled: bool
    next_run_at: Optional[datetime] = None
    last_run_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
