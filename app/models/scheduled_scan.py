"""Scheduled scan model - recurring scan definitions."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean

from app.models.base import BaseModel


class ScheduledScan(BaseModel):
    """Recurring scan schedule: target + OWASP + tools + frequency."""

    __tablename__ = "scheduled_scans"

    target = Column(String(255), nullable=False, index=True)
    owasp_category = Column(String(20), nullable=False, index=True)
    selected_tools = Column(Text, nullable=False)  # JSON list of tool names

    frequency = Column(String(20), nullable=False, default="weekly")  # "once" | "daily" | "weekly" | "monthly"
    enabled = Column(Boolean, default=True, nullable=False, index=True)
    next_run_at = Column(DateTime, nullable=True, index=True)  # when to run next (UTC)
    last_run_at = Column(DateTime, nullable=True)  # when we last triggered a scan for this schedule

    def __repr__(self):
        return f"<ScheduledScan(id={self.id}, target={self.target}, frequency={self.frequency})>"
