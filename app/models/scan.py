"""Scan model - represents a complete reconnaissance run."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, Enum as SQLEnum
from sqlalchemy.orm import relationship
import enum

from app.models.base import BaseModel


class ScanStatus(str, enum.Enum):
    """Scan status enumeration."""
    CREATING = "creating"
    PREPARING = "preparing"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"


class Scan(BaseModel):
    """Scan model representing a complete recon run for a target."""
    
    __tablename__ = "scans"
    
    # Target information
    target = Column(String(255), nullable=False, index=True)
    owasp_category = Column(String(20), nullable=False, index=True)
    
    # Status tracking
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.CREATING, nullable=False, index=True)
    completed_at = Column(DateTime, nullable=True)
    
    # Tool selection
    user_selected_tools = Column(Text, nullable=True)  # JSON list of tool names
    ai_tools_to_run = Column(Text, nullable=True)  # JSON list of tool names AI recommended
    ai_tools_skipped = Column(Text, nullable=True)  # JSON list of {tool, reason}
    ai_raw_response = Column(Text, nullable=True)  # Raw AI response for debugging
    
    # Error tracking
    error_summary = Column(Text, nullable=True)

    # Set when scan was triggered by a scheduled scan (scheduled_scans.id)
    scheduled_scan_id = Column(Integer, nullable=True, index=True)

    # Persisted AI-generated report HTML; once set, View Report never calls AI again for this scan
    report_html = Column(Text, nullable=True)

    # Intelligence layer data - endpoint classification results
    endpoint_classification = Column(Text, nullable=True)  # JSON classification data

    # Relationships
    tool_runs = relationship("ToolRun", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Scan(id={self.id}, target={self.target}, status={self.status})>"


