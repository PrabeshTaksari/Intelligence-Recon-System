"""ToolRun model - tracks execution of individual tools."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, Enum as SQLEnum
from sqlalchemy.orm import relationship
import enum

from app.models.base import BaseModel


class ToolRunStatus(str, enum.Enum):
    """Tool run status enumeration."""
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class ToolRun(BaseModel):
    """ToolRun model representing execution of a single tool within a scan."""
    
    __tablename__ = "tool_runs"
    
    # Scan relationship
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    scan = relationship("Scan", back_populates="tool_runs")
    
    # Tool information
    tool_name = Column(String(100), nullable=False, index=True)
    status = Column(SQLEnum(ToolRunStatus), default=ToolRunStatus.QUEUED, nullable=False)
    
    # Execution timing
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    
    # Output and results
    raw_output_path = Column(String(500), nullable=True)  # Path to raw output file
    summary = Column(Text, nullable=True)  # Short summary of results
    error_message = Column(Text, nullable=True)  # Error message if failed
    
    def __repr__(self):
        return f"<ToolRun(id={self.id}, tool={self.tool_name}, status={self.status})>"


