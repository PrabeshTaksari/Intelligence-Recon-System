"""Finding model - normalized security findings from tools."""
from sqlalchemy import Column, Integer, String, Text, ForeignKey, Enum as SQLEnum
from sqlalchemy.orm import relationship
import enum

from app.models.base import BaseModel


class FindingType(str, enum.Enum):
    """Finding type enumeration."""
    ASSET = "asset"
    ENDPOINT = "endpoint"
    PORT = "port"
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    INFORMATION = "information"


class FindingSeverity(str, enum.Enum):
    """Finding severity enumeration."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    """Finding model representing a normalized piece of reconnaissance data."""
    
    __tablename__ = "findings"
    
    # Scan relationship
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    scan = relationship("Scan", back_populates="findings")
    
    # Source information
    tool_name = Column(String(100), nullable=False, index=True)
    
    # Classification
    type = Column(SQLEnum(FindingType), nullable=False, index=True)
    severity = Column(SQLEnum(FindingSeverity), default=FindingSeverity.INFO, nullable=False, index=True)
    owasp_category = Column(String(20), nullable=True, index=True)
    
    # Finding details
    location = Column(String(500), nullable=False)  # URL, host:port, or resource identifier
    description = Column(Text, nullable=False)
    evidence = Column(Text, nullable=True)  # Supporting data (headers, payloads, etc.)
    
    def __repr__(self):
        return f"<Finding(id={self.id}, type={self.type}, severity={self.severity}, location={self.location})>"


