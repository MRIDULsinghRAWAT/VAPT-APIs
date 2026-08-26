"""
SQLAlchemy ORM models for scan history and findings.
"""

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    """Base class for all ORM models."""
    pass


class ScanStatus(str, enum.Enum):
    """Possible states of a scan."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, enum.Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Scan(Base):
    """Represents a single scan run against a target API."""

    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    target_url = Column(String(512), nullable=False)
    spec_file = Column(String(512), nullable=True)       # path to uploaded spec
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Stats (populated after scan completes)
    total_endpoints = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)

    # Relationships
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Scan id={self.id} name={self.name!r} status={self.status}>"


class Finding(Base):
    """A single confirmed vulnerability finding from a scan."""

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)

    # Classification
    title = Column(String(255), nullable=False)
    category = Column(String(100), nullable=False)           # BOLA, BrokenAuth, etc.
    severity = Column(Enum(Severity), nullable=False)
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(100), nullable=True)

    # Evidence
    endpoint = Column(String(512), nullable=False)
    method = Column(String(10), nullable=False)              # GET, POST, etc.
    description = Column(Text, nullable=False)
    evidence = Column(Text, nullable=True)                   # raw request/response proof
    remediation = Column(Text, nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    scan = relationship("Scan", back_populates="findings")

    def __repr__(self):
        return f"<Finding id={self.id} title={self.title!r} severity={self.severity}>"
