"""
Pydantic schemas for Scan CRUD operations.
"""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, HttpUrl


class ScanCreate(BaseModel):
    """Request body to create a new scan."""
    name: str
    target_url: HttpUrl
    spec_file: Optional[str] = None


class FindingResponse(BaseModel):
    """A single finding within a scan result."""
    id: int
    title: str
    category: str
    severity: str
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    endpoint: str
    method: str
    description: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ScanResponse(BaseModel):
    """Full scan detail response (includes findings)."""
    id: int
    name: str
    target_url: str
    spec_file: Optional[str] = None
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    total_endpoints: int
    total_findings: int
    findings: List[FindingResponse] = []

    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    """Lightweight scan entry for list views (no findings)."""
    id: int
    name: str
    target_url: str
    status: str
    created_at: datetime
    total_endpoints: int
    total_findings: int

    class Config:
        from_attributes = True
