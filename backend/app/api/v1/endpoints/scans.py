"""
Scan management endpoints — create, list, get, and run scans.
"""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.db.models import Scan, ScanStatus
from app.schemas.scan import ScanCreate, ScanResponse, ScanListResponse

router = APIRouter()


@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(scan_in: ScanCreate, db: AsyncSession = Depends(get_db)):
    """Create a new scan configuration."""
    scan = Scan(
        name=scan_in.name,
        target_url=str(scan_in.target_url),
        spec_file=scan_in.spec_file,
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)
    return scan


@router.get("/", response_model=List[ScanListResponse])
async def list_scans(db: AsyncSession = Depends(get_db)):
    """List all scans, newest first."""
    result = await db.execute(select(Scan).order_by(Scan.created_at.desc()))
    scans = result.scalars().all()
    return scans


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Get a specific scan by ID, including findings."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/{scan_id}/run", response_model=ScanResponse)
async def run_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    """
    Trigger a scan run. (Phase 2 — currently a stub.)
    Will parse the spec, run attack modules, and populate findings.
    """
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status == ScanStatus.RUNNING:
        raise HTTPException(status_code=409, detail="Scan is already running")

    # TODO (Phase 2): Wire up the actual attack engine here.
    # For now, mark it as running (the engine will update to completed).
    scan.status = ScanStatus.RUNNING
    await db.flush()
    await db.refresh(scan)

    return scan
