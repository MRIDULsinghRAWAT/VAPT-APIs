"""
Scan management endpoints — create, list, get, and run scans.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.db.session import get_db, async_session
from app.db.models import Scan, ScanStatus
from app.schemas.scan import ScanCreate, ScanResponse, ScanListResponse
from app.schemas.spec import ParsedSpec
from app.services.spec_parser import parse_openapi_spec
from app.services.scan_engine import ScanEngine
from app.services.auth_handler import AuthCredentials, AuthType

router = APIRouter()
engine = ScanEngine()


class RunScanRequest(BaseModel):
    spec_content: str
    target_url: str
    token: Optional[str] = None


async def _run_scan_background(scan_id: int, spec_content: str, target_url: str, token: Optional[str]):
    async with async_session() as db:
        try:
            parsed_spec = parse_openapi_spec(spec_content)
            auth_creds = AuthCredentials(auth_type=AuthType.BEARER, token=token) if token else None
            await engine.execute_scan(
                db=db,
                scan_id=scan_id,
                parsed_spec=parsed_spec,
                base_url=target_url,
                auth_creds=auth_creds,
            )
        except Exception:
            pass


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
    await db.commit()
    await db.refresh(scan)
    return scan


@router.get("/", response_model=List[ScanListResponse])
async def list_scans(db: AsyncSession = Depends(get_db)):
    """List all scans, newest first."""
    result = await db.execute(select(Scan).order_by(Scan.created_at.desc()))
    return result.scalars().all()


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Get a specific scan by ID, including findings."""
    result = await db.execute(
        select(Scan).options(selectinload(Scan.findings)).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/{scan_id}/run", response_model=ScanResponse)
async def run_scan(
    scan_id: int,
    req: RunScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Trigger an active vulnerability scan run asynchronously."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status == ScanStatus.RUNNING:
        raise HTTPException(status_code=409, detail="Scan is already running")

    scan.status = ScanStatus.RUNNING
    await db.commit()
    await db.refresh(scan)

    background_tasks.add_task(
        _run_scan_background,
        scan_id=scan.id,
        spec_content=req.spec_content,
        target_url=req.target_url,
        token=req.token,
    )

    return scan
