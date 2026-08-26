"""
API v1 router — aggregates all v1 sub-routers.
"""

from fastapi import APIRouter

from app.api.v1.endpoints import scans, specs, reports

router = APIRouter()

router.include_router(scans.router, prefix="/scans", tags=["Scans"])
router.include_router(specs.router, prefix="/specs", tags=["Spec Parser"])
router.include_router(reports.router, prefix="/reports", tags=["Reports"])
