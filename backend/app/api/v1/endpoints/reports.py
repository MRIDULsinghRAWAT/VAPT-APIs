"""
Report generation endpoints — PDF/HTML export of scan findings.
(Phase 3 — stub for now.)
"""

from fastapi import APIRouter, HTTPException

router = APIRouter()


@router.get("/{scan_id}/export")
async def export_report(scan_id: int, format: str = "html"):
    """
    Export a scan report as PDF or HTML.
    Phase 3 implementation — currently returns a stub.
    """
    if format not in ("html", "pdf"):
        raise HTTPException(status_code=400, detail="Format must be 'html' or 'pdf'")

    # TODO (Phase 3): Generate actual report using Jinja2 templates + WeasyPrint
    return {
        "scan_id": scan_id,
        "format": format,
        "status": "not_implemented",
        "message": "Report generation will be implemented in Phase 3.",
    }
