"""
Spec parsing endpoints — upload and parse OpenAPI/Swagger specs.
This is the core Phase 1 entry point.
"""

from fastapi import APIRouter, HTTPException, UploadFile, File
from app.schemas.spec import ParsedSpec
from app.services.spec_parser import parse_openapi_spec

router = APIRouter()


@router.post("/parse", response_model=ParsedSpec)
async def parse_spec(file: UploadFile = File(...)):
    """
    Upload an OpenAPI/Swagger spec (JSON or YAML) and get back
    a structured attack surface map.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    # Validate file extension
    allowed_extensions = {".json", ".yaml", ".yml"}
    ext = "." + file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Allowed: {allowed_extensions}",
        )

    content = await file.read()

    try:
        parsed = parse_openapi_spec(content.decode("utf-8"), file.filename)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Failed to parse spec: {str(e)}")

    return parsed


@router.post("/parse-url", response_model=ParsedSpec)
async def parse_spec_from_url(url: str):
    """
    Fetch an OpenAPI spec from a URL (e.g. /swagger.json) and parse it.
    """
    import httpx

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url)
            resp.raise_for_status()
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Failed to fetch spec: {str(e)}")

    try:
        parsed = parse_openapi_spec(resp.text, "remote_spec")
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Failed to parse spec: {str(e)}")

    return parsed
