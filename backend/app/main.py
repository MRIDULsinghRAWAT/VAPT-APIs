"""
Automated VAPT for Web APIs — FastAPI Application Entry Point

This is the main FastAPI app. It wires up:
  - API routers (scans, specs, reports, health)
  - CORS middleware (for React frontend)
  - Database lifecycle events
  - Global exception handlers
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.db.session import init_db
from app.api.v1 import router as api_v1_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    # ── Startup ──
    await init_db()
    yield
    # ── Shutdown ──
    # cleanup resources if needed


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Automated Vulnerability Assessment & Penetration Testing for Web APIs",
    version="0.1.0",
    lifespan=lifespan,
)

# ── CORS (allow React frontend) ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── API Routers ──
app.include_router(api_v1_router, prefix="/api/v1")


# ── Root health check ──
@app.get("/health", tags=["Health"])
async def health_check():
    """Basic health check endpoint."""
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": "0.1.0",
    }
