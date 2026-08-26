"""
Application configuration — loaded from environment variables with sensible defaults.
"""

from typing import List

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Global app settings, populated from .env or environment variables."""

    # ── General ──
    PROJECT_NAME: str = "VAPT for Web APIs"
    DEBUG: bool = True

    # ── Server ──
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    # ── CORS ──
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",   # Vite dev server
        "http://localhost:3000",   # CRA fallback
        "http://127.0.0.1:5173",
    ]

    # ── Database ──
    DATABASE_URL: str = "sqlite+aiosqlite:///./vapt.db"

    # ── Scan defaults ──
    DEFAULT_TIMEOUT: int = 30          # seconds per request
    DEFAULT_CONCURRENCY: int = 10      # max concurrent attack requests
    RATE_LIMIT_BURST_COUNT: int = 50   # requests in rate-limit probe

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


settings = Settings()
