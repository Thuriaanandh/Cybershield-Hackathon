"""
database.py - Database engine and session management for LiveBoot Sentinel.
Uses SQLAlchemy ORM to prevent SQL injection. Supports SQLite and PostgreSQL.
"""

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from models import Base

logger = logging.getLogger(__name__)

# ─── Database URL Configuration ───────────────────────────────────────────────
# Priority: env var > default SQLite

def _get_database_url() -> str:
    """
    Build database URL from environment variables.
    Supports SQLite (default) and PostgreSQL.
    Never logs credentials.
    """
    db_url = os.environ.get("LIVEBOOT_DB_URL", "")

    if db_url:
        # Validate scheme to prevent URL injection
        allowed_schemes = ("postgresql+asyncpg://", "sqlite+aiosqlite:///")
        if not any(db_url.startswith(s) for s in allowed_schemes):
            logger.error("Invalid database URL scheme — falling back to SQLite")
            db_url = ""

    if not db_url:
        # Default: SQLite with aiosqlite
        db_dir = Path(os.environ.get("LIVEBOOT_DB_DIR", "/var/lib/liveboot_sentinel"))
        db_dir.mkdir(parents=True, exist_ok=True)
        db_path = db_dir / "sentinel.db"
        db_url = f"sqlite+aiosqlite:///{db_path}"
        logger.info("Using SQLite database at: %s", db_path)

    return db_url


DATABASE_URL = _get_database_url()

# ─── Engine Setup ─────────────────────────────────────────────────────────────

_engine_kwargs: dict = {
    "echo": False,  # Never log SQL in production (may expose data)
}

if DATABASE_URL.startswith("sqlite"):
    # SQLite-specific settings for async compatibility
    _engine_kwargs["connect_args"] = {"check_same_thread": False}
    _engine_kwargs["poolclass"] = StaticPool

engine = create_async_engine(DATABASE_URL, **_engine_kwargs)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


# ─── Session Dependency ───────────────────────────────────────────────────────

async def get_db() -> AsyncSession:
    """
    FastAPI dependency for database sessions.
    Always closes session on exit, even on error.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ─── Database Initialization ──────────────────────────────────────────────────

async def init_db() -> None:
    """Create all tables if they don't exist."""
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.critical("Database initialization failed: %s", str(e)[:200])
        raise


async def close_db() -> None:
    """Dispose database connection pool."""
    await engine.dispose()
    logger.info("Database connections closed")
