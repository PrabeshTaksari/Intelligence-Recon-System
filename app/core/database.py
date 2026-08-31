"""Database configuration and session management."""
from typing import AsyncGenerator
import json
import time
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    create_async_engine,
    async_sessionmaker
)
from sqlalchemy.orm import declarative_base

from app.core.config import settings

# Create async engine
engine: AsyncEngine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True,
    pool_pre_ping=True
)

# Create async session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)

# Declarative base for models
Base = declarative_base()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for getting async database sessions.
    
    Yields:
        AsyncSession instance
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


def _ensure_scheduled_scan_id_column(sync_conn):
    """Add scans.scheduled_scan_id if missing (SQLite; DB created before column was added)."""
    if getattr(sync_conn.dialect, "name", None) != "sqlite":
        return
    try:
        result = sync_conn.execute(text("PRAGMA table_info(scans)"))
        rows = result.fetchall()
    except Exception:
        return  # Table might not exist yet; create_all will create it
    cols = [row[1] for row in rows]
    if "scheduled_scan_id" not in cols:
        sync_conn.execute(text("ALTER TABLE scans ADD COLUMN scheduled_scan_id INTEGER"))


def _ensure_scheduled_scans_next_run_at(sync_conn):
    """Add scheduled_scans.next_run_at if missing (SQLite)."""
    if getattr(sync_conn.dialect, "name", None) != "sqlite":
        return
    try:
        result = sync_conn.execute(text("PRAGMA table_info(scheduled_scans)"))
        rows = result.fetchall()
    except Exception:
        return
    cols = [row[1] for row in rows]
    if "next_run_at" not in cols:
        sync_conn.execute(text("ALTER TABLE scheduled_scans ADD COLUMN next_run_at DATETIME"))


def _ensure_report_html_column(sync_conn):
    """Add scans.report_html if missing (persisted View Report content; no AI on re-view)."""
    if getattr(sync_conn.dialect, "name", None) != "sqlite":
        return
    try:
        result = sync_conn.execute(text("PRAGMA table_info(scans)"))
        rows = result.fetchall()
    except Exception:
        return
    cols = [row[1] for row in rows]
    if "report_html" not in cols:
        sync_conn.execute(text("ALTER TABLE scans ADD COLUMN report_html TEXT"))


def _ensure_endpoint_classification_column(sync_conn):
    """Add scans.endpoint_classification if missing (intelligence layer data)."""
    if getattr(sync_conn.dialect, "name", None) != "sqlite":
        return
    try:
        result = sync_conn.execute(text("PRAGMA table_info(scans)"))
        rows = result.fetchall()
    except Exception:
        return
    cols = [row[1] for row in rows]
    if "endpoint_classification" not in cols:
        sync_conn.execute(text("ALTER TABLE scans ADD COLUMN endpoint_classification TEXT"))


async def init_db() -> None:
    """Initialize database tables."""
    from app.models import scan, tool_run, finding, scheduled_scan  # Import models to register them
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_ensure_scheduled_scan_id_column)
        await conn.run_sync(_ensure_scheduled_scans_next_run_at)
        await conn.run_sync(_ensure_report_html_column)
        await conn.run_sync(_ensure_endpoint_classification_column)


