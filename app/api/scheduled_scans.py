"""Scheduled scans API - CRUD and run-due."""
import json
from typing import List, Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, func, case, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.config import settings
from app.core.logging import get_logger
from app.models.scheduled_scan import ScheduledScan
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.finding import FindingSeverity
from app.schemas.scheduled_scan import (
    ScheduledScanCreate,
    ScheduledScanUpdate,
    ScheduledScanResponse,
    FREQUENCY_CHOICES,
)
router = APIRouter(prefix="/scheduled-scans", tags=["scheduled-scans"])
logger = get_logger(__name__)


# Static path must be declared before /{schedule_id} so GET /scan-results is not matched as schedule_id
@router.get("/scan-results", response_model=List[Dict[str, Any]])
async def list_scheduled_scan_results(db: AsyncSession = Depends(get_db)):
    """List only scans that were triggered by a schedule (for Scheduled Scans page results)."""
    result = await db.execute(
        select(Scan)
        .where(Scan.scheduled_scan_id.isnot(None))
        .order_by(desc(Scan.created_at))
    )
    scans = result.scalars().all()
    out = []
    for scan in scans:
        # Finding count
        r = await db.execute(select(func.count(Finding.id)).where(Finding.scan_id == scan.id))
        finding_count = r.scalar() or 0
        # Highest severity
        r2 = await db.execute(
            select(Finding.severity)
            .where(Finding.scan_id == scan.id)
            .order_by(
                case(
                    (Finding.severity == FindingSeverity.CRITICAL, 1),
                    (Finding.severity == FindingSeverity.HIGH, 2),
                    (Finding.severity == FindingSeverity.MEDIUM, 3),
                    (Finding.severity == FindingSeverity.LOW, 4),
                    (Finding.severity == FindingSeverity.INFO, 5),
                    else_=6,
                )
            )
            .limit(1)
        )
        top = r2.scalar_one_or_none()
        highest_severity = top.value if top else None
        is_saved = bool(
            getattr(scan, "is_saved", False)
            or (scan.error_summary and "SAVED_SCAN" in scan.error_summary)
        )
        out.append({
            "id": scan.id,
            "target": scan.target,
            "owasp_category": scan.owasp_category,
            "scheduled_scan_id": scan.scheduled_scan_id,
            "status": scan.status.value,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "finding_count": finding_count,
            "highest_severity": highest_severity,
            "is_saved": is_saved,
        })
    return out


@router.get("", response_model=List[ScheduledScanResponse])
async def list_scheduled_scans(db: AsyncSession = Depends(get_db)):
    """List all scheduled scans (enabled and disabled)."""
    result = await db.execute(
        select(ScheduledScan).order_by(ScheduledScan.created_at.desc())
    )
    rows = result.scalars().all()
    out = []
    for r in rows:
        tools = r.selected_tools
        if isinstance(tools, str):
            try:
                tools = json.loads(tools) if tools else []
            except Exception:
                tools = []
        out.append(ScheduledScanResponse(
            id=r.id,
            target=r.target,
            owasp_category=r.owasp_category,
            selected_tools=tools,
            frequency=r.frequency,
            enabled=r.enabled,
            next_run_at=getattr(r, "next_run_at", None),
            last_run_at=r.last_run_at,
            created_at=r.created_at,
            updated_at=r.updated_at,
        ))
    return out


@router.post("", response_model=ScheduledScanResponse, status_code=201)
async def create_scheduled_scan(
    data: ScheduledScanCreate,
    db: AsyncSession = Depends(get_db),
):
    """Create a new scheduled scan. Frequency: once, daily, weekly, or monthly."""
    if data.frequency not in FREQUENCY_CHOICES:
        raise HTTPException(
            status_code=400,
            detail=f"Frequency must be one of: once, daily, weekly, monthly (got {data.frequency!r})",
        )
    invalid = [t for t in data.selected_tools if t not in settings.AVAILABLE_TOOLS]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Invalid tools: {', '.join(invalid)}")

    schedule = ScheduledScan(
        target=data.target,
        owasp_category=data.owasp_category,
        selected_tools=json.dumps(data.selected_tools),
        frequency=data.frequency,
        enabled=True,
        next_run_at=data.next_run_at,
    )
    db.add(schedule)
    await db.commit()
    await db.refresh(schedule)
    return ScheduledScanResponse(
        id=schedule.id,
        target=schedule.target,
        owasp_category=schedule.owasp_category,
        selected_tools=data.selected_tools,
        frequency=schedule.frequency,
        enabled=schedule.enabled,
        next_run_at=schedule.next_run_at,
        last_run_at=schedule.last_run_at,
        created_at=schedule.created_at,
        updated_at=schedule.updated_at,
    )


@router.patch("/{schedule_id}", response_model=ScheduledScanResponse)
async def update_scheduled_scan(
    schedule_id: int,
    data: ScheduledScanUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update a scheduled scan (partial)."""
    result = await db.execute(select(ScheduledScan).where(ScheduledScan.id == schedule_id))
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")

    if data.target is not None:
        schedule.target = data.target.strip().lower().replace("http://", "").replace("https://", "").rstrip("/")
    if data.owasp_category is not None:
        schedule.owasp_category = data.owasp_category
    if data.selected_tools is not None:
        invalid = [t for t in data.selected_tools if t not in settings.AVAILABLE_TOOLS]
        if invalid:
            raise HTTPException(status_code=400, detail=f"Invalid tools: {', '.join(invalid)}")
        schedule.selected_tools = json.dumps(data.selected_tools)
    if data.frequency is not None:
        schedule.frequency = data.frequency
    if data.enabled is not None:
        schedule.enabled = data.enabled
    if data.next_run_at is not None:
        schedule.next_run_at = data.next_run_at

    await db.commit()
    await db.refresh(schedule)
    tools = schedule.selected_tools
    if isinstance(tools, str):
        try:
            tools = json.loads(tools) if tools else []
        except Exception:
            tools = []
    return ScheduledScanResponse(
        id=schedule.id,
        target=schedule.target,
        owasp_category=schedule.owasp_category,
        selected_tools=tools,
        frequency=schedule.frequency,
        enabled=schedule.enabled,
        next_run_at=schedule.next_run_at,
        last_run_at=schedule.last_run_at,
        created_at=schedule.created_at,
        updated_at=schedule.updated_at,
    )


@router.delete("/{schedule_id}", status_code=204)
async def delete_scheduled_scan(
    schedule_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Delete a scheduled scan."""
    result = await db.execute(select(ScheduledScan).where(ScheduledScan.id == schedule_id))
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")
    await db.delete(schedule)
    await db.commit()
    return None


@router.post("/run-due", status_code=200)
async def run_due_scheduled_scans(db: AsyncSession = Depends(get_db)):
    """Run all due scheduled scans (called by scheduler or cron). Returns count of scans started."""
    from app.services.scheduled_scan_service import run_due_schedules
    started = await run_due_schedules(db)
    return {"started": started}
