"""Run due scheduled scans - used by API and by the in-process scheduler."""
import json
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.scheduled_scan import ScheduledScan
from app.services.scan_service import ScanService

logger = get_logger(__name__)


def _next_run_after(last_run: datetime, frequency: str) -> datetime | None:
    """Compute next run time after last_run. Returns None for 'once'."""
    if frequency == "once":
        return None
    if frequency == "daily":
        return last_run + timedelta(days=1)
    if frequency == "weekly":
        return last_run + timedelta(days=7)
    if frequency == "monthly":
        # Run again after 30 days
        return last_run + timedelta(days=30)
    return None


async def run_due_schedules(db: AsyncSession) -> int:
    """
    Find all enabled scheduled scans where next_run_at <= now and start a scan for each.

    Behaviour:
    - If the server was online at the scheduled time (within a small grace window),
      the scan is created as normal.
    - If the scheduled time is in the past beyond the grace window (server was down),
      the run is considered "missed": no scan is created, and next_run_at is advanced
      to the next occurrence (or the schedule is disabled for 'once').

    Returns the number of scans started.
    """
    now = datetime.utcnow()
    # How far past the scheduled time we still consider a run "on time".
    # Anything older than this is treated as a missed run and skipped.
    grace_window = timedelta(minutes=2)
    result = await db.execute(
        select(ScheduledScan).where(
            ScheduledScan.enabled.is_(True),
            ScheduledScan.next_run_at.isnot(None),
            ScheduledScan.next_run_at <= now,
        )
    )
    schedules = result.scalars().all()
    started = 0
    for s in schedules:
        # If this schedule's next_run_at is far in the past, treat it as missed.
        if s.next_run_at and s.next_run_at < now - grace_window:
            next_run = _next_run_after(now, s.frequency)
            if next_run is None:
                # 'once' schedule missed while server was down: disable without running
                s.enabled = False
                s.next_run_at = None
            else:
                s.next_run_at = next_run
            s.last_run_at = None
            await db.commit()
            logger.info(
                f"Scheduled scan {s.id} missed its window at {s.next_run_at} and was skipped; "
                f"next run is scheduled at {s.next_run_at or 'disabled'}"
            )
            continue
        tools_str = s.selected_tools
        if isinstance(tools_str, str):
            try:
                tools_list = json.loads(tools_str) if tools_str else []
            except Exception:
                tools_list = []
        else:
            tools_list = list(tools_str) if tools_str else []
        if not tools_list:
            continue
        try:
            # scheduled_scan_id set → scan runs as scheduled flow (no clues, no AI; run chosen tools only)
            scan = await ScanService.create_scan(
                db=db,
                target=s.target,
                owasp_category=s.owasp_category,
                selected_tools=tools_list,
                scheduled_scan_id=s.id,
            )
            s.last_run_at = now
            next_run = _next_run_after(now, s.frequency)
            if next_run is None:
                # once: disable after run
                s.enabled = False
                s.next_run_at = None
            else:
                s.next_run_at = next_run
            await db.commit()
            started += 1
            logger.info(f"Scheduled scan {s.id} triggered scan {scan.id} for {s.target}")
        except ValueError as e:
            logger.warning(f"Scheduled scan {s.id} skipped: {e}")
            continue
        except Exception as e:
            logger.exception(f"Scheduled scan {s.id} failed: {e}")
            continue
    return started
