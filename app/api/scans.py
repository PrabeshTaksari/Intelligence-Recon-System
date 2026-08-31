"""Scan management endpoints."""
from typing import Optional, Dict, Any
import json
import time
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.config import settings
from app.core.logging import get_logger
from app.schemas.scan import (
    ScanCreate,
    ScanResponse,
    ScanStatus,
    ScanListResponse,
    ScanDetailResponse,
)
from app.services.scan_service import ScanService
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/scans", tags=["scans"])
logger = get_logger(__name__)


@router.post("", response_model=ScanResponse)
async def create_scan(
    scan_data: ScanCreate,
    db: AsyncSession = Depends(get_db),
):
    """Create and start a new scan (dashboard flow: clues → AI decision → execute). Never uses scheduled_scan_id."""
    # Validate selected tools
    invalid_tools = [
        tool for tool in scan_data.selected_tools
        if tool not in settings.AVAILABLE_TOOLS
    ]
    if invalid_tools:
        msg = f"Invalid tools: {', '.join(invalid_tools)}"
        logger.warning("POST /api/scans 400: %s", msg)
        raise HTTPException(status_code=400, detail=msg)

    if not scan_data.selected_tools:
        msg = "You must select at least one tool before starting a scan. AI will refine this list based on clues, but cannot choose tools from an empty selection."
        logger.warning("POST /api/scans 400: %s", msg)
        raise HTTPException(status_code=400, detail=msg)

    try:
        scan = await ScanService.create_scan(
            db=db,
            target=scan_data.target,
            owasp_category=scan_data.owasp_category,
            selected_tools=scan_data.selected_tools,
        )
    except ValueError as e:
        logger.warning("POST /api/scans 400: %s", str(e))
        raise HTTPException(status_code=400, detail=str(e))

    return ScanResponse(
        scan_id=scan.id,
        status=scan.status.value,
        message="Scan created successfully. AI decision and tool execution in progress.",
    )


@router.get("/any-running")
async def any_scan_running(db: AsyncSession = Depends(get_db)):
    """Return whether any scan is currently in progress, and its id if so (for cancel option)."""
    running = await ScanService.has_running_scan(db)
    running_scan_id = await ScanService.get_running_scan_id(db) if running else None
    return {"running": running, "running_scan_id": running_scan_id}


@router.post("/{scan_id}/mark-failed")
async def mark_scan_failed(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Mark a scan that is stuck in creating/preparing/running as failed so you can start a new scan."""
    updated = await ScanService.mark_scan_failed_if_stuck(db, scan_id)
    if not updated:
        raise HTTPException(
            status_code=404,
            detail="Scan not found or not in a running state (already completed/failed).",
        )
    return {"status": "ok", "message": f"Scan {scan_id} marked as failed."}


@router.get("/{scan_id}/status", response_model=ScanStatus)
async def get_scan_status(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Get scan status for polling."""
    status = await ScanService.get_scan_status(db, scan_id)

    if not status:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanStatus(**status)


@router.get("/{scan_id}/findings")
async def get_scan_findings(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Get all findings for a scan (for Target Scans table and compare)."""
    from app.models.finding import Finding
    result = await db.execute(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .order_by(Finding.created_at)
    )
    findings = result.scalars().all()
    return [
        {
            "id": f.id,
            "scan_id": f.scan_id,
            "tool_name": f.tool_name,
            "type": f.type.value if hasattr(f.type, "value") else str(f.type),
            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            "location": f.location,
            "description": f.description,
            "evidence": f.evidence,
            "created_at": f.created_at.isoformat() if f.created_at else None,
        }
        for f in findings
    ]


@router.get("/{scan_id}/intelligence-summary")
async def get_scan_intelligence_summary(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Get real-time intelligence summary for a scan.
    
    Returns structured narrative of the reconnaissance process as it unfolds.
    """
    from app.services.intelligence_service import IntelligenceService
    
    try:
        summary = await IntelligenceService.generate_intelligence_summary(db, scan_id)
        return summary
    except Exception as e:
        logger.error(f"Failed to generate intelligence summary for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate intelligence summary")


@router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan_detail(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Get detailed scan information."""
    detail = await ScanService.get_scan_detail(db, scan_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanDetailResponse(**detail)


@router.get("", response_model=ScanListResponse)
async def list_scans(
    target: Optional[str] = Query(None, description="Filter by target"),
    status: Optional[str] = Query(None, description="Filter by status"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    include_unsaved: bool = Query(True, description="Include unsaved scans"),
    db: AsyncSession = Depends(get_db),
):
    """List scans with optional filtering and pagination. By default, includes both saved and unsaved scans."""
    result = await ScanService.list_scans(
        db=db,
        target=target,
        status=status,
        page=page,
        page_size=page_size,
        include_unsaved=include_unsaved,
    )
    return ScanListResponse(**result)


@router.delete("/{scan_id}")
async def delete_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Delete a scan and its associated stored data."""
    deleted = await ScanService.delete_scan(db, scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found")
    return JSONResponse(status_code=200, content={"detail": "Scan deleted"})


@router.get("/stats/severity")
async def get_severity_stats(
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Get severity distribution of all findings across all scans (saved and unsaved)."""
    from app.models.finding import Finding, FindingSeverity
    from app.models.scan import Scan
    
    result = await db.execute(
        select(
            Finding.severity,
            func.count(Finding.id).label("count")
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .group_by(Finding.severity)
    )
    rows = result.fetchall()
    
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    
    for severity, count in rows:
        sev_str = severity.value if hasattr(severity, 'value') else str(severity).lower()
        if sev_str in severity_counts:
            severity_counts[sev_str] = count
    
    return severity_counts

@router.get("/stats/severity-saved")
async def get_severity_stats_saved(
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Get severity distribution of all findings across saved scans only (legacy endpoint)."""
    from app.models.finding import Finding, FindingSeverity
    from app.models.scan import Scan
    
    result = await db.execute(
        select(
            Finding.severity,
            func.count(Finding.id).label("count")
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .where(func.coalesce(Scan.error_summary, '').contains('SAVED_SCAN'))
        .group_by(Finding.severity)
    )
    rows = result.fetchall()
    
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    
    for severity, count in rows:
        sev_str = severity.value if hasattr(severity, 'value') else str(severity).lower()
        if sev_str in severity_counts:
            severity_counts[sev_str] = count
    
    return severity_counts


@router.get("/stats/severity-completed")
async def get_severity_stats_completed(
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Get severity distribution of all findings across completed scans only."""
    from app.models.finding import Finding, FindingSeverity
    from app.models.scan import Scan, ScanStatus
    
    result = await db.execute(
        select(
            Finding.severity,
            func.count(Finding.id).label("count")
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.status.in_([ScanStatus.COMPLETED, ScanStatus.COMPLETED_WITH_ERRORS]))
        .group_by(Finding.severity)
    )
    rows = result.fetchall()
    
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    
    for severity, count in rows:
        sev_str = severity.value if hasattr(severity, 'value') else str(severity).lower()
        if sev_str in severity_counts:
            severity_counts[sev_str] = count
    
    return severity_counts


@router.get("/stats/trend")
async def get_trend_stats(
    range_key: str = Query("7d", alias="range", pattern="^(7d|30d|90d)$"),
    date: Optional[str] = Query(None, description="Single date (YYYY-MM-DD) for that day's analytics"),
    start_date: Optional[str] = Query(None, description="Start date (YYYY-MM-DD) for custom range"),
    end_date: Optional[str] = Query(None, description="End date (YYYY-MM-DD) for custom range"),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Trend stats for Security Trend Analytics chart.
    Use start_date + end_date for custom range, or date for single day, or range=7d|30d|90d.
    """
    from app.models.finding import Finding

    use_custom_range = False
    if start_date and end_date:
        try:
            start = datetime.strptime(start_date, "%Y-%m-%d")
            end = datetime.strptime(end_date, "%Y-%m-%d")
            if start > end:
                start, end = end, start
            days = (end - start).days + 1
            end_exclusive = end + timedelta(days=1)
            date_filter = (Finding.created_at >= start, Finding.created_at < end_exclusive)
            use_custom_range = True
        except ValueError:
            pass
    if not use_custom_range:
        if date:
            try:
                start = datetime.strptime(date, "%Y-%m-%d")
            except ValueError:
                start = datetime.utcnow()
            end = start + timedelta(days=1)
            days = 1
            date_filter = (Finding.created_at >= start, Finding.created_at < end)
        else:
            days = 7 if range_key == "7d" else 30 if range_key == "30d" else 90
            now = datetime.utcnow()
            start = now - timedelta(days=days - 1)
            end = None
            date_filter = (Finding.created_at >= start,)

    result = await db.execute(
        select(Finding).where(*date_filter).order_by(Finding.created_at)
    )
    findings = result.scalars().all()

    date_map = {}
    vuln_map = {}  # Count only critical/high/medium (actual vulnerabilities)

    for finding in findings:
        date_key = finding.created_at.strftime("%Y-%m-%d")
        if date_key not in date_map:
            date_map[date_key] = 0
            vuln_map[date_key] = 0
        date_map[date_key] += 1
        sev = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        if sev in ("critical", "high", "medium"):
            vuln_map[date_key] += 1

    labels = []
    dates = []
    date_keys = []
    findings_data = []
    vuln_data = []

    for i in range(days):
        day = start + timedelta(days=i)
        label = day.strftime("%a")
        date_str = day.strftime("%b %d")
        date_key = day.strftime("%Y-%m-%d")

        labels.append(label)
        dates.append(date_str)
        date_keys.append(date_key)
        if date_key in date_map:
            findings_data.append(date_map[date_key])
            vuln_data.append(vuln_map.get(date_key, 0))
        else:
            findings_data.append(0)
            vuln_data.append(0)

    return {
        "labels": labels,
        "dates": dates,
        "date_keys": date_keys,
        "findings": findings_data,
        "vuln_targets": vuln_data,
    }


@router.get("/stats/trend/day-detail")
async def get_trend_day_detail(
    date: str = Query(..., description="Date (YYYY-MM-DD)"),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Findings for a single day (for Security Trend chart click modal). Uses Finding.created_at."""
    from app.models.finding import Finding
    from sqlalchemy.orm import selectinload

    try:
        day_start = datetime.strptime(date, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date; use YYYY-MM-DD")
    day_end = day_start + timedelta(days=1)

    result = await db.execute(
        select(Finding)
        .where(Finding.created_at >= day_start, Finding.created_at < day_end)
        .options(selectinload(Finding.scan))
        .order_by(Finding.created_at)
    )
    findings = result.scalars().unique().all()

    sev_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    vuln_targets = set()
    findings_list = []
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity).lower()
        if sev in sev_count:
            sev_count[sev] += 1
        if sev in ("critical", "high", "medium"):
            if f.scan:
                vuln_targets.add(f.scan.target or "")
        findings_list.append({
            "tool_name": f.tool_name,
            "type": f.type.value if hasattr(f.type, "value") else str(f.type),
            "severity": sev,
            "location": f.location,
            "description": f.description or "",
        })

    return {
        "date": date,
        "findings": findings_list,
        "severity_counts": sev_count,
        "affected_targets": len(vuln_targets),
    }


@router.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Delete a scan and all its associated data"""
    try:
        # Get the scan
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        
        # Delete all findings associated with this scan
        await db.execute(delete(Finding).where(Finding.scan_id == scan_id))
        
        # Delete the scan record
        await db.delete(scan)
        await db.commit()
        
        # Delete scan directory and files
        import shutil
        scan_dir = Path(settings.DATA_DIR) / "scans" / str(scan_id)
        if scan_dir.exists():
            shutil.rmtree(scan_dir)
        
        logger.info(f"Deleted scan {scan_id} and associated data")
        
        return {
            "status": "deleted",
            "scan_id": scan_id,
            "message": f"Scan {scan_id} and all associated data have been deleted"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting scan {scan_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/api/scans/{scan_id}/report")
async def delete_report(scan_id: int, format: str = "html", db: AsyncSession = Depends(get_db)):
    """Delete a specific report file for a scan"""
    try:
        # Verify scan exists
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        
        # Validate format
        if format not in ["html", "pdf"]:
            raise HTTPException(status_code=400, detail="Format must be 'html' or 'pdf'")
        
        # Delete report file
        scan_dir = Path(settings.DATA_DIR) / "scans" / str(scan_id)
        report_file = scan_dir / f"report.{format}"
        
        if report_file.exists():
            report_file.unlink()
            logger.info(f"Deleted {format.upper()} report for scan {scan_id}")
            return {
                "status": "deleted",
                "scan_id": scan_id,
                "format": format,
                "message": f"{format.upper()} report for scan {scan_id} has been deleted"
            }
        else:
            raise HTTPException(status_code=404, detail=f"Report file {scan_id} not found")
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting report for scan {scan_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/purge")
async def delete_all_scans(db: AsyncSession = Depends(get_db)):
    """Delete all scans and their associated data from the database"""
    try:
        # Get all scan IDs first
        result = await db.execute(select(Scan.id))
        scan_ids = [row[0] for row in result.fetchall()]
        
        # Delete all scans (this will cascade delete associated tool_runs and findings)
        await db.execute(delete(Scan))
        await db.commit()
        
        # Remove all scan directories from filesystem
        for scan_id in scan_ids:
            scan_dir = Path(settings.DATA_DIR) / "scans" / str(scan_id)
            if scan_dir.exists():
                import shutil
                shutil.rmtree(scan_dir)
        
        logger.info(f"Deleted {len(scan_ids)} scans and all associated data")
        
        return {
            "status": "deleted",
            "count": len(scan_ids),
            "message": f"All {len(scan_ids)} scans and associated data have been deleted"
        }
    
    except Exception as e:
        await db.rollback()
        logger.error(f"Error deleting all scans: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/targets/{target}/details")
async def get_target_details(
    target: str,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Get aggregated details for a specific target across all scans."""
    from app.models.finding import Finding, FindingSeverity
    from app.models.scan import Scan, ScanStatus
    from sqlalchemy import func, desc
    
    # Get all completed scans for this target
    result = await db.execute(
        select(Scan)
        .where(
            Scan.target == target,
            Scan.status.in_([ScanStatus.COMPLETED, ScanStatus.COMPLETED_WITH_ERRORS])
        )
        .order_by(desc(Scan.created_at))
    )
    scans = result.scalars().all()
    
    if not scans:
        raise HTTPException(status_code=404, detail="No completed scans found for this target")
    
    # Get all findings for this target
    scan_ids = [scan.id for scan in scans]
    result = await db.execute(
        select(Finding)
        .where(Finding.scan_id.in_(scan_ids))
        .order_by(desc(Finding.created_at))
    )
    findings = result.scalars().all()
    
    # Aggregate findings by severity
    severity_counts = {}
    for finding in findings:
        sev = finding.severity.value
        if sev not in severity_counts:
            severity_counts[sev] = 0
        severity_counts[sev] += 1
    
    # Group findings by type
    findings_by_type = {}
    for finding in findings:
        f_type = finding.type.value
        if f_type not in findings_by_type:
            findings_by_type[f_type] = []
        findings_by_type[f_type].append({
            "id": finding.id,
            "scan_id": finding.scan_id,
            "tool_name": finding.tool_name,
            "severity": finding.severity.value,
            "location": finding.location,
            "description": finding.description,
            "created_at": finding.created_at
        })
    
    # Create scan timeline
    timeline = []
    for scan in scans:
        # Get findings count for this scan
        scan_findings = [f for f in findings if f.scan_id == scan.id]
        timeline.append({
            "scan_id": scan.id,
            "created_at": scan.created_at,
            "status": scan.status.value,
            "owasp_category": scan.owasp_category,
            "findings_count": len(scan_findings),
            "critical": len([f for f in scan_findings if f.severity == FindingSeverity.CRITICAL]),
            "high": len([f for f in scan_findings if f.severity == FindingSeverity.HIGH]),
            "medium": len([f for f in scan_findings if f.severity == FindingSeverity.MEDIUM]),
            "low": len([f for f in scan_findings if f.severity == FindingSeverity.LOW]),
            "info": len([f for f in scan_findings if f.severity == FindingSeverity.INFO])
        })
    
    return {
        "target": target,
        "total_scans": len(scans),
        "total_findings": len(findings),
        "findings_by_severity": severity_counts,
        "findings_by_type": findings_by_type,
        "scan_timeline": timeline,
        "latest_scan": scans[0].created_at if scans else None
    }
