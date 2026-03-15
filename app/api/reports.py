"""Report generation endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.scan import Scan

from app.core.database import get_db
from app.services.report_service import ReportService

router = APIRouter(prefix="/scans", tags=["reports"])


@router.get("/{scan_id}/report")
async def get_scan_report(
    scan_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Generate and return scan report as HTML."""
    html = await ReportService.generate_html_report(db, scan_id)
    
    if not html:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return HTMLResponse(content=html)


@router.get("/{scan_id}/report/pdf")
async def get_scan_report_pdf(
    scan_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Generate and return scan report as PDF."""
    pdf_bytes = await ReportService.generate_pdf_report(db, scan_id)
    
    if not pdf_bytes:
        raise HTTPException(
            status_code=500,
            detail="Failed to generate PDF. Ensure WeasyPrint is installed and the scan exists."
        )
    
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=IRS_Scan_{scan_id}_Report.pdf"}
    )


@router.post("/{scan_id}/mark-saved")
async def mark_scan_as_saved(
    scan_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Mark a scan as saved for permanent storage.

    Also ensures the View Report content (AI-generated HTML) is persisted:
    if the report was never generated, generates it once and saves it, so that
    Saved Reports always have the same report content as View Report, and
    re-viewing never calls AI again.
    """
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Ensure View Report content is persisted (generate once if not yet generated)
    if not (scan.report_html and scan.report_html.strip()):
        await ReportService.generate_html_report(db, scan_id)

    # Re-fetch scan after possible report generation (it commits)
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one()

    # Mark the scan as saved
    if scan.error_summary:
        if "SAVED_SCAN" not in scan.error_summary:
            scan.error_summary = scan.error_summary + " | SAVED_SCAN"
    else:
        scan.error_summary = "SAVED_SCAN"

    await db.commit()

    return {"status": "success", "message": "Scan marked as saved", "scan_id": scan_id}

