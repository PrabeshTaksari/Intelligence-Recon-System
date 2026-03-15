"""Scan orchestration service."""
import asyncio
import json
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional
from sqlalchemy import select, func, desc, case
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.scan import Scan, ScanStatus
from app.models.tool_run import ToolRun, ToolRunStatus
from app.models.finding import Finding, FindingSeverity
from app.core.config import settings
from app.core.logging import get_logger
from app.tools.executor import execute_tool
from app.core.ws_updates import init_websocket_manager
from app.ai.decision_node import decide_tools
from app.ai.validation import validate_ai_plan_and_execution
from app.core.validation import validate_domain

logger = get_logger(__name__)


def _get_owasp_category_name(category_id: str) -> str:
    """Get the full OWASP category name from category ID.
    
    Args:
        category_id: OWASP category ID (e.g., A01:2021)
        
    Returns:
        Full category name
    """
    for category in settings.OWASP_CATEGORIES:
        if category["id"] == category_id:
            return category["name"]
    return f"Unknown ({category_id})"


class ScanService:
    """Service for managing scan lifecycle and orchestration."""

    # Scans in CREATING/PREPARING/RUNNING older than this are treated as stuck and do not block new scans.
    STALE_RUNNING_THRESHOLD_MINUTES = 30

    @staticmethod
    async def has_running_scan(db: AsyncSession) -> bool:
        """Return True if any scan is actively in creating, preparing, or running status.

        Scans stuck in those statuses for longer than STALE_RUNNING_THRESHOLD_MINUTES
        (e.g. after a crash or incomplete run) are ignored so the user can start a new scan.
        """
        threshold = datetime.utcnow() - timedelta(minutes=ScanService.STALE_RUNNING_THRESHOLD_MINUTES)
        result = await db.execute(
            select(Scan)
            .where(
                Scan.status.in_([
                    ScanStatus.CREATING,
                    ScanStatus.PREPARING,
                    ScanStatus.RUNNING,
                ]),
                Scan.updated_at >= threshold,
            )
            .limit(1)
        )
        return result.scalar_one_or_none() is not None

    @staticmethod
    async def get_running_scan_id(db: AsyncSession) -> Optional[int]:
        """Return the id of a scan that is currently in creating/preparing/running, or None.
        Uses the same stale threshold as has_running_scan."""
        threshold = datetime.utcnow() - timedelta(minutes=ScanService.STALE_RUNNING_THRESHOLD_MINUTES)
        result = await db.execute(
            select(Scan.id)
            .where(
                Scan.status.in_([
                    ScanStatus.CREATING,
                    ScanStatus.PREPARING,
                    ScanStatus.RUNNING,
                ]),
                Scan.updated_at >= threshold,
            )
            .order_by(Scan.id.desc())
            .limit(1)
        )
        row = result.scalar_one_or_none()
        if row is None:
            return None
        try:
            return int(row)
        except (TypeError, IndexError):
            return int(row[0])

    @staticmethod
    async def mark_scan_failed_if_stuck(
        db: AsyncSession, scan_id: int
    ) -> bool:
        """If the scan is in CREATING/PREPARING/RUNNING, set it to FAILED and return True. Otherwise return False."""
        result = await db.execute(
            select(Scan).where(
                Scan.id == scan_id,
                Scan.status.in_([
                    ScanStatus.CREATING,
                    ScanStatus.PREPARING,
                    ScanStatus.RUNNING,
                ]),
            )
        )
        scan = result.scalar_one_or_none()
        if not scan:
            return False
        old_status = scan.status
        scan.status = ScanStatus.FAILED
        scan.completed_at = datetime.utcnow()
        if scan.error_summary:
            scan.error_summary = f"Marked as failed (stuck). {scan.error_summary}"
        else:
            scan.error_summary = "Marked as failed (stuck or cancelled)."
        await db.commit()
        logger.info(f"Scan {scan_id} marked as failed (was {old_status}).")
        return True

    @staticmethod
    async def create_scan(
        db: AsyncSession,
        target: str,
        owasp_category: str,
        selected_tools: List[str],
        scheduled_scan_id: Optional[int] = None,
    ) -> Scan:
        """Create a new scan and start execution workflow.

        Args:
            db: Database session
            target: Target domain
            owasp_category: OWASP category ID
            selected_tools: User-selected tools
            scheduled_scan_id: If set, this scan was triggered by a schedule (for Scheduled Scans page).

        Returns:
            Created Scan object

        Raises:
            ValueError: If another scan is already running (only for user-started scans).
        """
        # Block if any scan is already in progress (only for manually started scans).
        # Scheduled scans are allowed to start at their time even if another scan is running or stuck.
        if scheduled_scan_id is None:
            has_running = await ScanService.has_running_scan(db)
            if has_running:
                raise ValueError(
                    "Another scan is still running. Please wait for it to complete before starting a new one."
                )

        # Validate that the target is a real, hosted domain or IP
        is_valid, validation_message = validate_domain(target)
        if not is_valid:
            raise ValueError(f"Invalid target: {validation_message}")
        
        # Create scan record
        scan = Scan(
            target=target,
            owasp_category=owasp_category,
            status=ScanStatus.CREATING,
            user_selected_tools=json.dumps(selected_tools),
            scheduled_scan_id=scheduled_scan_id,
        )

        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        # Initialize WebSocket manager
        init_websocket_manager()

        logger.info(
            f"Created scan {scan.id} for target={target}, owasp={owasp_category}"
        )

        # Start background workflow
        asyncio.create_task(
            ScanService._execute_scan_workflow(
                scan.id, target, owasp_category, selected_tools,
                scheduled_scan_id=scheduled_scan_id,
            )
        )

        return scan

    @staticmethod
    async def _execute_scan_workflow(
        scan_id: int,
        target: str,
        owasp_category: str,
        selected_tools: List[str],
        scheduled_scan_id: Optional[int] = None,
    ) -> None:
        """Execute complete scan workflow asynchronously.

        Two separate flows (do not merge):

        - DASHBOARD SCAN (scheduled_scan_id is None):
          User runs scan from dashboard → gather clues → send to AI → AI decides which tools
          to execute → execute those tools → output.

        - SCHEDULED SCAN (scheduled_scan_id is set):
          User added a schedule; at schedule time → no clue gathering, no AI decision →
          directly execute the tools the user chose when creating the schedule.
        """
        from app.core.database import AsyncSessionLocal

        async with AsyncSessionLocal() as db:
            try:
                # Update status to preparing
                await ScanService._update_scan_status(
                    db, scan_id, ScanStatus.PREPARING
                )

                valid_tools = set(settings.AVAILABLE_TOOLS)
                normalized_tools_to_run: List[str] = [
                    t for t in selected_tools if t in valid_tools
                ]

                # ----- SCHEDULED SCAN FLOW (not dashboard): no clues, no AI; run chosen tools only -----
                if scheduled_scan_id is not None:
                    logger.info(
                        f"Scan {scan_id}: Scheduled scan — running {len(normalized_tools_to_run)} user-selected tools only (no clues, no AI decision)"
                    )
                    try:
                        from app.core.ws_updates import send_scan_phase_update, send_log_message
                        await send_log_message(
                            scan_id, "System",
                            f"Scheduled scan: running {len(normalized_tools_to_run)} selected tools (no clue gathering or AI analysis)."
                        )
                        await send_scan_phase_update(
                            scan_id, "scheduled_run",
                            {"phase": "Scheduled scan", "tools": normalized_tools_to_run}
                        )
                    except ImportError:
                        pass
                    clues = {}
                    result = await db.execute(select(Scan).where(Scan.id == scan_id))
                    scan = result.scalar_one()
                    scan.ai_tools_to_run = json.dumps(normalized_tools_to_run)
                    scan.ai_tools_skipped = json.dumps([])
                    scan.ai_raw_response = None
                    await db.commit()
                else:
                    # ----- DASHBOARD SCAN FLOW: clues → AI decision → execute AI-chosen tools -----
                    # Phase 1 — Run initial clues tools
                    try:
                        from app.core.ws_updates import send_scan_phase_update
                        await send_scan_phase_update(scan_id, "clues_gathering", {"phase": "Clues Gathering", "clueTools": ["Naabu", "Httpx"]})
                    except ImportError:
                        pass

                    logger.info(f"Scan {scan_id}: Running initial clues phase")
                    try:
                        from app.core.ws_updates import send_scan_phase_update, send_log_message
                        await send_log_message(scan_id, "System", "Starting initial reconnaissance with Naabu for port scanning...")
                        await send_scan_phase_update(scan_id, "clues_gathering", {
                            "currentPhase": "clues_gathering",
                            "currentTool": "Naabu",
                            "command": f"naabu -host {target}"
                        })
                        await send_log_message(scan_id, "System", "Starting HTTP reconnaissance with Httpx...")
                        await send_scan_phase_update(scan_id, "clues_gathering", {
                            "currentPhase": "clues_gathering",
                            "currentTool": "Httpx",
                            "command": f"httpx -u {target}"
                        })
                    except ImportError:
                        pass

                    clues = await ScanService._gather_initial_clues(scan_id, target, db)

                    result = await db.execute(select(Scan).where(Scan.id == scan_id))
                    scan = result.scalar_one()
                    scan.error_summary = (
                        f"Initial Reconnaissance Clues:\n"
                        f"- Open Ports: {clues.get('open_ports', 'None detected')}\n"
                        f"- HTTP Services: {clues.get('http_services', 'None detected')}\n"
                        f"- Server Headers: {clues.get('server_headers', 'None detected')}\n"
                        f"- Page Titles: {clues.get('page_titles', 'None detected')}\n"
                        f"- Status Codes: {clues.get('status_codes', 'None detected')}\n"
                        f"- Technologies Detected: {clues.get('technologies', 'None detected')}\n\n"
                        f"{scan.error_summary or ''}"
                    )
                    await db.commit()

                    # Phase 2: Get AI decision (manual scans only)
                    logger.info(f"Scan {scan_id}: Getting AI decision")
                    try:
                        from app.core.ws_updates import send_scan_phase_update, send_log_message
                        await send_log_message(scan_id, "System", "Sending reconnaissance data to AI for analysis...")
                        await send_scan_phase_update(scan_id, "ai_decision", {
                            "currentPhase": "ai_decision",
                            "aiTools": selected_tools,
                            "clues": clues,
                        })
                    except ImportError:
                        pass
                    owasp_name = next(
                        (
                            cat["name"]
                            for cat in settings.OWASP_CATEGORIES
                            if cat["id"] == owasp_category
                        ),
                        "Unknown",
                    )

                    try:
                        ai_decision = await decide_tools(
                            target=target,
                            owasp_category=owasp_category,
                            owasp_name=owasp_name,
                            selected_tools=selected_tools,
                            clues=clues,
                        )
                        result = await db.execute(select(Scan).where(Scan.id == scan_id))
                        scan = result.scalar_one()
                        if scan.ai_raw_response:
                            scan.ai_raw_response = (
                                f"Initial Reconnaissance Clues:\n"
                                f"- Open Ports: {clues.get('open_ports', 'None detected')}\n"
                                f"- HTTP Services: {clues.get('http_services', 'None detected')}\n"
                                f"- Server Headers: {clues.get('server_headers', 'None detected')}\n"
                                f"- Page Titles: {clues.get('page_titles', 'None detected')}\n"
                                f"- Status Codes: {clues.get('status_codes', 'None detected')}\n"
                                f"- Technologies Detected: {clues.get('technologies', 'None detected')}\n\n"
                                f"{scan.ai_raw_response}"
                            )
                            await db.commit()
                    except Exception as e:
                        logger.error(
                            f"AI decision node failed for scan {scan_id}: {e}",
                            exc_info=True,
                        )
                        safe_tools = [
                            t for t in selected_tools if t in settings.AVAILABLE_TOOLS
                        ]
                        result = await db.execute(select(Scan).where(Scan.id == scan_id))
                        scan = result.scalar_one()
                        scan.ai_tools_to_run = json.dumps(safe_tools)
                        scan.ai_tools_skipped = json.dumps([])
                        scan.ai_raw_response = None
                        scan.error_summary = (
                            f"AI Decision error, falling back to user tools: {str(e)}"
                        )
                        await db.commit()

                        ai_decision = type("FallbackDecision", (), {})()
                        ai_decision.tools_to_run = safe_tools
                        ai_decision.tools_skipped = []
                        ai_decision.success = False
                        ai_decision.error = str(e)

                    normalized_tools_to_run = []
                    unknown_tools: List[str] = []
                    for t in ai_decision.tools_to_run or []:
                        if t in valid_tools:
                            normalized_tools_to_run.append(t)
                        else:
                            unknown_tools.append(t)
                    if not normalized_tools_to_run:
                        normalized_tools_to_run = [
                            t for t in selected_tools if t in valid_tools
                        ]

                    result = await db.execute(select(Scan).where(Scan.id == scan_id))
                    scan = result.scalar_one()
                    scan.ai_tools_to_run = json.dumps(normalized_tools_to_run)
                    scan.ai_tools_skipped = json.dumps(
                        ai_decision.tools_skipped or []
                    )
                    scan.ai_raw_response = getattr(
                        ai_decision, "raw_response", None
                    )

                    messages: List[str] = []
                    if not getattr(ai_decision, "success", True):
                        messages.append(
                            "AI decision reported an error: "
                            f"{getattr(ai_decision, 'error', 'Unknown error')}."
                        )
                    if unknown_tools:
                        messages.append(
                            "AI suggested unknown tools: "
                            + ", ".join(unknown_tools) + "."
                        )
                    if not normalized_tools_to_run:
                        messages.append(
                            "No valid tools were selected after validation."
                        )
                    if messages:
                        scan.error_summary = (scan.error_summary or "") + " " + " ".join(messages)
                    await db.commit()

                # Phase 3: Create tool run records (in execution order: discovery -> other -> exploit)
                discovery_tools = [t for t in normalized_tools_to_run if t in settings.DISCOVERY_TOOLS]
                exploit_tools = [t for t in normalized_tools_to_run if t in settings.EXPLOIT_TOOLS]
                other_tools = [t for t in normalized_tools_to_run if t not in discovery_tools and t not in exploit_tools]
                execution_order = discovery_tools + other_tools + exploit_tools
                logger.info(
                    f"Scan {scan_id}: Creating tool run records "
                    f"for {len(normalized_tools_to_run)} tools (order: discovery -> other -> exploit)"
                )
                for tool_name in execution_order:
                    tool_run = ToolRun(
                        scan_id=scan_id,
                        tool_name=tool_name,
                        status=ToolRunStatus.QUEUED,
                    )
                    db.add(tool_run)

                await db.commit()

                # Update status to running
                await ScanService._update_scan_status(
                    db, scan_id, ScanStatus.RUNNING
                )

                # Phase 4: Execute tools
                logger.info(f"Scan {scan_id}: Starting tool execution phase")
                
                # Send update for tool execution start
                try:
                    from app.core.ws_updates import send_scan_phase_update, send_log_message
                    await send_log_message(scan_id, "System", f"Starting execution of {len(normalized_tools_to_run)} tools...")
                    # Don't send a single event for all tools, individual events will be sent during execution
                except ImportError:
                    pass
                
                await ScanService._execute_tools(
                    db, scan_id, target, normalized_tools_to_run, clues=clues
                )

                # Phase 5: Finalize scan (includes AI validation)
                logger.info(f"Scan {scan_id}: Finalizing")
                await ScanService._finalize_scan(db, scan_id)

            except Exception as e:
                logger.error(
                    f"Scan {scan_id} workflow failed: {e}", exc_info=True
                )
                async with AsyncSessionLocal() as db:
                    result = await db.execute(
                        select(Scan).where(Scan.id == scan_id)
                    )
                    scan = result.scalar_one_or_none()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_summary = f"Workflow error: {str(e)}"
                        scan.completed_at = datetime.utcnow()
                        await db.commit()

    @staticmethod
    async def _gather_initial_clues(
        scan_id: int, target: str, db: AsyncSession
    ) -> Dict[str, Any]:
        """Run initial clues tools and gather reconnaissance data.

        Args:
            scan_id: Scan ID
            target: Target domain
            db: Database session

        Returns:
            Dictionary of clues
        """
        clues = {
            "open_ports": [],
            "http_services": [],
            "server_headers": [],
            "page_titles": [],
            "status_codes": [],
            "technologies": [],
        }

        # Run Naabu (port scan)
        try:
            naabu_result = await execute_tool(
                "Naabu", target, scan_id, timeout=120
            )
            if naabu_result.success:
                # Save findings to database
                for finding_data in naabu_result.findings:
                    desc = finding_data.get("description", "")
                    # Dedupe accidental description duplication at source
                    if desc and len(desc) >= 4:
                        half = len(desc) // 2
                        if desc[:half] == desc[half:]:
                            desc = desc[:half]
                    finding = Finding(
                        scan_id=scan_id,
                        tool_name="Naabu",
                        type=finding_data.get("type", "port"),
                        severity=finding_data.get("severity", "info"),
                        owasp_category=None,
                        location=finding_data.get("location", ""),
                        description=desc,
                        evidence=finding_data.get("evidence"),
                    )
                    db.add(finding)
                
                ports = [
                    f["location"].split(":")[-1]
                    for f in naabu_result.findings
                ]
                clues["open_ports"] = ports[:20]  # Limit
        except Exception as e:
            logger.error(f"Naabu clues failed: {e}")

        # Run Httpx (HTTP probe); pass clues so Httpx can probe Naabu's open ports (e.g. http://127.0.0.1:8080)
        try:
            httpx_result = await execute_tool(
                "Httpx", target, scan_id, timeout=120, clues=clues
            )
            if httpx_result.success:
                # Save findings to database
                for finding_data in httpx_result.findings:
                    desc = finding_data.get("description", "")
                    if desc and len(desc) >= 4:
                        half = len(desc) // 2
                        if desc[:half] == desc[half:]:
                            desc = desc[:half]
                    finding = Finding(
                        scan_id=scan_id,
                        tool_name="Httpx",
                        type=finding_data.get("type", "endpoint"),
                        severity=finding_data.get("severity", "info"),
                        owasp_category=None,
                        location=finding_data.get("location", ""),
                        description=desc,
                        evidence=finding_data.get("evidence"),
                    )
                    db.add(finding)
                
                for finding in httpx_result.findings:
                    try:
                        evidence = json.loads(
                            finding.get("evidence", "{}")
                        )
                        clues["http_services"].append(evidence.get("url", ""))

                        if evidence.get("title"):
                            clues["page_titles"].append(evidence["title"])
                        if evidence.get("status_code"):
                            clues["status_codes"].append(
                                str(evidence["status_code"])
                            )
                        if evidence.get("technologies"):
                            clues["technologies"].extend(
                                evidence["technologies"]
                            )
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            logger.error(f"Httpx clues failed: {e}")
        
        # Commit the findings from initial clues
        await db.commit()

        logger.info(f"Clues gathered: {clues}")
        return clues

    @staticmethod
    def _extract_urls_from_finding(location: str, target: str) -> Optional[str]:
        """Extract HTTP(S) URL from a finding location."""
        if not location:
            return None
        loc = str(location).strip()
        if loc.startswith("http://") or loc.startswith("https://"):
            return loc
        if "://" in loc:
            return loc
        # Subdomain or host:port - convert to URL
        if ":" in loc and not loc.startswith("http"):
            host, port = loc.rsplit(":", 1)
            if port in ("80", "443"):
                scheme = "https" if port == "443" else "http"
                return f"{scheme}://{host}"
        return f"https://{loc}" if loc else None

    @staticmethod
    async def _execute_tools(
        db: AsyncSession,
        scan_id: int,
        target: str,
        tool_names: List[str],
        clues: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Execute tools in phases: discovery first (to collect URLs), then exploit.

        Args:
            db: Database session
            scan_id: Scan ID
            target: Target domain
            tool_names: List of tool names to execute
            clues: Initial clues from Naabu/Httpx (http_services, etc.)
        """
        clues = clues or {}
        discovery_tools = [t for t in tool_names if t in settings.DISCOVERY_TOOLS]
        exploit_tools = [t for t in tool_names if t in settings.EXPLOIT_TOOLS]
        other_tools = [t for t in tool_names if t not in discovery_tools and t not in exploit_tools]
        # Order: discovery first, then other, then exploit (so exploit gets discovered URLs)
        ordered_tools = discovery_tools + other_tools + exploit_tools
        # Start with URLs from clues (Httpx already ran in clues phase)
        discovered_urls: List[str] = list(dict.fromkeys(
            u for u in (clues.get("http_services") or [])
            if u and (str(u).startswith("http://") or str(u).startswith("https://"))
        ))
        discovered_urls.extend([f"https://{target}", f"http://{target}"])
        discovered_urls = list(dict.fromkeys(discovered_urls))
        logger.info(f"Initial discovered_urls: {len(discovered_urls)} from clues")

        async def execute_one_tool(tool_name: str):
            # Get tool run record
            result = await db.execute(
                select(ToolRun).where(
                    ToolRun.scan_id == scan_id,
                    ToolRun.tool_name == tool_name,
                )
            )
            tool_run = result.scalar_one_or_none()

            if not tool_run:
                logger.warning(f"ToolRun not found for {tool_name}, creating new one")
                # Create a new tool run record if it doesn't exist
                tool_run = ToolRun(
                    scan_id=scan_id,
                    tool_name=tool_name,
                    status=ToolRunStatus.RUNNING,
                    started_at=datetime.utcnow()
                )
                db.add(tool_run)
                await db.commit()
                await db.refresh(tool_run)
            else:
                # Update to running
                tool_run.status = ToolRunStatus.RUNNING
                tool_run.started_at = datetime.utcnow()
                await db.commit()

            # Send update for tool execution
            try:
                from app.core.ws_updates import send_scan_phase_update, send_log_message
                await send_log_message(scan_id, "System", f"Starting execution of {tool_name}...")
                await send_scan_phase_update(scan_id, "tool_execution", {
                    "currentPhase": "tool_execution",
                    "currentTool": tool_name,
                    "command": f"Executing {tool_name} against {target}"
                })
            except ImportError:
                pass
            
            # Update to running
            tool_run.status = ToolRunStatus.RUNNING
            tool_run.started_at = datetime.utcnow()
            await db.commit()

            # Execute tool - pass discovered_urls and clues for exploit tools
            is_exploit = tool_name in settings.EXPLOIT_TOOLS
            tool_result = await execute_tool(
                tool_name, target, scan_id,
                discovered_urls=discovered_urls if is_exploit else None,
                clues=clues if is_exploit else None,
            )

            # Update tool run
            tool_run.finished_at = datetime.utcnow()

            if tool_result.success:
                tool_run.status = ToolRunStatus.COMPLETED
                tool_run.summary = tool_result.summary
                tool_run.raw_output_path = str(
                    settings.SCANS_DIR
                    / str(scan_id)
                    / f"{tool_name.lower()}.out"
                )

                # Save findings - skip duplicates (same tool+location already from clues)
                existing = await db.execute(
                    select(Finding.tool_name, Finding.location)
                    .where(Finding.scan_id == scan_id)
                )
                existing_pairs = {(r.tool_name, r.location) for r in existing.all()}
                for finding_data in tool_result.findings:
                    loc = (finding_data.get("location") or "").strip()
                    if not loc:
                        loc = "(no location)"
                    desc = (finding_data.get("description") or "").strip() or "No description"
                    # Don't save Sublist3r banner/log lines as findings (only real subdomains)
                    if tool_name == "Sublist3r":
                        from app.utils.finding_filters import is_sublist3r_noise
                        if is_sublist3r_noise(loc, desc):
                            continue
                    if (tool_name, loc) in existing_pairs:
                        continue
                    existing_pairs.add((tool_name, loc))
                    if desc and len(desc) >= 4:
                        half = len(desc) // 2
                        if desc[:half] == desc[half:]:
                            desc = desc[:half]
                    # Normalize type/severity to valid enum values
                    raw_type = (finding_data.get("type") or "information").lower()
                    raw_severity = (finding_data.get("severity") or "info").lower()
                    type_map = {"asset": "asset", "endpoint": "endpoint", "port": "port", "vulnerability": "vulnerability", "misconfiguration": "misconfiguration", "information": "information", "info": "information"}
                    sev_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}
                    ftype = type_map.get(raw_type, "information")
                    fsev = sev_map.get(raw_severity, "info")
                    finding = Finding(
                        scan_id=scan_id,
                        tool_name=tool_name,
                        type=ftype,
                        severity=fsev,
                        owasp_category=finding_data.get("owasp_category"),
                        location=loc,
                        description=desc,
                        evidence=finding_data.get("evidence"),
                    )
                    db.add(finding)
                    # Collect URLs from discovery tools for exploit phase
                    if tool_name in settings.DISCOVERY_TOOLS:
                        url = ScanService._extract_urls_from_finding(loc, target)
                        if url and url not in discovered_urls:
                            discovered_urls.append(url)
            else:
                if tool_result.error_message and "timeout" in (
                    tool_result.error_message or ""
                ).lower():
                    tool_run.status = ToolRunStatus.TIMEOUT
                else:
                    tool_run.status = ToolRunStatus.FAILED
                tool_run.error_message = tool_result.error_message

            await db.commit()
            logger.info(f"Completed {tool_name}: {tool_run.status}")
            
            # Generate per-tool report after completion
            try:
                from app.services.report_service import ReportService
                # Get the findings for this specific tool
                result = await db.execute(
                    select(Finding)
                    .where(
                        Finding.scan_id == scan_id,
                        Finding.tool_name == tool_name
                    )
                    .order_by(Finding.severity, Finding.type)
                )
                tool_findings = result.scalars().all()
                
                # Generate tool-specific report
                tool_report = await ReportService.generate_tool_report(
                    db, scan_id, tool_name, tool_findings, tool_result
                )
                
                if tool_report:
                    logger.info(f"Generated report for {tool_name}: {len(tool_findings)} findings")
                    # Store the report or send notification
                    # This could be extended to save to file or database
            except Exception as e:
                logger.warning(f"Failed to generate report for {tool_name}: {e}")

        # Execute tools in phase order: discovery -> other -> exploit
        for tool_name in ordered_tools:
            await execute_one_tool(tool_name)

    @staticmethod
    async def _update_scan_status(
        db: AsyncSession, scan_id: int, status: ScanStatus
    ) -> None:
        """Update scan status.

        Args:
            db: Database session
            scan_id: Scan ID
            status: New status
        """
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one()
        scan.status = status
        await db.commit()

    @staticmethod
    async def _finalize_scan(db: AsyncSession, scan_id: int) -> None:
        """Finalize scan after all tools complete.

        Args:
            db: Database session
            scan_id: Scan ID
        """
        # Get tool runs
        result = await db.execute(
            select(ToolRun).where(ToolRun.scan_id == scan_id)
        )
        tool_runs = result.scalars().all()

        has_errors = any(
            tr.status in [ToolRunStatus.FAILED, ToolRunStatus.TIMEOUT]
            for tr in tool_runs
        )

        # Update scan
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one()

        # AI-driven execution validation
        try:
            ai_tools_to_run = (
                json.loads(scan.ai_tools_to_run)
                if scan.ai_tools_to_run
                else []
            )
            ai_tools_skipped = (
                json.loads(scan.ai_tools_skipped)
                if scan.ai_tools_skipped
                else []
            )

            validation_summary, validation_details = (
                validate_ai_plan_and_execution(
                    scan=scan,
                    tool_runs=tool_runs,
                    ai_tools_to_run=ai_tools_to_run,
                    ai_tools_skipped=ai_tools_skipped,
                )
            )

            if validation_summary:
                if scan.error_summary:
                    scan.error_summary += " " + validation_summary
                else:
                    scan.error_summary = validation_summary

            # Optional: if you add a column like scan.ai_validation_result
            # scan.ai_validation_result = json.dumps(validation_details)
        except Exception as e:
            logger.error(
                f"AI validation failed for scan {scan_id}: {e}",
                exc_info=True,
            )

        if has_errors:
            scan.status = ScanStatus.COMPLETED_WITH_ERRORS
        else:
            scan.status = ScanStatus.COMPLETED

        scan.completed_at = datetime.utcnow()
        await db.commit()

        logger.info(f"Scan {scan_id} finalized with status: {scan.status}")

        # Fire-and-forget: send alert email if enabled
        try:
            from app.services.email_alert_service import send_scan_finished_alert
            status_val = scan.status.value if hasattr(scan.status, "value") else str(scan.status)
            findings_summary = None
            if scan.error_summary:
                findings_summary = f"Summary: {scan.error_summary}"
            asyncio.create_task(
                send_scan_finished_alert(
                    target=scan.target,
                    status=status_val,
                    scan_id=scan_id,
                    findings_summary=findings_summary,
                )
            )
        except Exception as e:
            logger.warning("Could not schedule scan-finished email: %s", e)

    @staticmethod
    async def get_scan_status(
        db: AsyncSession, scan_id: int
    ) -> Optional[Dict[str, Any]]:
        """Get scan status for polling.

        Args:
            db: Database session
            scan_id: Scan ID

        Returns:
            Status dictionary or None
        """
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()

        if not scan:
            return None

        # Get tool runs
        result = await db.execute(
            select(ToolRun)
            .where(ToolRun.scan_id == scan_id)
            .order_by(ToolRun.created_at)
        )
        tool_runs = result.scalars().all()

        return {
            "scan_id": scan.id,
            "status": scan.status.value,
            "target": scan.target,
            "owasp_category": scan.owasp_category,
            "owasp_category_name": _get_owasp_category_name(scan.owasp_category),
            "created_at": scan.created_at,
            "updated_at": scan.updated_at,
            "completed_at": scan.completed_at,
            "tools": [
                {
                    "tool_name": tr.tool_name,
                    "status": tr.status.value,
                    "started_at": tr.started_at,
                    "finished_at": tr.finished_at,
                }
                for tr in tool_runs
            ],
        }

    @staticmethod
    async def get_scan_detail(
        db: AsyncSession, scan_id: int
    ) -> Optional[Dict[str, Any]]:
        """Get detailed scan information.

        Args:
            db: Database session
            scan_id: Scan ID

        Returns:
            Detailed scan dictionary or None
        """
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()

        if not scan:
            return None

        # Get tool runs
        result = await db.execute(
            select(ToolRun)
            .where(ToolRun.scan_id == scan_id)
            .order_by(ToolRun.created_at)
        )
        tool_runs = result.scalars().all()

        # Get findings summary
        result = await db.execute(
            select(Finding.severity, func.count(Finding.id))
            .where(Finding.scan_id == scan_id)
            .group_by(Finding.severity)
        )
        raw_severity_counts = dict(result.all())
        
        # Convert raw severity counts to display severity counts
        # Also calculate total for info->low conversion logic
        severity_counts = {
            "critical": raw_severity_counts.get(FindingSeverity.CRITICAL.value, 0),
            "high": raw_severity_counts.get(FindingSeverity.HIGH.value, 0),
            "medium": raw_severity_counts.get(FindingSeverity.MEDIUM.value, 0),
            "low": raw_severity_counts.get(FindingSeverity.LOW.value, 0),
            "info": raw_severity_counts.get(FindingSeverity.INFO.value, 0),
        }
        
        # Apply the same logic as in the scan list: if there are only info findings,
        # treat them as low findings for display purposes
        total_actual_findings = sum(severity_counts.values())
        info_count = severity_counts.get("info", 0)
        
        # If all findings are info, convert them to low for consistency with scan list
        if total_actual_findings == info_count and info_count > 0:
            severity_counts["low"] = info_count
            severity_counts["info"] = 0

        # Findings list for detail response (used by comparison/details). Always defined.
        findings_dict_list = []

        # Calculate AI risk level and incorporate it into severity distribution
        # Only do this for completed scans
        if scan.status in [ScanStatus.COMPLETED, ScanStatus.COMPLETED_WITH_ERRORS]:
            # Calculate AI risk level based on scan results
            critical_findings = severity_counts.get("critical", 0)
            high_findings = severity_counts.get("high", 0)
            
            # Get all findings for calculating other metrics
            all_findings = await db.execute(
                select(Finding).where(Finding.scan_id == scan_id)
            )
            all_findings_list = all_findings.scalars().all()
                    
            # Convert findings to dictionary format for API response
            findings_dict_list = []
            for finding in all_findings_list:
                findings_dict_list.append({
                    "id": finding.id,
                    "tool_name": finding.tool_name,
                    "type": finding.type,
                    "severity": finding.severity,
                    "owasp_category": finding.owasp_category,
                    "location": finding.location,
                    "description": finding.description,
                    "evidence": finding.evidence,
                    "created_at": finding.created_at,
                    "updated_at": finding.updated_at
                })
            
            total_subdomains = len([f for f in all_findings_list if "subdomain" in f.description.lower() or "." in f.location])
            open_ports = len([f for f in all_findings_list if ":" in f.location and f.location.split(":")[-1].isdigit()])
            
            risk_score = 0
            if critical_findings > 0:
                risk_score += 3
            if high_findings > 2:
                risk_score += 2
            elif high_findings > 0:
                risk_score += 1
            if open_ports > 5:
                risk_score += 2
            elif open_ports > 2:
                risk_score += 1
            if total_subdomains > 20:
                risk_score += 2
            elif total_subdomains > 10:
                risk_score += 1
                
            ai_risk_level = "LOW"
            if risk_score >= 5:
                ai_risk_level = "HIGH"
            elif risk_score >= 3:
                ai_risk_level = "MEDIUM"
            
            # Add the AI risk level to the appropriate severity bucket
            # This ensures the severity distribution reflects the AI risk assessment
            if ai_risk_level.lower() in severity_counts:
                severity_counts[ai_risk_level.lower()] += 1
            else:
                # If AI risk level is CRITICAL but we don't have that in our counts
                # default to high as the closest severity
                if ai_risk_level == "CRITICAL" and "high" in severity_counts:
                    severity_counts["high"] += 1
        
        # Ensure all severity levels are present in the response
        all_display_severities = ["critical", "high", "medium", "low", "info"]
        for sev_str in all_display_severities:
            if sev_str not in severity_counts:
                severity_counts[sev_str] = 0

        result = await db.execute(
            select(Finding.owasp_category, func.count(Finding.id))
            .where(
                Finding.scan_id == scan_id,
                Finding.owasp_category.isnot(None),
            )
            .group_by(Finding.owasp_category)
        )
        owasp_counts = dict(result.all())

        # Parse stored JSON
        user_selected = (
            json.loads(scan.user_selected_tools)
            if scan.user_selected_tools
            else []
        )
        tools_to_run = (
            json.loads(scan.ai_tools_to_run) if scan.ai_tools_to_run else []
        )
        tools_skipped = (
            json.loads(scan.ai_tools_skipped)
            if scan.ai_tools_skipped
            else []
        )

        return {
            "id": scan.id,
            "target": scan.target,
            "owasp_category": scan.owasp_category,
            "owasp_category_name": _get_owasp_category_name(scan.owasp_category),
            "status": scan.status.value,
            "created_at": scan.created_at,
            "updated_at": scan.updated_at,
            "completed_at": scan.completed_at,
            "user_selected_tools": user_selected,
            "ai_decision": {
                "tools_to_run": tools_to_run,
                "tools_skipped": tools_skipped,
                "raw_response": scan.ai_raw_response,
            },
            "tool_runs": [
                {
                    "id": tr.id,
                    "tool_name": tr.tool_name,
                    "status": tr.status.value,
                    "started_at": tr.started_at,
                    "finished_at": tr.finished_at,
                    "summary": tr.summary,
                    "error_message": tr.error_message,
                }
                for tr in tool_runs
            ],
            "findings": findings_dict_list,
            "findings_summary": {
                "by_severity": {str(k): v for k, v in severity_counts.items()},
                "by_owasp": owasp_counts,
                "total": sum(severity_counts.values()),
            },
            "error_summary": scan.error_summary,
        }

    @staticmethod
    async def list_scans(
        db: AsyncSession,
        target: Optional[str] = None,
        status: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
        include_unsaved: bool = True,
    ) -> Dict[str, Any]:
        """List scans with optional filtering and pagination.

        Args:
            db: Database session
            target: Optional target filter
            status: Optional status filter
            page: Page number (1-indexed)
            page_size: Items per page
            include_unsaved: Whether to include unsaved scans

        Returns:
            Dictionary with scans list and pagination info
        """
        # Build query
        query = select(Scan)

        if target:
            query = query.where(Scan.target.like(f"%{target}%"))

        if status:
            query = query.where(Scan.status == status)

        # Filter by saved status if needed
        if not include_unsaved:
            query = query.where(func.coalesce(Scan.error_summary, '').contains('SAVED_SCAN'))

        # Get total count
        count_query = select(func.count()).select_from(query.subquery())
        result = await db.execute(count_query)
        total = result.scalar()

        # Get paginated results
        query = query.order_by(desc(Scan.created_at))
        query = query.offset((page - 1) * page_size).limit(page_size)

        result = await db.execute(query)
        scans = result.scalars().all()

        # Get highest severity for each scan
        scan_items = []
        for scan in scans:
            # Get highest severity
            result = await db.execute(
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
            highest_severity = result.scalar_one_or_none()
            
            # Get finding count
            result = await db.execute(
                select(func.count(Finding.id)).where(
                    Finding.scan_id == scan.id
                )
            )
            finding_count = result.scalar()
            
            # If no findings exist, set highest severity to LOW to indicate clean scan
            if finding_count == 0 and highest_severity is None:
                highest_severity = FindingSeverity.LOW
            # If only info findings exist, set highest severity to LOW to indicate clean scan
            elif finding_count > 0 and highest_severity == FindingSeverity.INFO:
                highest_severity = FindingSeverity.LOW

            scan_items.append(
                {
                    "id": scan.id,
                    "target": scan.target,
                    "owasp_category": scan.owasp_category,
                    "status": scan.status.value,
                    "created_at": scan.created_at,
                    "completed_at": scan.completed_at,
                    "highest_severity": highest_severity.value
                    if highest_severity
                    else None,
                    "finding_count": finding_count,
                }
            )

        return {
            "scans": scan_items,
            "total": total,
            "page": page,
            "page_size": page_size,
        }

    @staticmethod
    async def delete_scan(db: AsyncSession, scan_id: int) -> bool:
        """Delete a scan and its associated data (DB rows and raw output files).

        Args:
            db: Database session
            scan_id: Scan ID to delete

        Returns:
            True if deleted, False if not found
        """
        # Find the scan
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()

        if not scan:
            return False

        # Delete DB record (cascade will remove tool_runs and findings)
        try:
            await db.delete(scan)
            await db.commit()
        except Exception:
            await db.rollback()
            raise

        # Remove scan raw output directory if present
        try:
            scan_dir = Path(settings.SCANS_DIR) / str(scan_id)
            if scan_dir.exists():
                shutil.rmtree(scan_dir)
        except Exception:
            # Non-fatal: log and continue
            logger.exception(f"Failed to remove scan directory for {scan_id}")

        return True
