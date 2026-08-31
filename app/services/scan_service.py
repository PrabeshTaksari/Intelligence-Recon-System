"""Scan orchestration service."""
import asyncio
import json
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from sqlalchemy import select, func, desc, case
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.scan import Scan, ScanStatus
from app.models.tool_run import ToolRun, ToolRunStatus
from app.models.finding import Finding, FindingSeverity, FindingType
from app.core.config import settings
from app.core.logging import get_logger
from app.tools.executor import execute_tool
from app.ai.decision_node import SAFE_FALLBACK_TOOLS, decide_tools
from app.core.ws_updates import init_websocket_manager
from app.ai.validation import validate_ai_plan_and_execution
from app.core.validation import validate_domain

AI_FALLBACK_MARKER = "AI_FALLBACK_MODE_ACTIVE"

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

    # Passive/DNS-oriented tools can return irrelevant wildcard-like results
    # when the target is localhost / loopback. Skip them for accuracy.
    _LOCAL_DNS_TOOLS = {
        "Subfinder",
        "Amass",
        "Assetfinder",
        "Sublist3r",
        "DNSx",
        "ShuffleDNS",
    }

    @staticmethod
    def _is_local_target(target: str) -> bool:
        """Return True if target is localhost/loopback (including host:port)."""
        t = (target or "").strip().lower()
        if not t:
            return False
        # Strip protocol if present
        if t.startswith(("http://", "https://")):
            parsed = urlparse(t)
            t = (parsed.hostname or "").strip().lower()
        else:
            # If host:port, strip port (ignore IPv6 for now)
            if ":" in t and not t.startswith("[") and not t.count(":") > 1:
                t = t.split(":", 1)[0].strip().lower()
            # If bracketed IPv6: [::1]
            if t.startswith("[") and t.endswith("]"):
                t = t.strip("[]")

        return t in {"localhost", "127.0.0.1", "::1"} or t.endswith(".localhost")

    @staticmethod
    def _normalize_finding_classification(
        raw_type: Optional[str],
        raw_severity: Optional[str],
        raw_owasp_category: Optional[str],
    ) -> Dict[str, Optional[str]]:
        """Normalize finding type/severity/owasp to prevent recon misclassification.

        Rules:
        - Recon/discovery finding types (asset/endpoint/port/information) are always INFO
          and must not carry OWASP vulnerability category.
        - Only vulnerability/misconfiguration findings may keep low/medium/high/critical and OWASP category.
        """
        type_map = {
            "asset": "asset",
            "endpoint": "endpoint",
            "port": "port",
            "vulnerability": "vulnerability",
            "misconfiguration": "misconfiguration",
            "information": "information",
            "info": "information",
        }
        sev_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info",
        }

        ftype = type_map.get((raw_type or "information").lower(), "information")
        fsev = sev_map.get((raw_severity or "info").lower(), "info")
        owasp_category = raw_owasp_category
        
        # Strict guard: non-vulnerability findings should never be elevated severity.
        # EXCEPTION: endpoint findings can retain their severity if they represent sensitive resource exposure
        # (e.g., Katana/GoSpider discovering aws_secrets.docx, /admin panels, etc.)
        if ftype not in {"vulnerability", "misconfiguration"}:
            # Allow endpoint findings to keep their classified severity (from intelligent URL analysis)
            # Only force to info for pure reconnaissance types (assets, ports, information)
            if ftype in ("asset", "port", "information"):
                fsev = "info"
                owasp_category = None

        return {"type": ftype, "severity": fsev, "owasp_category": owasp_category}

    @staticmethod
    def _scan_has_owasp_focus(owasp_category: Optional[str]) -> bool:
        """True when the user picked an OWASP Top 10 category (A01–A10 style)."""
        if not owasp_category:
            return False
        o = str(owasp_category).strip().upper()
        return o.startswith("A") and ":2021" in o

    @staticmethod
    def _apply_owasp_scope_to_normalized(
        scan_owasp_category: Optional[str],
        normalized: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """When a scan is OWASP-focused, drop recon-only rows and align vuln/misconfig OWASP labels.

        Returns normalized dict to persist, or None to skip this finding entirely.
        """
        if not ScanService._scan_has_owasp_focus(scan_owasp_category):
            return normalized
        scan_o = str(scan_owasp_category).strip().upper()
        ftype = normalized.get("type")
        if hasattr(ftype, "value"):
            ftype = ftype.value
        ftype = (ftype or "information").lower()

        # Keep reconnaissance findings (ports, assets) but set them to info severity without OWASP category
        # EXCEPTION: endpoint findings from crawlers (Katana/GoSpider/FFuf/Wfuzz) can retain their classified severity
        # because they represent actual sensitive resource exposure (e.g., aws_secrets.docx, /admin, DVWA paths)
        if ftype in ("asset", "port", "information"):
            # Pure reconnaissance - force to info severity
            result = {**normalized, "severity": "info", "owasp_category": None}
            return result

        # For endpoint/vulnerability/misconfiguration findings, strict OWASP filter behavior:
        # - if declared category does not match selected scan category, keep as discovered finding
        #   (do not silently downgrade to info/endpoint); preserve severity classification.
        # - if matches, keep classification and align category.
        if ftype in ("endpoint", "vulnerability", "misconfiguration"):
            detected_owasp = normalized.get("owasp_category")
            if hasattr(detected_owasp, "value"):
                detected_owasp = detected_owasp.value
            detected_owasp = (detected_owasp or "").strip().upper()

            if detected_owasp != scan_o:
                # Keep finding but remove strict scope label; this prevents missed vulnerabilities
                # while still distinguishing scanned category context.
                return {**normalized, "owasp_category": None}

            return {**normalized, "owasp_category": scan_o}

        # Anything else (unlikely) can be scoped normally.
        ow = normalized.get("owasp_category")
        if ow:
            if str(ow).strip().upper() != scan_o:
                return None
        else:
            normalized = {**normalized, "owasp_category": scan_o}
        return normalized

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

                # Scheduled scans: for localhost/loopback, skip passive/DNS tools
                # to avoid irrelevant wildcard-like results.
                skipped_local: List[Dict[str, str]] = []
                if ScanService._is_local_target(target):
                    removed_local = [t for t in normalized_tools_to_run if t in ScanService._LOCAL_DNS_TOOLS]
                    if removed_local:
                        normalized_tools_to_run = [
                            t for t in normalized_tools_to_run if t not in ScanService._LOCAL_DNS_TOOLS
                        ]
                        skipped_local = [
                            {
                                "tool": t,
                                "reason": "Local/loopback target: skipping passive/DNS subdomain enumeration to avoid irrelevant results.",
                            }
                            for t in removed_local
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
                    scan.ai_tools_skipped = json.dumps(skipped_local)
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

                    clues = await ScanService._gather_initial_clues(
                        scan_id, target, db, owasp_category=owasp_category
                    )

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
                            t for t in SAFE_FALLBACK_TOOLS if t in settings.AVAILABLE_TOOLS
                        ]
                        result = await db.execute(select(Scan).where(Scan.id == scan_id))
                        scan = result.scalar_one()
                        scan.ai_tools_to_run = json.dumps(safe_tools)
                        scan.ai_tools_skipped = json.dumps([])
                        scan.ai_raw_response = None
                        scan.error_summary = (
                            f"AI decision fallback active: {str(e)}. {AI_FALLBACK_MARKER}"
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

                    # Naabu + Httpx are always executed once in the initial clues phase for dashboard scans.
                    # Ensure AI does not schedule them again in the main tool execution phase.
                    clue_tools = {"Naabu", "Httpx"}
                    removed_clue_tools = [t for t in normalized_tools_to_run if t in clue_tools]
                    if removed_clue_tools:
                        normalized_tools_to_run = [t for t in normalized_tools_to_run if t not in clue_tools]

                    # If local/loopback target, remove passive/DNS tools for accuracy.
                    skipped_local: List[Dict[str, str]] = []
                    if ScanService._is_local_target(target):
                        removed_local = [
                            t
                            for t in normalized_tools_to_run
                            if t in ScanService._LOCAL_DNS_TOOLS
                        ]
                        if removed_local:
                            normalized_tools_to_run = [
                                t
                                for t in normalized_tools_to_run
                                if t not in ScanService._LOCAL_DNS_TOOLS
                            ]
                            skipped_local = [
                                {
                                    "tool": t,
                                    "reason": "Local/loopback target: skipping passive/DNS subdomain enumeration to avoid irrelevant results.",
                                }
                                for t in removed_local
                            ]

                    result = await db.execute(select(Scan).where(Scan.id == scan_id))
                    scan = result.scalar_one()
                    scan.ai_tools_to_run = json.dumps(normalized_tools_to_run)
                    # Preserve AI skipped tools but also record clue tools removed to avoid duplicate execution.
                    skipped = list(ai_decision.tools_skipped or [])
                    for t in removed_clue_tools:
                        skipped.append({
                            "tool": t,
                            "reason": "Already executed in initial clues phase (runs once per scan)."
                        })
                    for entry in skipped_local:
                        skipped.append(entry)
                    scan.ai_tools_skipped = json.dumps(skipped)
                    scan.ai_raw_response = getattr(
                        ai_decision, "raw_response", None
                    )

                    if not getattr(ai_decision, "success", True):
                        if AI_FALLBACK_MARKER not in (scan.error_summary or ""):
                            scan.error_summary = (scan.error_summary or "") + " " + AI_FALLBACK_MARKER

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
                    db,
                    scan_id,
                    target,
                    normalized_tools_to_run,
                    clues=clues,
                    owasp_category=scan.owasp_category,
                )

                # PHASE 2: Intelligence Layer - Classify endpoints and tag risk
                logger.info(f"Scan {scan_id}: Intelligence Layer - classifying endpoints")
                try:
                    from app.core.ws_updates import send_scan_phase_update, send_log_message
                    await send_log_message(scan_id, "System", "Analyzing discovered endpoints and classifying by type/risk...")
                    await send_scan_phase_update(scan_id, "intelligence_layer", {
                        "currentPhase": "intelligence_layer",
                        "phase": "Intelligence Layer",
                        "description": "Classifying endpoints and tagging risk levels"
                    })
                except ImportError:
                    pass

                endpoint_classification = await ScanService._run_intelligence_layer(
                    db, scan_id, target, owasp_category, clues
                )

                # PHASE 4: Active Testing Engine - Custom HTTP requests
                logger.info(f"Scan {scan_id}: Active Testing Engine")
                try:
                    from app.core.ws_updates import send_scan_phase_update, send_log_message
                    await send_log_message(scan_id, "System", f"Running active testing for OWASP {owasp_category}...")
                    await send_scan_phase_update(scan_id, "active_testing", {
                        "currentPhase": "active_testing",
                        "phase": "Active Testing",
                        "description": f"Custom HTTP requests for {owasp_category}"
                    })
                except ImportError:
                    pass

                active_test_results = await ScanService._run_active_testing(
                    db,
                    scan_id,
                    target,
                    owasp_category,
                    endpoint_classification,
                    clues=clues,
                )

                # PHASE 5: Response Analysis - Analyze active test responses
                logger.info(f"Scan {scan_id}: Response Analysis")
                try:
                    from app.core.ws_updates import send_scan_phase_update, send_log_message
                    await send_log_message(scan_id, "System", "Analyzing responses for vulnerability indicators...")
                    await send_scan_phase_update(scan_id, "response_analysis", {
                        "currentPhase": "response_analysis",
                        "phase": "Response Analysis",
                        "description": "Parsing responses for vulnerability indicators"
                    })
                except ImportError:
                    pass

                vulnerability_findings = await ScanService._run_response_analysis(
                    db, scan_id, target, owasp_category, active_test_results
                )

                # PHASE 6: Correlation - Combine all results
                logger.info(f"Scan {scan_id}: Correlation")
                try:
                    from app.core.ws_updates import send_scan_phase_update, send_log_message
                    await send_log_message(scan_id, "System", "Correlating findings across all tools...")
                    await send_scan_phase_update(scan_id, "correlation", {
                        "currentPhase": "correlation",
                        "phase": "Correlation",
                        "description": "Combining results from all tools and active testing"
                    })
                except ImportError:
                    pass

                await ScanService._run_correlation(
                    db, scan_id, target, owasp_category, endpoint_classification
                )

                # PHASE 7: Smart Risk Scoring - Adjust severity based on verified exploits
                logger.info(f"Scan {scan_id}: Smart Risk Scoring")
                try:
                    from app.core.ws_updates import send_scan_phase_update, send_log_message
                    await send_log_message(scan_id, "System", "Applying smart risk scoring based on verified exploits...")
                    await send_scan_phase_update(scan_id, "risk_scoring", {
                        "currentPhase": "risk_scoring",
                        "phase": "Risk Scoring",
                        "description": "Adjusting severity based on exploit verification"
                    })
                except ImportError:
                    pass

                await ScanService._run_smart_risk_scoring(db, scan_id, owasp_category)

                # Phase 8: Finalize scan (includes AI validation)
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
        scan_id: int,
        target: str,
        db: AsyncSession,
        owasp_category: Optional[str] = None,
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
        
        # If target is already a URL, add it as a known HTTP service immediately
        # This prevents "HTTP services: 0" misleading message when user scans a URL directly
        if target.startswith("http://") or target.startswith("https://"):
            clues["http_services"].append(target)

        # Run Naabu (port scan)
        try:
            naabu_result = await execute_tool(
                "Naabu", target, scan_id, timeout=120
            )
            if naabu_result.success:
                # Always save reconnaissance findings from initial clues (they're info severity)
                # These provide valuable context even in OWASP-focused scans
                for finding_data in naabu_result.findings:
                    desc = finding_data.get("description", "")
                    if desc and len(desc) >= 4:
                        half = len(desc) // 2
                        if desc[:half] == desc[half:]:
                            desc = desc[:half]
                    normalized = ScanService._normalize_finding_classification(
                        raw_type=finding_data.get("type", "port"),
                        raw_severity=finding_data.get("severity", "info"),
                        raw_owasp_category=None,
                    )
                    finding = Finding(
                        scan_id=scan_id,
                        tool_name="Naabu",
                        type=normalized["type"],
                        severity=normalized["severity"],
                        owasp_category=normalized["owasp_category"],
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
                # Always save reconnaissance findings from initial clues (they're info severity)
                # These provide valuable context even in OWASP-focused scans
                for finding_data in httpx_result.findings:
                    desc = finding_data.get("description", "")
                    if desc and len(desc) >= 4:
                        half = len(desc) // 2
                        if desc[:half] == desc[half:]:
                            desc = desc[:half]
                    normalized = ScanService._normalize_finding_classification(
                        raw_type=finding_data.get("type", "endpoint"),
                        raw_severity=finding_data.get("severity", "info"),
                        raw_owasp_category=None,
                    )
                    finding = Finding(
                        scan_id=scan_id,
                        tool_name="Httpx",
                        type=normalized["type"],
                        severity=normalized["severity"],
                        owasp_category=normalized["owasp_category"],
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
        owasp_category: Optional[str] = None,
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
        # Reduce noisy TLS failures for local targets (we typically only have HTTP here).
        if ScanService._is_local_target(target):
            discovered_urls.extend([f"http://{target}"])
        else:
            discovered_urls.extend([f"https://{target}", f"http://{target}"])
        discovered_urls = list(dict.fromkeys(discovered_urls))

        # OWASP endpoint enrichment:
        # Feed Nuclei additional "likely" endpoints so it has something concrete to test
        # even when crawling doesn't extract paths.
        #
        # To avoid hampering other scans (extra noise / longer runtimes), we only enrich
        # when we currently have a small URL set (usually base URL + a few clue URLs).
        if target and owasp_category and owasp_category.startswith("A"):
            # If we already have many endpoints from Httpx/crawlers, avoid adding more.
            if len(discovered_urls) <= 6:
                local = ScanService._is_local_target(target)

                # Balanced, low-noise endpoint lists (paths only; no query strings/payloads).
                category_to_paths = {
                    "A01:2021": [
                        "/admin",
                        "/dashboard",
                        "/roles",
                        "/permissions",
                        "/account",
                        "/api/roles",
                    ],
                    "A02:2021": [
                        "/api/login",
                        "/password-reset",
                        "/oauth/token",
                        "/auth/callback",
                    ],
                    "A03:2021": [
                        "/search",
                        "/query",
                        "/api/search",
                        "/product",
                    ],
                    "A04:2021": [
                        "/profile",
                        "/settings",
                        "/account",
                        "/api/account",
                    ],
                    "A05:2021": [
                        "/swagger",
                        "/swagger-ui",
                        "/robots.txt",
                        "/actuator/health",
                    ],
                    "A06:2021": [
                        "/version",
                        "/api/version",
                        "/robots.txt",
                        "/.well-known/security.txt",
                    ],
                    "A07:2021": [
                        # Juice Shop (auth)
                        "/rest/user/login",
                        "/rest/user/logout",
                        # Generic auth routes
                        "/login",
                        "/signin",
                        "/auth/login",
                        "/account/login",
                    ],
                    "A08:2021": [
                        "/upload",
                        "/uploads",
                        "/download",
                        "/api/upload",
                    ],
                    "A09:2021": [
                        "/logs",
                        "/admin/logs",
                        "/monitoring",
                        "/api/logs",
                    ],
                    "A10:2021": [
                        "/proxy",
                        "/fetch",
                        "/download",
                        "/api/proxy",
                    ],
                }

                endpoint_paths = category_to_paths.get(owasp_category, [])
                if endpoint_paths:
                    # Avoid https:// enrichment for local targets (TLS negotiation can fail).
                    schemes = ["http"] if local else ["https", "http"]
                    for scheme in schemes:
                        for p in endpoint_paths:
                            discovered_urls.append(f"{scheme}://{target}{p}")
                    discovered_urls = list(dict.fromkeys(discovered_urls))

        # For local host:port scans (e.g. localhost:3000), keep Nuclei focused on the selected
        # application port to avoid long hangs on unrelated local services (e.g. :631, :8081).
        if ScanService._is_local_target(target) and ":" in str(target):
            try:
                target_port = str(target).rsplit(":", 1)[1].strip()
                filtered_urls: List[str] = []
                for u in discovered_urls:
                    pu = urlparse(str(u))
                    p = pu.port
                    # Keep explicit target port URLs and plain host URLs without explicit port.
                    if p is None or str(p) == target_port:
                        filtered_urls.append(u)
                # Never drop everything; fallback to original set if filter became empty.
                discovered_urls = filtered_urls or discovered_urls
            except Exception:
                pass
        logger.info(f"Initial discovered_urls: {len(discovered_urls)} from clues")

        async def execute_one_tool(tool_name: str):
            # Initialize counter for findings added (must be defined before any try/except blocks)
            findings_added = 0
            
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
            logger.info(f"EXECUTE_TOOL CALL: tool_name={tool_name}, is_exploit={is_exploit}, discovered_urls_count={len(discovered_urls) if discovered_urls else 0}, owasp_category={owasp_category}")
            tool_result = await execute_tool(
                tool_name, target, scan_id,
                discovered_urls=discovered_urls if is_exploit else None,
                clues=clues if is_exploit else None,
                owasp_category=owasp_category,
            )

            # Update tool run
            tool_run.finished_at = datetime.utcnow()
            tool_run.summary = tool_result.summary
            tool_run.raw_output_path = str(
                settings.SCANS_DIR
                / str(scan_id)
                / f"{tool_name.lower()}.out"
            )

            async def persist_tool_findings(findings_list):
                nonlocal discovered_urls
                findings_added = 0

                if not findings_list:
                    return findings_added

                from app.utils.finding_filters import extract_host_port

                existing = await db.execute(
                    select(Finding.tool_name, Finding.location, Finding.evidence)
                    .where(Finding.scan_id == scan_id)
                )
                existing_keys = set()
                for r in existing.all():
                    if (r.tool_name or "").lower() == "nuclei":
                        host, port = extract_host_port(r.location)
                        template_id = None
                        if r.evidence:
                            try:
                                evidence_data = json.loads(r.evidence)
                                template_id = evidence_data.get("template-id") or evidence_data.get("template_id")
                            except Exception:
                                pass
                        key = (r.tool_name, host, port, template_id) if template_id else (r.tool_name, host, port)
                    else:
                        key = (r.tool_name, (r.location or "").strip())
                    existing_keys.add(key)

                logger.info(f"Tool {tool_name} has {len(findings_list)} raw findings, {len(existing_keys)} already exist in DB")

                for finding_data in findings_list:
                    loc = (finding_data.get("location") or "").strip()
                    if not loc:
                        loc = "(no location)"
                    desc = (finding_data.get("description") or "").strip() or "No description"

                    if tool_name in settings.DISCOVERY_TOOLS:
                        url = ScanService._extract_urls_from_finding(loc, target)
                        if url and url not in discovered_urls:
                            discovered_urls.append(url)

                    host, port = extract_host_port(loc)

                    template_id = None
                    if tool_name == "Nuclei" and finding_data.get("evidence"):
                        try:
                            evidence_data = json.loads(finding_data.get("evidence"))
                            template_id = evidence_data.get("template-id") or evidence_data.get("template_id")
                        except Exception:
                            pass

                    if tool_name == "Sublist3r":
                        from app.utils.finding_filters import is_sublist3r_noise
                        if is_sublist3r_noise(loc, desc):
                            continue

                    if tool_name.lower() == "nuclei":
                        dedup_key = (tool_name, host, port, template_id) if template_id else (tool_name, host, port)
                    else:
                        dedup_key = (tool_name, loc)
                    if dedup_key in existing_keys:
                        continue
                    existing_keys.add(dedup_key)
                    if desc and len(desc) >= 4:
                        half = len(desc) // 2
                        if desc[:half] == desc[half:]:
                            desc = desc[:half]
                    normalized = ScanService._normalize_finding_classification(
                        raw_type=finding_data.get("type"),
                        raw_severity=finding_data.get("severity"),
                        raw_owasp_category=finding_data.get("owasp_category"),
                    )
                    scoped = ScanService._apply_owasp_scope_to_normalized(
                        owasp_category, normalized
                    )
                    if scoped is None:
                        logger.debug(f"Finding filtered by OWASP scope: type={finding_data.get('type')}, location={loc}")
                        continue
                    finding = Finding(
                        scan_id=scan_id,
                        tool_name=tool_name,
                        type=scoped["type"],
                        severity=scoped["severity"],
                        owasp_category=scoped["owasp_category"],
                        location=loc,
                        description=desc,
                        evidence=finding_data.get("evidence"),
                    )
                    db.add(finding)
                    findings_added += 1
                    logger.info(f"Added finding: {finding.tool_name} - {finding.type} - {finding.severity} at {finding.location}")

                return findings_added

            if tool_result.success:
                tool_run.status = ToolRunStatus.COMPLETED
                
                # Track if Nuclei had findings but also had issues (for better error reporting)
                if tool_name == "Nuclei" and tool_result.findings:
                    # Log finding count for diagnostics
                    vuln_count = sum(1 for f in tool_result.findings if (f.get("type") or "").lower() == "vulnerability")
                    info_count = len(tool_result.findings) - vuln_count
                    logger.info(f"Nuclei findings: {vuln_count} vulnerabilities, {info_count} information")

                findings_added = await persist_tool_findings(tool_result.findings)
            else:
                if tool_result.error_message and "timeout" in (
                    tool_result.error_message or ""
                ).lower():
                    tool_run.status = ToolRunStatus.TIMEOUT
                else:
                    tool_run.status = ToolRunStatus.FAILED
                tool_run.error_message = tool_result.error_message

                # Keep partial findings from timed-out tools (especially Nuclei) if available.
                findings_added = await persist_tool_findings(tool_result.findings)

            await db.commit()
            logger.info(f"Completed {tool_name}: {tool_run.status}, added {findings_added} new findings to DB")
            
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

        timeout_only = bool(tool_runs) and all(
            tr.status in [ToolRunStatus.COMPLETED, ToolRunStatus.TIMEOUT]
            for tr in tool_runs
        ) and any(tr.status == ToolRunStatus.TIMEOUT for tr in tool_runs)

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

        if timeout_only:
            scan.status = ScanStatus.COMPLETED
            timeout_note = (
                "Due to time limit, running phase completed with partial results."
            )
            if scan.error_summary:
                if timeout_note not in scan.error_summary:
                    scan.error_summary += f" {timeout_note}"
            else:
                scan.error_summary = timeout_note
        elif has_errors:
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

    AI_FALLBACK_MARKER = "AI_FALLBACK_MODE_ACTIVE"

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

        fallback_active = bool(scan.error_summary and AI_FALLBACK_MARKER in scan.error_summary)
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
            "ai_fallback_active": fallback_active,
            "ai_decision_error": scan.error_summary if fallback_active else None,
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

        fallback_active = bool(scan.error_summary and AI_FALLBACK_MARKER in scan.error_summary)
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
                "success": not fallback_active,
                "error": scan.error_summary if fallback_active else None,
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
    async def _run_intelligence_layer(
        db: AsyncSession,
        scan_id: int,
        target: str,
        owasp_category: str,
        clues: Dict[str, Any]
    ) -> Dict[str, Any]:
        """PHASE 2: Intelligence Layer - Classify endpoints and tag risk.

        Returns endpoint classification data for use in active testing.
        """
        from app.engines.endpoint_classifier import EndpointClassifier

        # Get all discovered URLs from findings
        result = await db.execute(
            select(Finding.location)
            .where(
                Finding.scan_id == scan_id,
                Finding.type.in_([FindingType.ENDPOINT, FindingType.PORT])
            )
            .distinct()
        )
        discovered_locations = [row[0] for row in result.all()]

        # Add HTTP services from clues
        http_services = clues.get("http_services", [])
        all_urls = list(set(discovered_locations + http_services))

        # Filter to HTTP URLs only
        http_urls = [u for u in all_urls if str(u).startswith(("http://", "https://"))]

        # Classify endpoints
        classified_endpoints = EndpointClassifier.classify(http_urls)

        # Store classification in scan metadata for later phases
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one()
        scan.endpoint_classification = json.dumps({
            "classified_endpoints": classified_endpoints,
            "total_endpoints": len(classified_endpoints),
            "auth_endpoints": len(EndpointClassifier.get_by_type(classified_endpoints, "auth")),
            "admin_endpoints": len(EndpointClassifier.get_by_type(classified_endpoints, "admin")),
            "api_endpoints": len(EndpointClassifier.get_by_type(classified_endpoints, "api")),
        })
        await db.commit()

        logger.info(f"Intelligence Layer: classified {len(classified_endpoints)} endpoints for scan {scan_id}")

        return {
            "classified_endpoints": classified_endpoints,
            "auth_endpoints": EndpointClassifier.get_by_type(classified_endpoints, "auth"),
            "admin_endpoints": EndpointClassifier.get_by_type(classified_endpoints, "admin"),
            "api_endpoints": EndpointClassifier.get_by_type(classified_endpoints, "api"),
        }

    @staticmethod
    async def _run_active_testing(
        db: AsyncSession,
        scan_id: int,
        target: str,
        owasp_category: str,
        endpoint_classification: Dict[str, Any],
        clues: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """PHASE 4: Active Testing Engine - Run custom HTTP requests for OWASP category."""
        from app.engines.active_tester import ActiveTester

        clues = clues or {}
        # URLs from DB (when recon findings were persisted) plus initial clues (always when Naabu/Httpx ran)
        discovered_urls: List[str] = []
        result = await db.execute(
            select(Finding.location)
            .where(
                Finding.scan_id == scan_id,
                Finding.type.in_([FindingType.ENDPOINT, FindingType.PORT])
            )
            .distinct()
        )
        discovered_urls = [row[0] for row in result.all()]

        result = await db.execute(
            select(Finding.location)
            .where(
                Finding.scan_id == scan_id,
                Finding.tool_name == "Httpx"
            )
        )
        discovered_urls.extend(row[0] for row in result.all())
        for u in clues.get("http_services") or []:
            if u:
                discovered_urls.append(u)
        discovered_urls = list(dict.fromkeys(discovered_urls))

        # Filter to HTTP URLs only
        http_urls = [u for u in discovered_urls if str(u).startswith(("http://", "https://"))]

        # Run OWASP-specific active testing for ALL categories
        active_test_results = await ActiveTester.run_owasp_tests(http_urls, owasp_category, target)

        # Convert ActiveTestResult objects to dictionaries
        results = []
        for r in active_test_results:
            results.append({
                "url": r.url,
                "payload": r.payload,
                "status_code": r.status_code,
                "success": r.success,
                "confidence": r.confidence,
                "evidence": r.evidence,
                "owasp_category": r.owasp_category,
                "severity": r.severity,
                "indicators": r.indicators,
                "test_type": owasp_category.split(":")[0].lower()  # e.g., "a01", "a07"
            })

        # Save active testing results to database as findings
        for result_data in results:
            if result_data.get("success") or result_data.get("confidence") in ["high", "medium"]:
                normalized = ScanService._normalize_finding_classification(
                    raw_type="vulnerability",
                    raw_severity=result_data.get("severity", "medium"),
                    raw_owasp_category=owasp_category,
                )

                finding = Finding(
                    scan_id=scan_id,
                    tool_name="ActiveTester",
                    type=normalized["type"],
                    severity=normalized["severity"],
                    owasp_category=normalized["owasp_category"],
                    location=result_data["url"],
                    description=f"Active Testing: {result_data.get('evidence', 'Potential vulnerability detected')}",
                    evidence=json.dumps({
                        "payload": result_data.get("payload"),
                        "status_code": result_data["status_code"],
                        "indicators": result_data.get("indicators", []),
                        "test_type": result_data.get("test_type"),
                        "confidence": result_data.get("confidence")
                    }),
                )
                db.add(finding)

        await db.commit()

        logger.info(f"Active Testing: completed {len(results)} tests for scan {scan_id}")
        return results

    @staticmethod
    async def _run_response_analysis(
        db: AsyncSession,
        scan_id: int,
        target: str,
        owasp_category: str,
        active_test_results: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """PHASE 5: Response Analysis - Analyze responses for vulnerability indicators."""
        from app.engines.response_analyzer import analyze_login_response

        vulnerability_findings = []

        for result in active_test_results:
            test_type = result.get("test_type", "")

            if test_type == "a07":  # Authentication bypass
                # Analyze login responses
                analysis = analyze_login_response(
                    status_code=result["status_code"],
                    body="",  # We don't have the full body, just status
                    headers={}
                )

                if analysis["success"] and analysis["confidence"] in ["high", "medium"]:
                    vulnerability_findings.append({
                        "type": "vulnerability",
                        "severity": "high",
                        "location": result["url"],
                        "description": f"Authentication Bypass: {analysis['evidence']}",
                        "evidence": json.dumps({
                            "analysis": analysis,
                            "payload": result.get("payload"),
                            "test_type": test_type
                        }),
                        "owasp_category": owasp_category
                    })

            elif test_type == "a01":  # IDOR
                # For IDOR, successful access to other user's data is a vulnerability
                if result.get("success") and result["status_code"] == 200:
                    vulnerability_findings.append({
                        "type": "vulnerability",
                        "severity": "high",
                        "location": result["url"],
                        "description": f"IDOR Vulnerability: {result.get('evidence', 'Access to unauthorized resource')}",
                        "evidence": json.dumps({
                            "status_code": result["status_code"],
                            "payload": result.get("payload"),
                            "test_type": test_type
                        }),
                        "owasp_category": owasp_category
                    })

            elif test_type in ["a03", "a04", "a05", "a06", "a08", "a09", "a10"]:
                # For other categories, any successful test indicates a potential vulnerability
                if result.get("success") or result.get("confidence") in ["high", "medium"]:
                    vulnerability_findings.append({
                        "type": "vulnerability",
                        "severity": result.get("severity", "medium"),
                        "location": result["url"],
                        "description": f"OWASP {test_type.upper()} Vulnerability: {result.get('evidence', 'Potential security issue detected')}",
                        "evidence": json.dumps({
                            "status_code": result["status_code"],
                            "payload": result.get("payload"),
                            "test_type": test_type,
                            "confidence": result.get("confidence")
                        }),
                        "owasp_category": owasp_category
                    })

        # Save response analysis findings
        for finding_data in vulnerability_findings:
            normalized = ScanService._normalize_finding_classification(
                raw_type=finding_data["type"],
                raw_severity=finding_data["severity"],
                raw_owasp_category=owasp_category,
            )

            finding = Finding(
                scan_id=scan_id,
                tool_name="ResponseAnalyzer",
                type=normalized["type"],
                severity=normalized["severity"],
                owasp_category=normalized["owasp_category"],
                location=finding_data["location"],
                description=finding_data["description"],
                evidence=finding_data["evidence"],
            )
            db.add(finding)

        await db.commit()

        logger.info(f"Response Analysis: found {len(vulnerability_findings)} vulnerabilities for scan {scan_id}")
        return vulnerability_findings

    @staticmethod
    async def _run_correlation(
        db: AsyncSession,
        scan_id: int,
        target: str,
        owasp_category: str,
        endpoint_classification: Dict[str, Any]
    ) -> None:
        """PHASE 6: Correlation - Combine results from all tools and active testing."""
        # Get all findings for this scan
        result = await db.execute(
            select(Finding)
            .where(Finding.scan_id == scan_id)
            .order_by(Finding.created_at)
        )
        all_findings = result.scalars().all()

        # Group findings by location/endpoint
        findings_by_location = {}
        for finding in all_findings:
            loc = finding.location
            if loc not in findings_by_location:
                findings_by_location[loc] = []
            findings_by_location[loc].append(finding)

        # Look for correlated vulnerabilities
        correlation_findings = []

        # Example: If Nuclei finds SQL injection and active testing confirms it
        for location, findings in findings_by_location.items():
            nuclei_sqli = any(
                f.tool_name == "Nuclei" and "sql" in f.description.lower()
                for f in findings
            )
            active_sqli_confirm = any(
                f.tool_name == "ActiveTester" and "sqli" in f.evidence.lower()
                for f in findings
            )

            if nuclei_sqli and active_sqli_confirm:
                correlation_findings.append({
                    "type": "vulnerability",
                    "severity": "high",
                    "location": location,
                    "description": "Correlated SQL Injection: Detected by Nuclei and confirmed by active testing",
                    "evidence": json.dumps({
                        "correlation_type": "sqli_confirmation",
                        "tools": ["Nuclei", "ActiveTester"],
                        "findings_count": len(findings)
                    }),
                    "owasp_category": owasp_category
                })

        # Save correlation findings
        for finding_data in correlation_findings:
            normalized = ScanService._normalize_finding_classification(
                raw_type=finding_data["type"],
                raw_severity=finding_data["severity"],
                raw_owasp_category=owasp_category,
            )

            finding = Finding(
                scan_id=scan_id,
                tool_name="CorrelationEngine",
                type=normalized["type"],
                severity=normalized["severity"],
                owasp_category=normalized["owasp_category"],
                location=finding_data["location"],
                description=finding_data["description"],
                evidence=finding_data["evidence"],
            )
            db.add(finding)

        await db.commit()

        logger.info(f"Correlation: created {len(correlation_findings)} correlated findings for scan {scan_id}")

    @staticmethod
    async def _run_smart_risk_scoring(
        db: AsyncSession,
        scan_id: int,
        owasp_category: str
    ) -> None:
        """PHASE 7: Smart Risk Scoring - Adjust severity based on verified exploits."""
        # Get all findings
        result = await db.execute(
            select(Finding)
            .where(Finding.scan_id == scan_id)
        )
        findings = result.scalars().all()

        for finding in findings:
            original_severity = finding.severity

            # Boost severity for verified exploits
            if finding.tool_name == "ActiveTester":
                # Active testing results are verified exploits
                if finding.severity == FindingSeverity.MEDIUM:
                    finding.severity = FindingSeverity.HIGH
                elif finding.severity == FindingSeverity.LOW:
                    finding.severity = FindingSeverity.MEDIUM

            elif finding.tool_name == "CorrelationEngine":
                # Correlated findings are high confidence
                finding.severity = FindingSeverity.HIGH

            elif finding.tool_name == "ResponseAnalyzer":
                # Response analysis indicates real vulnerabilities
                if "bypass" in finding.description.lower():
                    finding.severity = FindingSeverity.CRITICAL

            # Log severity changes
            if finding.severity != original_severity:
                logger.info(
                    f"Risk Scoring: {finding.location} severity {original_severity.value} -> {finding.severity.value} "
                    f"(tool: {finding.tool_name})"
                )

        await db.commit()

        logger.info(f"Smart Risk Scoring: completed severity adjustments for scan {scan_id}")

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
