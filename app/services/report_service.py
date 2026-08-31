"""Report generation service."""
import asyncio
import base64
import html
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Scan
from app.models.tool_run import ToolRun
from app.models.finding import Finding
from app.core.logging import get_logger
from app.core.config import settings
from app.services.intelligence_service import IntelligenceService
from app.ai.report_generator import (
    generate_report_executive_summary,
    generate_report_conclusion,
    generate_remediation_playbook_table_html,
    _fallback_ai_analysis,
    _fallback_attack_relevance,
)


logger = get_logger(__name__)

# In-memory cache for generated HTML reports: scan_id -> html. Once generated, same scan serves cached.
_REPORT_HTML_CACHE: Dict[int, str] = {}
_REPORT_CACHE_MAX = 100


class ReportService:
    """Service for generating scan reports."""

    @staticmethod
    def _severity_rank(severity: str) -> int:
        rank = {
            "info": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }
        return rank.get(str(severity).lower(), 0)

    @staticmethod
    async def generate_html_report(
        db: AsyncSession, scan_id: int, for_pdf: bool = False
    ):
        """Generate HTML report for a scan.

        - If report was already generated (stored in scan.report_html or in-memory cache),
          returns it without calling AI. Re-clicking View Report never calls AI after first generation.
        - First time: runs AI, builds HTML, persists to scan.report_html, then returns.
        - When for_pdf=True, returns (full_html, front_html, main_html) for PDF merge so
          main content page numbers start at 1. Otherwise returns full_html (str).
        """
        if scan_id in _REPORT_HTML_CACHE and not for_pdf:
            cached_html = _REPORT_HTML_CACHE[scan_id]
            if not any(
                token in cached_html
                for token in (
                    "{n_detailed}",
                    "{detailed_findings_inner}",
                    "{n_relevance}",
                    "{relevance_html",
                    "{n_conclusion}",
                    "{concl_esc}",
                )
            ):
                return cached_html
            _REPORT_HTML_CACHE.pop(scan_id, None)

        # Get scan data
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()

        if not scan:
            return None

        # Return persisted report only if it uses the current format (Summary, TOC, AI intel section, etc.)
        # When for_pdf=True we always build to get front/main HTML parts for PDF merge.
        _CURRENT_REPORT_MARKER = "irs-summary-page"
        _REPORT_VERSION_MARKER = "irs-report-pdf-v4"
        # Only use cached/persisted report if it is up-to-date
        # If an older report body contains raw template tokens, force a rebuild even if
        # it already exists in the database/cache. This prevents stale broken reports
        # from being served after template fixes.
        if scan.report_html and any(
            token in scan.report_html
            for token in (
                "{n_detailed}",
                "{detailed_findings_inner}",
                "{n_relevance}",
                "{relevance_html",
                "{n_conclusion}",
                "{concl_esc}",
            )
        ):
            scan.report_html = None
            await db.commit()
            _REPORT_HTML_CACHE.pop(scan_id, None)
        report_is_current = False
        if (
            scan.report_html
            and scan.report_html.strip()
            and _CURRENT_REPORT_MARKER in scan.report_html
            and _REPORT_VERSION_MARKER in scan.report_html
        ):
            # Try to extract the report generation date from the HTML (footer or summary)
            # Fallback: if scan.updated_at <= scan.created_at, assume current
            # (If updated_at is newer, findings/status/etc. may have changed)
            if scan.updated_at <= scan.created_at:
                report_is_current = True
            # Optionally, parse the report HTML for a date and compare, but this is a safe default
        if report_is_current and not for_pdf:
            _REPORT_HTML_CACHE[scan_id] = scan.report_html
            return scan.report_html
        if scan.report_html and (
            _CURRENT_REPORT_MARKER not in scan.report_html
            or _REPORT_VERSION_MARKER not in scan.report_html
        ):
            scan.report_html = None
            await db.commit()
            _REPORT_HTML_CACHE.pop(scan_id, None)

        # Get tool runs
        result = await db.execute(
            select(ToolRun)
            .where(ToolRun.scan_id == scan_id)
            .order_by(ToolRun.tool_name)
        )
        tool_runs = result.scalars().all()

        # Get findings
        result = await db.execute(
            select(Finding)
            .where(Finding.scan_id == scan_id)
            .order_by(Finding.severity, Finding.type)
        )
        findings = result.scalars().all()

        # Build deduplicated view for severity counts and executive summary (choose max severity for same key)
        deduped_findings = {}
        for f in findings:
            key = (
                (f.location or "").strip().lower(),
                (f.description or "").strip().lower(),
            )
            current = deduped_findings.get(key)
            if not current:
                deduped_findings[key] = f
                continue
            if ReportService._severity_rank(f.severity.value if hasattr(f.severity, "value") else str(f.severity)) > ReportService._severity_rank(
                current.severity.value if hasattr(current.severity, "value") else str(current.severity)
            ):
                deduped_findings[key] = f

        deduped_findings_list = list(deduped_findings.values())

        tools_to_run = json.loads(scan.ai_tools_to_run) if scan.ai_tools_to_run else []
        user_tools = json.loads(scan.user_selected_tools) if scan.user_selected_tools else []
        tools_used = tools_to_run or user_tools or [tr.tool_name for tr in tool_runs]
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in deduped_findings_list:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            if sev in severity_counts:
                severity_counts[sev] += 1
        # Top findings for the AI executive summary: deduplicated by (severity, description)
        seen_top = set()
        top_findings = []
        for f in deduped_findings_list:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            desc = (f.description or "")[:150]
            key = (sev, desc)
            if key in seen_top:
                continue
            seen_top.add(key)
            top_findings.append({"severity": sev, "description": desc})
            if len(top_findings) >= 10:
                break
        owasp_name = next(
            (c["name"] for c in settings.OWASP_CATEGORIES if c["id"] == scan.owasp_category),
            scan.owasp_category,
        )

        # Build findings summary once so we can reuse it for relevance and other sections
        findings_summary = [
            {
                "tool": f.tool_name or "",
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "location": (f.location or "")[:120],
                "description": IntelligenceService._dedupe_description(f.description or "")[:200],
            }
            for f in deduped_findings_list
        ]

        # Relevance to chosen attack type for the report: always use local fallback (no extra AI call)
        try:
            relevance_data = _fallback_attack_relevance(
                scan.target, scan.owasp_category, owasp_name, findings_summary
            )
        except Exception as e:
            logger.warning("Fallback attack relevance failed (skipping relevance section): %s", e)
            relevance_data = None

        # Try AI intelligence summary; on failure (e.g. 429 rate limit) use fallback so report still generates
        try:
            ai_summary = await IntelligenceService.generate_intelligence_summary(db, scan_id)
        except Exception as e:
            logger.warning(
                "AI intelligence summary failed (report will use fallback content): %s", e
            )
            ai_summary = ReportService._build_fallback_ai_summary(scan, tool_runs, findings)

        recs = []
        if ai_summary and not ai_summary.get("error"):
            for s in ai_summary.get("sections", []):
                if s.get("type") == "combined_summary":
                    act = s.get("content", {}).get("actionable_intelligence", {})
                    recs = act.get("priority_recommendations", [])[:5]
                    break

        try:
            exec_summary = await generate_report_executive_summary(
                scan.target, scan.owasp_category, owasp_name, severity_counts, tools_used, top_findings
            )
        except Exception as e:
            logger.warning("AI executive summary failed (using fallback): %s", e)
            exec_summary = ReportService._fallback_exec_summary(
                scan.target, scan.owasp_category, owasp_name, severity_counts, tools_used, top_findings
            )

        # Throttle: avoid bursting Gemini (reduce 429 risk)
        await asyncio.sleep(2)

        try:
            conclusion = await generate_report_conclusion(
                scan.target, severity_counts, len(findings), recs
            )
        except Exception as e:
            logger.warning("AI conclusion failed (using fallback): %s", e)
            conclusion = ReportService._fallback_conclusion(
                scan.target, severity_counts, len(findings), recs
            )

        remediation_playbook_html = ""
        findings_payload = []
        for i, f in enumerate(findings[:18], 1):
            findings_payload.append(
                {
                    "ref": i,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "tool": f.tool_name or "",
                    "location": (f.location or "")[:220],
                    "description": IntelligenceService._dedupe_description(f.description or "")[:450],
                }
            )
        try:
            remediation_playbook_html = await generate_remediation_playbook_table_html(
                findings_payload, scan.target, f"{scan.owasp_category} — {owasp_name}"
            )
        except Exception as e:
            logger.warning("AI remediation playbook failed (using rule-based table): %s", e)
            remediation_playbook_html = ReportService._remediation_table_fallback(findings)
        if not (remediation_playbook_html or "").strip():
            remediation_playbook_html = ReportService._remediation_table_fallback(findings)

        await asyncio.sleep(1)

        if for_pdf:
            full_html, front_html, main_html = ReportService._build_html_report(
                scan,
                tool_runs,
                findings,
                ai_summary,
                exec_summary,
                conclusion,
                relevance_data,
                remediation_playbook_html=remediation_playbook_html,
                return_parts=True,
            )
            html_content = full_html
        else:
            html_content = ReportService._build_html_report(
                scan,
                tool_runs,
                findings,
                ai_summary,
                exec_summary,
                conclusion,
                relevance_data,
                remediation_playbook_html=remediation_playbook_html,
            )

        # Persist so re-viewing this report never calls AI again
        scan.report_html = html_content
        await db.commit()

        while len(_REPORT_HTML_CACHE) >= _REPORT_CACHE_MAX and _REPORT_HTML_CACHE:
            oldest = next(iter(_REPORT_HTML_CACHE))
            del _REPORT_HTML_CACHE[oldest]
        _REPORT_HTML_CACHE[scan_id] = html_content

        if for_pdf:
            return (html_content, front_html, main_html)
        return html_content

    @staticmethod
    async def generate_pdf_report(db: AsyncSession, scan_id: int) -> Optional[bytes]:
        """Generate PDF report for a scan using WeasyPrint.

        Args:
            db: Database session
            scan_id: Scan ID

        Returns:
            PDF bytes or None if scan not found or generation fails
        """
        try:
            from weasyprint import HTML
            from io import BytesIO
        except ImportError:
            logger.error("WeasyPrint not installed. Run: pip install weasyprint")
            return None

        result = await ReportService.generate_html_report(db, scan_id, for_pdf=True)
        if not result:
            return None
        _full_html, front_html, main_html = result

        try:
            logger.info("Generating PDF report with WeasyPrint for scan %s", scan_id)
            pdf_io = BytesIO()
            doc_front = HTML(string=front_html).render()
            doc_main = HTML(string=main_html).render()
            all_pages = list(doc_front.pages) + list(doc_main.pages)
            doc_front.copy(all_pages).write_pdf(pdf_io)
            return pdf_io.getvalue()
        except Exception as e:
            logger.exception("PDF generation failed: %s", e)
            return None

    @staticmethod
    def _escape(text: Optional[str]) -> str:
        """Escape HTML and preserve newlines."""
        if not text:
            return ""
        return html.escape(str(text)).replace("\n", "<br>")

    @staticmethod
    def _target_domain_type(target: str) -> str:
        """Return a short label for the type of target (for Introduction)."""
        if not target or not isinstance(target, str):
            return "target"
        t = target.strip()
        if not t:
            return "target"
        first = t.split("/")[0].split("?")[0]
        if "/" in t or t.startswith("http://") or t.startswith("https://"):
            return "URL (web address, possibly with path)"
        if ":" in first:
            return "hostname with port"
        if re.match(r"^[\d.]+$", first) or re.match(r"^\[[\da-fA-F:.]+\]$", first):
            return "IP address"
        return "hostname (domain name)"

    @staticmethod
    def _build_fallback_ai_summary(
        scan: Scan, tool_runs: list, findings: list
    ) -> Dict[str, Any]:
        """Build a minimal AI summary from scan data when Gemini is unavailable (e.g. 429)."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        findings_by_tool: Dict[str, list] = {}
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            if sev in severity_counts:
                severity_counts[sev] += 1
            if f.tool_name not in findings_by_tool:
                findings_by_tool[f.tool_name] = []
            findings_by_tool[f.tool_name].append(f)
        tools_with_findings = list(findings_by_tool.keys())
        risk_score = (
            severity_counts["critical"] * 25
            + severity_counts["high"] * 15
            + severity_counts["medium"] * 8
            + severity_counts["low"] * 3
        )
        if risk_score == 0 and (severity_counts["info"] or findings):
            risk_score = min(29, 10 + severity_counts["info"] * 2)
        risk_score = min(100, risk_score)
        if risk_score >= 80:
            risk_level, business_impact = "CRITICAL", "SEVERE - Data could be stolen or services disrupted. Act now."
        elif risk_score >= 60:
            risk_level, business_impact = "HIGH", "HIGH - Business could be affected. Fix soon."
        elif risk_score >= 40:
            risk_level, business_impact = "MODERATE", "MODERATE - Some risk. Plan fixes."
        elif risk_score >= 10:
            risk_level, business_impact = "LOW", "LOW - Small impact. Fix when you can."
        else:
            risk_level, business_impact = "INFO", "MINIMAL"
        findings_summary = [
            {
                "tool": f.tool_name or "",
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "location": (f.location or "")[:120],
                "description": (f.description or "")[:200],
            }
            for f in findings
        ]
        fallback = _fallback_ai_analysis(
            severity_counts, tools_with_findings, risk_level, risk_score, findings_summary
        )
        rec = fallback.get("recommendation", "Review the detailed findings below.")
        return {
            "scan_id": scan.id,
            "target": scan.target,
            "status": getattr(scan.status, "value", str(scan.status)),
            "sections": [
                {
                    "type": "combined_summary",
                    "title": "Full Scan Summary (fallback: AI temporarily unavailable)",
                    "content": {
                        "status": f"Scan of {scan.target} is complete. {fallback.get('assessment', '')}",
                        "risk_assessment": {
                            "overall_risk_level": risk_level,
                            "business_impact": business_impact,
                        },
                        "actionable_intelligence": {
                            "priority_recommendations": [rec],
                            "next_steps": ["Review detailed findings and recommendations below."],
                        },
                    },
                }
            ],
            "updated_at": scan.created_at.isoformat() if scan.created_at else datetime.utcnow().isoformat(),
        }

    @staticmethod
    def _fallback_exec_summary(
        target: str,
        owasp_category: str,
        owasp_name: str,
        severity_counts: Dict[str, int],
        tools_used: List[str],
        top_findings: List[Dict[str, Any]],
    ) -> str:
        """Fallback executive summary when Gemini is unavailable."""
        c = severity_counts.get("critical", 0)
        h = severity_counts.get("high", 0)
        m = severity_counts.get("medium", 0)
        total = sum(severity_counts.values())
        if c or h or m:
            return (
                f"The target {target} was analyzed for {owasp_category} ({owasp_name}). "
                f"Findings: {c} critical, {h} high, {m} medium. "
                f"Tools used: {', '.join(tools_used[:5]) if tools_used else 'N/A'}. "
                "Immediate remediation is recommended for higher-severity issues."
            )
        if total > 0:
            return (
                f"The target {target} was analyzed. No critical or high severity vulnerabilities were detected. "
                f"Total findings: {total}. See the detailed findings and recommendations below."
            )
        return (
            f"The target {target} was scanned. No findings to report. "
            "Scan completed successfully."
        )

    @staticmethod
    def _fallback_conclusion(
        target: str,
        severity_counts: Dict[str, int],
        findings_count: int,
        recs: List[str],
    ) -> str:
        """Fallback conclusion when Gemini is unavailable."""
        c = severity_counts.get("critical", 0)
        h = severity_counts.get("high", 0)
        if c or h:
            return (
                f"Remediate critical and high severity findings for {target} as soon as possible. "
                "Re-run the scan after applying fixes to verify."
            )
        if findings_count > 0:
            return (
                f"Review the {findings_count} {'finding' if findings_count == 1 else 'findings'} and apply the recommendations above. "
                "Run a follow-up scan to confirm remediation."
            )
        return f"Scan of {target} completed with no findings. No immediate action required."

    @staticmethod
    def _sections_to_html(sections: list) -> str:
        """Convert AI intelligence sections to HTML for the report."""
        if not sections:
            return ""
        out = []
        for s in sections:
            stype = s.get("type", "")
            title = s.get("title", "").replace("🎯", "").replace("📋", "").replace("📊", "").replace("🛡️", "").replace("🔍", "").replace("🔧", "").strip()
            content = s.get("content", {})
            if isinstance(content, str):
                content = {"text": content}
            block = f'<div class="irs-ai-section"><h4 class="irs-ai-section-title">{ReportService._escape(title)}</h4>'
            if stype == "executive_summary":
                c = content
                block += f'<p><strong>Target:</strong> {ReportService._escape(str(c.get("target", "")))} | '
                block += f'<strong>Status:</strong> {ReportService._escape(str(c.get("status", "")))} | '
                block += f'<strong>Total Findings:</strong> {c.get("total_findings", 0)}</p>'
                block += f'<p><strong>Risk Level:</strong> {ReportService._escape(str(c.get("risk_level", "N/A")))} | '
                block += f'Tools: {c.get("tools_completed", 0)}/{c.get("tools_total", 0)} completed</p>'
                top = c.get("top_findings", [])[:5]
                if top:
                    block += "<ul class=\"irs-ai-list\">"
                    for f in top:
                        block += f"<li><span class=\"sev-badge sev-{f.get('severity','')}\">{f.get('severity','').upper()}</span> "
                        block += f"{ReportService._escape(f.get('description','')[:120])}</li>"
                    block += "</ul>"
            elif stype == "combined_summary":
                c = content
                act = c.get("actionable_intelligence", {})
                recs = act.get("priority_recommendations", [])
                steps = act.get("next_steps", [])
                block += f'<p>{ReportService._escape(str(c.get("status", "")))}</p>'
                ra = c.get("risk_assessment", {})
                if ra:
                    sb = ra.get("severity_breakdown") or {}
                    if isinstance(sb, dict) and sb:
                        block += '<table class="irs-ai-table irs-mini-table"><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>'
                        for k in ("critical", "high", "medium", "low", "info"):
                            if k in sb:
                                block += f"<tr><td>{k.upper()}</td><td>{sb.get(k, 0)}</td></tr>"
                        block += "</tbody></table>"
                    block += f'<p><strong>Risk Level:</strong> {ReportService._escape(str(ra.get("overall_risk_level", "N/A")))} | '
                    block += f'<strong>Score:</strong> {ra.get("risk_score", "N/A")} | '
                    block += f'<strong>Business Impact:</strong> {ReportService._escape(str(ra.get("business_impact", "")))}</p>'
                tf = c.get("technical_findings", {})
                if isinstance(tf, dict) and tf:
                    ie = tf.get("infrastructure_exposure", {}) or {}
                    sp = tf.get("security_posture", {}) or {}
                    if ie or sp:
                        block += '<table class="irs-ai-table"><thead><tr><th>Area</th><th>Metric</th><th>Value</th></tr></thead><tbody>'
                        for label, key, sub in (
                            ("Infrastructure", "Subdomains (est.)", "total_subdomains"),
                            ("Infrastructure", "Endpoints (est.)", "valid_endpoints"),
                            ("Infrastructure", "Open ports (est.)", "open_ports"),
                            ("Infrastructure", "Web services (est.)", "public_web_services"),
                            ("Security posture", "Vulnerability-class findings", "vulnerabilities"),
                            ("Security posture", "Misconfigurations", "misconfigurations"),
                            ("Security posture", "Informational", "informational_findings"),
                        ):
                            val = None
                            if label.startswith("Security"):
                                val = sp.get(sub) if sub in sp else None
                            else:
                                val = ie.get(sub) if sub in ie else None
                            if val is not None:
                                block += f"<tr><td>{html.escape(label)}</td><td>{html.escape(key)}</td><td>{val}</td></tr>"
                        block += "</tbody></table>"
                if recs:
                    block += "<p><strong>Priority recommendations:</strong></p><ol class=\"irs-ai-list\">"
                    for r in recs[:12]:
                        block += f"<li>{ReportService._escape(str(r))}</li>"
                    block += "</ol>"
                if steps:
                    block += "<p><strong>Next steps:</strong></p><ul class=\"irs-ai-list\">"
                    for st in steps[:8]:
                        block += f"<li>{ReportService._escape(str(st))}</li>"
                    block += "</ul>"
                rt = act.get("remediation_timeline") or {}
                if isinstance(rt, dict) and rt:
                    block += "<p><strong>Remediation timeline (guidance):</strong></p><table class=\"irs-ai-table irs-mini-table\"><thead><tr><th>Window</th><th>Action</th></tr></thead><tbody>"
                    for window, action in list(rt.items())[:8]:
                        block += f"<tr><td>{ReportService._escape(str(window))}</td><td>{ReportService._escape(str(action))}</td></tr>"
                    block += "</tbody></table>"
            elif stype == "attack_relevance":
                c = content
                block += f'<p>{ReportService._escape(str(c.get("relevance_summary", "")))}</p>'
                if c.get("can_support_attack") is not None:
                    block += f'<p><strong>Could support chosen attack type:</strong> {"Yes" if c.get("can_support_attack") else "No"}</p>'
                dbs = c.get("detail_bullets") or []
                if isinstance(dbs, list) and dbs:
                    block += "<ul class=\"irs-ai-list\">"
                    for b in dbs[:8]:
                        block += f"<li>{ReportService._escape(str(b))}</li>"
                    block += "</ul>"
            elif stype == "findings_table":
                rows = content.get("rows", [])[:30]
                if rows:
                    block += '<table class="irs-ai-table"><thead><tr><th>Tool</th><th>Severity</th><th>Location</th><th>Description</th></tr></thead><tbody>'
                    for r in rows:
                        block += f"<tr><td>{ReportService._escape(str(r.get('tool','')))}</td>"
                        block += f"<td><span class=\"sev-badge sev-{r.get('severity','')}\">{ReportService._escape(str(r.get('severity','')).upper())}</span></td>"
                        block += f"<td><code>{ReportService._escape(str(r.get('location',''))[:80])}</code></td>"
                        block += f"<td>{ReportService._escape(str(r.get('description',''))[:150])}</td></tr>"
                    block += "</tbody></table>"
                block += f'<p class="irs-ai-note">{ReportService._escape(str(content.get("severity_info", "")))}</p>'
            elif stype == "configuration":
                c = content
                block += f'<p><strong>Target:</strong> {ReportService._escape(str(c.get("target", "")))} | '
                block += f'<strong>Attack Type:</strong> {ReportService._escape(str(c.get("attack_type", "")))}</p>'
                tools = c.get("user_selected_tools", [])
                if tools:
                    block += f'<p><strong>Tools:</strong> {ReportService._escape(", ".join(str(t) for t in tools))}</p>'
            elif stype == "ai_decision":
                dec = content.get("decision", content)
                tools_run = dec.get("tools_to_run", [])
                block += f'<p><strong>Tools to Run:</strong> {ReportService._escape(", ".join(str(t) for t in tools_run)) if tools_run else "None"}</p>'
                block += f'<p><strong>Reason:</strong> {ReportService._escape(str(dec.get("reason", "Based on reconnaissance clues.")))}</p>'
            elif stype == "clues":
                stats = content.get("statistics", {})
                if isinstance(stats, dict):
                    # Count actual findings from clue insights
                    findings_count = stats.get("total_findings", 0)
                    block += f'<p><strong>Total Findings:</strong> {findings_count}</p>'
                insights = content.get("findings", content.get("insights", []))
                if insights:
                    block += "<ul class=\"irs-ai-list\">"
                    for i in insights:
                        block += f"<li>{ReportService._escape(str(i))}</li>"
                    block += "</ul>"
                if content.get("intelligence_insight"):
                    block += f'<p><strong>Intelligence Insight:</strong> {ReportService._escape(str(content.get("intelligence_insight", "")))}</p>'
            elif stype in ("dns_validation", "port_exposure", "vulnerability", "http_service", "subdomain", "tool_result"):
                stats = content.get("statistics", content)
                if isinstance(stats, dict):
                    # Count actual findings from the findings dict, don't rely on total_findings key
                    findings_count = 0
                    if "findings" in content and isinstance(content["findings"], dict):
                        findings_count = sum(content["findings"].values()) if isinstance(content["findings"], dict) else len(content.get("findings", []))
                    elif "findings" in stats and isinstance(stats["findings"], dict):
                        findings_count = sum(stats["findings"].values())
                    else:
                        findings_count = stats.get("total_findings", 0)
                    block += f'<p><strong>Total Findings:</strong> {findings_count}</p>'
                if content.get("impact"):
                    block += f'<p><strong>Impact:</strong> {ReportService._escape(str(content.get("impact", "")))}</p>'
                cmd = content.get("command")
                if cmd:
                    block += f'<p><strong>Command / scope:</strong> <code>{ReportService._escape(str(cmd))}</code></p>'
                findings_counts = content.get("findings")
                if isinstance(findings_counts, dict):
                    block += '<table class="irs-ai-table irs-mini-table"><thead><tr>'
                    block += "".join(f"<th>{html.escape(k)}</th>" for k in findings_counts.keys())
                    block += "</tr></thead><tbody><tr>"
                    block += "".join(f"<td>{html.escape(str(v))}</td>" for v in findings_counts.values())
                    block += "</tr></tbody></table>"
                issues = content.get("detected_issues") or []
                if isinstance(issues, list) and issues:
                    block += "<p><strong>Detected issues (excerpt):</strong></p><ul class=\"irs-ai-list\">"
                    for issue in issues[:15]:
                        block += f"<li>{ReportService._escape(str(issue)[:200])}</li>"
                    block += "</ul>"
                ro = content.get("readable_output")
                if isinstance(ro, list) and ro:
                    block += "<p><strong>Evidence lines:</strong></p><pre class=\"irs-ai-pre\">"
                    block += html.escape("\n".join(str(x) for x in ro[:25]))
                    block += "</pre>"
                elif isinstance(ro, str) and ro.strip():
                    block += f'<pre class="irs-ai-pre">{html.escape(ro[:8000])}</pre>'
            block += "</div>"
            out.append(block)
        return "".join(out)

    @staticmethod
    def _findings_overview_table(findings: list) -> str:
        """Compact matrix of all findings for PDF overview."""
        if not findings:
            return '<p class="irs-empty">No findings in this scan.</p>'
        rows = [
            '<table class="irs-findings-overview"><thead><tr>',
            "<th>#</th><th>Severity</th><th>Tool</th><th>Location</th><th>Description (excerpt)</th>",
            "</tr></thead><tbody>",
        ]
        for i, f in enumerate(findings[:40], 1):
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            sev_cls = "".join(c for c in str(sev).lower() if c.isalnum()) or "info"
            desc = IntelligenceService._dedupe_description(f.description or "")[:160]
            loc = (f.location or "")[:100]
            rows.append(
                "<tr>"
                f"<td>{i}</td>"
                f'<td><span class="sev-badge sev-{sev_cls}">{html.escape(sev.upper())}</span></td>'
                f"<td>{html.escape(f.tool_name or '')}</td>"
                f"<td><code>{ReportService._escape(loc)}</code></td>"
                f"<td>{ReportService._escape(desc)}</td>"
                "</tr>"
            )
        rows.append("</tbody></table>")
        if len(findings) > 40:
            rows.append(f'<p class="irs-ai-note">Showing 40 of {len(findings)} findings. See detailed cards below.</p>')
        return "".join(rows)

    @staticmethod
    def _remediation_table_fallback(findings: list) -> str:
        """Rule-based remediation table when AI playbook is unavailable."""
        if not findings:
            return ""
        parts = [
            '<table class="irs-remediation-table"><thead><tr>',
            "<th>#</th><th>Severity</th><th>Location</th><th>Impact</th><th>Recommendation</th>",
            "</tr></thead><tbody>",
        ]
        for i, f in enumerate(findings[:25], 1):
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            ft = f.type.value if hasattr(f.type, "value") else str(f.type)
            impact, rec = ReportService._impact_recommendation(sev, ft, f.description or "")
            loc = ReportService._escape((f.location or "")[:140])
            parts.append(
                f"<tr><td>{i}</td><td>{html.escape(sev)}</td>"
                f"<td><code>{loc}</code></td>"
                f"<td>{ReportService._escape(impact[:280])}</td>"
                f"<td>{ReportService._escape(rec[:450])}</td></tr>"
            )
        parts.append("</tbody></table>")
        return "".join(parts)

    # Short explanations for report sections and tools (detail explanation of output)
    _TOOL_DESCRIPTIONS = {
        "Nuclei": "Vulnerability scanner that runs templates against URLs to find known CVEs, misconfigurations, and security issues.",
        "ActiveTest": "Active Testing Engine that sends custom HTTP requests to verify default credentials and other A07 (Authentication) vulnerabilities.",
        "Naabu": "Fast port scanner that discovers open ports on the target for further analysis.",
        "Httpx": "HTTP probe that checks which URLs respond, fetches titles and technologies, and validates web services.",
        "Subfinder": "Subdomain discovery tool that finds subdomains using passive sources and APIs.",
        "Amass": "In-depth attack surface mapping and asset discovery including subdomains and related infrastructure.",
        "Assetfinder": "Finds related domains and subdomains for the target domain.",
        "Sublist3r": "Subdomain enumeration using search engines and other public sources.",
        "GAU": "GetAllUrls: fetches known URLs for a domain from Wayback Machine and other archives.",
        "Katana": "Crawler that discovers endpoints and links by crawling the target web application.",
        "GoSpider": "Fast web spider for discovering URLs, parameters, and endpoints.",
        "FFuf": "Fast web fuzzer for discovering hidden paths, parameters, and testing for vulnerabilities.",
        "Wfuzz": "Web application fuzzer for finding hidden resources and testing input validation.",
        "CeWL": "Generates custom wordlists from target websites for password or fuzzing use.",
        "DNSx": "DNS toolkit for resolution, wildcard checks, and DNS record enumeration.",
        "ShuffleDNS": "Mass DNS resolver and subdomain bruteforce using a wordlist.",
    }

    @staticmethod
    def _tool_description(tool_name: str) -> str:
        """Return a brief explanation of what the tool does for the report."""
        return ReportService._TOOL_DESCRIPTIONS.get(
            (tool_name or "").strip(),
            "Security or reconnaissance tool used in this scan. See summary and findings for what it detected."
        )

    # Max bytes to include from a tool's raw output file (avoid huge reports)
    _RAW_OUTPUT_MAX_BYTES = 512 * 1024

    @staticmethod
    def _read_tool_raw_output(raw_output_path: Optional[str]) -> Optional[str]:
        """Read tool raw output from file; return None if missing or unreadable."""
        if not raw_output_path or not raw_output_path.strip():
            return None
        try:
            p = Path(raw_output_path)
            if not p.is_file():
                return None
            content = p.read_text(encoding="utf-8", errors="replace")
            if len(content) > ReportService._RAW_OUTPUT_MAX_BYTES:
                content = content[: ReportService._RAW_OUTPUT_MAX_BYTES] + "\n\n... (output truncated)"
            return content.strip() or None
        except Exception:
            return None

    @staticmethod
    def _impact_recommendation(severity: str, ftype: str, description: str) -> tuple:
        """Return (impact, recommendation) for a finding based on severity and type."""
        sev = (severity or "").lower()
        ft = (ftype or "").lower()
        desc = (description or "").lower()
        impact = "Varies based on exploitation. Review the finding description for specifics."
        rec = "Apply security best practices: input validation, parameterized queries, security headers, and keep components updated."
        if sev == "critical":
            impact = "Attackers could fully compromise the system, steal data, or disrupt services. Immediate action required."
            rec = "Fix within 24 hours. Use parameterized queries for injection, patch vulnerable components, and apply temporary mitigations."
        elif sev == "high":
            impact = "Serious risk if exploited. Attackers could gain unauthorized access or extract sensitive information."
            rec = "Fix within 7 days. Implement proper input validation, use prepared statements, and review access controls."
        elif sev == "medium":
            impact = "Moderate risk. Could be exploited under certain conditions. Should be addressed promptly."
            rec = "Plan remediation within 30 days. Apply security patches and follow secure coding guidelines."
        elif sev == "low":
            impact = "Limited impact. Minor security concern that could contribute to a larger attack chain."
            rec = "Address during next maintenance window. Improve security posture incrementally."
        else:
            impact = "Informational. Useful for reconnaissance and mapping. Not a direct vulnerability."
            rec = "Document for awareness. No immediate action required unless combined with other findings."
        if "sql" in desc or "injection" in desc:
            rec = "Use parameterized queries or prepared statements. Never concatenate user input into SQL. Apply input validation."
        elif "xss" in desc or "cross-site" in desc:
            rec = "Encode output properly (HTML entity encoding). Use Content-Security-Policy header. Validate and sanitize input."
        elif "header" in desc or "missing" in desc:
            rec = "Add security headers: X-Content-Type-Options, X-Frame-Options, Content-Security-Policy, Strict-Transport-Security."
        return (impact, rec)

    @staticmethod
    def _build_html_report(
        scan: Scan,
        tool_runs: list,
        findings: list,
        ai_summary: Optional[Dict[str, Any]] = None,
        exec_summary: str = "",
        conclusion: str = "",
        relevance_data: Optional[Dict[str, Any]] = None,
        remediation_playbook_html: str = "",
        return_parts: bool = False,
    ):
        """Build professional HTML report with AI-generated content.

        When return_parts=True, returns (full_html, front_html, main_html) for PDF merge
        so main content pages are numbered from 1. Otherwise returns full_html (str).
        """
        tools_to_run = json.loads(scan.ai_tools_to_run) if scan.ai_tools_to_run else []
        user_tools = json.loads(scan.user_selected_tools) if scan.user_selected_tools else []
        # Use tools that actually executed (completed or timed out), not tools that were planned
        actually_executed_tools = [tr.tool_name for tr in tool_runs if tr.status in ("COMPLETED", "TIMEOUT")]
        tools_used = ", ".join(actually_executed_tools or tools_to_run or user_tools or [])
        owasp_name = next(
            (c["name"] for c in settings.OWASP_CATEGORIES if c["id"] == scan.owasp_category),
            scan.owasp_category,
        )
        target_type_str = ReportService._target_domain_type(scan.target or "")

        findings_by_severity = {}
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            sev = finding.severity.value
            if sev not in findings_by_severity:
                findings_by_severity[sev] = []
            findings_by_severity[sev].append(finding)
            if sev in severity_counts:
                severity_counts[sev] += 1

        target_esc = html.escape(scan.target)
        _fmt = "%b %d, %Y at %I:%M:%S %p UTC"
        created_str = scan.created_at.strftime(_fmt)
        completed_str = scan.completed_at.strftime(_fmt) if scan.completed_at else "N/A"
        # PDF reports omit per-section timestamps (no duplicate date/time footers on every section)
        ts_html = ""
        system_name = "IRS"
        scan_duration = "N/A"
        if scan.completed_at and scan.created_at:
            delta = scan.completed_at - scan.created_at
            mins = int(delta.total_seconds() // 60)
            secs = int(delta.total_seconds() % 60)
            scan_duration = f"{mins} min {secs} sec" if mins else f"{secs} sec"

        # Severity cards
        severity_cards = ""
        colors = {"critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04", "low": "#16a34a", "info": "#6b7280"}
        for sev, count in severity_counts.items():
            if count == 0:
                continue
            bg = colors.get(sev, "#6b7280")
            severity_cards += f'<div class="irs-severity-card" style="--sev-color:{bg}"><span class="irs-severity-count">{count}</span><span class="irs-severity-label">{sev.upper()}</span></div>'

        # Severity bar chart (CSS-based)
        total_f = sum(severity_counts.values()) or 1
        bar_parts = []
        for sev in ["critical", "high", "medium", "low", "info"]:
            c = severity_counts.get(sev, 0)
            if c > 0:
                pct = int(100 * c / total_f)
                bar_parts.append(f'<div class="irs-bar-seg sev-{sev}" style="width:{pct}%"></div>')
        severity_bars = "".join(bar_parts) if bar_parts else '<div class="irs-bar-seg sev-info" style="width:100%">0</div>'

        # Scan info table (always show scan date)
        scan_info_table = f"""
        <table class=\"irs-report-table\">
        <tr><th>Target</th><td><code>{target_esc}</code></td></tr>
        <tr><th>Scan ID</th><td>{scan.id}</td></tr>
        <tr><th>Status</th><td>{html.escape(scan.status.value if hasattr(scan.status, "value") else str(scan.status))}</td></tr>
        """ + ts_html + """
        <tr><th>Tools Used</th><td>{html.escape(tools_used or "N/A")}</td></tr>
        <tr><th>Scan Duration</th><td>{scan_duration}</td></tr>
        <tr><th>Scan Date</th><td>{created_str}</td></tr>
        </table>"""

        # Relevance to chosen attack type for the report: always use local fallback (no extra AI call)
        relevance_html = ""
        if ai_summary and not ai_summary.get("error") and ai_summary.get("sections"):
            ar_section = None
            for s in ai_summary["sections"]:
                if s.get("type") == "attack_relevance":
                    ar_section = s
                    break
            if ar_section:
                relevance_html = f'<div class="irs-relevance-rich">{ReportService._sections_to_html([ar_section])}</div>'
        elif relevance_data:
            rel_summary = ReportService._escape(relevance_data.get("relevance_summary", ""))
            bullets = relevance_data.get("detail_bullets", []) or []
            can_sup = relevance_data.get("can_support_attack")
            bullets_html = ""
            if bullets:
                items = "".join(f"<li>{ReportService._escape(str(b))}</li>" for b in bullets[:15])
                bullets_html = f"<ul class=\"irs-relevance-bullets\">{items}</ul>"
            can_line = ""
            if can_sup is not None:
                can_line = (
                    f"<p><strong>Could support chosen attack type:</strong> {'Yes' if can_sup else 'No'}</p>"
                )
            relevance_html = f"""
            <div class="irs-card">
            <p><strong>Overview:</strong> {rel_summary}</p>
            {can_line}
            {bullets_html}
            </div>"""

        # Detailed findings with Impact & Recommendation
        findings_html = ""
        owasp_esc = html.escape(scan.owasp_category)
        for severity in ["critical", "high", "medium", "low", "info"]:
            if severity not in findings_by_severity:
                continue
            sev_findings = findings_by_severity[severity]
            for idx, f in enumerate(sev_findings, 1):
                impact, rec = ReportService._impact_recommendation(f.severity.value, f.type.value, f.description)
                loc_esc = ReportService._escape(f.location)
                desc_esc = ReportService._escape(f.description).replace("<br>", " ")
                findings_html += f"""
                <div class="irs-finding-card">
                <div class="irs-finding-header">
                <span class="sev-badge sev-{severity}">{severity.upper()}</span>
                <span class="irs-finding-num">#{idx}</span>
                <span class="irs-finding-tool">{html.escape(f.tool_name)}</span>
                {f'<span class="badge bg-outline">OWASP: {owasp_esc}</span>' if f.owasp_category else ''}
                </div>
                <div class="irs-finding-body">
                <p><strong>URL/Location:</strong> <code>{loc_esc}</code></p>
                <p><strong>Tool Detected By:</strong> {html.escape(f.tool_name)}</p>
                <p><strong>Description:</strong> {desc_esc}</p>
                <p><strong>Impact:</strong> {ReportService._escape(impact)}</p>
                <p><strong>Recommendation:</strong> {ReportService._escape(rec)}</p>
                </div>
                </div>"""
        if not findings_html:
            findings_html = '<p class="irs-empty">No findings to display.</p>'

        findings_overview_html = ReportService._findings_overview_table(findings)
        rem_body = (remediation_playbook_html or "").strip() or ReportService._remediation_table_fallback(findings)

        # Tools output section: list full scan output of each tool (no evidence in findings)
        tools_output_html = ""
        for tr in tool_runs:
            cmd = f"{tr.tool_name} -target {scan.target}" if tr.tool_name else "N/A"
            tool_desc = ReportService._tool_description(tr.tool_name)
            tool_desc_esc = ReportService._escape(tool_desc)
            raw_content = ReportService._read_tool_raw_output(getattr(tr, "raw_output_path", None))
            if raw_content:
                output_esc = html.escape(raw_content)
                output_block = f'<pre class="irs-scan-output-pre">{output_esc}</pre>'
            else:
                parts = []
                if tr.summary:
                    parts.append(ReportService._escape(tr.summary))
                if tr.error_message:
                    parts.append("Error: " + ReportService._escape(tr.error_message))
                fallback_text = "\n\n".join(parts) or "No output captured."
                output_block = f'<pre class="irs-scan-output-pre">{html.escape(fallback_text)}</pre>'
            tools_output_html += f"""
            <div class="irs-tool-output-card">
            <h5>{html.escape(tr.tool_name)}</h5>
            <p class="irs-tool-desc"><strong>What this tool does:</strong> {tool_desc_esc}</p>
            <p><strong>Command:</strong> <code>{html.escape(cmd)}</code></p>
            <p><strong>Scan output:</strong></p>
            {output_block}
            </div>"""

        exec_esc = ReportService._escape(exec_summary) if exec_summary else ReportService._escape("The target was analyzed. See detailed findings below.")
        concl_esc = ReportService._escape(conclusion) if conclusion else ReportService._escape("Review the detailed findings and apply recommended remediations. Run follow-up scans to verify fixes.")

        # Risk level for summary (from severity counts) - use consistent naming
        c, h, m = severity_counts.get("critical", 0), severity_counts.get("high", 0), severity_counts.get("medium", 0)
        low, info = severity_counts.get("low", 0), severity_counts.get("info", 0)
        if c:
            risk_level = "CRITICAL"
        elif h:
            risk_level = "HIGH"
        elif m:
            risk_level = "MEDIUM"
        elif low:
            risk_level = "LOW"
        else:
            risk_level = "INFO"
        risk_level_esc = html.escape(risk_level)

        # Scheduled scans have no AI decision; omit that section and renumber
        is_scheduled_scan = bool(getattr(scan, "scheduled_scan_id", None))

        # AI reasoning for report (from scan AI decision)
        ai_reasoning_esc = ""
        try:
            from app.services.intelligence_service import IntelligenceService
            reason = IntelligenceService._extract_ai_reasoning(scan.ai_raw_response)
            if reason:
                executed_tool_names = [
                    tr.tool_name
                    for tr in tool_runs
                    if tr.status in ("COMPLETED", "TIMEOUT")
                ]
                executed_tool_lookup = {name.lower() for name in executed_tool_names}
                reason_lower = reason.lower()
                mentions_unexecuted_tool = any(
                    tool.lower() in reason_lower and tool.lower() not in executed_tool_lookup
                    for tool in settings.AVAILABLE_TOOLS
                )

                if mentions_unexecuted_tool or " and and " in reason_lower or "user-selected ." in reason_lower:
                    executed_label = ", ".join(executed_tool_names) if executed_tool_names else "the executed tools"
                    reason = (
                        f"The strategy focused on the tools that actually ran: {executed_label}. "
                        "Initial clues confirmed active web services, so the report prioritized the executed tools "
                        "to expand the attack surface before vulnerability scanning."
                    )

                ai_reasoning_esc = ReportService._escape(reason.strip())
            else:
                ai_reasoning_esc = ReportService._escape("AI decision based on initial clues and selected tools.")
        except Exception:
            ai_reasoning_esc = ReportService._escape("AI decision based on initial clues and selected tools.")

        # Tool execution order: discovery → other → exploit (for report section)
        discovery_tools = [tr for tr in tool_runs if tr.tool_name in settings.DISCOVERY_TOOLS]
        exploit_tools = [tr for tr in tool_runs if tr.tool_name in settings.EXPLOIT_TOOLS]
        other_tools = [tr for tr in tool_runs if tr.tool_name not in settings.DISCOVERY_TOOLS and tr.tool_name not in settings.EXPLOIT_TOOLS]
        ordered_tool_runs = discovery_tools + other_tools + exploit_tools
        tool_execution_phases = []
        if discovery_tools:
            tool_execution_phases.append(("Discovery", discovery_tools, "Identify assets, subdomains, and endpoints."))
        if other_tools:
            tool_execution_phases.append(("Other", other_tools, "Additional reconnaissance and analysis."))
        if exploit_tools:
            tool_execution_phases.append(("Vulnerability Finding", exploit_tools, "Vulnerability scanning and testing."))
        if not tool_execution_phases:
            tool_execution_phases = [("Tools executed", list(tool_runs), "Tools run in scan order.")]

        tool_execution_html = ""
        for phase_name, runs, phase_desc in tool_execution_phases:
            if not runs:
                continue
            tool_execution_html += f'<div class="irs-tool-phase"><h4>{html.escape(phase_name)}</h4><p class="irs-phase-desc">{ReportService._escape(phase_desc)}</p><ul class="irs-tool-list">'
            for tr in runs:
                st = getattr(tr.status, "value", str(tr.status)) if hasattr(tr, "status") else "completed"
                tool_execution_html += f'<li><strong>{html.escape(tr.tool_name)}</strong>: {st}</li>'
            tool_execution_html += "</ul></div>"

        # Summary: one overview (table + AI narrative). No separate "Executive Summary" section.
        total_findings = sum(severity_counts.values())
        summary_sev = " · ".join(f"{k.upper()}: {severity_counts.get(k, 0)}" for k in ["critical", "high", "medium", "low", "info"])
        summary_html = f"""
        <div class=\"irs-summary-page\">
        <h3 class=\"irs-section-title irs-summary-title\">Summary</h3>
        <p class=\"irs-summary-p\">This report presents the results of a security scan performed by the Intelligence Recon System (IRS).</p>
        <table class=\"irs-report-table irs-summary-table\">
        <tr><th>Target</th><td>{target_esc}</td></tr>
        <tr><th>Scan ID</th><td>{scan.id}</td></tr>
        <tr><th>Status</th><td>{html.escape(scan.status.value if hasattr(scan.status, "value") else str(scan.status))}</td></tr>
        <tr><th>Risk Level</th><td><strong>{risk_level_esc}</strong></td></tr>
        <tr><th>Total Findings</th><td>{total_findings}</td></tr>
        <tr><th>Severity Breakdown</th><td>{summary_sev}</td></tr>
        <tr><th>Tools Used</th><td>{html.escape(tools_used or "N/A")}</td></tr>
        <tr><th>Scan Duration</th><td>{scan_duration}</td></tr>
        <tr><th>Attack Type</th><td>{html.escape(owasp_name)} ({scan.owasp_category})</td></tr>
        <tr><th>Scan Date</th><td>{created_str}</td></tr>
        </table>
        <p class=\"irs-summary-p\">{exec_esc}</p>
        <p class=\"irs-summary-p\">The following sections provide the table of contents, introduction, severity distribution, AI intelligence analysis,{'' if is_scheduled_scan else ' AI tool selection,'} tool execution order, detailed findings with remediation guidance, relevance to the chosen attack type, and conclusions.</p>
        </div>"""

        # Same structured content as the in-app intelligence summary (omit attack_relevance here; it has its own section)
        ai_sections_html = ""
        if ai_summary and not ai_summary.get("error") and ai_summary.get("sections"):
            _sec_pdf = [
                s
                for s in ai_summary["sections"]
                if s.get("type") != "attack_relevance"
            ]
            ai_sections_html = ReportService._sections_to_html(_sec_pdf)
        has_intel = bool((ai_sections_html or "").strip())

        toc_parts = [
            "Introduction (Target, Attack Type, Tools Used, Scan Information)",
            "Severity Distribution",
        ]
        if has_intel:
            toc_parts.append(
                "AI Intelligence Analysis (executive overview, risk tables, per-tool results, recommendations)"
            )
        if not is_scheduled_scan:
            toc_parts.append("AI Decision (tools selected and reasoning)")
        toc_parts.extend(
            [
                "Tool Execution (phases: Discovery, Other, Vulnerability Finding)",
                "Detailed Findings (overview matrix, remediation playbook, per-finding cards)",
                "Relevance to Attack Type",
                "Conclusion and Recommendations",
            ]
        )
        toc_items_html = "".join(f"<li>{html.escape(p)}</li>" for p in toc_parts)
        toc_html = f"""
        <div class="irs-toc">
        <h3 class="irs-section-title">Table of Contents</h3>
        <ol class="irs-toc-list" start="1">
        {toc_items_html}
        </ol>
        </div>"""

        # Embed IRS logo for cover (base64 so PDF is self-contained); use favicon.svg
        logo_data_url = ""
        try:
            logo_path = settings.BASE_DIR / "Frontend" / "favicon.svg"
            if logo_path.is_file():
                logo_bytes = logo_path.read_bytes()
                logo_b64 = base64.b64encode(logo_bytes).decode("ascii")
                logo_data_url = f"data:image/svg+xml;base64,{logo_b64}"
        except Exception:
            pass
        logo_img = f'<img src="{html.escape(logo_data_url)}" alt="IRS" class="irs-cover-logo" />' if logo_data_url else ""

        sec_num = 3
        intel_section_html = ""
        if has_intel:
            intel_section_html = f"""
    <section class=\"irs-section irs-intelligence-section\">
    <h3 class=\"irs-section-title\">{sec_num}. AI Intelligence Analysis</h3>
    <p class=\"irs-section-intro\">Full intelligence summary aligned with the web UI: executive metrics, combined risk assessment, findings tables, per-tool analysis, and prioritized recommendations.</p>
    <div class=\"irs-ai-sections-wrap\">{ai_sections_html}</div>
    """ + ts_html + f"""
    </section>"""
            sec_num += 1
        n_ai_decision = sec_num
        if not is_scheduled_scan:
            sec_num += 1
        n_tool = sec_num
        sec_num += 1
        n_detailed = sec_num
        sec_num += 1
        n_relevance = sec_num
        sec_num += 1
        n_conclusion = sec_num

        detailed_findings_inner = f"""
    <h4 class=\"irs-subheading\">Findings overview (matrix)</h4>
    {findings_overview_html}
    <h4 class=\"irs-subheading\">Remediation playbook</h4>
    <p class=\"irs-section-intro\">Concrete fixes and how to verify them. Produced by AI when the report is generated; otherwise rule-based guidance from severity and description.</p>
    {rem_body}
    <h4 class=\"irs-subheading\">Per-finding detail</h4>
    {findings_html}
    """

        _ai_section = ""
        if not is_scheduled_scan:
            _ai_section = f"""
    <section class=\"irs-section\">
    <h3 class=\"irs-section-title\">{n_ai_decision}. AI Decision</h3>
    <p class=\"irs-section-intro\">The following tools were selected to run based on the initial clues and AI analysis.</p>
    <p><strong>Tools executed:</strong> {html.escape(tools_used or "N/A")}</p>
    <div class=\"irs-ai-decision-box\">
    <p><strong>Reasoning:</strong></p>
    <p>{ai_reasoning_esc}</p>
    </div>
    """ + ts_html + f"""
    </section>"""

        # Paged content block: numbered sections after Summary / TOC
        _intro_sev = (
            f"""
    <div class=\"irs-paged-content\">
    <section class=\"irs-section\">
    <h3 class=\"irs-section-title\">1. Introduction</h3>
    <p class=\"irs-section-intro\">This section describes the scan target, attack type, tools used, and scan information for this report.</p>
    <p class=\"irs-section-intro\"><strong>Target:</strong> {target_esc}. This is a {html.escape(target_type_str)} that was scanned for this report.</p>
    <p class=\"irs-section-intro\"><strong>Attack Type:</strong> {html.escape(owasp_name)} ({scan.owasp_category}). This is the kind of security testing performed for this scan.</p>
    <p class=\"irs-section-intro\"><strong>Tools Used:</strong> {html.escape(tools_used or "N/A")}. These are the security tools that were executed for this scan.</p>
    <div class=\"irs-card\">{scan_info_table}</div>
    """
            + ts_html
            + f"""
    </section>

<section class="irs-section">
<h3 class="irs-section-title">2. Severity Distribution</h3>
<p class="irs-section-intro">Findings by severity across all tools. Critical and high findings should be remediated first.</p>
<div class="irs-severity-row">{severity_cards}</div>
<div class="irs-bar-chart">{severity_bars}</div>
<table class="irs-report-table">
<tr><th>Critical</th><td>{severity_counts.get("critical", 0)}</td></tr>
<tr><th>High</th><td>{severity_counts.get("high", 0)}</td></tr>
<tr><th>Medium</th><td>{severity_counts.get("medium", 0)}</td></tr>
<tr><th>Low</th><td>{severity_counts.get("low", 0)}</td></tr>
<tr><th>Info</th><td>{severity_counts.get("info", 0)}</td></tr>
</table>
"""
            + ts_html
            + """
</section>"""
        )
        _tool_findings_relevance_concl = f"""
    <section class=\"irs-section\">
    <h3 class=\"irs-section-title\">{n_tool}. Tool Execution</h3>
    <p class=\"irs-section-intro\">Tools were executed in phases: Discovery (asset and endpoint discovery), Other (additional reconnaissance), and Vulnerability Finding (vulnerability scanning).</p>
    {tool_execution_html}
    """ + ts_html + f"""
    </section>

    <section class=\"irs-section\">
    <h3 class=\"irs-section-title\">{n_detailed}. Detailed Findings</h3>
    <p class=\"irs-section-intro\">Overview matrix, remediation playbook, and per-finding cards with impact and recommendation. Page breaks keep each card intact where possible.</p>
    {detailed_findings_inner}
    """ + ts_html + f"""
    </section>

    <section class=\"irs-section\">
    <h3 class=\"irs-section-title\">{n_relevance}. Relevance to Attack Type</h3>
    <p class=\"irs-section-intro\">How the findings relate to the chosen OWASP attack type ({html.escape(scan.owasp_category)}) and whether they could support this kind of attack.</p>
    {relevance_html if relevance_html else '<p class="irs-empty">No findings are directly related to this attack type.</p>'}
phaSE 3 tool orchestration explain for all tools     """ + ts_html + f"""
    </section>

    <section class=\"irs-section\">
    <h3 class=\"irs-section-title\">{n_conclusion}. Conclusion &amp; Recommendations</h3>
    <p class=\"irs-section-intro\">AI-generated next steps and prioritization. Use them to plan remediation and follow-up scans.</p>
    <div class=\"irs-concl-box\"><p>{concl_esc}</p></div>
    """ + ts_html + f"""
    </section>
    </div>"""
        _tool_findings_relevance_concl_scheduled = f"""
<section class="irs-section">
<h3 class="irs-section-title">{n_tool}. Tool Execution</h3>
<p class="irs-section-intro">Tools were executed in phases: Discovery (asset and endpoint discovery), Other (additional reconnaissance), and Vulnerability Finding (vulnerability scanning).</p>
{tool_execution_html}
""" + ts_html + f"""
</section>

<section class="irs-section">
<h3 class="irs-section-title">{n_detailed}. Detailed Findings</h3>
<p class="irs-section-intro">Overview matrix, remediation playbook, and per-finding cards with impact and recommendation.</p>
{detailed_findings_inner}
""" + ts_html + f"""
</section>

<section class="irs-section">
<h3 class="irs-section-title">{n_relevance}. Relevance to Attack Type</h3>
<p class="irs-section-intro">How the findings relate to the chosen OWASP attack type ({html.escape(scan.owasp_category)}) and whether they could support this kind of attack.</p>
{relevance_html if relevance_html else '<p class="irs-empty">No findings are directly related to this attack type.</p>'}
""" + ts_html + f"""
</section>

<section class="irs-section">
<h3 class="irs-section-title">{n_conclusion}. Conclusion &amp; Recommendations</h3>
<p class="irs-section-intro">Next steps and prioritization. Use them to plan remediation and follow-up scans.</p>
<div class="irs-concl-box"><p>{concl_esc}</p></div>
""" + ts_html + f"""
</section>
</div>"""
        if is_scheduled_scan:
            paged_content_html = _intro_sev + intel_section_html + _tool_findings_relevance_concl_scheduled
        else:
            paged_content_html = _intro_sev + intel_section_html + _ai_section + _tool_findings_relevance_concl

        footer_block = f"""
    <footer class="irs-footer">
    <p>Generated by Intelligence Recon System (IRS) on {created_str}</p>
    <p>Report ID: Scan {scan.id} | Target: {target_esc}</p>
    </footer>"""

        # Complete HTML document - User-friendly, justified, each heading on new page, findings not split
        report_html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IRS Scan Report - {target_esc}</title>
<style>
:root{{--irs-bg:#ffffff;--irs-surface:#ffffff;--irs-surface-2:#e5e7eb;--irs-text:#000000;--irs-muted:#374151;--irs-accent:#1d4ed8;}}
*{{box-sizing:border-box;}}
html, body{{width:100%;margin:0;padding:0;background:#e5e7eb;}}
body{{font-family:Helvetica,Arial,sans-serif;background:#e5e7eb;color:#000000;font-size:12pt;line-height:1.5;text-align:justify;overflow-x:hidden;max-width:100%;padding:1rem 0;}}
p,li,td,th{{text-align:justify;line-height:1.5;}}
.irs-container{{width:min(210mm, calc(100vw - 2rem));max-width:210mm;margin:0 auto;padding:0 15mm;background:#ffffff;box-sizing:border-box;box-shadow:0 8px 24px rgba(0,0,0,0.08);border-radius:8px;}}
.irs-cover{{min-height:90vh;display:flex;flex-direction:column;justify-content:center;align-items:center;text-align:center;page-break-after:always;padding:2rem;background:#ffffff;color:#000000;page: no-footer;}}
.irs-cover p, .irs-cover h1, .irs-cover h2, .irs-cover-meta, .irs-cover-meta p, .irs-cover-confidential{{text-align:center;}}
.irs-cover-logo{{width:120px;height:120px;margin-bottom:1.5rem;display:block;object-fit:contain;}}
.irs-cover h1{{font-size:2rem;margin-bottom:0.5rem;color:#000000;}}
.irs-cover h2{{font-size:1.2rem;font-weight:400;color:#374151;margin-bottom:2rem;}}
.irs-cover-meta{{font-size:0.95rem;line-height:2;color:#000000;}}
.irs-cover-meta p{{color:#000000;}}
.irs-cover-confidential{{margin-top:3rem;font-size:0.8rem;color:#000000;border:1px solid #d1d5db;padding:1rem 2rem;border-radius:8px;background:#f9fafb;}}
.irs-summary-page{{page: no-footer;}}
.irs-toc{{page: no-footer;}}
.irs-paged-content{{page: main; counter-reset: page 1;}}
@page {{size: A4; margin: 0.5in;}}
@page no-footer{{size: A4; margin: 0.5in;}}
@page main{{size: A4; margin: 0.5in; @bottom-left{{content: "Intelligence Recon System"; font-size: 8pt; color: #374151;}} @bottom-right{{content: counter(page); font-size: 9pt; color: #000000;}}}}
@media print{{
body{{background:#ffffff;padding:0;}}
.irs-container{{width:auto;max-width:none;margin:0;padding:0;box-shadow:none;border-radius:0;}}
}}
.irs-paged-content > .irs-section{{page-break-before:always;}}
.irs-paged-content > .irs-section:first-child{{page-break-before:auto;}}
.irs-section{{margin-bottom:1rem;}}
.irs-section-title{{font-size:14pt;font-weight:700;color:#000000;margin-bottom:0.5rem;padding-bottom:0.35rem;border-bottom:1px solid #e5e7eb;page-break-after:avoid;}}
.irs-section-title.irs-first-on-page{{page-break-before:auto;}}
.irs-summary-title{{page-break-before:auto;font-size:14pt;}}
.irs-card{{background:#ffffff;border-radius:12px;padding:1.5rem;border:1px solid #e5e7eb;}}
.irs-report-table{{width:100%;border-collapse:collapse;}}
.irs-report-table th, .irs-report-table td{{padding:0.6rem 1rem;text-align:left;border-bottom:1px solid #e5e7eb;color:#000000;}}
.irs-report-table th{{width:180px;color:#374151;font-weight:500;}}
.irs-report-table code{{color:#000000;}}
.irs-severity-row{{display:flex;flex-wrap:wrap;gap:0.75rem;margin:1rem 0;}}
.irs-severity-card{{background:#ffffff;border-radius:10px;padding:0.75rem 1.25rem;display:flex;flex-direction:column;align-items:center;min-width:85px;border:1px solid #e5e7eb;border-left:4px solid var(--sev-color);}}
.irs-severity-count{{font-size:1.4rem;font-weight:700;color:#000000;}}
.irs-severity-label{{font-size:0.65rem;color:#374151;text-transform:uppercase;}}
.irs-bar-chart{{display:flex;height:24px;border-radius:6px;overflow:hidden;margin:1rem 0;}}
.irs-bar-seg{{min-width:2px;}}.irs-bar-seg.sev-critical{{background:#dc2626;}}.irs-bar-seg.sev-high{{background:#ea580c;}}.irs-bar-seg.sev-medium{{background:#ca8a04;}}.irs-bar-seg.sev-low{{background:#16a34a;}}.irs-bar-seg.sev-info{{background:#6b7280;}}
.irs-finding-card{{background:#ffffff;border-radius:10px;padding:1.25rem;margin-bottom:1.5rem;border:1px solid #e5e7eb;page-break-inside:avoid;overflow:visible;display:block;clear:both;}}
.irs-finding-has-evidence{{page-break-after:always;}}
.irs-finding-header{{display:flex;flex-wrap:wrap;align-items:center;gap:0.5rem;margin-bottom:0.75rem;}}
.irs-finding-body{{word-break:break-all;overflow-wrap:break-word;max-width:100%;overflow-x:hidden;}}
.irs-finding-body p{{margin:0.4rem 0;color:#000000;text-align:justify;word-break:break-all;overflow-wrap:break-word;max-width:100%;}}
.irs-finding-body code{{word-break:break-all;overflow-wrap:break-word;max-width:100%;}}
.irs-finding-tool{{font-size:0.9rem;color:#1d4ed8;}}
.irs-evidence-pre{{font-family:monospace;font-size:0.7rem;background:#ffffff;color:#000000;padding:0.75rem;border-radius:8px;border:1px solid #d1d5db;white-space:pre-wrap;word-break:break-all;overflow-wrap:break-word;margin:0.5rem 0 0 0;page-break-inside:avoid;display:block;max-width:100%;box-sizing:border-box;}}
.irs-finding-evidence{{margin-top:0.75rem;padding-top:0.75rem;border-top:1px solid #e5e7eb;page-break-before:auto;display:block;clear:both;}}
.irs-finding-evidence strong{{color:#000000;}}
.sev-badge{{padding:3px 8px;border-radius:4px;font-size:0.75rem;font-weight:600;}}
.sev-critical{{background:#dc2626;color:#fff;}}.sev-high{{background:#ea580c;color:#fff;}}.sev-medium{{background:#ca8a04;color:#000;}}.sev-low{{background:#16a34a;color:#fff;}}.sev-info{{background:#6b7280;color:#fff;}}
.badge.bg-outline{{background:transparent;border:1px solid #d1d5db;color:#374151;font-size:0.75rem;padding:2px 6px;border-radius:4px;}}
.irs-tool-output-card{{background:#ffffff;border-radius:10px;padding:1rem;margin-bottom:1rem;border:1px solid #e5e7eb;}}
.irs-tool-output-card h5{{margin:0 0 0.5rem 0;color:#000000;}}
.irs-tool-output-card p{{color:#000000;text-align:justify;}}
.irs-tool-output-card code{{color:#000000;}}
.irs-section-timestamp{{text-align:right;color:#6b7280;font-size:0.85rem;margin-top:0.6rem;}}
.irs-tool-desc{{color:#374151;font-size:0.9rem;margin-bottom:0.75rem;}}
.irs-scan-output-pre{{font-family:monospace;font-size:0.75rem;background:#f8fafc;color:#000000;padding:0.75rem;border-radius:8px;border:1px solid #e5e7eb;white-space:pre-wrap;word-break:break-all;overflow-wrap:break-word;margin:0.5rem 0 0 0;max-height:50rem;overflow:auto;display:block;}}
.irs-section-intro{{color:#374151;font-size:12pt;line-height:1.5;margin-bottom:0.5rem;padding:0.25rem 0;text-align:justify;}}
.irs-summary-page{{padding:0.5rem 0.25rem;}}
.irs-summary-p{{margin:0.75rem 0;text-align:justify;font-size:12pt;line-height:1.5;}}
.irs-summary-table{{margin:0.5rem 0;}}
.irs-toc{{padding:0.5rem 0;}}
.irs-toc-list{{margin:1rem 0;padding-left:1.5rem;line-height:1.8;color:#000000;}}
.irs-tool-phase{{margin-bottom:1.5rem;}}
.irs-tool-phase h4{{margin:0.5rem 0 0.25rem 0;color:#000000;font-size:1rem;}}
.irs-phase-desc{{margin:0.25rem 0 0.5rem 0;font-size:0.9rem;color:#374151;text-align:justify;}}
.irs-tool-list{{margin:0.5rem 0;padding-left:1.25rem;}}
.irs-ai-decision-box{{background:#f8fafc;border-left:4px solid #1d4ed8;padding:1rem 1.25rem;border-radius:8px;margin:1rem 0;}}
.irs-ai-decision-box p{{margin:0.4rem 0;text-align:justify;}}
.irs-empty{{color:#374151;font-style:italic;padding:1.5rem;text-align:center;}}
.irs-footer{{text-align:center;color:#374151;font-size:0.8rem;margin-top:2.5rem;padding-top:1.5rem;border-top:1px solid #e5e7eb;}}
.irs-exec-box{{background:#f8fafc;border-left:4px solid #1d4ed8;padding:1rem 1.25rem;border-radius:8px;margin:1rem 0;}}
.irs-exec-box p{{color:#000000;text-align:justify;}}
.irs-concl-box{{background:#f0fdf4;border-left:4px solid #16a34a;padding:1rem 1.25rem;border-radius:8px;margin:1rem 0;}}
.irs-concl-box p{{color:#000000;text-align:justify;}}
.irs-intelligence-section{{page-break-before:always;}}
.irs-ai-sections-wrap .irs-ai-section{{margin-bottom:1.75rem;padding:1rem 1.25rem;border:1px solid #e5e7eb;border-radius:10px;background:#fafafa;page-break-inside:avoid;}}
.irs-ai-section-title{{font-size:1.05rem;margin:0 0 0.75rem 0;color:#111827;border-bottom:1px solid #e5e7eb;padding-bottom:0.35rem;}}
.irs-ai-table{{width:100%;border-collapse:collapse;margin:0.75rem 0;font-size:0.88rem;}}
.irs-ai-table th,.irs-ai-table td{{padding:0.45rem 0.65rem;border:1px solid #d1d5db;text-align:left;vertical-align:top;}}
.irs-ai-table thead th{{background:#f3f4f6;font-weight:600;color:#111827;}}
.irs-mini-table{{font-size:0.85rem;}}
.irs-findings-overview{{width:100%;border-collapse:collapse;margin:0.75rem 0;font-size:0.82rem;page-break-inside:auto;}}
.irs-findings-overview th,.irs-findings-overview td{{padding:0.4rem 0.5rem;border:1px solid #d1d5db;vertical-align:top;}}
.irs-findings-overview thead th{{background:#1e293b;color:#fff;font-weight:600;}}
.irs-remediation-table{{width:100%;border-collapse:collapse;margin:0.75rem 0;font-size:0.8rem;page-break-inside:auto;}}
.irs-remediation-table th,.irs-remediation-table td{{padding:0.45rem 0.55rem;border:1px solid #cbd5e1;vertical-align:top;}}
.irs-remediation-table thead th{{background:#1d4ed8;color:#fff;}}
.irs-subheading{{font-size:12pt;color:#0f172a;margin:0.6rem 0 0.35rem 0;font-weight:600;}}
.irs-ai-pre{{font-family:monospace;font-size:0.72rem;background:#f8fafc;padding:0.65rem;border:1px solid #e5e7eb;border-radius:6px;white-space:pre-wrap;word-break:break-word;max-height:24rem;overflow:hidden;}}
.irs-ai-list{{margin:0.35rem 0;padding-left:1.2rem;}}
.irs-ai-note{{font-size:0.85rem;color:#6b7280;margin-top:0.5rem;}}
</style>
</head>
<body><!-- irs-report-pdf-v4 -->
<div class="irs-cover">
{logo_img}
<h1>Intelligence Recon System</h1>
<h2>Security Scan Report</h2>
<div class="irs-cover-meta">
<p><strong>Project Name:</strong> Intelligent Recon System</p>
<p><strong>Scan ID:</strong> {scan.id}</p>
<p><strong>Target Domain:</strong> {target_esc}</p>
<p><strong>Attack Type:</strong> {html.escape(owasp_name)} ({scan.owasp_category})</p>
<p><strong>Scan Date:</strong> {created_str}</p>
<p><strong>Generated by:</strong> {html.escape(system_name)}</p>
</div>
<div class="irs-cover-confidential">CONFIDENTIAL - This report contains sensitive security information. Distribution should be limited to authorized personnel only.</div>
</div>

<div class="irs-container">
<section class="irs-section">{summary_html}</section>

<section class="irs-section">{toc_html}</section>

{paged_content_html}
{footer_block}
</div>
</body>
</html>"""

        if return_parts:
            # Front matter (cover + summary + TOC) for PDF; no page numbers
            idx = report_html.find("<div class=\"irs-paged-content\">")
            front_html = report_html[:idx].rstrip() + "\n</div></body></html>"
            # Main content only: when rendered as its own PDF, pages are 1, 2, 3...
            main_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IRS Scan Report - {target_esc}</title>
<style>
:root{{--irs-bg:#ffffff;--irs-surface:#ffffff;--irs-surface-2:#e5e7eb;--irs-text:#000000;--irs-muted:#374151;--irs-accent:#1d4ed8;}}
*{{box-sizing:border-box;}}
html, body{{width:100%;margin:0;padding:0;background:#e5e7eb;}}
body{{font-family:Helvetica,Arial,sans-serif;background:#e5e7eb;color:#000000;font-size:12pt;line-height:1.5;text-align:justify;overflow-x:hidden;max-width:100%;padding:1rem 0;}}
p,li,td,th{{text-align:justify;line-height:1.5;}}
.irs-container{{width:min(210mm, calc(100vw - 2rem));max-width:210mm;margin:0 auto;padding:0 15mm;background:#ffffff;box-sizing:border-box;box-shadow:0 8px 24px rgba(0,0,0,0.08);border-radius:8px;}}
.irs-paged-content{{page: main; counter-reset: page 1;}}
@page {{size: A4; margin: 0.5in;}}
@page main{{size: A4; margin: 0.5in; @bottom-left{{content: "Intelligence Recon System"; font-size: 8pt; color: #374151;}} @bottom-right{{content: counter(page); font-size: 9pt; color: #000000;}}}}
@media print{{
body{{background:#ffffff;padding:0;}}
.irs-container{{width:auto;max-width:none;margin:0;padding:0;box-shadow:none;border-radius:0;}}
}}
.irs-paged-content > .irs-section{{page-break-before:always;}}
.irs-paged-content > .irs-section:first-child{{page-break-before:auto;}}
.irs-section{{margin-bottom:1rem;}}
.irs-section-title{{font-size:14pt;font-weight:700;color:#000000;margin-bottom:0.5rem;padding-bottom:0.35rem;border-bottom:1px solid #e5e7eb;page-break-after:avoid;}}
.irs-card{{background:#ffffff;border-radius:12px;padding:1.5rem;border:1px solid #e5e7eb;}}
.irs-report-table{{width:100%;border-collapse:collapse;}}
.irs-report-table th, .irs-report-table td{{padding:0.6rem 1rem;text-align:left;border-bottom:1px solid #e5e7eb;color:#000000;}}
.irs-report-table th{{width:180px;color:#374151;font-weight:500;}}
.irs-severity-row{{display:flex;flex-wrap:wrap;gap:0.75rem;margin:1rem 0;}}
.irs-severity-card{{background:#ffffff;border-radius:10px;padding:0.75rem 1.25rem;display:flex;flex-direction:column;align-items:center;min-width:85px;border:1px solid #e5e7eb;border-left:4px solid var(--sev-color);}}
.irs-severity-count{{font-size:1.4rem;font-weight:700;color:#000000;}}
.irs-severity-label{{font-size:0.65rem;color:#374151;text-transform:uppercase;}}
.irs-bar-chart{{display:flex;height:24px;border-radius:6px;overflow:hidden;margin:1rem 0;}}
.irs-bar-seg{{min-width:2px;}}.irs-bar-seg.sev-critical{{background:#dc2626;}}.irs-bar-seg.sev-high{{background:#ea580c;}}.irs-bar-seg.sev-medium{{background:#ca8a04;}}.irs-bar-seg.sev-low{{background:#16a34a;}}.irs-bar-seg.sev-info{{background:#6b7280;}}
.irs-finding-card{{background:#ffffff;border-radius:10px;padding:1.25rem;margin-bottom:1.5rem;border:1px solid #e5e7eb;page-break-inside:avoid;overflow:visible;display:block;clear:both;}}
.irs-finding-has-evidence{{page-break-after:always;}}
.irs-finding-header{{display:flex;flex-wrap:wrap;align-items:center;gap:0.5rem;margin-bottom:0.75rem;}}
.irs-finding-body{{word-break:break-all;overflow-wrap:break-word;max-width:100%;overflow-x:hidden;}}
.irs-finding-body p{{margin:0.4rem 0;color:#000000;text-align:justify;word-break:break-all;overflow-wrap:break-word;max-width:100%;}}
.irs-finding-body code{{word-break:break-all;overflow-wrap:break-word;max-width:100%;}}
.irs-finding-tool{{font-size:0.9rem;color:#1d4ed8;}}
.irs-evidence-pre{{font-family:monospace;font-size:0.7rem;background:#ffffff;color:#000000;padding:0.75rem;border-radius:8px;border:1px solid #d1d5db;white-space:pre-wrap;word-break:break-all;overflow-wrap:break-word;margin:0.5rem 0 0 0;page-break-inside:avoid;display:block;max-width:100%;box-sizing:border-box;}}
.irs-finding-evidence{{margin-top:0.75rem;padding-top:0.75rem;border-top:1px solid #e5e7eb;}}
.sev-badge{{padding:3px 8px;border-radius:4px;font-size:0.75rem;font-weight:600;}}
.sev-critical{{background:#dc2626;color:#fff;}}.sev-high{{background:#ea580c;color:#fff;}}.sev-medium{{background:#ca8a04;color:#000;}}.sev-low{{background:#16a34a;color:#fff;}}.sev-info{{background:#6b7280;color:#fff;}}
.irs-tool-phase{{margin-bottom:1.5rem;}}
.irs-tool-phase h4{{margin:0.5rem 0 0.25rem 0;color:#000000;font-size:1rem;}}
.irs-phase-desc{{margin:0.25rem 0 0.5rem 0;font-size:0.9rem;color:#374151;text-align:justify;}}
.irs-tool-list{{margin:0.5rem 0;padding-left:1.25rem;}}
.irs-ai-decision-box{{background:#f8fafc;border-left:4px solid #1d4ed8;padding:1rem 1.25rem;border-radius:8px;margin:1rem 0;}}
.irs-ai-decision-box p{{margin:0.4rem 0;text-align:justify;}}
.irs-empty{{color:#374151;font-style:italic;padding:1.5rem;text-align:center;}}
.irs-footer{{text-align:center;color:#374151;font-size:0.8rem;margin-top:2.5rem;padding-top:1.5rem;border-top:1px solid #e5e7eb;}}
.irs-section-intro{{color:#374151;font-size:12pt;line-height:1.5;margin-bottom:0.5rem;padding:0.25rem 0;text-align:justify;}}
.irs-concl-box{{background:#f0fdf4;border-left:4px solid #16a34a;padding:1rem 1.25rem;border-radius:8px;margin:1rem 0;}}
.irs-concl-box p{{color:#000000;text-align:justify;}}
.irs-intelligence-section{{page-break-before:always;}}
.irs-ai-sections-wrap .irs-ai-section{{margin-bottom:1rem;padding:0.75rem 1rem;border:1px solid #e5e7eb;border-radius:10px;background:#fafafa;page-break-inside:avoid;}}
.irs-ai-section-title{{font-size:12pt;font-weight:600;margin:0 0 0.5rem 0;color:#111827;border-bottom:1px solid #e5e7eb;padding-bottom:0.35rem;}}
.irs-ai-table{{width:100%;border-collapse:collapse;margin:0.75rem 0;font-size:0.88rem;}}
.irs-ai-table th,.irs-ai-table td{{padding:0.45rem 0.65rem;border:1px solid #d1d5db;text-align:left;vertical-align:top;}}
.irs-ai-table thead th{{background:#f3f4f6;font-weight:600;color:#111827;}}
.irs-mini-table{{font-size:0.85rem;}}
.irs-findings-overview{{width:100%;border-collapse:collapse;margin:0.75rem 0;font-size:0.82rem;page-break-inside:auto;}}
.irs-findings-overview th,.irs-findings-overview td{{padding:0.4rem 0.5rem;border:1px solid #d1d5db;vertical-align:top;}}
.irs-findings-overview thead th{{background:#1e293b;color:#fff;font-weight:600;}}
.irs-remediation-table{{width:100%;border-collapse:collapse;margin:0.75rem 0;font-size:0.8rem;page-break-inside:auto;}}
.irs-remediation-table th,.irs-remediation-table td{{padding:0.45rem 0.55rem;border:1px solid #cbd5e1;vertical-align:top;}}
.irs-remediation-table thead th{{background:#1d4ed8;color:#fff;}}
.irs-subheading{{font-size:12pt;color:#0f172a;margin:0.6rem 0 0.35rem 0;font-weight:600;}}
.irs-ai-pre{{font-family:monospace;font-size:0.72rem;background:#f8fafc;padding:0.65rem;border:1px solid #e5e7eb;border-radius:6px;white-space:pre-wrap;word-break:break-word;max-height:24rem;overflow:hidden;}}
.irs-ai-list{{margin:0.35rem 0;padding-left:1.2rem;}}
.irs-ai-note{{font-size:0.85rem;color:#6b7280;margin-top:0.5rem;}}
.badge.bg-outline{{background:transparent;border:1px solid #d1d5db;color:#374151;font-size:0.75rem;padding:2px 6px;border-radius:4px;}}
</style>
</head>
<body>
<div class="irs-container">
{paged_content_html}
{footer_block}
</div>
</body>
</html>"""
            return (report_html, front_html, main_html)
        return report_html

    @staticmethod
    async def generate_tool_report(
        db: AsyncSession, 
        scan_id: int, 
        tool_name: str, 
        findings: List[Finding], 
        tool_result: Any
    ) -> Optional[str]:
        """Generate HTML report for a specific tool execution.
        
        Args:
            db: Database session
            scan_id: Scan ID
            tool_name: Name of the tool
            findings: Findings from this tool
            tool_result: Tool execution result
            
        Returns:
            HTML report string or None
        """
        # Get scan data
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        
        if not scan:
            return None
        
        # Get tool run data
        result = await db.execute(
            select(ToolRun)
            .where(
                ToolRun.scan_id == scan_id,
                ToolRun.tool_name == tool_name
            )
        )
        tool_run = result.scalar_one_or_none()
        
        if not tool_run:
            return None
        
        # Generate tool-specific HTML
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>{tool_name} Report - Scan {scan_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .header {{ border-bottom: 2px solid #007bff; padding-bottom: 15px; margin-bottom: 20px; }}
        .header h1 {{ color: #333; margin: 0; }}
        .header p {{ margin: 5px 0; color: #666; }}
        .summary-box {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .findings-table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        .findings-table th, .findings-table td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        .findings-table th {{ background: #007bff; color: white; }}
        .severity-critical {{ background: #dc3545; color: white; padding: 3px 8px; border-radius: 3px; font-size: 12px; }}
        .severity-high {{ background: #fd7e14; color: white; padding: 3px 8px; border-radius: 3px; font-size: 12px; }}
        .severity-medium {{ background: #ffc107; color: black; padding: 3px 8px; border-radius: 3px; font-size: 12px; }}
        .severity-low {{ background: #28a745; color: white; padding: 3px 8px; border-radius: 3px; font-size: 12px; }}
        .severity-info {{ background: #17a2b8; color: white; padding: 3px 8px; border-radius: 3px; font-size: 12px; }}
        .tool-info {{ display: flex; justify-content: space-between; margin-bottom: 15px; }}
        .tool-status {{ padding: 8px 15px; border-radius: 20px; font-weight: bold; }}
        .status-completed {{ background: #d4edda; color: #155724; }}
        .status-failed {{ background: #f8d7da; color: #721c24; }}
        .status-running {{ background: #cce7ff; color: #004085; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔧 {tool_name} Execution Report</h1>
            <p><strong>Scan ID:</strong> {scan_id} | <strong>Target:</strong> {scan.target}</p>
            <p><strong>OWASP Category:</strong> {scan.owasp_category}</p>
        </div>
        
        <div class="tool-info">
            <div>
                <p><strong>Execution Time:</strong> {tool_run.started_at.strftime('%Y-%m-%d %H:%M:%S') if tool_run.started_at else 'N/A'} - 
                {tool_run.finished_at.strftime('%Y-%m-%d %H:%M:%S') if tool_run.finished_at else 'N/A'}</p>
                <p><strong>Duration:</strong> {str(tool_run.finished_at - tool_run.started_at) if tool_run.started_at and tool_run.finished_at else 'N/A'}</p>
            </div>
            <div>
                <span class="tool-status status-{tool_run.status.value}">{tool_run.status.value.upper()}</span>
            </div>
        </div>
        
        <div class="summary-box">
            <h3>📊 Execution Summary</h3>
            <p><strong>Command:</strong> {tool_name} -target {scan.target}</p>
            <p><strong>Total Findings:</strong> {len(findings)}</p>
            <p><strong>Status:</strong> {tool_result.summary if hasattr(tool_result, 'summary') else 'N/A'}</p>
            {f'<p><strong>Error:</strong> {tool_result.error_message}</p>' if hasattr(tool_result, 'error_message') and tool_result.error_message else ''}
        </div>
        
        <h3>🔍 Findings</h3>
        """
        
        if findings:
            html += """
        <table class="findings-table">
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>Location</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
            """
            
            for finding in findings:
                severity_class = f"severity-{finding.severity.value}" if hasattr(finding.severity, 'value') else f"severity-{finding.severity}"
                severity_display = finding.severity.value.upper() if hasattr(finding.severity, 'value') else finding.severity.upper()
                
                html += f"""
                <tr>
                    <td><span class="{severity_class}">{severity_display}</span></td>
                    <td>{finding.type.value if hasattr(finding.type, 'value') else finding.type}</td>
                    <td>{finding.location}</td>
                    <td>{finding.description}</td>
                </tr>
                """
            
            html += """
            </tbody>
        </table>
            """
        else:
            html += "<p>No findings detected by this tool.</p>"
        
        # Use scan.created_at for consistent report date
        created_str = scan.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') if scan.created_at else 'N/A'
        html += f"""
        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; text-align: center; color: #666; font-size: 12px;">
            <p>Generated by Intelligence Recon System (IRS) on {created_str}</p>
            <p>Scan {scan_id} | Tool: {tool_name}</p>
        </div>
    </div>
</body>
</html>
        """
        return html

