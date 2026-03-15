"""Intelligence service for generating real-time reconnaissance narratives."""
import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Scan, ScanStatus
from app.models.tool_run import ToolRun, ToolRunStatus
from app.models.finding import Finding
from app.core.logging import get_logger
from app.core.config import settings

logger = get_logger(__name__)

# In-memory cache so repeated views of the same scan's intelligence summary
# reuse the existing result instead of calling Gemini again.
_INTELLIGENCE_SUMMARY_CACHE: Dict[int, Dict[str, Any]] = {}


class IntelligenceService:
    """Service for generating intelligence-driven reconnaissance summaries."""

    @staticmethod
    def _get_real_command(tool_name: str, target: str) -> str:
        """Return the actual CLI command that would be run for this tool (for display)."""
        try:
            from app.tools.tools_impl import TOOL_REGISTRY
            klass = TOOL_REGISTRY.get(tool_name)
            if klass:
                out = Path(settings.SCANS_DIR) / "0" / f"{tool_name.lower()}.out"
                return " ".join(str(x) for x in klass().build_command(target, out))
        except Exception:
            pass
        return f"{tool_name.lower()} -target {target}"

    @staticmethod
    async def generate_intelligence_summary(
        db: AsyncSession, scan_id: int
    ) -> Dict[str, Any]:
        """Generate structured intelligence summary for a scan.
        
        Args:
            db: Database session
            scan_id: Scan ID
            
        Returns:
            Dictionary containing intelligence narrative sections
        """
        # Get scan details
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        
        if not scan:
            return {"error": "Scan not found"}

        # If this scan is already completed and we have a cached summary, reuse it.
        if (
            scan.status in [ScanStatus.COMPLETED, ScanStatus.COMPLETED_WITH_ERRORS]
            and scan_id in _INTELLIGENCE_SUMMARY_CACHE
        ):
            return _INTELLIGENCE_SUMMARY_CACHE[scan_id]
        # Get findings
        result = await db.execute(
            select(Finding)
            .where(Finding.scan_id == scan_id)
            .order_by(Finding.created_at)
        )
        findings = result.scalars().all()
        # Exclude Sublist3r banner/log noise from display (so All Findings shows only real subdomains)
        from app.utils.finding_filters import is_sublist3r_noise
        findings = [
            f for f in findings
            if not (f.tool_name == "Sublist3r" and is_sublist3r_noise(f.location or "", f.description or ""))
        ]
        
        # Get tool runs
        result = await db.execute(
            select(ToolRun)
            .where(ToolRun.scan_id == scan_id)
            .order_by(ToolRun.created_at)
        )
        tool_runs = result.scalars().all()
        
        # Check if scan has meaningful findings
        # Only show summary for scans with significant findings
        meaningful_findings = len([f for f in findings if f.severity.value in ["critical", "high", "medium", "low"]])
        
        # Even if no meaningful findings, still generate basic scan summary
        sections = []
        
        # Phase 0: Executive Summary (at-a-glance for users)
        exec_section = IntelligenceService._generate_executive_summary(scan, tool_runs, findings)
        sections.append(exec_section)
        # When AI is enabled, classify Key Findings so each value goes in the right column (and new columns for new types)
        if settings.INTELLIGENCE_AI_ENABLED and exec_section.get("content", {}).get("top_findings"):
            try:
                from app.ai.report_generator import classify_key_findings_table
                key_table = await classify_key_findings_table(exec_section["content"]["top_findings"])
                if key_table:
                    exec_section["content"]["key_findings_table"] = key_table
            except Exception as e:
                logger.warning("AI Key Findings classification skipped: %s", e)

        # Phase 1: Configuration Section
        sections.append(
            IntelligenceService._generate_configuration_section(scan)
        )
        
        # Phase 2: Clues/Results Section (even if no significant findings)
        sections.append(
            IntelligenceService._generate_clues_section(scan, tool_runs, findings)
        )
        
        # Phase 3: AI Analysis & Decision (if AI has made decisions)
        if scan.ai_tools_to_run:
            sections.append(
                IntelligenceService._generate_ai_decision_section(scan, tool_runs)
            )
        
        # Phase 4: Tool Execution Results - only for completed tools (completed, failed, timeout)
        # Skip queued/running so summary shows output only after each tool finishes
        for tool_run in tool_runs:
            if tool_run.status not in (ToolRunStatus.COMPLETED, ToolRunStatus.FAILED, ToolRunStatus.TIMEOUT):
                continue
            # Match by tool name (case-insensitive so DB/code casing differences don't drop findings)
            tool_findings = [f for f in findings if (f.tool_name or "").lower() == (tool_run.tool_name or "").lower()]
            sections.append(
                IntelligenceService._generate_tool_result_section(
                    tool_run, tool_findings, scan
                )
            )
        
        # Phase 5: After scan complete — Relevance first, then Full Scan Summary
        if scan.status in [ScanStatus.COMPLETED, ScanStatus.COMPLETED_WITH_ERRORS]:
            # 1) Relevance to Chosen Attack Type (always, using fallback-only logic)
            try:
                attack_relevance_section = await IntelligenceService._generate_attack_relevance_section_async(
                    scan, findings
                )
                if attack_relevance_section:
                    sections.append(attack_relevance_section)
            except Exception as e:
                logger.warning("Attack relevance section failed (skipping): %s", e)
            # 2) Full Scan Summary (contains Actionable Intelligence in UI)
            sections.append(
                await IntelligenceService._generate_combined_summary(scan, tool_runs, findings)
            )
        
        summary = {
            "scan_id": scan_id,
            "target": scan.target,
            "status": scan.status.value,
            "sections": sections,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "updated_at": datetime.utcnow().isoformat(),
        }
        # Cache summaries for completed scans so subsequent views don't call Gemini again.
        if scan.status in [ScanStatus.COMPLETED, ScanStatus.COMPLETED_WITH_ERRORS]:
            _INTELLIGENCE_SUMMARY_CACHE[scan_id] = summary
        return summary
    
    @staticmethod
    def _generate_executive_summary(
        scan: Scan, tool_runs: List[ToolRun], findings: List[Finding]
    ) -> Dict[str, Any]:
        """Generate executive summary - key metrics at a glance."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        completed_tools = [tr for tr in tool_runs if tr.status == ToolRunStatus.COMPLETED]
        failed_tools = [tr for tr in tool_runs if tr.status in (ToolRunStatus.FAILED, ToolRunStatus.TIMEOUT)]
        failed_tool_names = [tr.tool_name for tr in failed_tools]
        
        total = len(findings)
        critical = severity_counts["critical"]
        high = severity_counts["high"]
        medium = severity_counts["medium"]
        low = severity_counts["low"]
        info = severity_counts["info"]
        
        # Risk based only on real findings (score aligned with combined summary)
        # If all findings are Info, overall risk level is INFO not LOW
        risk_level = "N/A"
        risk_score = 0
        if critical > 0:
            risk_level = "CRITICAL"
            risk_score = min(100, 70 + critical * 10)
        elif high > 0:
            risk_level = "HIGH"
            risk_score = min(69, 50 + high * 5)
        elif medium > 0:
            risk_level = "MEDIUM"
            risk_score = min(49, 30 + medium * 4)
        elif low > 0:
            risk_level = "LOW"
            risk_score = min(29, 10 + (low + info) * 2)
        elif info > 0:
            risk_level = "INFO"
            risk_score = min(29, 10 + info * 2)
        if total == 0 and risk_score == 0:
            risk_level = "N/A"

        # Key Findings: one row per finding (port, endpoint, information, asset, vulnerability); dedupe by (tool, location)
        active_types = ("port", "endpoint", "information", "asset", "vulnerability")
        top_findings = []
        seen_key = set()
        for f in findings:
            ftype = f.type.value if hasattr(f.type, "value") else str(f.type)
            if ftype not in active_types:
                continue
            key = (f.tool_name or "", f.location or "")
            if key in seen_key:
                continue
            seen_key.add(key)
            desc = IntelligenceService._dedupe_description(f.description)
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            top_findings.append({
                "tool": f.tool_name,
                "type": ftype,
                "severity": sev,
                # Keep location/description readable but allow wrapping across multiple lines (no ellipsis truncation)
                "location": (f.location or "")[:200],
                "description": desc if len(desc) <= 300 else desc[:300],
            })
        
        # Group all findings by severity for clickable severity badges
        seen = set()
        findings_by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for f in findings:
            key = (f.tool_name, f.location)
            if key in seen:
                continue
            seen.add(key)
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            if sev in findings_by_severity:
                desc = IntelligenceService._dedupe_description(f.description)
                findings_by_severity[sev].append({
                    "tool": f.tool_name,
                    "severity": sev,
                    "location": f.location[:80] + ("..." if len(f.location) > 80 else ""),
                    "description": (desc[:200] + "...") if len(desc) > 200 else desc,
                })
        # Clues summary: what Naabu and Httpx found (so both tools are visible even when one has 0)
        naabu_count = len([f for f in findings if (f.tool_name or "").lower() == "naabu"])
        httpx_count = len([f for f in findings if (f.tool_name or "").lower() == "httpx"])
        clues_summary = f"Initial clues: Naabu {naabu_count} port(s), Httpx {httpx_count} HTTP service(s)."

        # Per-tool severity breakdown: include all completed tools (even 0 findings) so "combined" is clear
        tools_that_ran = list({tr.tool_name for tr in completed_tools if tr.tool_name})
        severity_by_tool = {}
        for tool_name in tools_that_ran:
            severity_by_tool[tool_name] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            if f.tool_name and f.tool_name in severity_by_tool and sev in severity_by_tool[f.tool_name]:
                severity_by_tool[f.tool_name][sev] += 1
        tools_list_for_note = ", ".join(sorted(severity_by_tool.keys())) if severity_by_tool else "N/A"
        severity_combined_note = f"Combined from all tools ({tools_list_for_note})."

        return {
            "type": "executive_summary",
            "title": "Executive Summary",
            "icon": "📋",
            "content": {
                "target": scan.target,
                "status": scan.status.value,
                "total_findings": total,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": severity_counts["low"],
                "info": severity_counts["info"],
                "risk_level": risk_level,
                "risk_score": risk_score,
                "tools_completed": len(completed_tools),
                "tools_failed": len(failed_tools),
                "tools_failed_names": failed_tool_names,
                "tools_total": len(tool_runs),
                "top_findings": top_findings,
                "findings_by_severity": findings_by_severity,
                "clues_summary": clues_summary,
                "severity_combined_note": severity_combined_note,
                "severity_by_tool": severity_by_tool,
            },
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    @staticmethod
    def _dedupe_description(desc: str) -> str:
        """Remove accidental duplication (e.g. 'Open port: 80Open port: 80' -> 'Open port: 80')."""
        if not desc or len(desc) < 4:
            return desc
        # Exact half repetition
        half = len(desc) // 2
        if desc[:half] == desc[half:]:
            return desc[:half]
        # Find smallest repeating unit (handles odd lengths, extra chars)
        for n in range(1, len(desc) // 2 + 1):
            unit = desc[:n]
            reps = len(desc) // n
            if reps >= 2 and unit * reps == desc[:n * reps]:
                return unit
        return desc

    @staticmethod
    def _generate_findings_table_section(findings: List[Finding]) -> Dict[str, Any]:
        """Generate structured findings table - deduplicated by tool+location."""
        from app.utils.finding_filters import is_sublist3r_noise
        seen = set()
        unique = []
        for f in findings:
            # Never show Sublist3r banner/log lines in All Findings (defensive filter)
            if getattr(f, "tool_name", None) == "Sublist3r" and is_sublist3r_noise(
                getattr(f, "location", "") or "", getattr(f, "description", "") or ""
            ):
                continue
            key = (f.tool_name, f.location)
            if key in seen:
                continue
            seen.add(key)
            unique.append(f)
        rows = []
        # Send all findings to frontend (cap at 500 to avoid huge payloads; increase if needed)
        for f in unique[:500]:
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            ftype = f.type.value if hasattr(f.type, 'value') else str(f.type)
            desc = IntelligenceService._dedupe_description(f.description)
            desc = (desc[:150] + "...") if len(desc) > 150 else desc
            rows.append({
                "tool": f.tool_name,
                "type": ftype,
                "severity": sev,
                "location": f.location,
                "description": desc,
            })
        return {
            "type": "findings_table",
            "title": "All Findings",
            "icon": "📊",
            "content": {
                "total": len(unique),
                "displayed": len(rows),
                "rows": rows,
                "severity_info": "Understanding severity: Info = discovery data (open ports, URLs found) that helps map the target, not security flaws. Low = minor issues. Critical/High/Medium = real security problems that need fixing.",
            },
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    @staticmethod
    def _generate_configuration_section(scan: Scan) -> Dict[str, Any]:
        """Generate initial scan configuration section."""
        user_tools = json.loads(scan.user_selected_tools) if scan.user_selected_tools else []
        
        # Get the full OWASP category name from settings
        from app.core.config import settings
        owasp_name = next(
            (
                cat["name"]
                for cat in settings.OWASP_CATEGORIES
                if cat["id"] == scan.owasp_category
            ),
            scan.owasp_category  # fallback to ID if not found
        )
        
        return {
            "type": "configuration",
            "title": "🎯 Scan Configuration",
            "icon": "🎯",
            "content": {
                "target": scan.target,
                "attack_type": f"{owasp_name} ({scan.owasp_category})",
                "user_selected_tools": user_tools,
            },
            "timestamp": scan.created_at.isoformat(),
        }
    
    @staticmethod
    async def _generate_attack_relevance_section_async(
        scan: Scan, findings: List[Finding]
    ) -> Optional[Dict[str, Any]]:
        """Generate attack relevance section using local fallback (no external AI calls)."""
        from app.ai.report_generator import _fallback_attack_relevance

        owasp_name = next(
            (c["name"] for c in settings.OWASP_CATEGORIES if c["id"] == scan.owasp_category),
            scan.owasp_category,
        )
        attack_label = f"{owasp_name} ({scan.owasp_category})"
        tools_with_findings = list(
            {(f.tool_name or "").strip() for f in findings if (f.tool_name or "").strip()}
        )

        findings_summary = [
            {
                "tool": f.tool_name or "",
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "location": (f.location or "")[:120],
                "description": IntelligenceService._dedupe_description(f.description or "")[:200],
            }
            for f in findings
        ]

        try:
            rel = _fallback_attack_relevance(
                scan.target, scan.owasp_category, owasp_name, findings_summary
            )
        except Exception as e:
            logger.warning("Fallback attack relevance failed (skipping section): %s", e)
            return None

        vuln_count = sum(
            1 for f in findings
            for sev in [f.severity.value if hasattr(f.severity, "value") else str(f.severity)]
            if sev in ("critical", "high", "medium")
        )
        return {
            "type": "attack_relevance",
            "title": "⚔️ Relevance to Chosen Attack Type",
            "icon": "⚔️",
            "content": {
                "attack_type": attack_label,
                "relevance_summary": rel.get("relevance_summary", ""),
                "can_support_attack": rel.get("can_support_attack", False),
                "vulnerability_count": vuln_count,
                "tools_with_findings": tools_with_findings,
                "detail_bullets": rel.get("detail_bullets", []),
            },
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    @staticmethod
    def _generate_clues_section(
        scan: Scan, all_tool_runs: List[ToolRun], findings: List[Finding]
    ) -> Dict[str, Any]:
        """Generate detailed clues gathering section with enhanced information."""
        # Group findings by tool and type for better organization
        findings_by_tool = {}
        findings_by_severity = {}
        findings_by_type = {}
        
        for finding in findings:
            # Group by tool
            if finding.tool_name not in findings_by_tool:
                findings_by_tool[finding.tool_name] = []
            findings_by_tool[finding.tool_name].append(finding)
            
            # Group by severity
            sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            if sev not in findings_by_severity:
                findings_by_severity[sev] = []
            findings_by_severity[sev].append(finding)
            
            # Group by type
            ftype = finding.type.value if hasattr(finding.type, 'value') else str(finding.type)
            if ftype not in findings_by_type:
                findings_by_type[ftype] = []
            findings_by_type[ftype].append(finding)
        
        # Get detailed clues data from error_summary
        clues_data = {}
        if scan.error_summary:
            # Extract detailed information from the error summary
            import re
            clues_match = re.search(r'Initial Reconnaissance Clues:(.*?)(?:\n\n[^I]|\n\n$|$)', scan.error_summary, re.DOTALL)
            if clues_match:
                clues_text = clues_match.group(1)
                for line in clues_text.split('\n'):
                    if ':' in line and '- ' in line:
                        key_val = line.split(':', 1)
                        if len(key_val) > 1:
                            key = key_val[0].replace('- ', '').strip()
                            value = key_val[1].strip()
                            # Parse different types of values
                            if value.lower() in ['none detected', 'none', 'null', '[]']:
                                value = []
                            elif value.startswith('[') and value.endswith(']'):
                                try:
                                    cleaned = value[1:-1].strip()
                                    if cleaned:
                                        value = [item.strip().strip("'").strip('"') for item in cleaned.split(',')]
                                    else:
                                        value = []
                                except:
                                    value = []
                            clues_data[key.lower().replace(' ', '_')] = value
        
        # Extract detailed technical information from findings (with deduplication)
        detailed_findings = []
        seen_details = set()
        for finding in findings:
            desc = IntelligenceService._dedupe_description(finding.description)
            key = (
                finding.tool_name,
                finding.type.value if hasattr(finding.type, "value") else str(finding.type),
                finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                finding.location,
                desc,
            )
            if key in seen_details:
                continue
            seen_details.add(key)

            finding_detail = {
                "id": finding.id,
                "tool": finding.tool_name,
                "type": key[1],
                "severity": key[2],
                "location": finding.location,
                "description": desc,
                "owasp_category": finding.owasp_category,
                "evidence": None,
                "timestamp": finding.created_at.isoformat(),
            }

            # Parse evidence JSON if available
            if finding.evidence:
                try:
                    evidence_data = json.loads(finding.evidence)
                    finding_detail["evidence"] = evidence_data
                except:
                    finding_detail["evidence"] = finding.evidence

            detailed_findings.append(finding_detail)
        
        # Calculate statistics
        total_findings = len(findings)
        severity_stats = {sev: len(findings_by_severity.get(sev, [])) for sev in ["critical", "high", "medium", "low", "info"]}
        type_stats = {ftype: len(findings_by_type.get(ftype, [])) for ftype in ["vulnerability", "misconfiguration", "information", "port", "endpoint", "asset"]}
        
        # Generate detailed insights
        insights = []
        
        # Add initial reconnaissance clues
        if clues_data.get('open_ports'):
            port_list = ', '.join(str(p) for p in clues_data['open_ports'][:10])
            insights.append(f"🌐 Initial reconnaissance detected open ports: {port_list}")
        
        if clues_data.get('http_services'):
            service_count = len(clues_data['http_services'])
            insights.append(f"🌐 Initial reconnaissance identified {service_count} HTTP services")
        
        if clues_data.get('technologies'):
            tech_list = ', '.join(list(set(clues_data['technologies']))[:5])
            insights.append(f"🛠️ Initial reconnaissance detected technologies: {tech_list}")
        
        # Add actual security findings
        if total_findings > 0:
            # Severity breakdown
            if severity_stats["critical"] > 0:
                insights.append(f"🚨 {severity_stats['critical']} CRITICAL vulnerabilities requiring immediate attention")
            if severity_stats["high"] > 0:
                insights.append(f"⚠️ {severity_stats['high']} HIGH severity issues needing prompt remediation")
            if severity_stats["medium"] > 0:
                insights.append(f"⚠️ {severity_stats['medium']} MEDIUM severity findings to address")
        else:
            insights.append("🔍 No security vulnerabilities detected in detailed analysis")
        
        # Tool execution summary
        completed_tools = [tr for tr in all_tool_runs if tr.status == ToolRunStatus.COMPLETED]
        failed_tools = [tr for tr in all_tool_runs if tr.status in (ToolRunStatus.FAILED, ToolRunStatus.TIMEOUT)]
        failed_tool_names = [tr.tool_name for tr in failed_tools]
        
        if completed_tools:
            insights.append(f"✅ {len(completed_tools)} tools executed successfully")
        if failed_tools:
            names_str = ", ".join(failed_tool_names)
            insights.append(f"❌ {len(failed_tools)} tool(s) encountered issues: {names_str}")
        
        # Risk assessment - based ONLY on real scan findings
        risk_level = "N/A"
        risk_score = 0
        if severity_stats["critical"] > 0:
            risk_level = "CRITICAL"
            risk_score = min(100, 70 + severity_stats["critical"] * 10)
        elif severity_stats["high"] > 0:
            risk_level = "HIGH"
            risk_score = min(69, 50 + severity_stats["high"] * 5)
        elif severity_stats["medium"] > 0:
            risk_level = "MEDIUM"
            risk_score = min(49, 30 + severity_stats["medium"] * 4)
        elif severity_stats["low"] > 0:
            risk_level = "LOW"
            risk_score = min(29, 10 + (severity_stats["low"] + severity_stats["info"]) * 2)
        elif severity_stats["info"] > 0:
            risk_level = "INFO"
            risk_score = min(29, 10 + severity_stats["info"] * 2)
        
        # Intelligence insight
        intelligence_insight = f"Detailed reconnaissance on {scan.target} completed. "
        if total_findings > 0:
            intelligence_insight += f"Identified {total_findings} security findings across {len(findings_by_tool)} different tools. "
            intelligence_insight += f"Risk assessment: {risk_level} (Score: {risk_score}/100 based on findings). "
        else:
            # Check if we have initial reconnaissance clues
            initial_clues_count = sum(1 for key, value in clues_data.items() if value and key != 'http_services')
            if initial_clues_count > 0:
                intelligence_insight += f"Initial reconnaissance phase completed with {initial_clues_count} indicators. "
                intelligence_insight += "No significant security vulnerabilities detected in detailed analysis. "
                intelligence_insight += "Target appears to have basic infrastructure exposure but no critical issues found."
            else:
                intelligence_insight += "No reconnaissance data or security findings detected. "
                intelligence_insight += "Target may be unreachable or security controls are effective."
        
        # Build findings-by-tool summary for professional display
        findings_by_tool_summary = [
            {"tool": tool, "count": len(items)}
            for tool, items in sorted(findings_by_tool.items(), key=lambda x: -len(x[1]))
        ]

        # Per-tool severity so "Severity distribution" is explicitly combined from all tools
        # Include every tool that has findings (findings_by_tool keys); tools with 0 findings are in executive_summary only
        severity_by_tool = {}
        for tool_name, items in findings_by_tool.items():
            severity_by_tool[tool_name] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for f in items:
                sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                if sev in severity_by_tool[tool_name]:
                    severity_by_tool[tool_name][sev] += 1
        tools_list_str = ", ".join(sorted(findings_by_tool.keys())) if findings_by_tool else "N/A"
        severity_combined_note = f"Combined from all tools ({tools_list_str})."

        return {
            "type": "clues",
            "title": "Detailed Reconnaissance Findings",
            "icon": "🔍",
            "content": {
                "target": scan.target,
                "scan_id": scan.id,
                "description": f"Reconnaissance analysis for {scan.target}",
                "statistics": {
                    "total_findings": total_findings,
                    "severity_breakdown": severity_stats,
                    "severity_combined_note": severity_combined_note,
                    "severity_by_tool": severity_by_tool,
                    "type_breakdown": type_stats,
                    "tools_executed": len(completed_tools),
                    "tools_failed": len(failed_tools),
                    "tools_failed_names": failed_tool_names,
                    "findings_by_tool": findings_by_tool_summary,
                },
                "findings": insights,
                "detailed_findings": detailed_findings[:15],
                "risk_assessment": {
                    "level": risk_level,
                    "score": risk_score,
                    "business_impact": "No findings" if total_findings == 0 else "Review detailed findings for specific impact assessment"
                },
                "intelligence_insight": intelligence_insight,
            },
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    @staticmethod
    def _extract_ai_reasoning(ai_raw_response: Optional[str]) -> Optional[str]:
        """Extract reasoning from AI raw response JSON."""
        if not ai_raw_response:
            return None
        try:
            # Handle markdown-wrapped JSON
            text = ai_raw_response.strip()
            if "```json" in text.lower():
                start = text.lower().index("```json") + 7
                end = text.find("```", start)
                if end > start:
                    text = text[start:end]
            elif "```" in text:
                start = text.index("```") + 3
                end = text.find("```", start)
                if end > start:
                    text = text[start:end]
            start_brace = text.find("{")
            if start_brace >= 0:
                brace_count = 0
                end_pos = start_brace
                for i in range(start_brace, len(text)):
                    if text[i] == "{":
                        brace_count += 1
                    elif text[i] == "}":
                        brace_count -= 1
                        if brace_count == 0:
                            end_pos = i + 1
                            break
                data = json.loads(text[start_brace:end_pos])
                return data.get("reasoning")
        except (json.JSONDecodeError, ValueError):
            pass
        return None
    
    @staticmethod
    def _generate_ai_decision_section(scan: Scan, tool_runs: List[ToolRun]) -> Dict[str, Any]:
        """Generate AI analysis and decision section - all from real scan data."""
        ai_tools_to_run = json.loads(scan.ai_tools_to_run) if scan.ai_tools_to_run else []
        ai_tools_skipped = json.loads(scan.ai_tools_skipped) if scan.ai_tools_skipped else []
        
        # AI analysis - based on actual completed tools
        analysis_points = []
        if any(tr.tool_name in ["Subfinder", "Amass"] for tr in tool_runs if tr.status == ToolRunStatus.COMPLETED):
            analysis_points.append("Potential publicly exposed services")
        if any(tr.tool_name in ["Naabu", "Nmap"] for tr in tool_runs if tr.status == ToolRunStatus.COMPLETED):
            analysis_points.append("High likelihood of open web ports")
        if any(tr.tool_name in ["DNSx", "ShuffleDNS"] for tr in tool_runs if tr.status == ToolRunStatus.COMPLETED):
            analysis_points.append("Possible hidden DNS records")
        
        # Reason - from real AI response when available
        reason = IntelligenceService._extract_ai_reasoning(scan.ai_raw_response)
        if not reason:
            # Fallback only when AI response not parseable - describe actual state
            if ai_tools_skipped:
                skipped_reasons = [s.get("reason", "") for s in ai_tools_skipped if isinstance(s, dict) and s.get("reason")]
                reason = " | ".join(skipped_reasons) if skipped_reasons else "Tool selection optimized based on scan context."
            else:
                reason = f"AI selected {len(ai_tools_to_run)} tools based on target and OWASP focus."
        
        return {
            "type": "ai_decision",
            "title": "🧠 AI Analysis & Strategic Decision",
            "icon": "🧠",
            "content": {
                "analysis": analysis_points,
                "decision": {
                    "tools_to_run": ai_tools_to_run,
                    "tools_skipped": ai_tools_skipped,
                    "reason": reason,
                },
            },
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    @staticmethod
    def _generate_tool_result_section(
        tool_run: ToolRun, findings: List[Finding], scan: Scan
    ) -> Dict[str, Any]:
        """Generate individual tool result section - for completed, failed, or timeout."""
        tool_name = tool_run.tool_name.lower()
        target = scan.target
        
        # For failed/timeout - return a simple status report
        if tool_run.status != ToolRunStatus.COMPLETED:
            status_label = tool_run.status.value.replace("_", " ").title()
            readable_output = [f"Status: {status_label}"]
            if tool_run.error_message:
                readable_output.append(f"Details: {tool_run.error_message[:300]}")
            return {
                "type": "tool_result",
                "title": f"🔧 {tool_run.tool_name} Execution Report",
                "icon": "🔧",
                "content": {
                    "command": IntelligenceService._get_real_command(tool_run.tool_name, target),
                    "result": {
                        "status": tool_run.status.value,
                        "findings_count": 0,
                    },
                    "impact": f"Tool {status_label}: {tool_run.error_message or 'No details'}"[:200],
                    "status": tool_run.status.value,
                    "error_message": tool_run.error_message,
                    "readable_output": readable_output,
                },
                "timestamp": (tool_run.finished_at or tool_run.started_at).isoformat() if (tool_run.finished_at or tool_run.started_at) else datetime.utcnow().isoformat(),
            }
        
        # Tool-specific content generation (completed only)
        if tool_name == "dnsx":
            return IntelligenceService._generate_dns_validation_report(tool_run, findings, target)
        elif tool_name == "naabu":
            return IntelligenceService._generate_port_exposure_report(tool_run, findings, target)
        elif tool_name == "nuclei":
            return IntelligenceService._generate_vulnerability_report(tool_run, findings, target)
        elif tool_name == "httpx":
            return IntelligenceService._generate_http_service_report(tool_run, findings, target)
        elif tool_name == "subfinder":
            return IntelligenceService._generate_subdomain_report(tool_run, findings, target)
        else:
            # Generic tool report - impact and list of findings so frontend can show actual output
            n = len(findings)
            impact = f"Executed {tool_run.tool_name} reconnaissance. Found {n} {'finding' if n == 1 else 'findings'}." if n > 0 else f"Executed {tool_run.tool_name} reconnaissance. No findings."
            detected_issues = []
            readable_output = [f"Findings: {n}"] if n > 0 else ["No findings."]
            for f in findings[:40]:
                loc = (f.location or "").strip()
                if len(loc) > 80:
                    loc = loc[:80] + "..."
                desc = (f.description or "").replace("\n", " ").strip()[:120]
                if len((f.description or "").strip()) > 120:
                    desc = desc + "..."
                line = f"{loc}: {desc}" if desc else (loc or "(no details)")
                if line.strip():
                    detected_issues.append(line)
                    readable_output.append(line)
            return {
                "type": "tool_result",
                "title": f"🔧 {tool_run.tool_name} Execution Report",
                "icon": "🔧",
                "content": {
                    "command": IntelligenceService._get_real_command(tool_run.tool_name, target),
                    "result": {
                        "findings_count": n,
                        "status": "completed",
                    },
                    "impact": impact,
                    "detected_issues": detected_issues,
                    "readable_output": readable_output,
                },
                "timestamp": tool_run.finished_at.isoformat() if tool_run.finished_at else datetime.utcnow().isoformat(),
            }
    
    @staticmethod
    def _generate_dns_validation_report(
        tool_run: ToolRun, findings: List[Finding], target: str
    ) -> Dict[str, Any]:
        """Generate DNS validation report."""
        valid_count = len([f for f in findings if "valid" in f.description.lower()])
        wildcard_count = len([f for f in findings if "wildcard" in f.description.lower()])
        hidden_count = len([f for f in findings if "hidden" in f.description.lower() or "new" in f.description.lower()])
        
        impact = "No valid subdomains found." if valid_count == 0 else f"Confirmed {valid_count} live valid subdomain(s)."
        if wildcard_count > 0:
            impact += f" {wildcard_count} wildcard entry(ies) detected."
        if hidden_count > 0:
            impact += f" {hidden_count} hidden/new subdomain(s) identified."
        readable_output = [
            f"Valid subdomains confirmed: {valid_count}",
            f"Wildcard entries filtered: {wildcard_count}",
            f"Hidden subdomains identified: {hidden_count}",
        ]
        seen = set()
        for f in findings[:30]:
            loc = (f.location or "").strip()
            if loc and loc not in seen:
                seen.add(loc)
                readable_output.append(f"Validated: {loc}")
        return {
            "type": "dns_validation",
            "title": "🔧 DNS Validation Report",
            "icon": "🔧",
            "content": {
                "command": IntelligenceService._get_real_command(tool_run.tool_name, target),
                "result": {
                    "valid_subdomains": valid_count,
                    "wildcard_entries": wildcard_count,
                    "hidden_subdomains": hidden_count,
                },
                "impact": impact.strip(),
                "readable_output": readable_output,
            },
            "timestamp": tool_run.finished_at.isoformat() if tool_run.finished_at else datetime.utcnow().isoformat(),
        }
    
    @staticmethod
    def _generate_port_exposure_report(
        tool_run: ToolRun, findings: List[Finding], target: str
    ) -> Dict[str, Any]:
        """Generate port exposure report."""
        open_ports = []
        for finding in findings:
            if ":" in finding.location:
                port = finding.location.split(":")[-1]
                if port.isdigit():
                    open_ports.append(int(port))
        
        open_ports = sorted(list(set(open_ports)))  # Remove duplicates and sort
        
        port_services = {
            80: "HTTP",
            443: "HTTPS", 
            8080: "Alternate HTTP",
            8443: "Secure Admin Panel",
            22: "SSH",
            21: "FTP",
            25: "SMTP",
            3306: "MySQL",
            5432: "PostgreSQL",
        }
        
        port_descriptions = []
        for port in open_ports[:10]:  # Limit to top 10
            service = port_services.get(port, "Unknown Service")
            port_descriptions.append(f"{port} ({service})")
        
        # Align with overall risk: use severity of this tool's findings (Naabu findings are info)
        risk_level = "INFO"
        for f in findings:
            sev = (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).lower()
            if sev == "critical":
                risk_level = "CRITICAL"
                break
            if sev == "high" and risk_level not in ("CRITICAL",):
                risk_level = "HIGH"
            if sev == "medium" and risk_level not in ("CRITICAL", "HIGH"):
                risk_level = "MEDIUM"
            if sev == "low" and risk_level not in ("CRITICAL", "HIGH", "MEDIUM"):
                risk_level = "LOW"
        if not findings:
            risk_level = "N/A"
        
        impact = "No open ports detected." if len(open_ports) == 0 else f"{len(open_ports)} open port(s) detected: {', '.join(port_descriptions[:5])}{'...' if len(open_ports) > 5 else ''}."
        readable_output = [f"Port {p} ({port_services.get(p, 'Unknown')}) — open" for p in open_ports[:25]] if open_ports else ["No open ports detected."]
        return {
            "type": "port_exposure",
            "title": "🔧 Port Exposure Report",
            "icon": "🔧",
            "content": {
                "command": IntelligenceService._get_real_command(tool_run.tool_name, target),
                "result": {
                    "open_ports": port_descriptions,
                    "total_ports": len(open_ports),
                },
                "risk_indicator": risk_level,
                "impact": impact,
                "readable_output": readable_output,
            },
            "timestamp": tool_run.finished_at.isoformat() if tool_run.finished_at else datetime.utcnow().isoformat(),
        }
    
    @staticmethod
    def _generate_vulnerability_report(
        tool_run: ToolRun, findings: List[Finding], target: str
    ) -> Dict[str, Any]:
        """Generate vulnerability detection summary (includes info/low so Nuclei info findings are shown)."""
        def _sev(f):
            return f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        critical_count = len([f for f in findings if _sev(f) == "critical"])
        high_count = len([f for f in findings if _sev(f) == "high"])
        medium_count = len([f for f in findings if _sev(f) == "medium"])
        low_count = len([f for f in findings if _sev(f) == "low"])
        info_count = len([f for f in findings if _sev(f) == "info"])
        
        issues = []
        readable_output = []
        for finding in findings[:25]:
            raw = (finding.description or "").strip()
            desc = (raw[:150] + "...") if len(raw) > 150 else raw
            if desc:
                issues.append(desc)
            sev = _sev(finding)
            line = f"[{sev.upper()}] {desc}" if desc else f"[{sev.upper()}] {finding.location or 'Finding'}"
            readable_output.append(line)
        if not readable_output:
            readable_output = ["No vulnerabilities or info findings reported."]
        return {
            "type": "vulnerability",
            "title": "🔧 Vulnerability Detection Summary",
            "icon": "🔧",
            "content": {
                "command": IntelligenceService._get_real_command(tool_run.tool_name, target),
                "findings": {
                    "critical": critical_count,
                    "high": high_count,
                    "medium": medium_count,
                    "low": low_count,
                    "info": info_count,
                },
                "detected_issues": issues,
                "readable_output": readable_output,
            },
            "timestamp": tool_run.finished_at.isoformat() if tool_run.finished_at else datetime.utcnow().isoformat(),
        }
    
    @staticmethod
    def _generate_http_service_report(
        tool_run: ToolRun, findings: List[Finding], target: str
    ) -> Dict[str, Any]:
        """Generate HTTP service analysis report with beginner-friendly output lines."""
        http_findings = [f for f in findings if "http" in (f.location or "").lower() or "https" in (f.location or "").lower()]
        titles = []
        techs = []
        readable_output = []
        for finding in http_findings[:30]:
            try:
                evidence = json.loads(finding.evidence) if finding.evidence else {}
                url = finding.location or evidence.get("url", "")
                title = evidence.get("title") or "No title"
                server = evidence.get("webserver") or "Unknown"
                status = evidence.get("status_code") or "—"
                tech_list = evidence.get("technologies") or []
                tech_str = ", ".join(tech_list[:5]) if tech_list else "None detected"
                parts = [f"URL: {url}", f"Title: {title}", f"Server: {server}", f"Status: {status}", f"Technologies: {tech_str}"]
                readable_output.append(" | ".join(parts))
                if evidence.get("title"):
                    titles.append(evidence["title"])
                if evidence.get("technologies"):
                    techs.extend(evidence["technologies"])
            except Exception:
                readable_output.append(f"Service: {finding.location or 'Unknown'} — {finding.description or 'Detected'}")
        unique_techs = list(set(techs))[:5]
        impact = "No HTTP services identified." if len(http_findings) == 0 else f"Identified {len(http_findings)} web service(s)."
        if unique_techs:
            impact += f" Technologies: {', '.join(unique_techs[:3])}{'...' if len(unique_techs) > 3 else ''}."
        if not readable_output:
            readable_output = ["No web services detected."]
        detected_issues = [f.location or "" for f in http_findings[:30]]
        return {
            "type": "http_service",
            "title": "🔧 HTTP Service Analysis",
            "icon": "🔧",
            "content": {
                "command": IntelligenceService._get_real_command(tool_run.tool_name, target),
                "result": {
                    "web_services": len(http_findings),
                    "page_titles": list(set(titles))[:3],
                    "technologies": unique_techs,
                },
                "impact": impact.strip(),
                "detected_issues": detected_issues,
                "readable_output": readable_output,
            },
            "timestamp": tool_run.finished_at.isoformat() if tool_run.finished_at else datetime.utcnow().isoformat(),
        }
    
    @staticmethod
    def _generate_subdomain_report(
        tool_run: ToolRun, findings: List[Finding], target: str
    ) -> Dict[str, Any]:
        """Generate subdomain enumeration report with beginner-friendly output lines."""
        subdomain_count = len(findings)
        dev_subdomains = len([f for f in findings if any(keyword in (f.location or "").lower() for keyword in ["dev", "staging", "test", "admin"])])
        mail_subdomains = len([f for f in findings if "mail" in (f.location or "").lower() or "smtp" in (f.location or "").lower()])
        impact = "No subdomains discovered." if subdomain_count == 0 else f"Discovered {subdomain_count} subdomain(s)."
        if dev_subdomains > 0:
            impact += f" {dev_subdomains} development/staging subdomain(s)."
        if mail_subdomains > 0:
            impact += f" {mail_subdomains} mail-related subdomain(s)."
        readable_output = [f"Total subdomains: {subdomain_count}", f"Development/staging: {dev_subdomains}", f"Mail-related: {mail_subdomains}"]
        for f in findings[:50]:
            loc = (f.location or "").strip()
            if loc:
                readable_output.append(f"Discovered: {loc}")
        if subdomain_count == 0:
            readable_output = ["No subdomains discovered."]
        detected_issues = [f.location or "" for f in findings[:50]]
        return {
            "type": "subdomain",
            "title": "🔧 Subdomain Enumeration Report",
            "icon": "🔧",
            "content": {
                "command": IntelligenceService._get_real_command(tool_run.tool_name, target),
                "result": {
                    "total_subdomains": subdomain_count,
                    "development_subdomains": dev_subdomains,
                    "mail_subdomains": mail_subdomains,
                },
                "impact": impact.strip(),
                "detected_issues": detected_issues,
                "readable_output": readable_output,
            },
            "timestamp": tool_run.finished_at.isoformat() if tool_run.finished_at else datetime.utcnow().isoformat(),
        }
    
    @staticmethod
    async def _generate_combined_summary(
        scan: Scan, tool_runs: List[ToolRun], findings: List[Finding]
    ) -> Dict[str, Any]:
        """Generate combined summary with analysis and actionable intelligence.

        When settings.INTELLIGENCE_AI_ENABLED is true, this will try to use Gemini-backed
        helpers from app.ai.report_generator. When false, or on failure, it falls back
        to local analysis that does NOT call external AI.
        """
        from app.ai.report_generator import (
            generate_actionable_intelligence_content,
            _fallback_actionable_intelligence,
        )

        findings_by_severity = {}
        findings_by_type = {}
        findings_by_tool = {}

        for finding in findings:
            sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            if sev not in findings_by_severity:
                findings_by_severity[sev] = []
            findings_by_severity[sev].append(finding)

            ftype = finding.type.value if hasattr(finding.type, 'value') else str(finding.type)
            if ftype not in findings_by_type:
                findings_by_type[ftype] = []
            findings_by_type[ftype].append(finding)

            if finding.tool_name not in findings_by_tool:
                findings_by_tool[finding.tool_name] = []
            findings_by_tool[finding.tool_name].append(finding)

        total_findings = len(findings)
        severity_counts = {sev: len(findings_by_severity.get(sev, [])) for sev in ["critical", "high", "medium", "low", "info"]}
        type_counts = {ftype: len(findings_by_type.get(ftype, [])) for ftype in ["vulnerability", "misconfiguration", "information", "port", "endpoint", "asset"]}

        completed_tools = [tr for tr in tool_runs if tr.status == ToolRunStatus.COMPLETED]
        tool_coverage = len(completed_tools) / max(len(tool_runs), 1)

        # Risk assessment - align with reconnaissance section so score is consistent
        risk_level = "N/A"
        risk_score = 0
        if severity_counts["critical"] > 0:
            risk_level = "CRITICAL"
            risk_score = min(100, 70 + severity_counts["critical"] * 10)
        elif severity_counts["high"] > 0:
            risk_level = "HIGH"
            risk_score = min(69, 50 + severity_counts["high"] * 5)
        elif severity_counts["medium"] > 0:
            risk_level = "MEDIUM"
            risk_score = min(49, 30 + severity_counts["medium"] * 4)
        elif severity_counts["low"] > 0:
            risk_level = "LOW"
            risk_score = min(29, 10 + (severity_counts["low"] + severity_counts["info"]) * 2)
        elif severity_counts["info"] > 0:
            risk_level = "INFO"
            risk_score = min(29, 10 + severity_counts["info"] * 2)

        if total_findings == 0 and risk_score == 0:
            risk_level = "N/A"
            risk_color = "#6b7280"
        elif risk_score >= 80:
            risk_level = "CRITICAL"
            risk_color = "#dc2626"
        elif risk_score >= 60:
            risk_level = "HIGH"
            risk_color = "#ea580c"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
            risk_color = "#ca8a04"
        elif risk_score >= 10:
            # Only LOW when there are low-severity findings; otherwise INFO (e.g. all findings are info)
            if severity_counts["low"] > 0:
                risk_level = "LOW"
                risk_color = "#22c55e"
            else:
                risk_level = "INFO"
                risk_color = "#3b82f6"
        else:
            risk_level = "INFO"
            risk_color = "#3b82f6"

        business_impact = "MINIMAL"
        if risk_score >= 80:
            business_impact = "SEVERE - Data could be stolen or services disrupted. Act now."
        elif risk_score >= 60:
            business_impact = "HIGH - Business could be affected. Fix soon."
        elif risk_score >= 40:
            business_impact = "MODERATE - Some risk. Plan fixes."
        elif risk_score >= 20:
            business_impact = "LOW - Small impact. Fix when you can."

        tools_with_findings = list(findings_by_tool.keys())
        findings_summary = [
            {
                "tool": f.tool_name or "",
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "location": (f.location or "")[:120],
                "description": IntelligenceService._dedupe_description(f.description or "")[:200],
            }
            for f in findings
        ]

        # Recommendations: respect INTELLIGENCE_AI_ENABLED and avoid extra Gemini calls
        if not settings.INTELLIGENCE_AI_ENABLED:
            actionable_result = _fallback_actionable_intelligence(
                severity_counts, findings_summary, tools_with_findings
            )
        else:
            try:
                actionable_result = await generate_actionable_intelligence_content(
                    scan.target, severity_counts, findings_summary, tools_with_findings
                )
            except Exception as e:
                logger.warning(
                    "Actionable intelligence content failed (using fallback): %s", e
                )
                actionable_result = _fallback_actionable_intelligence(
                    severity_counts, findings_summary, tools_with_findings
                )

        return {
            "type": "combined_summary",
            "title": "📊 Full Scan Summary",
            "icon": "📊",
            "content": {
                "status": f"Scan of {scan.target} is complete. See the analysis below.",
                "executive_summary": {
                    "target": scan.target,
                    "scan_id": scan.id,
                    "total_findings": total_findings,
                    "tools_executed": len(completed_tools),
                    "scan_duration": str(scan.completed_at - scan.created_at) if scan.completed_at else "N/A"
                },
                "risk_assessment": {
                    "overall_risk_level": risk_level,
                    "risk_score": risk_score,
                    "risk_color": risk_color,
                    "business_impact": business_impact,
                    "severity_breakdown": severity_counts,
                    "type_breakdown": type_counts
                },
                "technical_findings": {
                    "infrastructure_exposure": {
                        "total_subdomains": len([f for f in findings if "subdomain" in (f.description or "").lower() or "domain" in (f.location or "").lower()]),
                        "valid_endpoints": len([f for f in findings if getattr(f.type, "value", str(f.type)) == "endpoint"]),
                        "open_ports": len([f for f in findings if getattr(f.type, "value", str(f.type)) == "port"]),
                        "public_web_services": len([f for f in findings if (f.location or "").startswith("http")])
                    },
                    "security_posture": {
                        "vulnerabilities": severity_counts["critical"] + severity_counts["high"] + severity_counts["medium"] + severity_counts["low"],
                        "misconfigurations": len(findings_by_type.get("misconfiguration", [])),
                        "informational_findings": severity_counts["info"]
                    }
                },
                "actionable_intelligence": {
                    "priority_recommendations": actionable_result.get("priority_recommendations", []),
                    "compliance_considerations": [f"OWASP Category: {scan.owasp_category}"] if scan.owasp_category else [],
                    "next_steps": actionable_result.get("next_steps", []),
                    "remediation_timeline": actionable_result.get("remediation_timeline", {}),
                }
            },
            "timestamp": datetime.utcnow().isoformat(),
        }