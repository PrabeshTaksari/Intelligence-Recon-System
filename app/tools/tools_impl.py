import asyncio
import os
import re
import json
import shutil
import socket
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from datetime import datetime

from app.core.config import settings
from app.core.logging import get_logger
from app.tools.base import BaseTool, ToolResult
from app.core.ws_updates import (
    send_tool_start_update,
    send_tool_status_update,
    send_tool_output_update,
    send_tool_complete_update,
    send_log_message,
)

logger = get_logger(__name__)

# Nuclei configuration (only set if not already defined)
os.environ.setdefault('NUCLEI_REQUEST_TIMEOUT', str(settings.NUCLEI_REQUEST_TIMEOUT))
os.environ.setdefault('NUCLEI_DISABLE_MHE', '1')
os.environ.setdefault('NUCLEI_RETRIES', str(settings.NUCLEI_RETRIES))
os.environ.setdefault('NUCLEI_SEVERITIES', 'critical,high,medium,low,info')
os.environ.setdefault('NUCLEI_STOP_ON_FINDINGS', str(settings.NUCLEI_STOP_ON_FINDINGS))

# Strip ANSI escape sequences (e.g. [91m, [0m) so tool output is readable in UI
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]?")
def _strip_ansi(text: str) -> str:
    if not text:
        return text
    return _ANSI_ESCAPE.sub("", text)


def _get_httpx_path() -> str:
    go_bin = os.path.expanduser("/home/prabesh/go/bin/httpx")
    if os.path.isfile(go_bin):
        return go_bin
    path = shutil.which("httpx")
    return path or "httpx"

class NucleiTool(BaseTool):
    def __init__(self):
        super().__init__("Nuclei")

    _INFO_URL_HINTS = (
        "/robots.txt",
        "/sitemap.xml",
        "/security.txt",
        "/.well-known/security.txt",
    )

    def format_live_output(self, line: str) -> str:
        """Convert Nuclei JSONL into a concise human-readable line for the UI."""
        try:
            data = json.loads(line)
        except Exception:
            return line

        info = data.get("info") or {}
        severity = str(info.get("severity") or "info").strip().lower()
        title = str(info.get("name") or data.get("template-id") or "Nuclei finding").strip()
        matcher_name = str(data.get("matcher-name") or "").strip()
        location = str(
            data.get("matched-at")
            or data.get("url")
            or data.get("host")
            or data.get("target")
            or ""
        ).strip()

        parts = [f"[{severity.upper()}]", title]
        if matcher_name:
            parts.append(f"matcher: {matcher_name}")
        if location:
            parts.append(location)
        return " | ".join(parts)

    @classmethod
    def _is_info_url(cls, url: str) -> bool:
        """Return True for URLs that are typically informational/discovery-only pages."""
        candidate = (url or "").strip().lower()
        if not candidate:
            return False

        try:
            parsed = urlparse(candidate)
            path = (parsed.path or "").lower()
        except Exception:
            path = candidate

        return any(hint in path for hint in cls._INFO_URL_HINTS)

    @classmethod
    def _filter_info_urls(cls, urls: List[str]) -> List[str]:
        """Drop informational URLs while keeping real application endpoints."""
        if not urls:
            return []

        filtered = []
        for url in urls:
            if cls._is_info_url(url):
                continue
            filtered.append(url)
        return filtered

    @staticmethod
    def _phase_specs() -> List[Dict[str, Any]]:
        """Return the fixed three-phase severity plan for Nuclei (optimized for fast execution on prioritized OWASP-relevant URLs)."""
        return [
            {
                "label": "Critical/High",
                "suffix": "critical_high",
                "severities": "critical,high",
                "concurrency": 15,
                "bulk_size": 15,
                "rate_limit": 75,
                "timeout_multiplier": 1.2,
            },
            {
                "label": "Medium/Low",
                "suffix": "medium_low",
                "severities": "medium,low",
                "concurrency": 15,
                "bulk_size": 15,
                "rate_limit": 75,
                "timeout_multiplier": 1.1,
            },
            {
                "label": "Info",
                "suffix": "info",
                "severities": "info",
                "concurrency": 20,
                "bulk_size": 20,
                "rate_limit": 100,
                "timeout_multiplier": 1.0,
            },
        ]

    @staticmethod
    def _phase_output_path(base_output: Path, suffix: str) -> Path:
        """Create the per-phase output path next to the combined output file."""
        return base_output.with_name(f"{base_output.stem}_{suffix}.out")

    async def _run_single_phase(
        self,
        target: str,
        output_file: Path,
        timeout: int,
        scan_id: Optional[int],
        command: List[str],
    ) -> ToolResult:
        """Run one Nuclei phase and return its parsed result."""
        started_at = datetime.utcnow()

        if scan_id:
            await send_tool_status_update(
                scan_id,
                self.tool_name,
                "running",
                {"command": " ".join(command)},
            )

        self.logger.info(f"Executing command: {' '.join(command)}")
        if scan_id:
            await send_log_message(scan_id, self.tool_name, f"Running command: {' '.join(command)}")

        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=1024 * 1024,
        )

        raw_output_lines: List[str] = []
        stderr_lines: List[str] = []

        nuclei_stop_threshold = 1
        nuclei_stop_enabled = False
        try:
            nuclei_stop_threshold = int(os.getenv("NUCLEI_STOP_ON_FINDINGS", "1") or "1")
            nuclei_stop_enabled = nuclei_stop_threshold > 0
        except ValueError:
            nuclei_stop_threshold = 1
            nuclei_stop_enabled = True

        def _parse_nuclei_severity(line: str) -> Optional[str]:
            try:
                data = json.loads(line)
                return (data.get("info") or {}).get("severity")
            except Exception:
                return None

        finding_count = 0

        async def read_stdout_live():
            nonlocal finding_count
            while process.stdout:
                try:
                    line = await process.stdout.readline()
                except (ValueError, asyncio.LimitOverrunError) as e:
                    if getattr(e, "consumed", None) and process.stdout:
                        try:
                            await process.stdout.readexactly(e.consumed)
                        except (asyncio.IncompleteReadError, Exception):
                            pass
                    self.logger.warning(f"[{self.tool_name}] Skipped oversize stdout line")
                    continue
                if not line:
                    break
                decoded = line.decode(errors="replace").rstrip()
                if decoded:
                    clean = _strip_ansi(decoded)
                    raw_output_lines.append(clean)
                    display_line = self.format_live_output(clean)
                    if display_line:
                        if scan_id:
                            await send_tool_output_update(scan_id, self.tool_name, display_line)
                        self.logger.info(f"[{self.tool_name}] {display_line}")

                    if nuclei_stop_enabled:
                        severity = _parse_nuclei_severity(clean)
                        if severity:
                            severity_lower = str(severity).strip().lower()
                            if severity_lower in {"critical", "high", "medium", "low", "info"}:
                                if severity_lower != "info":
                                    finding_count += 1
                                    if finding_count >= nuclei_stop_threshold:
                                        self.logger.info(
                                            f"[{self.tool_name}] stop-on-findings threshold reached ({finding_count}); terminating process"
                                        )
                                        process.kill()
                                        break
            if process.stdout:
                try:
                    rest = await process.stdout.read()
                except (ValueError, asyncio.LimitOverrunError):
                    rest = b""
                if rest:
                    decoded = rest.decode(errors="replace").rstrip()
                    if decoded:
                        for ln in decoded.split("\n"):
                            ln = _strip_ansi(ln.strip())
                            if ln:
                                raw_output_lines.append(ln)
                                display_line = self.format_live_output(ln)
                                if display_line:
                                    if scan_id:
                                        await send_tool_output_update(scan_id, self.tool_name, display_line)
                                    self.logger.info(f"[{self.tool_name}] {display_line}")

        async def read_stderr_live():
            while process.stderr:
                try:
                    line = await process.stderr.readline()
                except (ValueError, asyncio.LimitOverrunError) as e:
                    if getattr(e, "consumed", None) and process.stderr:
                        try:
                            await process.stderr.readexactly(e.consumed)
                        except (asyncio.IncompleteReadError, Exception):
                            pass
                    self.logger.warning(f"[{self.tool_name}] Skipped oversize stderr line")
                    continue
                if not line:
                    break
                decoded = line.decode(errors="replace").rstrip()
                if decoded:
                    clean = _strip_ansi(decoded)
                    stderr_lines.append(clean)
                    display_line = self.format_live_output(clean)
                    if display_line:
                        if scan_id:
                            await send_tool_output_update(scan_id, self.tool_name, display_line)
                        self.logger.info(f"[{self.tool_name}] [stderr] {display_line}")
            if process.stderr:
                try:
                    rest = await process.stderr.read()
                except (ValueError, asyncio.LimitOverrunError):
                    rest = b""
                if rest:
                    decoded = rest.decode(errors="replace").rstrip()
                    if decoded:
                        for ln in decoded.split("\n"):
                            ln = _strip_ansi(ln.strip())
                            if ln:
                                stderr_lines.append(ln)
                                display_line = self.format_live_output(ln)
                                if display_line:
                                    if scan_id:
                                        await send_tool_output_update(scan_id, self.tool_name, display_line)
                                    self.logger.info(f"[{self.tool_name}] [stderr] {display_line}")

        async def run_with_timeout():
            stdout_task = asyncio.create_task(read_stdout_live())
            stderr_task = asyncio.create_task(read_stderr_live())
            await asyncio.gather(stdout_task, stderr_task)
            await process.wait()

        try:
            await asyncio.wait_for(run_with_timeout(), timeout=timeout)
            raw_output = "\n".join(raw_output_lines)
            stderr_output = "\n".join(stderr_lines)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            stderr_output = "\n".join(stderr_lines)
            try:
                file_content = output_file.read_text(encoding="utf-8", errors="replace") if output_file.exists() else ""
            except Exception:
                file_content = ""
            _file = (file_content or "").strip()
            if "=== STDOUT ===" in _file:
                _file = _file.split("=== STDOUT ===")[0].strip()
            content_for_parsing = (_file or "\n".join(raw_output_lines)) or ""
            findings = self.parse_output(content_for_parsing, target)
            summary = self.generate_summary(findings, content_for_parsing)
            error_msg = f"Execution timed out after {timeout} seconds"
            self.logger.error(error_msg)
            if scan_id:
                await send_tool_complete_update(scan_id, self.tool_name, False)
            return ToolResult(
                tool_name=self.tool_name,
                success=False,
                summary=f"Execution timeout: {summary}" if findings else "Execution timeout",
                error_message=error_msg,
                findings=findings,
                raw_output=raw_output if 'raw_output' in locals() else "\n".join(raw_output_lines),
                started_at=started_at,
                finished_at=datetime.utcnow(),
            )

        if process.returncode is None:
            await process.wait()

        tool_return_code = process.returncode
        self.logger.info(f"{self.tool_name} completed with return code: {tool_return_code}")

        has_execution_error = tool_return_code > 1

        output_file.parent.mkdir(parents=True, exist_ok=True)
        file_content = ""
        if output_file.exists():
            try:
                file_content = output_file.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                self.logger.warning(f"Could not read tool output file: {e}")

        _file = file_content.strip()
        if "=== STDOUT ===" in _file:
            _file = _file.split("=== STDOUT ===")[0].strip()
        content_for_parsing = (_file or raw_output) or ""
        combined = "\n\n=== STDOUT ===\n" + raw_output + "\n\n=== STDERR ===\n" + stderr_output
        output_file.write_text(combined)

        findings = self.parse_output(content_for_parsing, target)
        summary = self.generate_summary(findings, content_for_parsing)
        finished_at = datetime.utcnow()

        if has_execution_error:
            error_msg = f"{self.tool_name} exited with error code {tool_return_code}"
            self.logger.error(error_msg)
            if scan_id:
                await send_tool_complete_update(scan_id, self.tool_name, False)
            return ToolResult(
                tool_name=self.tool_name,
                success=False,
                summary=f"Execution error: {summary}",
                error_message=error_msg,
                findings=findings,
                raw_output=raw_output,
                started_at=started_at,
                finished_at=finished_at,
            )

        return ToolResult(
            tool_name=self.tool_name,
            success=True,
            summary=summary,
            findings=findings,
            raw_output=raw_output,
            started_at=started_at,
            finished_at=finished_at,
        )

    async def execute(
        self,
        target: str,
        output_file: Path,
        timeout: int = 300,
        scan_id: Optional[int] = None,
        **kwargs,
    ) -> ToolResult:
        """Execute Nuclei in three severity phases and merge the results."""
        started_at = datetime.utcnow()
        self.owasp_category = kwargs.get("owasp_category")

        if scan_id:
            await send_tool_start_update(scan_id, self.tool_name)
            await send_tool_status_update(
                scan_id,
                self.tool_name,
                "running",
                {"command": "three-phase nuclei execution"},
            )

        if not self.check_installed():
            error_msg = f"{self.tool_name} is not installed or not in PATH"
            self.logger.error(error_msg)
            if scan_id:
                await send_tool_complete_update(scan_id, self.tool_name, False)
            return ToolResult(
                tool_name=self.tool_name,
                success=False,
                summary="Tool not installed",
                error_message=error_msg,
                started_at=started_at,
                finished_at=datetime.utcnow(),
            )

        phase_findings: List[Dict[str, Any]] = []
        phase_summaries: List[str] = []
        phase_outputs: List[str] = []
        had_timeout = False
        had_error = False

        phase_specs = self._phase_specs()

        for index, phase in enumerate(phase_specs, start=1):
            phase_output_file = self._phase_output_path(output_file, phase["suffix"])
            phase_timeout = max(1, int(timeout * float(phase.get("timeout_multiplier", 1.0))))
            phase_kwargs = dict(kwargs)
            phase_kwargs.update(
                {
                    "nuclei_severities": phase["severities"],
                    "nuclei_concurrency": phase["concurrency"],
                    "nuclei_bulk_size": phase["bulk_size"],
                    "nuclei_rate_limit": phase["rate_limit"],
                }
            )
            command = self.build_command(target, phase_output_file, **phase_kwargs)

            if scan_id:
                await send_log_message(
                    scan_id,
                    self.tool_name,
                    f"Starting phase {index}/3 ({phase['label']}) with {phase['severities']} severity templates.",
                )

            phase_result = await self._run_single_phase(
                target=target,
                output_file=phase_output_file,
                timeout=phase_timeout,
                scan_id=scan_id,
                command=command,
            )

            phase_findings.extend(phase_result.findings)
            phase_summaries.append(f"{phase['label']}: {phase_result.summary}")

            if phase_output_file.exists():
                try:
                    phase_outputs.append(
                        f"=== PHASE {index}/3: {phase['label']} ===\n"
                        + phase_output_file.read_text(encoding="utf-8", errors="replace")
                    )
                except Exception:
                    phase_outputs.append(f"=== PHASE {index}/3: {phase['label']} ===\n")

            if not phase_result.success:
                message = (phase_result.error_message or "").lower()
                if "timeout" in message or "timed out" in message:
                    had_timeout = True
                else:
                    had_error = True

            if scan_id:
                await send_log_message(
                    scan_id,
                    self.tool_name,
                    f"Completed phase {index}/3 ({phase['label']}): {phase_result.summary}",
                )
                await send_tool_output_update(
                    scan_id,
                    self.tool_name,
                    f"[PHASE {index}/3 {phase['label']}] {phase_result.summary}",
                )

        combined_output = "\n\n".join(phase_outputs).strip()
        if combined_output:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(combined_output)

        summary = self.generate_summary(phase_findings, combined_output)
        if had_timeout and not had_error:
            summary = f"Three-phase Nuclei scan completed with partial results due to time limits. {summary}"
        elif had_timeout and had_error:
            summary = f"Three-phase Nuclei scan completed with partial results and some phase errors. {summary}"

        success = not had_error
        if had_timeout and phase_findings:
            success = True

        if scan_id:
            await send_tool_complete_update(scan_id, self.tool_name, success)

        finished_at = datetime.utcnow()
        return ToolResult(
            tool_name=self.tool_name,
            success=success,
            summary=summary if phase_summaries else "Nuclei did not identify any findings.",
            findings=phase_findings,
            raw_output=combined_output,
            error_message=("One or more Nuclei phases timed out" if had_timeout and not had_error else ("One or more Nuclei phases failed" if had_error else None)),
            started_at=started_at,
            finished_at=finished_at,
        )

    @staticmethod
    def _adjust_severity_by_context(severity: str, description: str, template_id: str = None) -> str:
        """
        Adjust Nuclei severity based on context and potential impact.
        
        Rules for severity escalation:
        - Sensitive data exposure → escalate by 1 level
        - Authentication bypass indicators → escalate to HIGH
        - Information disclosure with PII/credentials → escalate to MEDIUM/HIGH
        """
        desc_lower = (description or "").lower()
        template_lower = (template_id or "").lower()
        
        # Keywords indicating sensitive data exposure
        sensitive_keywords = [
            "exposure", "disclosure", "sensitive", "credential", "password",
            "api key", "secret", "token", "pii", "personal information",
            "email", "phone", "ssn", "credit card", "database", "backup",
            "configuration", "env", "private", "leak", "dump"
        ]
        
        # Check if this involves sensitive data
        has_sensitive_data = any(kw in desc_lower or kw in template_lower for kw in sensitive_keywords)
        
        # Severity escalation logic
        if has_sensitive_data:
            if severity == "info":
                return "medium"  # Info + sensitive data = medium
            elif severity == "low":
                return "medium"  # Low + sensitive data = medium
            elif severity == "medium":
                return "high"  # Medium + sensitive data = high
            # high/critical stay as-is
        
        # Specific patterns that need escalation
        if any(pattern in desc_lower for pattern in [
            "apache server status",  # Can reveal sensitive app info
            "directory listing",  # Information disclosure
            "git repository",  # Source code exposure
            "svn repository",  # Source code exposure
            ".env file",  # Environment variables exposure
            "phpinfo",  # Full server information disclosure
        ]):
            if severity in ["info", "low"]:
                return "medium"
        
        return severity  # No adjustment needed

    @staticmethod
    def _nuclei_tags_for_owasp(owasp_category: Optional[str]) -> Optional[str]:
        """Map OWASP Top 10 selection to Nuclei template tags.

        Note: Nuclei tag names must match template tags. If a mapping is unknown,
        we return None to keep Nuclei behavior unchanged.
        
        OPTIMIZED FOR: Maximum vulnerability detection with minimal scan time
        Strategy: Focus on high-impact, fast-executing templates only
        """
        if not owasp_category:
            return None

        ow = str(owasp_category).strip().upper()
        # Broader, category-specific template sets. Each can be overridden via env vars
        # so advanced users can tune coverage without affecting other tools.
        category_tags = {
            "A01:2021": os.getenv(
                "NUCLEI_A01_TAGS",
                "unauth,traversal,lfi,idor,redirect",
            ),
            "A02:2021": os.getenv(
                "NUCLEI_A02_TAGS",
                "ssl,tls,expired-ssl,certificate",
            ),
            "A03:2021": os.getenv(
                "NUCLEI_A03_TAGS",
                "sqli,xss,command-injection,ssti,xxe",
            ),
            "A04:2021": os.getenv(
                "NUCLEI_A04_TAGS",
                "logic-bypass,auth-bypass,access-control,misconfig",
            ),
            "A05:2021": os.getenv(
                "NUCLEI_A05_TAGS",
                "misconfig,cors,headers,exposure",
            ),
            "A06:2021": os.getenv(
                "NUCLEI_A06_TAGS",
                "cve,known-vuln,version-detect,outdated",
            ),
            "A07:2021": os.getenv(
                "NUCLEI_A07_TAGS",
                "default-login,auth-bypass,jwt,login",
            ),
            "A08:2021": os.getenv(
                "NUCLEI_A08_TAGS",
                "deserialization,file-upload,xxe,path-traversal",
            ),
            "A09:2021": os.getenv(
                "NUCLEI_A09_TAGS",
                "log4j,logging,exposure,debug-page",
            ),
            "A10:2021": os.getenv(
                "NUCLEI_A10_TAGS",
                "ssrf,graphql",
            ),
        }

        tags = str(category_tags.get(ow, "")).strip()
        if tags:
            return tags

        # For remaining OWASP categories, keep behavior unchanged (no -tags filter).
        return None

    @staticmethod
    def _owasp_url_keywords(owasp_category: Optional[str]) -> List[str]:
        """Path keywords to prioritize URLs likely relevant to the selected OWASP category."""
        ow = str(owasp_category or "").strip().upper()
        mapping = {
            "A01:2021": ["admin", "account", "role", "permission", "user", "profile", "api"],
            "A02:2021": ["login", "auth", "token", "oauth", "jwt", "crypto", "cert", "key"],
            "A03:2021": ["search", "query", "filter", "api", "sql", "id", "q", "cmd", "exec", "template"],
            "A04:2021": ["workflow", "checkout", "payment", "order", "state", "business", "logic"],
            "A05:2021": ["admin", "debug", "config", "swagger", "actuator", "health", ".git", "backup"],
            "A06:2021": ["version", "about", "changelog", "plugin", "component", "release", "status"],
            "A07:2021": ["login", "signin", "auth", "session", "reset", "password", "mfa", "otp"],
            "A08:2021": ["upload", "import", "package", "artifact", "update", "install", "plugin"],
            "A09:2021": ["logs", "audit", "admin", "events", "monitor", "report", "security"],
            "A10:2021": ["proxy", "fetch", "url", "redirect", "callback", "webhook", "ssrf"],
        }
        return mapping.get(ow, [])

    @staticmethod
    def _owasp_fuzz_keywords(owasp_category: Optional[str]) -> List[str]:
        """Return extra wordlist keywords for FFuf/Wfuzz based on OWASP category."""
        ow = str(owasp_category or "").strip().upper()
        mapping = {
            "A01:2021": ["admin", "console", "dashboard", "user", "role", "permission", "account", "profile"],
            "A02:2021": ["login", "auth", "token", "password", "ssl", "tls", "crypto", "cert", "certificate"],
            "A03:2021": ["sql", "id", "query", "filter", "search", "cmd", "exec", "payload", "eval", "template"],
            "A04:2021": ["workflow", "checkout", "payment", "order", "state", "business", "logic", "process"],
            "A05:2021": ["phpinfo.php", "openapi.yaml", "compose.yml", "swagger", "debug", "config", "backup", "admin", "health", "actuator"],
            "A06:2021": ["version", "about", "changelog", "component", "dependency", "cve", "vulnerable", "outdated"],
            "A07:2021": ["login", "signin", "auth", "oauth", "session", "reset", "password", "2fa", "mfa", "otp"],
            "A08:2021": ["upload", "import", "package", "artifact", "update", "install", "plugin", "dependency"],
            "A09:2021": ["logs", "audit", "report", "monitor", "admin", "events", "alert", "trace"],
            "A10:2021": ["proxy", "fetch", "url", "callback", "redirect", "webhook", "ssrf"],
        }
        return mapping.get(ow, [])

    @staticmethod
    def _owasp_allowed_paths(owasp_category: Optional[str]) -> List[str]:
        """Return canonical path fragments to restrict scanning for a given OWASP category.

        These are conservative high-value paths (from policy) used when strict filtering
        is enabled so Nuclei only targets endpoints likely relevant to the selected category.
        """
        ow = str(owasp_category or "").strip().upper()
        mapping = {
            "A01:2021": ["/admin", "/dashboard", "/roles", "/permissions", "/account", "/api/roles", "/api/user", "/api/admin", "/profile", "/user/"],
            "A02:2021": ["/login", "/auth", "/oauth", "/token", "/jwt", "/session", "/password", "/reset", "/api/login", "/crypto", "/cert"],
            "A03:2021": ["/search", "/query", "/filter", "/api/", "/exec", "/cmd", "/vulnerabilities/sqli", "/vulnerabilities/xss", "/comment", "/post"],
            "A04:2021": ["/checkout", "/payment", "/order", "/workflow", "/process", "/transfer", "/account", "/balance", "/settings", "/profile"],
            "A05:2021": ["/admin", "/debug", "/swagger", "/swagger-ui", "/actuator/health", "/robots.txt", "/sitemap.xml", "/.env", "/.git", "/config", "/backup", "/phpmyadmin"],
            "A06:2021": ["/version", "/about", "/changelog", "/plugin", "/component", "/status", "/vendor", "/wp-content", "/wp-includes", "/joomla", "/drupal", "/magento"],
            "A07:2021": ["/login", "/signin", "/auth", "/session", "/register", "/logout", "/password", "/reset", "/oauth", "/token", "/mfa", "/otp"],
            "A08:2021": ["/upload", "/uploads", "/download", "/import", "/package", "/install", "/plugin", "/api/upload", ".zip", ".tar", ".jar"],
            "A09:2021": ["/logs", "/audit", "/monitor", "/events", "/admin", "/debug", "/trace", "/error", "/actuator", "/health", "/metrics"],
            "A10:2021": ["/proxy", "/fetch", "/url", "/redirect", "/callback", "/webhook", "/download", "?url=", "?path=", "?redirect="],
        }
        return mapping.get(ow, [])

    @staticmethod
    def _prioritize_urls_for_owasp(urls: List[str], owasp_category: Optional[str]) -> List[str]:
        """Prioritize likely-relevant URLs for selected OWASP category; keep stable deterministic order."""
        if not urls:
            return []
        keywords = NucleiTool._owasp_url_keywords(owasp_category)
        if not keywords:
            return list(dict.fromkeys(urls))

        def score_url(u: str) -> int:
            s = (u or "").strip().lower()
            if not s:
                return -1
            try:
                p = urlparse(s)
                path = (p.path or "").lower()
                query = (p.query or "").lower()
                hay = f"{path}?{query}"
            except Exception:
                hay = s
            score = 0
            for kw in keywords:
                if kw in hay:
                    score += 3
            # Injection often benefits from paramized endpoints.
            if str(owasp_category or "").upper() == "A03:2021":
                if "?" in s or "=" in s:
                    score += 4
                if any(tok in hay for tok in ["/api/", "search", "query", "filter"]):
                    score += 2
            # Prefer non-root deeper paths over base homepage.
            if hay.count("/") >= 2:
                score += 1
            return score

        unique = list(dict.fromkeys(urls))
        ranked = sorted(unique, key=lambda u: (-score_url(u), unique.index(u)))
        # Cap URL list for speed; configurable to avoid hampering other flows.
        limit = int(os.getenv("NUCLEI_URL_LIMIT", "120"))

        # Optionally enforce strict OWASP path filtering: only keep URLs whose path
        # contains one of the canonical fragments for the chosen category. When
        # filtering yields no results we gracefully fall back to the ranked list.
        strict = str(os.getenv("NUCLEI_STRICT_OWASP_PATHS", "1")).strip().lower() in (
            "1",
            "true",
            "yes",
            "y",
        )
        if strict:
            allowed = NucleiTool._owasp_allowed_paths(owasp_category)
            if allowed:
                def matches_allowed(u: str) -> bool:
                    try:
                        p = urlparse(u)
                        path = (p.path or "").lower()
                        query = (p.query or "").lower()
                        hay = f"{path}?{query}"
                    except Exception:
                        hay = u.lower()
                    for frag in allowed:
                        if frag.lower() in hay:
                            return True
                    return False

                filtered = [u for u in ranked if matches_allowed(u)]
                if filtered:
                    logger.info(f"OWASP path filter applied for {owasp_category}: {len(ranked)} -> {len(filtered)}")
                    return filtered[:max(1, limit)]
                else:
                    logger.info(f"OWASP path filter produced no matches for {owasp_category}; falling back to ranked list")

        return ranked[:max(1, limit)]

    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        discovered_urls = kwargs.get("discovered_urls") or []
        clues = kwargs.get("clues") or {}
        owasp_category = kwargs.get("owasp_category")
        http_services = clues.get("http_services") or []

        all_urls = list(
            dict.fromkeys(
                [u for u in discovered_urls if u and (u.startswith("http://") or u.startswith("https://"))]
                + [u for u in http_services if u and (str(u).startswith("http://") or str(u).startswith("https://"))]
            )
        )
        if not all_urls:
            all_urls = [_base_url_for_web_tools(target, **kwargs)]

        all_urls = self._prioritize_urls_for_owasp(all_urls, owasp_category)
        all_urls = self._filter_info_urls(all_urls)

        max_urls = int(os.getenv("NUCLEI_MAX_URLS", str(settings.NUCLEI_MAX_URLS)))
        if len(all_urls) > max_urls:
            logger.info(f"Nuclei URL cap applied: {len(all_urls)} -> {max_urls}")
            all_urls = all_urls[:max_urls]

        if not all_urls:
            all_urls = [_base_url_for_web_tools(target, **kwargs)]

        fast_mode = str(os.getenv("NUCLEI_FAST_MODE", "0")).strip().lower() in ("1", "true", "yes", "y")
        nuclei_severities = str(
            kwargs.get("nuclei_severities") or os.getenv("NUCLEI_SEVERITIES", "critical,high,medium,low,info")
        ).strip() or "critical,high,medium,low,info"
        if fast_mode:
            fast_tags = os.getenv("NUCLEI_FAST_TAGS", "sqli,xss").strip()
            if fast_tags:
                logger.info(f"Nuclei fast mode active. Using tags: {fast_tags}")
            nuclei_severities = os.getenv("NUCLEI_FAST_SEVERITIES", nuclei_severities).strip() or nuclei_severities
            os.environ.setdefault("NUCLEI_REQUEST_TIMEOUT", os.getenv("NUCLEI_FAST_TEMPLATE_TIMEOUT", "7"))
            os.environ.setdefault("NUCLEI_RETRIES", os.getenv("NUCLEI_FAST_RETRIES", "1"))

        nuclei_concurrency = str(kwargs.get("nuclei_concurrency", 25))
        nuclei_bulk_size = str(kwargs.get("nuclei_bulk_size", 25))
        nuclei_rate_limit = str(kwargs.get("nuclei_rate_limit", 100))
        nuclei_request_timeout = int(
            kwargs.get("nuclei_timeout", os.getenv("NUCLEI_REQUEST_TIMEOUT", str(settings.NUCLEI_REQUEST_TIMEOUT)))
        )
        nuclei_retries = int(kwargs.get("nuclei_retries", os.getenv("NUCLEI_RETRIES", str(settings.NUCLEI_RETRIES))))

        disable_mhe = os.getenv("NUCLEI_DISABLE_MHE", "1").strip().lower() in ("1", "true", "yes", "y")
        extra = [
            "-timeout",
            str(nuclei_request_timeout),
            "-retries",
            str(nuclei_retries),
            "-no-color",
            "-disable-update-check",
        ]
        if disable_mhe:
            extra.append("-nmhe")

        nuclei_tags = self._nuclei_tags_for_owasp(owasp_category)
        if fast_mode:
            nuclei_tags = os.getenv("NUCLEI_FAST_TAGS", nuclei_tags or "sqli,xss").strip()

        # The critical/high pass is the most fragile with tag filtering; let severity drive it.
        if nuclei_severities == "critical,high":
            nuclei_tags = ""
        tag_args = ["-tags", nuclei_tags] if nuclei_tags else []

        base_command = ["nuclei", "-jsonl", "-o", str(output_file), "-silent"]
        perf_args = ["-c", nuclei_concurrency, "-bulk-size", nuclei_bulk_size, "-rl", nuclei_rate_limit]

        if len(all_urls) == 1:
            return ["nuclei", "-u", all_urls[0]] + base_command[1:] + perf_args + ["-severity", nuclei_severities] + tag_args + extra

        urls_file = output_file.parent / "nuclei_urls.txt"
        with open(urls_file, "w", encoding="utf-8") as f:
            f.write("\n".join(all_urls))
        return ["nuclei", "-l", str(urls_file)] + base_command[1:] + perf_args + ["-severity", nuclei_severities] + tag_args + extra
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        findings = []
        seen = set()  # Deduplicate by template-id:host:port:matched-at
        
        for line in output.strip().split('\n'):
            if not line: continue
            try:
                data = json.loads(line)
                severity = (data.get("info") or {}).get("severity", "info")
                template_id = (data.get("template-id") or data.get("template_id") or "")
                description = data.get("info", {}).get("name", "Unknown")
                
                # Create dedup key: template-id + host + port + matcher-name
                host = data.get("host", "")
                port = data.get("port", "")
                matcher_name = data.get("matcher-name", "")
                dedup_key = f"{template_id}:{host}:{port}:{matcher_name}"
                
                # Skip duplicates
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                
                # Apply AI-based severity adjustment based on context
                adjusted_severity = self._adjust_severity_by_context(
                    severity=severity,
                    description=description,
                    template_id=template_id
                )
                
                # Only real issues (low+) are "vulnerability"; info = detection/fingerprint = "information"
                ftype = "vulnerability" if adjusted_severity in ("low", "medium", "high", "critical") else "information"
                findings.append({
                    "type": ftype,
                    "severity": adjusted_severity,  # Use adjusted severity
                    "location": data.get("matched-at", target),
                    "description": description,
                    "evidence": json.dumps(data, indent=2),
                    "original_severity": severity,  # Keep original for transparency
                    "severity_adjusted": severity != adjusted_severity  # Flag if adjusted
                })
            except json.JSONDecodeError:
                continue
        return findings

    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        if not findings:
            has_output = bool(raw_output and raw_output.strip())
            if has_output:
                return "Nuclei finished with output but no parseable findings were produced."
            return "Nuclei did not identify any findings."

        severity_order = ("critical", "high", "medium", "low", "info")
        severity_counts = {key: 0 for key in severity_order}
        for finding in findings:
            severity = str(finding.get("severity", "info")).strip().lower()
            if severity not in severity_counts:
                severity = "info"
            severity_counts[severity] += 1

        severity_summary = ", ".join(
            f"{severity.title()}={severity_counts[severity]}" for severity in severity_order
        )
        return f"Nuclei findings by severity: {severity_summary}."

class NaabuTool(BaseTool):
    def __init__(self):
        super().__init__("Naabu")
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        # Real Naabu CLI: scan top 1000 ports, JSON to file, silent (no banner)
        host = _resolve_host_ip(_normalize_host(target))
        return ["naabu", "-host", host, "-top-ports", "1000", "-json", "-o", str(output_file), "-silent"]
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        findings = []
        # Track unique ports to avoid duplicates
        seen_ports = set()
        
        for line in output.strip().split('\n'):
            if not line: continue
            try:
                data = json.loads(line)
                port = data.get("port", "")
                host = data.get('host', target)
                port_key = f"{host}:{port}"
                
                # Only add if we haven't seen this port for this host
                if port_key not in seen_ports:
                    seen_ports.add(port_key)
                    ip = data.get("ip", "")
                    desc = f"Open port: {port}"
                    if ip:
                        desc += f"\nIP: {ip}"
                    findings.append({
                        "type": "port",
                        "severity": "info",
                        "location": port_key,
                        "description": desc,
                        "evidence": json.dumps(data)
                    })
            except json.JSONDecodeError:
                match = re.search(r':(\d+)', line)
                if match:
                    port = match.group(1)
                    port_key = f"{target}:{port}"
                    
                    # Only add if we haven't seen this port
                    if port_key not in seen_ports:
                        seen_ports.add(port_key)
                        findings.append({
                            "type": "port",
                            "severity": "info",
                            "location": port_key,
                            "description": f"Open port: {port}",
                            "evidence": line
                        })
        return findings
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        if not findings: return "No open ports detected"
        ports = [f.get("location", "").split(":")[-1] for f in findings]
        unique_ports = list(set(ports))  # Remove duplicates for summary
        return f"Found {len(findings)} unique open ports: {', '.join(sorted(unique_ports))}"

# Common web ports to probe when target is IP/host (so Httpx finds services on 8080, 80, etc.)
_WEB_PORTS = ("80", "443", "8080", "8000", "8443", "3000", "5000", "7070", "8888", "9000")

def _is_ip_or_localhost(t: str) -> bool:
    if not t or " " in t:
        return False
    t = t.strip().lower()
    if t in ("localhost", "127.0.0.1", "::1"):
        return True
    # IPv4
    parts = t.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return False


def _normalize_host(target: str) -> str:
    """
    Normalize user input (domain, URL, or IP) to a bare host for tools that expect a domain/IP.
    - If target is a URL, extract hostname (without scheme/path/port).
    - If target is host:port, strip the port.
    """
    t = (target or "").strip()
    if not t:
        return ""
    host = t
    # Extract host from URL if scheme present
    if "://" in t:
        try:
            parsed = urlparse(t)
            host = parsed.hostname or t
        except Exception:
            host = t
    # Strip path if accidentally included
    if "/" in host:
        host = host.split("/", 1)[0]
    # Strip port if present
    if ":" in host and not _is_ip_or_localhost(host):
        host = host.split(":", 1)[0]
    return host


def _resolve_host_ip(host: str) -> str:
    """Resolve a hostname to a single IPv4/IPv6 address for tools that require a raw IP."""
    candidate = (host or "").strip()
    if not candidate:
        return candidate
    if _is_ip_or_localhost(candidate):
        return candidate

    try:
        results = socket.getaddrinfo(candidate, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return candidate

    for family, _, _, _, sockaddr in results:
        if family == socket.AF_INET and sockaddr:
            return sockaddr[0]
    for family, _, _, _, sockaddr in results:
        if family == socket.AF_INET6 and sockaddr:
            return sockaddr[0]

    return candidate


def _base_url_for_web_tools(target: str, **kwargs) -> str:
    """Return a base URL for tools that need one (Wfuzz, GoSpider). Supports domain, IP, or full URL."""
    t = (target or "").strip()
    if t.startswith("http://") or t.startswith("https://"):
        return t.rstrip("/")
    clues = kwargs.get("clues") or {}
    http_services = list(clues.get("http_services") or [])
    discovered_urls = list(kwargs.get("discovered_urls") or [])
    # Prefer first discovered URL (e.g. http://127.0.0.1:8080 from Httpx) so IP+port works
    for u in discovered_urls + http_services:
        u = (u or "").strip()
        if u.startswith("http://") or u.startswith("https://"):
            return u.rstrip("/")
    if _is_ip_or_localhost(t):
        return f"http://{t}"
    return f"https://{t}"

OWASP_URL_PATTERNS = {
    "A01:2021": [
        r'/admin', r'/dashboard', r'/manage', r'/panel',
        r'/api/user', r'/api/admin', r'/account',
        r'/role', r'/permission', r'/profile',
        r'/user/\d+', r'/api/\d+',
    ],
    "A02:2021": [
        r'/login', r'/auth', r'/oauth', r'/token',
        r'/jwt', r'/session', r'/password',
        r'/reset', r'/crypto', r'/cert', r'/api/login',
    ],
    "A03:2021": [
        r'/vulnerabilities/sqli', r'/vulnerabilities/exec',
        r'/vulnerabilities/xss', r'/vulnerabilities/fi',
        r'sqli', r'injection', r'/exec', r'/cmd',
        r'/search', r'/query', r'/filter', r'/api/',
        r'create_paste', r'import_paste', r'upload_paste',
        r'openapi\.yaml', r'graphql', r'\?.*=',
        r'/login', r'/comment', r'/post',
    ],
    "A04:2021": [
        r'/checkout', r'/payment', r'/order',
        r'/workflow', r'/process', r'/state',
        r'/transfer', r'/account', r'/balance',
        r'/settings', r'/profile',
    ],
    "A05:2021": [
        r'/admin', r'/debug', r'/swagger',
        r'actuator', r'phpinfo', r'\.git',
        r'\.env', r'/config', r'/backup',
        r'robots\.txt', r'sitemap\.xml',
        r'/console', r'/phpmyadmin',
        r'compose\.yml', r'openapi\.yaml',
    ],
    "A06:2021": [
        r'/version', r'/about', r'/changelog',
        r'/plugin', r'/component', r'/status',
        r'wp-content', r'wp-includes',
        r'/joomla', r'/drupal', r'/magento',
        r'jquery', r'bootstrap', r'/vendor',
    ],
    "A07:2021": [
        r'/login', r'/signin', r'/auth',
        r'/session', r'/reset', r'/password',
        r'/mfa', r'/otp', r'/register',
        r'/logout', r'/oauth', r'/token',
        r'/account', r'/user',
    ],
    "A08:2021": [
        r'/upload', r'/import', r'/package',
        r'/update', r'/install', r'/plugin',
        r'/artifact', r'/download', r'/deploy',
        r'upload_paste', r'import_paste',
        r'\.zip', r'\.tar', r'\.jar',
    ],
    "A09:2021": [
        r'/logs', r'/audit', r'/monitor',
        r'/events', r'/report', r'/admin',
        r'/debug', r'/trace', r'/error',
        r'/actuator', r'/health', r'/metrics',
    ],
    "A10:2021": [
        r'/proxy', r'/fetch', r'/url',
        r'/redirect', r'/callback', r'/webhook',
        r'/download', r'/import', r'/load',
        r'\?.*url=', r'\?.*path=', r'\?.*src=',
        r'\?.*redirect=', r'\?.*next=',
    ],
}

def _get_owasp_category_for_url(url: str) -> Optional[str]:
    """Classify a URL and return the most relevant OWASP category, or None."""
    url_lower = url.lower()
    scores = {}
    for category, patterns in OWASP_URL_PATTERNS.items():
        score = sum(1 for p in patterns if re.search(p, url_lower))
        if score > 0:
            scores[category] = score
    if not scores:
        return None
    return max(scores, key=scores.get)
class HttpxTool(BaseTool):


    def __init__(self):
        super().__init__("Httpx")
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        httpx_bin = _get_httpx_path()
        # If already a full URL, use as-is (single probe)
        if target.startswith("http://") or target.startswith("https://"):
            return [httpx_bin, "-u", target, "-json", "-o", str(output_file), "-silent", "-title", "-td", "-sc", "-web-server", "-ip", "-cname"]
        # During clues gathering: when user enters an IP we switch it to URLs (http(s)://ip:port)
        # using Naabu open ports so Httpx finds HTTP services instead of probing only https://ip.
        clues = kwargs.get("clues") or {}
        open_ports = list(clues.get("open_ports") or [])
        # IMPORTANT:
        # For targets like `localhost:3000`, we must strip the port once.
        # We then append candidate web ports from Naabu, otherwise we build invalid URLs
        # like `http://localhost:3000:80`.
        host = _normalize_host(target)
        urls = []
        if open_ports:
            # Prefer ports Naabu found; keep common web ports plus any from Naabu
            ports_to_try = set(_WEB_PORTS) | {str(p) for p in open_ports}
            for port in ports_to_try:
                try:
                    if int(port) > 65535:
                        continue
                except ValueError:
                    continue
                urls.append(f"http://{host}:{port}")
                urls.append(f"https://{host}:{port}")
        elif _is_ip_or_localhost(host):
            # No clues: for IP/localhost still probe common web ports
            for port in _WEB_PORTS:
                urls.append(f"http://{host}:{port}")
                urls.append(f"https://{host}:{port}")
        else:
            # Domain: probe common web ports (80, 443, 8080...) so we don't rely only on Naabu
            for port in _WEB_PORTS:
                urls.append(f"http://{host}:{port}")
                urls.append(f"https://{host}:{port}")
        # Httpx accepts multiple -u; flatten [bin, "-u", u1, "-u", u2, ...]
        cmd = [httpx_bin]
        for u in urls[:50]:  # cap to avoid huge CLI
            cmd.extend(["-u", u])
        cmd.extend(["-json", "-o", str(output_file), "-silent", "-title", "-td", "-sc", "-web-server", "-ip", "-cname"])
        return cmd
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        findings = []
        for line in output.strip().split('\n'):
            if not line: continue
            try:
                data = json.loads(line)
                findings.append({
                    "type": "endpoint",
                    "severity": "info",
                    "location": data.get("url", target),
                    "description": f"HTTP service: {data.get('status_code', 'N/A')} - {data.get('title', 'No title')}",
                    "evidence": json.dumps(data, indent=2)
                })
            except json.JSONDecodeError:
                continue
        return findings
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        if not findings: return "No HTTP services detected"
        return f"Found {len(findings)} HTTP endpoints"

class SubfinderTool(BaseTool):
    def __init__(self):
        super().__init__("Subfinder")
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        domain = _normalize_host(target)
        return ["subfinder", "-d", domain, "-o", str(output_file), "-silent"]
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        findings = []
        # Track unique subdomains to avoid duplicates
        seen_subdomains = set()
        
        for line in output.strip().split('\n'):
            if line and line.strip():
                subdomain = line.strip()
                # Only add if we haven't seen this subdomain
                if subdomain not in seen_subdomains:
                    seen_subdomains.add(subdomain)
                    findings.append({
                        "type": "asset",
                        "severity": "info",
                        "location": subdomain,
                        "description": f"Subdomain discovered: {subdomain}",
                        "evidence": subdomain
                    })
        return findings
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        if not findings: return "No subdomains discovered"
        return f"Discovered {len(findings)} unique subdomains"

class AmassTool(BaseTool):
    def __init__(self):
        super().__init__("Amass")
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        domain = _normalize_host(target)
        return ["amass", "enum", "-d", domain, "-o", str(output_file), "-passive"]
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        findings = []
        # Track unique subdomains to avoid duplicates
        seen_subdomains = set()
        
        for line in output.strip().split('\n'):
            if line and line.strip():
                subdomain = line.strip()
                # Only add if we haven't seen this subdomain
                if subdomain not in seen_subdomains:
                    seen_subdomains.add(subdomain)
                    findings.append({
                        "type": "asset",
                        "severity": "info",
                        "location": subdomain,
                        "description": f"Subdomain discovered: {subdomain}",
                        "evidence": subdomain
                    })
        return findings
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        if not findings: return "No subdomains discovered"
        return f"Discovered {len(findings)} unique subdomains"

class AssetfinderTool(BaseTool):
    def __init__(self):
        super().__init__("Assetfinder")
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        domain = _normalize_host(target)
        return ["assetfinder", "--subs-only", domain, "-o", str(output_file)]
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        findings = []
        for line in output.strip().split('\n'):
            if line and line.strip():
                findings.append({
                    "type": "asset",
                    "severity": "info",
                    "location": line.strip(),
                    "description": f"Subdomain discovered: {line.strip()}",
                    "evidence": line.strip()
                })
        return findings
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        if not findings: return "No subdomains discovered"
        return f"Discovered {len(findings)} subdomains"

class Sublist3rTool(BaseTool):
    # Virustotal excluded (blocking). DNSdumpster excluded (site HTML changed, causes IndexError in sublist3r).
    SUBLIST3R_ENGINES = "google,yahoo,bing,baidu,ask,netcraft,threatcrowd,passivedns"

    def __init__(self):
        super().__init__("Sublist3r")
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        domain = _normalize_host(target)
        return [
            "sublist3r", "-d", domain, "-o", str(output_file),
            "-e", self.SUBLIST3R_ENGINES,
        ]
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        findings = []
        seen = set()
        # Normalize target to domain (no scheme/path)
        domain = target.strip().lower()
        if "://" in domain:
            domain = domain.split("://", 1)[1]
        if "/" in domain:
            domain = domain.split("/", 1)[0]
        # Only accept lines that look like subdomains of target (hostname, no ANSI/logs)
        hostname_re = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$")
        skip_patterns = (
            "searching now", "enumerating subdomains", "coded by", "error:",
            "probably now is blocking", "___", "finished now", "traceback", "file \"",
        )
        for line in output.strip().split("\n"):
            line = _strip_ansi(line).strip()
            if not line:
                continue
            # Skip log lines and banner
            if line.startswith("[") or line.startswith("#") or "|" in line and "___" in line:
                continue
            if any(p in line.lower() for p in skip_patterns):
                continue
            # Must look like a hostname (no spaces, valid chars)
            if " " in line or not hostname_re.match(line):
                continue
            # Must be the target or a subdomain of it
            line_lower = line.lower()
            if line_lower != domain and not (line_lower.endswith("." + domain)):
                continue
            if line_lower in seen:
                continue
            seen.add(line_lower)
            clean = line  # already stripped of ANSI
            findings.append({
                "type": "asset",
                "severity": "info",
                "location": clean,
                "description": f"Subdomain discovered: {clean}",
                "evidence": clean,
            })
        return findings
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        if not findings:
            return "No subdomains discovered"
        return f"Discovered {len(findings)} subdomains"

class GAUTool(BaseTool):
    def __init__(self):
        super().__init__("GAU")
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        # GAU uses --o for output file (not -o)
        domain = _normalize_host(target)
        return ["gau", domain, "--o", str(output_file), "--timeout", "15"]
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        findings = []
        for line in output.strip().split('\n'):
            if line and line.startswith('http'):
                findings.append({"type": "endpoint","severity": "info","location": line.strip(),"description": f"Historical URL: {line.strip()}","evidence": line.strip()})
        return findings
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        if not findings: return "No historical URLs found"
        return f"Found {len(findings)} historical URLs"

class KatanaTool(BaseTool):
    def __init__(self):
        super().__init__("Katana")
    
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        base_url = _base_url_for_web_tools(target, **kwargs)
        return ["katana", "-u", base_url, "-o", str(output_file), "-silent", "-d", "3", "-jc", "-kf", "all", "-c", "25", "-fx"]
    
    @staticmethod
    def _classify_url_severity(url: str) -> str:
        """Classify URL severity based on sensitive patterns."""
        url_lower = url.lower()
        
        # CRITICAL: Most severe exposures for A05.
        critical_patterns = [
            r'/documents/internal/',           # Internal documents are critical by design
            r'aws_secrets', r'firewall_rules', r'config_backup', r'ip_config',
            r'network\.pptx$', r'aws_secrets\.docx$',
            r'password_policy\.docx$', r'draft\.docx$',
            r'/backup/', r'/private/', r'/confidential/',
        ]
        for pattern in critical_patterns:
            if re.search(pattern, url_lower):
                return "critical"

        # HIGH: Authentication/security items and potentially sensitive documents.
        high_patterns = [
            r'/vulnerabilities/',              # Known vulnerable apps (DVWA)
            r'phpinfo\.php',                   # PHP info disclosure
            r'/admin', r'/login', r'/auth',    # Admin/auth endpoints
            r'vpn_setup', r'pentest_results', r'compliance_audit', r'business_plan',
            r'ip_config', r'contract',
            r'/documents/(?!internal).*\.(docx|pptx|xlsx)$',
            r'\.(bak|old|backup|sql|env)$',   # Backup/config files
        ]
        for pattern in high_patterns:
            if re.search(pattern, url_lower):
                return "high"
        
        # MEDIUM: Information disclosure
        medium_patterns = [
            r'/compose\.yml', r'docker-compose',  # Docker configs
            r'openapi\.yaml', r'swagger',         # API specs
            r'/graphql',                           # GraphQL endpoints
            r'\.(json|xml|yaml|yml)$',             # Config/data files
            r'/test/', r'/dev/', r'/staging/',      # Non-prod environments
            r'/documents/.*\.(docx|pptx|xlsx)$',   # Non-internal documents are medium risk
            r'\.git', r'\.svn',                   # Version control metadata
        ]
        for pattern in medium_patterns:
            if re.search(pattern, url_lower):
                return "medium"

        # LOW: Potentially interesting
        low_patterns = [
            r'/debug', r'/trace',                 # Debug endpoints
            r'robots\.txt', r'sitemap\.xml',    # Site maps
        ]
        for pattern in low_patterns:
            if re.search(pattern, url_lower):
                return "low"

        low_patterns = [
            r'\.git', r'\.svn',                 # Version control
            r'/debug', r'/trace',               # Debug endpoints
            r'robots\.txt', r'sitemap\.xml',    # Site maps
        ]
        for pattern in low_patterns:
            if re.search(pattern, url_lower):
                return "low"
        
        # Default: Info
        return "info"
    
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        findings = []
        owasp_keywords = NucleiTool._owasp_url_keywords(getattr(self, 'owasp_category', None))
        strict_owasp = str(os.getenv("OWASP_STRICT_FILTER", "true")).strip().lower() in ("1", "true", "yes")

        for line in output.strip().split('\n'):
            if line and line.startswith('http'):
                url = line.strip()
                url_l = url.lower()

                if owasp_keywords and not any(kw in url_l for kw in owasp_keywords):
                    if strict_owasp:
                        continue
                    # Non-strict mode: keep secondary category hits too

                # Intelligently classify severity based on URL content
                severity = self._classify_url_severity(url)
                
                # Generate descriptive label based on severity
                if severity == "critical":
                    description = "Critical sensitive resource exposed"
                elif severity == "high":
                    description = "High-risk endpoint discovered"
                elif severity == "medium":
                    description = "Potentially sensitive endpoint"
                elif severity == "low":
                    description = "Low-priority endpoint"
                else:
                    description = "Crawled endpoint"
                
                finding_type = "vulnerability" if severity in ("critical", "high", "medium", "low") else "endpoint"
                findings.append({
                    "type": finding_type,
                    "severity": severity,
                    "location": url,
                    "description": description,
                    "evidence": url,
                    "owasp_category": _get_owasp_category_for_url(url),
                })

        return findings
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        if not findings: return "No URLs crawled"
        return f"Crawled {len(findings)} URLs"

class GoSpiderTool(BaseTool):
    def __init__(self):
        super().__init__("GoSpider")
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        # Use a temporary directory for gospider output; sanitize target for path safety
        safe_target = re.sub(r"[^\w.-]", "_", target)[:64]
        temp_dir = output_file.parent / f"gospider_temp_{safe_target}"
        try:
            temp_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            temp_dir = output_file.parent / "gospider_temp"
            temp_dir.mkdir(parents=True, exist_ok=True)
        # Support domain, IP, or full URL (use base URL from clues/discovered_urls when target is IP)
        base_url = _base_url_for_web_tools(target, **kwargs)
        return ["bash", "-c", f"gospider -s {base_url} -o {temp_dir} -q -d 2 2>&1 | tee {output_file}"]
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        findings = []
        owasp_keywords = NucleiTool._owasp_url_keywords(getattr(self, 'owasp_category', None))
        strict_owasp = str(os.getenv("OWASP_STRICT_FILTER", "true")).strip().lower() in ("1", "true", "yes")

        for line in output.strip().split('\n'):
            match = re.search(r'https?://[^\s]+', line)
            if match:
                url = match.group(0)
                url_l = url.lower()

                if owasp_keywords and not any(kw in url_l for kw in owasp_keywords):
                    if strict_owasp:
                        continue
                    # Non-strict mode includes secondary category matches as well


                # Intelligently classify severity based on URL content (same logic as Katana)
                severity = KatanaTool._classify_url_severity(url)
                
                # Generate descriptive label based on severity
                if severity == "critical":
                    description = "Critical sensitive resource exposed"
                elif severity == "high":
                    description = "High-risk endpoint discovered"
                elif severity == "medium":
                    description = "Potentially sensitive endpoint"
                elif severity == "low":
                    description = "Low-priority endpoint"
                else:
                    description = "Crawled endpoint"
                
                finding_type = "vulnerability" if severity in ("critical", "high", "medium", "low") else "endpoint"
                findings.append({
                    "type": finding_type,
                    "severity": severity,
                    "location": url,
                    "description": description,
                    "evidence": line,
                    "owasp_category": _get_owasp_category_for_url(url),
                })
        return findings
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        if not findings: return "No URLs crawled"
        return f"Crawled {len(findings)} URLs"

def _extract_paths_from_urls(urls: List[str]) -> List[str]:
    """Extract path segments from URLs for wordlist enrichment."""
    from urllib.parse import urlparse
    paths = set()
    for u in urls or []:
        try:
            parsed = urlparse(str(u))
            path = parsed.path.strip("/")
            if path:
                for seg in path.split("/"):
                    if seg and len(seg) < 50:
                        paths.add(seg)
                paths.add(path)
        except Exception:
            pass
    return list(paths)[:50]


class FFufTool(BaseTool):
    def __init__(self):
        super().__init__("FFuf")
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        import os
        wordlist_paths = [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt",
            "/tmp/quick_wordlist.txt"
        ]
        wordlist_path = None
        for path in wordlist_paths:
            if os.path.exists(path):
                wordlist_path = path
                break
        base_words = "admin\nlogin\napi\ntest\ndebug\nbackup\nconfig\nindex.php\nlogin.php\nadmin.php\n"
        owasp_category = kwargs.get("owasp_category")
        # Include confidence keywords for this OWASP category (if selected)
        owasp_words = NucleiTool._owasp_fuzz_keywords(owasp_category)
        if owasp_words:
            base_words += "\n" + "\n".join(owasp_words) + "\n"

        if not wordlist_path:
            wordlist_path = "/tmp/quick_wordlist.txt"
            with open(wordlist_path, 'w') as f:
                f.write(base_words)
        # Enrich with paths from discovered URLs
        discovered_urls = kwargs.get("discovered_urls") or []
        clues = kwargs.get("clues") or {}
        http_services = clues.get("http_services") or []
        all_urls = list(dict.fromkeys(discovered_urls + [str(u) for u in http_services]))
        extra_paths = _extract_paths_from_urls(all_urls)
        if extra_paths:
            combined_path = output_file.parent / "ffuf_combined_wordlist.txt"
            with open(combined_path, "w") as f:
                if wordlist_path and os.path.exists(wordlist_path):
                    f.write(open(wordlist_path).read())
                else:
                    f.write(base_words)
                f.write("\n" + "\n".join(extra_paths))
            wordlist_path = str(combined_path)
        base_url = _base_url_for_web_tools(target, **kwargs)
        fuzz_url = f"{base_url}/FUZZ"
        return ["ffuf", "-w", wordlist_path,
                "-u", fuzz_url,
                "-o", str(output_file), "-of", "json"]
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        import json
        findings = []
        try:
            # Parse JSON output from ffuf
            data = json.loads(output)
            results = data.get("results", [])
            for item in results:
                status_code = item.get("status", 0)
                if status_code in [200, 201, 202, 204, 301, 302, 307, 403]:  # Interesting status codes
                    fuzz_val = item.get("input", {}).get("FUZZ", "")
                    location = item.get("url") if isinstance(item.get("url"), str) and item.get("url", "").startswith("http") else f"https://{target}/{fuzz_val}"
                    
                    # Classify severity based on path patterns
                    severity = KatanaTool._classify_url_severity(location)
                    
                    # Adjust severity based on status code
                    if status_code == 403:
                        severity = "medium"  # Forbidden - potentially interesting
                    elif status_code in [200, 201, 204]:
                        pass  # Keep classified severity
                    elif status_code in [301, 302, 307]:
                        if severity == "info":
                            severity = "low"  # Redirects are slightly more interesting
                    
                    finding_type = "vulnerability" if severity in ("critical", "high", "medium", "low") else "endpoint"
                    findings.append({
                        "type": finding_type,
                        "severity": severity,
                        "location": location,
                        "description": f"Discovered endpoint: {fuzz_val} (Status: {status_code})",
                        "evidence": json.dumps(item),
                        "owasp_category": _get_owasp_category_for_url(location),
                    })

        except json.JSONDecodeError:
            # Fallback parsing - only accept lines that look like real results
            for line in output.strip().split('\n'):
                line = line.strip()
                if not line or len(line) < 10:
                    continue
                # Skip header/separator lines and command examples
                if "::" in line or "Matcher" in line or "wfuzz " in line or line.startswith("ffuf"):
                    continue
                if "FUZZ" in line or "FUZ2Z" in line:  # Example payload
                    continue
                # Accept: URL-like lines with status codes, or path + status
                if ('200' in line or '302' in line or '301' in line) and (
                    line.startswith("http") or "/" in line or re.search(r'\b\d{3}\b', line)
                ):
                    loc = line.split()[0] if line.split() else line
                    if loc.startswith("http"):
                        # Extract status code for severity adjustment
                        status_match = re.search(r'\b(200|201|202|204|301|302|307|403)\b', line)
                        status = int(status_match.group(1)) if status_match else 200
                        
                        severity = KatanaTool._classify_url_severity(loc)
                        if status == 403:
                            severity = "medium"
                        
                        finding_type = "vulnerability" if severity in ("critical", "high", "medium", "low") else "endpoint"
                        findings.append({
                            "type": finding_type,
                            "severity": severity,
                            "location": loc,
                            "description": "Potentially interesting endpoint found",
                            "evidence": line,
                            "owasp_category": _get_owasp_category_for_url(loc),
                        })
                    
        return findings[:50]  # Limit results to prevent overwhelming
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        if not findings: return "No interesting endpoints found"
        return f"Discovered {len(findings)} potential endpoints for further investigation"

class WfuzzTool(BaseTool):
    def __init__(self):
        super().__init__("Wfuzz")
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        import os
        wordlist_paths = [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt",
            "/tmp/common.txt"
        ]
        wordlist_path = None
        for path in wordlist_paths:
            if os.path.exists(path):
                wordlist_path = path
                break
        base_words = "admin\nlogin\napi\ntest\ndebug\nbackup\nconfig\n"
        owasp_category = kwargs.get("owasp_category")
        owasp_words = NucleiTool._owasp_fuzz_keywords(owasp_category)
        if owasp_words:
            base_words += "\n" + "\n".join(owasp_words) + "\n"

        if not wordlist_path:
            wordlist_path = "/tmp/wfuzz_default_wordlist.txt"
            with open(wordlist_path, 'w') as f:
                f.write(base_words)
        # Enrich with paths from discovered URLs
        discovered_urls = kwargs.get("discovered_urls") or []
        clues = kwargs.get("clues") or {}
        http_services = clues.get("http_services") or []
        all_urls = list(dict.fromkeys(discovered_urls + [str(u) for u in http_services]))
        extra_paths = _extract_paths_from_urls(all_urls)
        if extra_paths:
            combined_path = output_file.parent / "wfuzz_combined_wordlist.txt"
            with open(combined_path, "w") as f:
                if wordlist_path and os.path.exists(wordlist_path):
                    f.write(open(wordlist_path).read())
                else:
                    f.write(base_words)
                f.write("\n" + "\n".join(extra_paths))
            wordlist_path = str(combined_path)
        # Support domain, IP, or full URL (use base URL from clues/discovered_urls when target is IP)
        base_url = _base_url_for_web_tools(target, **kwargs)
        fuzz_url = f"{base_url}/FUZZ"
        # Wfuzz 3.x: -z file,wordlist (not -w); -f file,format single arg (not -o json -f file json)
        return ["wfuzz", "-c", "--hc=404", "-z", f"file,{wordlist_path}",
                "-f", f"{output_file},json", fuzz_url]
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            # Try to parse JSON output first (Wfuzz 3.x writes a top-level array; some versions use {"results": [...]})
            data = json.loads(output)
            results = data if isinstance(data, list) else data.get("results", [])
            for item in results:
                code = item.get("code") or item.get("Response") or item.get("status")
                payload = item.get("payload") or item.get("Payload") or item.get("input", {}).get("FUZZ", "")
                if code is None:
                    code = 0
                if code not in [404, 403]:  # Filter out common error codes
                    location = item.get("url") or f"https://{target}/{payload}"
                    
                    # Classify severity based on path patterns
                    severity = KatanaTool._classify_url_severity(location)
                    
                    # Adjust based on status code
                    if int(code) == 403:
                        severity = "medium"
                    elif int(code) in [200, 201, 204]:
                        pass  # Keep classified severity
                    elif int(code) in [301, 302, 307]:
                        if severity == "info":
                            severity = "low"
                    
                    finding_type = "vulnerability" if severity in ("critical", "high", "medium", "low") else "endpoint"
                    findings.append({
                        "type": finding_type,
                        "severity": severity,
                        "location": location,
                        "description": f"Discovered endpoint: {payload} (Status: {code}) - Size: {item.get('lines', item.get('Chars', 0))}",
                        "evidence": json.dumps(item),
                        "owasp_category": _get_owasp_category_for_url(location),
                    })
        except json.JSONDecodeError:
            # Fallback parsing - only accept lines that look like real results
            for line in output.strip().split('\n'):
                line = line.strip()
                if not line or len(line) < 10:
                    continue
                if "::" in line or "Matcher" in line or "wfuzz " in line or "ffuf" in line:
                    continue
                if "FUZZ" in line or "FUZ2Z" in line:
                    continue
                if ("200" in line or "302" in line or "301" in line) and (
                    line.startswith("http") or "/" in line or re.search(r'\b\d{3}\b', line)
                ):
                    loc = line.split()[0] if line.split() else line
                    if loc.startswith("http"):
                        severity = KatanaTool._classify_url_severity(loc)
                        finding_type = "vulnerability" if severity in ("critical", "high", "medium", "low") else "endpoint"
                        findings.append({
                            "type": finding_type,
                            "severity": severity,
                            "location": loc,
                            "description": "Potentially interesting endpoint found",
                            "evidence": line,
                            "owasp_category": _get_owasp_category_for_url(loc),
                        })
        return findings[:50]  # Limit results to prevent overwhelming
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        if not findings: return "No interesting endpoints found"
        return f"Discovered {len(findings)} potential endpoints for further investigation"


class CeWLTool(BaseTool):
    def __init__(self):
        super().__init__("CeWL")
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        base_url = _base_url_for_web_tools(target, **kwargs)
        return ["cewl", base_url, "-w", str(output_file), "-d", "2", "-m", "5"]
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        words = [w.strip() for w in output.strip().split('\n') if w.strip()]
        if words:
            return [{"type": "information","severity": "info","location": target,"description": f"Generated wordlist with {len(words)} words","evidence": f"Sample words: {', '.join(words[:10])}"}]
        return []
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        words_count = len([w for w in raw_output.strip().split('\n') if w.strip()])
        return f"Generated wordlist with {words_count} words"

class DNSxTool(BaseTool):
    def __init__(self):
        super().__init__("DNSx")
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        # Newer dnsx requires -w with -d (wordlist bruteforce). Use -l with a list file to resolve the domain(s).
        domain = _normalize_host(target)
        domains_file = output_file.parent / "dnsx_domains.txt"
        domains_file.write_text(domain.strip() + "\n")
        return ["dnsx", "-l", str(domains_file), "-silent", "-resp", "-o", str(output_file)]
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        findings = []
        # Skip error/usage lines (e.g. "flag provided but not defined: -retries")
        skip_patterns = ("flag provided", "not defined", "usage:", "error:", "panic:", "failed")
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            if any(p in line.lower() for p in skip_patterns):
                continue
            # Real dnsx output: domain [A: 1.2.3.4] or domain.com
            if "[" in line and "]" in line and ("A:" in line or "AAAA:" in line or "CNAME:" in line):
                loc = line.split()[0] if line.split() else target
            elif re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$", line):
                loc = line
            else:
                continue
            findings.append({
                "type": "asset",
                "severity": "info",
                "location": loc,
                "description": f"DNS record found: {line}",
                "evidence": line,
            })
        return findings
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        if not findings: return "No DNS records found"
        return f"Found {len(findings)} DNS records"

class ShuffleDNSTool(BaseTool):
    def __init__(self):
        super().__init__("ShuffleDNS")
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        import os
        # ShuffleDNS requires -r resolver file (list of DNS resolver IPs)
        resolver_paths = [
            "/usr/share/seclists/Discovery/DNS/dns-resolvers.txt",
            output_file.parent / "resolvers.txt",
            Path("/tmp/shuffledns_resolvers.txt"),
        ]
        resolver_file = None
        for p in resolver_paths:
            path = Path(p) if not isinstance(p, Path) else p
            if path.exists():
                resolver_file = str(path)
                break
        if not resolver_file:
            default_resolvers = "8.8.8.8\n8.8.4.4\n1.1.1.1\n1.0.0.1\n9.9.9.9\n208.67.222.222\n208.67.220.220\n"
            resolvers_path = output_file.parent / "resolvers.txt"
            resolvers_path.parent.mkdir(parents=True, exist_ok=True)
            resolvers_path.write_text(default_resolvers)
            resolver_file = str(resolvers_path)
        # Wordlist for subdomain bruteforcing
        wordlist_paths = [
            "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
            "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
            "/tmp/subdomains_small.txt",
        ]
        wordlist_path = None
        for path in wordlist_paths:
            if os.path.exists(path):
                wordlist_path = path
                break
        if not wordlist_path:
            wordlist_path = "/tmp/subdomains_small.txt"
            Path(wordlist_path).parent.mkdir(parents=True, exist_ok=True)
            Path(wordlist_path).write_text("www\nmail\nftp\nadmin\ntest\ndev\nstaging\nprod\napi\nsupport\nblog\nshop\n")
        # v1.2+ requires -mode (bruteforce | resolve | filter)
        domain = _normalize_host(target)
        return ["shuffledns", "-d", domain, "-r", resolver_file, "-w", wordlist_path, "-mode", "bruteforce", "-o", str(output_file)]
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        seen = set()
        domain = _normalize_host(target).lower()
        if domain.startswith("www."):
            domain = domain[4:]

        hostname_re = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$")
        skip_prefixes = ("[inf]", "[wrn]", "[err]", "usage:", "error:", "panic:", "flag provided")
        skip_exact = {"=== stdout ===", "=== stderr ==="}

        for raw in (output or "").split("\n"):
            line = _strip_ansi(raw).strip()
            if not line:
                continue
            low = line.lower()
            if low in skip_exact:
                continue
            if any(low.startswith(p) for p in skip_prefixes):
                continue
            # Skip obvious banners / ascii art lines
            if "projectdiscovery" in low or low.startswith("__") or low.startswith("___") or low.startswith("/___"):
                continue
            # ShuffleDNS output may be either:
            # - hostname
            # - hostname A 1.2.3.4
            parts = line.split()
            candidate = parts[0].strip() if parts else ""
            if not candidate or " " in candidate or not hostname_re.match(candidate):
                continue
            cand_low = candidate.lower()
            if cand_low != domain and not cand_low.endswith("." + domain):
                continue
            if cand_low in seen:
                continue
            seen.add(cand_low)
            findings.append({
                "type": "asset",
                "severity": "info",
                "location": candidate,
                "description": f"Subdomain discovered: {candidate}",
                "evidence": line,
            })

        return findings
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        if not findings: return "No subdomains discovered via bruteforce"
        return f"Bruteforced {len(findings)} subdomains"

TOOL_REGISTRY = {
    "Nuclei": NucleiTool,
    "Naabu": NaabuTool,
    "Httpx": HttpxTool,
    "Subfinder": SubfinderTool,
    "Amass": AmassTool,
    "Assetfinder": AssetfinderTool,
    "Sublist3r": Sublist3rTool,
    "GAU": GAUTool,
    "Katana": KatanaTool,
    "GoSpider": GoSpiderTool,
    "FFuf": FFufTool,
    "Wfuzz": WfuzzTool,
    "CeWL": CeWLTool,
    "DNSx": DNSxTool,
    "ShuffleDNS": ShuffleDNSTool
}
