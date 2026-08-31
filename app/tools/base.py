# app/tools/base.py
"""
Base classes for recon tool execution.

This module provides:
- ToolResult: a dataclass representing the outcome of a tool execution.
- BaseTool: an abstract base class that all recon tools inherit from.
"""

import asyncio
import json
import os
import re
import shutil
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

# Strip ANSI escape sequences so tool output is readable in UI and logs
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]?")


def _strip_ansi(line: str) -> str:
    if not line:
        return line
    return _ANSI_ESCAPE.sub("", line)

from app.core.logging import get_logger
from app.core.ws_updates import (
    send_tool_start_update,
    send_tool_status_update,
    send_tool_output_update,
    send_tool_complete_update,
    send_log_message
)

logger = get_logger(__name__)


@dataclass
class ToolResult:
    """Holds the result of a single tool execution."""
    tool_name: str
    success: bool
    summary: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    raw_output: str = ""
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class BaseTool(ABC):
    """
    Abstract base class for all recon tools.

    Handles:
    - Command execution
    - Timeout handling
    - Output parsing
    - WebSocket notifications
    """

    def __init__(self, tool_name: str):
        self.tool_name = tool_name
        self.logger = get_logger(f"tool.{tool_name.lower()}")

    @abstractmethod
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        """
        Build the command line arguments for this tool.

        Returns:
            List of strings representing the command.
        """
        pass

    @abstractmethod
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        """
        Parse raw tool output into a structured list of findings.

        Each finding is a dictionary with keys:
        - type
        - severity
        - location
        - description
        - evidence
        """
        pass

    def format_live_output(self, line: str) -> str:
        """Format a live output line for the UI.

        Tools can override this to present concise, human-readable output while
        keeping their raw output files intact for parsing and evidence.
        """
        return line

    def check_installed(self) -> bool:
        """Check if the tool exists in the system PATH."""
        cmd_name = self.tool_name.lower()
        
        # Special case for Httpx - check go bin or PATH
        if cmd_name == "httpx":
            go_bin = os.path.expanduser("/home/prabesh/go/bin/httpx")
            return os.path.isfile(go_bin) or shutil.which("httpx") is not None
        
        return shutil.which(cmd_name) is not None

    async def execute(
        self,
        target: str,
        output_file: Path,
        timeout: int = 300,
        scan_id: Optional[int] = None,
        **kwargs
    ) -> ToolResult:
        """
        Execute the tool asynchronously and parse results.

        Args:
            target: target domain or host
            output_file: path to save raw output
            timeout: max time in seconds
            scan_id: optional scan identifier for WS updates
            **kwargs: tool-specific options
        """
        started_at = datetime.utcnow()

        # Notify WS: tool start
        if scan_id:
            await send_tool_start_update(scan_id, self.tool_name)
            await send_tool_status_update(scan_id, self.tool_name, "running", {"command": " ".join(self.build_command(target, output_file, **kwargs))})

        # Capture OWASP category for post-processing in parse_output
        self.owasp_category = kwargs.get("owasp_category")

        # Check installation
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
                finished_at=datetime.utcnow()
            )

        try:
            # Build command
            command = self.build_command(target, output_file, **kwargs)
            self.logger.info(f"Executing command: {' '.join(command)}")
            if scan_id:
                await send_log_message(scan_id, self.tool_name, f"Running command: {' '.join(command)}")

            # Run command asynchronously (limit=1MB so long lines e.g. Nuclei JSONL don't raise LimitOverrunError)
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=1024 * 1024,
            )

            raw_output_lines = []
            stderr_lines = []

            # Stop-on-findings support for Nuclei (optional)
            is_nuclei = self.tool_name.lower() == "nuclei"
            nuclei_stop_threshold = 1
            nuclei_stop_enabled = False
            if is_nuclei:
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
                """Read stdout line-by-line and send to WebSocket as each line arrives."""
                nonlocal raw_output_lines, finding_count
                while process.stdout:
                    try:
                        line = await process.stdout.readline()
                    except (ValueError, asyncio.LimitOverrunError) as e:
                        # One line exceeded buffer (e.g. Nuclei long JSONL); consume and continue
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
                                            self.logger.info(f"[{self.tool_name}] stop-on-findings threshold reached ({finding_count}); terminating process")
                                            process.kill()
                                            break
                # Drain remaining
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
                """Read stderr line-by-line and send to WebSocket as each line arrives."""
                nonlocal stderr_lines
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

            async def monitor_nuclei_file():
                """Monitor Nuclei JSONL output file and stop on first relevant finding."""
                nonlocal finding_count
                if not output_file:
                    return
                try:
                    position = 0
                    if output_file.exists():
                        with open(output_file, 'r', encoding='utf-8', errors='replace') as f:
                            f.seek(0, 2)
                            position = f.tell()
                except Exception:
                    position = 0

                while is_nuclei and nuclei_stop_enabled and process.returncode is None:
                    await asyncio.sleep(0.7)
                    try:
                        if not output_file.exists():
                            continue
                        with open(output_file, 'r', encoding='utf-8', errors='replace') as f:
                            f.seek(position)
                            for line in f:
                                ln = line.strip()
                                if not ln:
                                    continue
                                try:
                                    data = json.loads(ln)
                                    sev = (data.get('info') or {}).get('severity')
                                    if sev:
                                        sev_lower = str(sev).strip().lower()
                                        if sev_lower in {'critical', 'high', 'medium', 'low'}:
                                            finding_count += 1
                                            if finding_count >= nuclei_stop_threshold:
                                                self.logger.info(f"[{self.tool_name}] stop-on-findings threshold reached ({finding_count}), terminating process")
                                                try:
                                                    process.kill()
                                                except Exception:
                                                    pass
                                                return
                                except Exception:
                                    continue
                            position = f.tell()
                    except Exception:
                        continue

            async def run_with_timeout():
                stdout_task = asyncio.create_task(read_stdout_live())
                stderr_task = asyncio.create_task(read_stderr_live())
                nuclei_file_task = None
                if is_nuclei and nuclei_stop_enabled:
                    nuclei_file_task = asyncio.create_task(monitor_nuclei_file())
                if nuclei_file_task:
                    await asyncio.gather(stdout_task, stderr_task, nuclei_file_task)
                else:
                    await asyncio.gather(stdout_task, stderr_task)
                await process.wait()

            try:
                await asyncio.wait_for(run_with_timeout(), timeout=timeout)
                raw_output = "\n".join(raw_output_lines)
                stderr_output = "\n".join(stderr_lines)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                # Preserve any partial output already produced before the timeout.
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
                    started_at=started_at,
                    finished_at=datetime.utcnow()
                )
            
            # Wait for process to complete if not already done
            if process.returncode is None:
                await process.wait()

            # Check return code - non-zero indicates error (except for Nuclei which uses 1 for "no findings")
            # Nuclei: 0 = success with findings, 1 = no findings/errors, >1 = actual errors
            # Other tools: 0 = success, non-zero = error
            tool_return_code = process.returncode
            self.logger.info(f"{self.tool_name} completed with return code: {tool_return_code}")
            
            # For Nuclei, return code 1 is normal (no vulnerabilities found)
            # For other tools, any non-zero return code indicates failure
            is_nuclei = self.tool_name.lower() == "nuclei"
            has_execution_error = False
            
            if is_nuclei:
                # Nuclei returns 1 when no vulnerabilities found (not an error)
                # Returns >1 only for actual execution errors
                has_execution_error = tool_return_code > 1
            else:
                # Standard behavior: non-zero = error
                has_execution_error = tool_return_code != 0

            # Many tools write to -o output_file and use -silent (stdout empty). Read file first.
            output_file.parent.mkdir(parents=True, exist_ok=True)
            file_content = ""
            if output_file.exists():
                try:
                    file_content = output_file.read_text(encoding="utf-8", errors="replace")
                except Exception as e:
                    self.logger.warning(f"Could not read tool output file: {e}")
            # Prefer file content for parsing (where tools write results); fallback to stdout
            _file = file_content.strip()
            if "=== STDOUT ===" in _file:
                _file = _file.split("=== STDOUT ===")[0].strip()
            content_for_parsing = (_file or raw_output) or ""
            # Persist full output: file + stdout + stderr so nothing is lost
            combined = "\n\n=== STDOUT ===\n" + raw_output + "\n\n=== STDERR ===\n" + stderr_output
            output_file.write_text(combined)

            # Parse findings from the content the tool actually produced (file or stdout)
            findings = self.parse_output(content_for_parsing, target)

            # Generate summary
            summary = self.generate_summary(findings, content_for_parsing)

            finished_at = datetime.utcnow()

            # If execution error occurred, notify failure and return early
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
                    findings=findings,  # Include any partial findings
                    started_at=started_at,
                    finished_at=finished_at
                )

            # Notify WS: tool complete
            if scan_id:
                await send_tool_complete_update(scan_id, self.tool_name, True)

            return ToolResult(
                tool_name=self.tool_name,
                success=True,
                summary=summary,
                findings=findings,
                raw_output=raw_output,
                started_at=started_at,
                finished_at=finished_at
            )

        except Exception as e:
            error_msg = f"Tool execution failed: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            if scan_id:
                await send_tool_complete_update(scan_id, self.tool_name, False)
            return ToolResult(
                tool_name=self.tool_name,
                success=False,
                summary="Execution failed",
                error_message=error_msg,
                started_at=started_at,
                finished_at=datetime.utcnow()
            )

    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        """

        Returns a string like:
        "Found 12 items: 3 high, 5 medium, 4 low"
        """
        if not findings:
            return "No results found"

        # Count severities
        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "info").upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        severity_summary = ", ".join([f"{v} {k}" for k, v in severity_counts.items()])
        return f"Found {len(findings)} items: {severity_summary}"
