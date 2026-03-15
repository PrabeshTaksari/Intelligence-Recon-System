# app/tools/base.py
"""
Base classes for recon tool execution.

This module provides:
- ToolResult: a dataclass representing the outcome of a tool execution.
- BaseTool: an abstract base class that all recon tools inherit from.
"""

import asyncio
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

            async def read_stdout_live():
                """Read stdout line-by-line and send to WebSocket as each line arrives."""
                nonlocal raw_output_lines
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
                        if scan_id:
                            await send_tool_output_update(scan_id, self.tool_name, clean)
                        self.logger.info(f"[{self.tool_name}] {clean}")
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
                                    if scan_id:
                                        await send_tool_output_update(scan_id, self.tool_name, ln)
                                    self.logger.info(f"[{self.tool_name}] {ln}")

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
                        if scan_id:
                            await send_tool_output_update(scan_id, self.tool_name, clean)
                        self.logger.info(f"[{self.tool_name}] [stderr] {clean}")
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
                                    if scan_id:
                                        await send_tool_output_update(scan_id, self.tool_name, ln)
                                    self.logger.info(f"[{self.tool_name}] [stderr] {ln}")

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
                error_msg = f"Execution timed out after {timeout} seconds"
                self.logger.error(error_msg)
                if scan_id:
                    await send_tool_complete_update(scan_id, self.tool_name, False)
                return ToolResult(
                    tool_name=self.tool_name,
                    success=False,
                    summary="Execution timeout",
                    error_message=error_msg,
                    started_at=started_at,
                    finished_at=datetime.utcnow()
                )
            
            # Wait for process to complete if not already done
            if process.returncode is None:
                await process.wait()

            # Many tools write to -o output_file and use -silent (stdout empty). Read file first.
            output_file.parent.mkdir(parents=True, exist_ok=True)
            file_content = ""
            if output_file.exists():
                try:
                    file_content = output_file.read_text(encoding="utf-8", errors="replace")
                except Exception as e:
                    self.logger.warning(f"Could not read tool output file: {e}")
            # Prefer file content for parsing (where tools write results); fallback to stdout
            content_for_parsing = (file_content.strip() or raw_output) or ""
            # Persist full output: file + stdout + stderr so nothing is lost
            combined = (file_content.strip() or "") + "\n\n=== STDOUT ===\n" + raw_output + "\n\n=== STDERR ===\n" + stderr_output
            output_file.write_text(combined)

            # Parse findings from the content the tool actually produced (file or stdout)
            findings = self.parse_output(content_for_parsing, target)

            # Generate summary
            summary = self.generate_summary(findings, content_for_parsing)

            finished_at = datetime.utcnow()

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
