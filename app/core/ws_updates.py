"""
WebSocket/SSE update stubs (live status tracker backend removed).
Frontend uses polling GET /api/scans/{id}/status only.
"""

import logging
import time
from typing import Any, Dict

logger = logging.getLogger(__name__)

ws_manager = None
WEBSOCKET_MANAGER_AVAILABLE = False


def init_websocket_manager():
    """No-op: live push disabled."""
    pass


async def register_connection(websocket):
    """No-op."""
    pass


async def unregister_connection(websocket):
    """No-op."""
    pass


async def broadcast(message: Dict[str, Any]):
    """No-op: no SSE/WebSocket; frontend polls status."""
    pass


async def send_tool_start_update(scan_id: int, tool_name: str):
    logger.info(f"[Scan {scan_id}] Tool started: {tool_name}")
    await broadcast({"type": "tool_start", "scan_id": scan_id, "tool": tool_name})


async def send_tool_status_update(scan_id: int, tool_name: str, status: str, details: Dict[str, Any] = None):
    logger.debug(f"[Scan {scan_id}] {tool_name} status: {status}")
    await broadcast({
        "type": "tool_status",
        "scan_id": scan_id,
        "data": {"tool_name": tool_name, "status": status, "details": details or {}, "timestamp": time.time()},
    })


async def send_tool_output_update(scan_id: int, tool_name: str, output: str):
    logger.debug(f"[Scan {scan_id}] {tool_name} output chunk")
    await broadcast({"type": "tool_output", "scan_id": scan_id, "tool": tool_name, "output": output})


async def send_tool_complete_update(scan_id: int, tool_name: str, status: str):
    logger.info(f"[Scan {scan_id}] Tool completed: {tool_name} ({status})")
    await broadcast({"type": "tool_complete", "scan_id": scan_id, "tool": tool_name, "status": status})


async def send_command_update(scan_id: int, tool_name: str, command: str, status: str, output: str = None, is_error: bool = False):
    logger.debug(f"[Scan {scan_id}] {tool_name} command {status}")
    await broadcast({
        "type": "command_update",
        "scan_id": scan_id,
        "data": {"tool_name": tool_name, "command": command, "status": status, "output": output, "is_error": is_error, "timestamp": time.time()},
    })


async def send_log_message(scan_id: int, tool_name: str, message: str):
    logger.info(f"[Scan {scan_id}] {tool_name}: {message}")
    await broadcast({"type": "log", "scan_id": scan_id, "level": "info", "message": f"[{tool_name}] {message}"})


async def send_scan_status_update(scan_id: int, status: str):
    logger.info(f"[Scan {scan_id}] Scan status: {status}")
    await broadcast({"type": "scan_status", "scan_id": scan_id, "status": status})


async def send_scan_phase_update(scan_id: int, phase: str, details: Dict[str, Any] = None):
    logger.info(f"[Scan {scan_id}] Scan phase: {phase}")
    await broadcast({
        "type": "scan_phase",
        "scan_id": scan_id,
        "phase": phase,
        "details": details or {},
        "timestamp": time.time(),
    })
