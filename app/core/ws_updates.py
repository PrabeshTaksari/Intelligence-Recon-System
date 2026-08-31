"""In-process scan update fan-out for SSE clients.

This module intentionally does not use WebSockets. It keeps a per-scan list of
asyncio queues. The SSE endpoint registers a queue for each connected client,
and the scan workflow broadcasts update payloads into those queues.
"""

import asyncio
import logging
import time
from typing import Any, Dict, Set

logger = logging.getLogger(__name__)

_scan_subscribers: Dict[int, Set[asyncio.Queue]] = {}
_subscriber_lock = asyncio.Lock()


def init_websocket_manager():
    """Compatibility no-op kept for existing scan startup flow."""
    return None


async def register_connection(scan_id: int) -> asyncio.Queue:
    """Register an SSE subscriber queue for a scan."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=200)
    async with _subscriber_lock:
        subscribers = _scan_subscribers.setdefault(scan_id, set())
        subscribers.add(queue)
    logger.debug("Registered SSE subscriber for scan %s", scan_id)
    return queue


async def unregister_connection(scan_id: int, queue: asyncio.Queue) -> None:
    """Remove an SSE subscriber queue for a scan."""
    async with _subscriber_lock:
        subscribers = _scan_subscribers.get(scan_id)
        if not subscribers:
            return
        subscribers.discard(queue)
        if not subscribers:
            _scan_subscribers.pop(scan_id, None)
    logger.debug("Unregistered SSE subscriber for scan %s", scan_id)


async def broadcast(message: Dict[str, Any]):
    """Broadcast a scan event to all SSE subscribers for that scan."""
    scan_id = message.get("scan_id")
    if scan_id is None:
      return

    if isinstance(scan_id, str) and scan_id.isdigit():
        scan_id = int(scan_id)

    async with _subscriber_lock:
        subscribers = list(_scan_subscribers.get(scan_id, set()))

    if not subscribers:
        return

    for queue in subscribers:
        try:
            queue.put_nowait(message)
        except asyncio.QueueFull:
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:
                logger.debug("Dropped SSE update for scan %s because subscriber queue is full", scan_id)


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
    await broadcast({"type": "scan_status", "scan_id": scan_id, "status": status, "timestamp": time.time()})


async def send_scan_phase_update(scan_id: int, phase: str, details: Dict[str, Any] = None):
    logger.info(f"[Scan {scan_id}] Scan phase: {phase}")
    await broadcast({
        "type": "scan_phase",
        "scan_id": scan_id,
        "phase": phase,
        "details": details or {},
        "timestamp": time.time(),
    })
