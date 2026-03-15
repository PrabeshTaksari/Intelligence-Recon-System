"""Tool execution coordinator."""
from pathlib import Path
from typing import Optional, List, Dict, Any

from app.tools.base import ToolResult, BaseTool
from app.tools.tools_impl import TOOL_REGISTRY
from app.core.logging import get_logger
from app.core.config import settings

logger = get_logger(__name__)


async def execute_tool(
    tool_name: str,
    target: str,
    scan_id: int,
    timeout: Optional[int] = None,
    discovered_urls: Optional[List[str]] = None,
    clues: Optional[Dict[str, Any]] = None,
) -> ToolResult:
    """Execute a single recon tool.

    Args:
        tool_name: Name of the tool to execute
        target: Target domain/host
        scan_id: ID of the scan this tool run belongs to
        timeout: Optional timeout override
        discovered_urls: URLs from discovery tools (for Nuclei, FFuf, Wfuzz)
        clues: Initial clues from Naabu/Httpx (http_services, etc.)

    Returns:
        ToolResult object
    """
    # Get tool class
    tool_class = TOOL_REGISTRY.get(tool_name)

    if not tool_class:
        logger.error(f"Unknown tool: {tool_name}")
        return ToolResult(
            tool_name=tool_name,
            success=False,
            summary="Unknown tool",
            error_message=f"Tool '{tool_name}' not found in registry"
        )

    # Create output file path
    output_dir = settings.SCANS_DIR / str(scan_id)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"{tool_name.lower()}.out"

    # Build kwargs for tools that use discovered URLs
    extra_kwargs = {}
    if discovered_urls is not None:
        extra_kwargs["discovered_urls"] = discovered_urls
    if clues is not None:
        extra_kwargs["clues"] = clues

    # Nuclei needs longer timeout (runs many templates)
    if tool_name == "Nuclei" and timeout is None:
        timeout = settings.NUCLEI_TIMEOUT

    # Execute tool with exception handling
    try:
        tool: BaseTool = tool_class()
        timeout_value = timeout or settings.TOOL_TIMEOUT

        logger.info(f"Executing {tool_name} for scan {scan_id}, target={target}, timeout={timeout_value}s")

        result = await tool.execute(
            target=target,
            output_file=output_file,
            timeout=timeout_value,
            scan_id=scan_id,
            **extra_kwargs
        )

        logger.info(f"{tool_name} completed: success={result.success}, findings={len(result.findings)}")
        return result

    except Exception as e:
        logger.exception(f"Execution failed for {tool_name} on scan {scan_id}: {e}")
        return ToolResult(
            tool_name=tool_name,
            success=False,
            summary="Execution exception",
            error_message=str(e),
            findings=[]
        )
