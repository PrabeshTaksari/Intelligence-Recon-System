"""Tool execution coordinator."""
from pathlib import Path
from typing import Optional, List, Dict, Any

from app.tools.base import ToolResult, BaseTool
from app.tools.tools_impl import TOOL_REGISTRY
from app.core.logging import get_logger
from app.core.config import settings

logger = get_logger(__name__)

def _estimate_nuclei_timeout(
    base_timeout: int,
    discovered_urls: Optional[List[str]],
    clues: Optional[Dict[str, Any]],
    owasp_category: Optional[str] = None,
) -> int:
    """Scale Nuclei timeout based on URL count and OWASP category complexity.
    
    Different OWASP categories use different template types with varying execution times:
    - Fast categories (A05): Header checks, misconfigurations (~milliseconds per request)
    - Medium categories (A01, A07, A08): Access control, auth tests (~1-3s per request)
    - Slow categories (A03, A06): Injection, CVE scanning (~3-10s+ per request)
    """
    # Category-specific base timeout multipliers
    CATEGORY_TIMEOUT_MULTIPLIERS = {
        # Fast: Security Misconfiguration
        "A05:2021": 1.0,
        # Medium: Access Control, Authentication, Integrity Failures, SSRF
        "A01:2021": 1.2,
        "A07:2021": 1.2,
        "A08:2021": 1.2,
        "A10:2021": 1.2,
        # Medium-Slow: Cryptographic, Design, Logging
        "A02:2021": 1.3,
        "A04:2021": 1.3,
        "A09:2021": 1.3,
        # Slow: Injection, Vulnerable Components
        "A03:2021": 1.5,
        "A06:2021": 1.5,
    }
    
    # Get category multiplier (default to 1.5 if unknown or not specified)
    category_multiplier = CATEGORY_TIMEOUT_MULTIPLIERS.get(owasp_category, 1.5)
    
    # Apply category multiplier to base timeout
    adjusted_timeout = int(base_timeout * category_multiplier)
    urls = set()
    for u in discovered_urls or []:
        s = str(u or "").strip()
        if s.startswith("http://") or s.startswith("https://"):
            urls.add(s)
    http_services = (clues or {}).get("http_services") or []
    for u in http_services:
        s = str(u or "").strip()
        if s.startswith("http://") or s.startswith("https://"):
            urls.add(s)

    n = len(urls)
    # Keep default behavior for small scans, increase only when Nuclei input grows.
    # URL count scaling applied after category adjustment (with new 20-URL cap, this rarely triggers)
    if n >= 100:
        return max(adjusted_timeout, 1200)  # 20 min for very large URL sets
    if n >= 50:
        return max(adjusted_timeout, 900)   # 15 min for medium URL sets
    return adjusted_timeout


async def execute_tool(
    tool_name: str,
    target: str,
    scan_id: int,
    timeout: Optional[int] = None,
    discovered_urls: Optional[List[str]] = None,
    clues: Optional[Dict[str, Any]] = None,
    owasp_category: Optional[str] = None,
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
    if owasp_category is not None:
        extra_kwargs["owasp_category"] = owasp_category

    # Nuclei needs longer timeout (runs many templates)
    # Timeout now scales based on both URL count AND OWASP category complexity
    if tool_name == "Nuclei" and timeout is None:
        timeout = _estimate_nuclei_timeout(
            base_timeout=settings.NUCLEI_TIMEOUT,
            discovered_urls=discovered_urls,
            clues=clues,
            owasp_category=owasp_category,  # Pass category for smart timeout calculation
        )
        logger.info(f"SMART TIMEOUT: Calculated Nuclei timeout={timeout}s (base={settings.NUCLEI_TIMEOUT}, urls={len(discovered_urls) if discovered_urls else 0}, owasp={owasp_category})")
    elif tool_name == "Nuclei":
        logger.info(f"SMART TIMEOUT: Using provided timeout={timeout}s (not calculating)")

    # Execute tool with exception handling
    try:
        tool: BaseTool = tool_class()
        timeout_value = timeout or settings.TOOL_TIMEOUT
        
        if tool_name == "Nuclei":
            logger.info(f"NUCLEI FINAL TIMEOUT: timeout_value={timeout_value}s, timeout_param={timeout}, settings.TOOL_TIMEOUT={settings.TOOL_TIMEOUT}")

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
