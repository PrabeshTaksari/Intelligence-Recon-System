# app/ai/validation.py

from typing import List, Dict, Any, Tuple
from app.models.scan import Scan
from app.models.tool_run import ToolRun, ToolRunStatus


def validate_ai_plan_and_execution(
    scan: Scan,
    tool_runs: List[ToolRun],
    ai_tools_to_run: List[str],
    ai_tools_skipped: List[str],
) -> Tuple[str, Dict[str, Any]]:
    """
    Validate AI-selected tools and their execution results.

    Returns:
        summary: Human-readable summary string.
        details: Structured dict with flags and counts.
    """
    summary_parts: List[str] = []
    details: Dict[str, Any] = {
        "ai_tools_to_run": ai_tools_to_run,
        "ai_tools_skipped": ai_tools_skipped,
        "total_tools_planned": len(ai_tools_to_run),
        "total_tools_executed": 0,
        "total_success": 0,
        "total_failed": 0,
        "total_timeout": 0,
        "missing_tool_runs": [],
    }

    # Index tool runs by name
    runs_by_name = {tr.tool_name: tr for tr in tool_runs}
    executed_names = set(runs_by_name.keys())

    # Count by status
    for tr in tool_runs:
        details["total_tools_executed"] += 1
        if tr.status == ToolRunStatus.COMPLETED:
            details["total_success"] += 1
        elif tr.status == ToolRunStatus.FAILED:
            details["total_failed"] += 1
        elif tr.status == ToolRunStatus.TIMEOUT:
            details["total_timeout"] += 1

    # Detect planned but missing executions
    for name in ai_tools_to_run:
        if name not in executed_names:
            details["missing_tool_runs"].append(name)

    # Build summary text
    if not ai_tools_to_run:
        summary_parts.append(
            "AI did not select any tools to run. This may indicate an error in the decision step."
        )
    else:
        summary_parts.append(
            f"AI selected {len(ai_tools_to_run)} tools and {len(ai_tools_skipped)} tools were skipped."
        )

    if details["missing_tool_runs"]:
        summary_parts.append(
            f"The following AI-selected tools have no execution record: {', '.join(details['missing_tool_runs'])}."
        )

    if details["total_tools_executed"] == 0:
        summary_parts.append(
            "No tools were successfully started; scan results may be incomplete."
        )
    else:
        summary_parts.append(
            f"{details['total_success']} tools completed, "
            f"{details['total_failed']} failed, "
            f"{details['total_timeout']} timed out."
        )

    # Simple quality flag
    if details["total_success"] == 0 and details["total_tools_planned"] > 0:
        details["overall_status"] = "poor"
        summary_parts.append(
            "Overall AI execution quality is poor because none of the planned tools completed successfully."
        )
    elif details["missing_tool_runs"]:
        details["overall_status"] = "mixed"
    else:
        details["overall_status"] = "good"

    summary = " ".join(summary_parts)
    return summary, details
