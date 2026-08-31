"""Tools API - e.g. get command for a tool (for Tool Library display)."""
from pathlib import Path

from fastapi import APIRouter, HTTPException

from app.core.config import settings
from app.tools.tools_impl import TOOL_REGISTRY

router = APIRouter(tags=["tools"])


@router.get("/tools/{tool_name}/command")
async def get_tool_command(tool_name: str, target: str = "example.com"):
    """
    Return the CLI command that would be run for the given tool and target.
    Used by Tool Library to show the command when user clicks "Run [Tool Name]".
    """
    if tool_name not in settings.AVAILABLE_TOOLS:
        raise HTTPException(status_code=404, detail=f"Unknown tool: {tool_name}")
    tool_class = TOOL_REGISTRY.get(tool_name)
    if not tool_class:
        raise HTTPException(status_code=404, detail=f"Tool not implemented: {tool_name}")
    try:
        instance = tool_class()
        # Placeholder output path (not used for execution, only to build the command)
        output_file = Path(settings.SCANS_DIR) / "0" / f"{tool_name.lower()}.out"
        cmd_list = instance.build_command(target, output_file)
        command = " ".join(str(x) for x in cmd_list)
        return {"tool_name": tool_name, "target": target, "command": command}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to build command: {str(e)}")
