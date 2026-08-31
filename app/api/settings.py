"""App settings API (alert email, etc.)."""
import json
from pathlib import Path
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.core.config import settings

router = APIRouter(prefix="/settings", tags=["settings"])

ALERT_SETTINGS_FILE = settings.DATA_DIR / "alert_settings.json"


def _load_alert_settings() -> Dict[str, Any]:
    if not ALERT_SETTINGS_FILE.exists():
        return {"enabled": False, "emails": []}
    try:
        data = json.loads(ALERT_SETTINGS_FILE.read_text())
        return {
            "enabled": bool(data.get("enabled", False)),
            "emails": list(data.get("emails", [])) if isinstance(data.get("emails"), list) else [],
        }
    except Exception:
        return {"enabled": False, "emails": []}


def _save_alert_settings(enabled: bool, emails: List[str]) -> None:
    settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
    ALERT_SETTINGS_FILE.write_text(
        json.dumps({"enabled": enabled, "emails": emails}, indent=2)
    )


class AlertEmailUpdate(BaseModel):
    enabled: bool = False
    emails: List[str] = []


@router.get("/alert-email")
async def get_alert_email() -> Dict[str, Any]:
    """Get alert email settings (enabled + list of recipient emails)."""
    return _load_alert_settings()


@router.put("/alert-email")
async def put_alert_email(body: AlertEmailUpdate) -> Dict[str, Any]:
    """Update alert email settings. Emails are validated (basic format)."""
    emails = [e.strip().lower() for e in body.emails if e and isinstance(e, str) and e.strip()]
    # Basic email format: something@something.something
    import re
    pattern = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
    valid = [e for e in emails if pattern.match(e)]
    if body.enabled and not valid:
        raise HTTPException(
            status_code=400,
            detail="At least one valid email address is required when enabling alerts.",
        )
    _save_alert_settings(body.enabled, valid)
    return {"enabled": body.enabled, "emails": valid}
