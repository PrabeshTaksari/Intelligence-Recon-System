"""Send email alerts when a scan finishes."""
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Any, Dict, List, Optional

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

ALERT_SETTINGS_FILE = settings.DATA_DIR / "alert_settings.json"


def _load_alert_settings() -> Dict[str, Any]:
    if not ALERT_SETTINGS_FILE.exists():
        return {"enabled": False, "emails": []}
    try:
        import json
        data = json.loads(ALERT_SETTINGS_FILE.read_text())
        return {
            "enabled": bool(data.get("enabled", False)),
            "emails": list(data.get("emails", [])) if isinstance(data.get("emails"), list) else [],
        }
    except Exception:
        return {"enabled": False, "emails": []}


def _send_email_sync(
    to_emails: List[str],
    subject: str,
    body_text: str,
) -> None:
    if not to_emails:
        return
    host = getattr(settings, "SMTP_HOST", None) or ""
    if not host or not host.strip():
        logger.info("SMTP not configured; skipping scan-finished email.")
        return
    port = getattr(settings, "SMTP_PORT", 587) or 587
    user = (getattr(settings, "SMTP_USER", None) or "").strip()
    password = (getattr(settings, "SMTP_PASSWORD", None) or "").strip()
    from_addr = (getattr(settings, "SMTP_FROM", None) or user or "irs@localhost").strip()
    use_tls = getattr(settings, "SMTP_USE_TLS", True)
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = ", ".join(to_emails)
        msg.attach(MIMEText(body_text, "plain"))
        with smtplib.SMTP(host, port, timeout=30) as smtp:
            if use_tls:
                smtp.starttls()
            if user and password:
                smtp.login(user, password)
            smtp.sendmail(from_addr, to_emails, msg.as_string())
        logger.info("Scan-finished alert email sent to %s", to_emails)
    except Exception as e:
        logger.exception("Failed to send scan-finished email: %s", e)


def _name_from_email(email: str) -> str:
    """Derive a display name from email (e.g. john.doe@example.com -> John Doe)."""
    if not email or "@" not in email:
        return "User"
    local = email.strip().split("@")[0]
    if not local:
        return "User"
    name = local.replace(".", " ").replace("_", " ").strip()
    return name.title() if name else "User"


def send_scan_finished_alert_sync(
    target: str,
    status: str,
    scan_id: int,
    findings_summary: Optional[str] = None,
) -> None:
    """Synchronous send (call from thread/executor)."""
    cfg = _load_alert_settings()
    if not cfg.get("enabled") or not cfg.get("emails"):
        return
    subject = f"[IRS] Scan finished: {target} ({status})"
    base_body = (
        "Your scan has been successfully completed. Go and check report on Intelligence Recon System.\n\n"
        "Thank You!\n"
        "IRS"
    )
    for to_email in cfg["emails"]:
        name = _name_from_email(to_email)
        body = f"Dear {name},\n\n{base_body}"
        _send_email_sync([to_email], subject, body)


async def send_scan_finished_alert(
    target: str,
    status: str,
    scan_id: int,
    findings_summary: Optional[str] = None,
) -> None:
    """Fire-and-forget: send alert email in thread so we don't block."""
    import asyncio
    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(
            None,
            send_scan_finished_alert_sync,
            target,
            status,
            scan_id,
            findings_summary,
        )
    except Exception as e:
        logger.exception("Alert email task failed: %s", e)
