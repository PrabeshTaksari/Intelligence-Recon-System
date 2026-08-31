"""Response analyzer - detects vulnerability indicators from HTTP responses."""
from typing import Dict, Any, Optional
import re
import json


# Patterns that suggest successful login
_JWT_PATTERN = re.compile(
    r'["\']?(?:access[_-]?token|id[_-]?token|token|jwt|bearer)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-.]{20,})["\']',
    re.I
)
_SESSION_PATTERN = re.compile(
    r'(?:session|sid|auth|connect\.sid)[=:]["\']?([A-Za-z0-9_\-%]{10,})["\']?',
    re.I
)
_SUCCESS_INDICATORS = [
    "logout", "dashboard", "welcome", "home", "profile",
    "success", "authenticated", "token", "redirect",
]
_ERROR_INDICATORS = [
    "invalid", "incorrect", "wrong", "failed", "error",
    "unauthorized", "forbidden", "invalid credentials",
]


def analyze_login_response(
    status_code: int,
    body: str,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Analyze an HTTP response to determine if login succeeded.

    Returns:
        dict with: success (bool), confidence (str), indicators (list), evidence (str)
    """
    headers = headers or {}
    body_lower = (body or "").lower()
    body_sample = (body or "")[:2000]

    result = {
        "success": False,
        "confidence": "none",
        "indicators": [],
        "evidence": "",
    }

    # Strong success: 200 + JWT or session token in body
    if status_code == 200:
        jwt_match = _JWT_PATTERN.search(body_sample)
        session_match = _SESSION_PATTERN.search(body_sample)
        if jwt_match:
            result["success"] = True
            result["confidence"] = "high"
            result["indicators"].append("jwt_in_response")
            result["evidence"] = f"JWT/token found in response (status {status_code})"
            return result
        if session_match:
            result["success"] = True
            result["confidence"] = "high"
            result["indicators"].append("session_cookie_in_response")
            result["evidence"] = f"Session token found in response (status {status_code})"
            return result

        # Check for success keywords in body
        for kw in _SUCCESS_INDICATORS:
            if kw in body_lower:
                result["indicators"].append(f"keyword:{kw}")
        # If we have success keywords and no error keywords, medium confidence
        if result["indicators"] and not any(e in body_lower for e in _ERROR_INDICATORS):
            result["success"] = True
            result["confidence"] = "medium"
            result["evidence"] = f"Success indicators in body (status {status_code})"
            return result

    # 3xx redirect to dashboard/home can indicate success
    if 300 <= status_code < 400:
        loc = headers.get("location", "").lower()
        for kw in ["dashboard", "home", "profile", "admin"]:
            if kw in loc:
                result["success"] = True
                result["confidence"] = "medium"
                result["indicators"].append(f"redirect_to:{kw}")
                result["evidence"] = f"Redirect to {kw} (status {status_code})"
                return result

    # Auth failure indicators
    if status_code in (401, 403):
        result["evidence"] = f"Auth rejected (status {status_code})"
        return result

    # 500 might mean internal error (not necessarily auth failure)
    if status_code >= 500:
        result["evidence"] = f"Server error (status {status_code})"
        return result

    result["evidence"] = f"No clear login success (status {status_code})"
    return result
