"""Endpoint classifier - Intelligence Layer for Central Vulnerability Detection Engine.

Classifies discovered URLs by type (auth, admin, API, file_upload) and risk context.
"""
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
import re


# Path patterns for classification (lowercase; checked with startswith or 'in')
_AUTH_PATTERNS = [
    "/login", "/signin", "/sign-in", "/auth/login", "/auth/signin",
    "/account/login", "/user/login", "/rest/user/login", "/rest/user/logout",
    "/api/login", "/api/auth", "/session/login", "/oauth", "/sso",
]
_ADMIN_PATTERNS = [
    "/admin", "/dashboard", "/manage", "/management", "/panel",
    "/cp", "/control", "/backend", "/console",
]
_API_PATTERNS = ["/api/", "/rest/", "/v1/", "/v2/", "/graphql"]
_FILE_UPLOAD_PATTERNS = [
    "/upload", "/uploads", "/file", "/files", "/attachment",
    "/import", "/api/upload",
]
_SENSITIVE_PATTERNS = [
    "/config", "/settings", "/profile", "/account", "/user/",
    "/password", "/reset", "/logs", "/debug", "/actuator",
]


def _normalize_path(url: str) -> str:
    """Extract and normalize path from URL for pattern matching."""
    try:
        parsed = urlparse(str(url).strip())
        path = (parsed.path or "").strip().lower()
        return path if path else "/"
    except Exception:
        return "/"


def _match_patterns(path: str, patterns: List[str]) -> bool:
    """Return True if path matches any pattern."""
    for p in patterns:
        if p in path or path.startswith(p.rstrip("/")):
            return True
    return False


def classify_url(url: str) -> Dict[str, Any]:
    """Classify a single URL into endpoint type and risk context.

    Returns:
        dict with keys: type, risk, url, path
        type: "auth" | "admin" | "api" | "file_upload" | "sensitive" | "dynamic" | "static"
        risk: "sensitive" | "auth_required" | "public"
    """
    path = _normalize_path(url)
    url_clean = (url or "").strip()
    if not url_clean or not url_clean.startswith(("http://", "https://")):
        return {"url": url_clean, "path": path, "type": "unknown", "risk": "public"}

    has_query = "?" in url_clean
    endpoint_type = "dynamic" if has_query else "static"
    risk = "public"

    if _match_patterns(path, _AUTH_PATTERNS):
        endpoint_type = "auth"
        risk = "auth_required"
    elif _match_patterns(path, _ADMIN_PATTERNS):
        endpoint_type = "admin"
        risk = "sensitive"
    elif _match_patterns(path, _API_PATTERNS):
        if endpoint_type == "dynamic":
            pass
        else:
            endpoint_type = "api"
        if _match_patterns(path, _SENSITIVE_PATTERNS):
            risk = "sensitive"
        else:
            risk = "auth_required" if risk == "public" else risk
    elif _match_patterns(path, _FILE_UPLOAD_PATTERNS):
        endpoint_type = "file_upload"
        risk = "sensitive"
    elif _match_patterns(path, _SENSITIVE_PATTERNS):
        endpoint_type = "sensitive"
        risk = "sensitive"

    return {
        "url": url_clean,
        "path": path,
        "type": endpoint_type,
        "risk": risk,
    }


class EndpointClassifier:
    """Classifies a list of URLs and groups them by type."""

    @staticmethod
    def classify(urls: List[str]) -> List[Dict[str, Any]]:
        """Classify each URL and return list of classified results."""
        seen = set()
        results = []
        for u in urls or []:
            u = (u or "").strip()
            if not u or u in seen:
                continue
            seen.add(u)
            if u.startswith("http://") or u.startswith("https://"):
                results.append(classify_url(u))
        return results

    @staticmethod
    def get_by_type(
        classified: List[Dict[str, Any]], endpoint_type: str
    ) -> List[str]:
        """Extract URLs of a given type (e.g. 'auth', 'admin')."""
        return [
            c["url"] for c in classified
            if c.get("type") == endpoint_type
        ]

    @staticmethod
    def get_auth_endpoints(urls: List[str]) -> List[str]:
        """Convenience: get all auth-related URLs from a URL list."""
        classified = EndpointClassifier.classify(urls)
        return EndpointClassifier.get_by_type(classified, "auth")

    @staticmethod
    def get_admin_endpoints(urls: List[str]) -> List[str]:
        """Get admin-related URLs."""
        classified = EndpointClassifier.classify(urls)
        return EndpointClassifier.get_by_type(classified, "admin")

    @staticmethod
    def get_api_endpoints(urls: List[str]) -> List[str]:
        """Get API-related URLs."""
        classified = EndpointClassifier.classify(urls)
        return EndpointClassifier.get_by_type(classified, "api")

    @staticmethod
    def get_idor_candidate_urls(urls: List[str]) -> List[str]:
        """Get URLs that look like IDOR candidates (e.g. /api/user/1, /user/123)."""
        import re
        candidates = []
        for u in urls or []:
            u = (u or "").strip()
            if not u or not u.startswith(("http://", "https://")):
                continue
            path = _normalize_path(u)
            if re.search(r"/\d+/?$", path) or re.search(r"/\d+/", path):
                candidates.append(u)
        return candidates[:10]


def classify_urls(urls: List[str]) -> List[Dict[str, Any]]:
    """Convenience function to classify URLs."""
    return EndpointClassifier.classify(urls)
