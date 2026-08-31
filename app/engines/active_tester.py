"""Active Testing Engine - sends custom HTTP requests for vulnerability testing.

Runs OWASP-specific attack payloads for all A01-A10 categories.
"""
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
import json
import asyncio
import re

from app.engines.endpoint_classifier import EndpointClassifier
from app.engines.response_analyzer import analyze_login_response


# Default credentials for A07 testing
_DEFAULT_CREDENTIALS = [
    ("admin@juice-sh.op", "admin123"),
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("administrator", "administrator"),
    ("root", "root"),
    ("test", "test"),
    ("user", "user"),
]


@dataclass
class ActiveTestResult:
    """Result of a single active test."""
    url: str
    payload: Dict[str, Any]
    status_code: int
    success: bool
    confidence: str
    evidence: str
    owasp_category: str
    severity: str = "medium"
    indicators: List[str] = field(default_factory=list)


async def _http_request(
    method: str, url: str, timeout: float = 12.0, **kwargs: Any
) -> Dict[str, Any]:
    """Send HTTP request. Returns status_code, body, headers, error."""
    try:
        import httpx
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            resp = await client.request(method, url, **kwargs)
            return {
                "status_code": resp.status_code,
                "body": resp.text,
                "headers": dict(resp.headers),
            }
    except Exception as e:
        return {"status_code": 0, "body": "", "headers": {}, "error": str(e)}


async def _send_login_request(
    url: str, credentials: Tuple[str, str], use_json: bool = True, timeout: float = 15.0
) -> Dict[str, Any]:
    """Send login POST. Returns status_code, body, headers."""
    try:
        import httpx
        email_or_user, password = credentials
        payloads = [
            {"email": email_or_user, "password": password},
            {"username": email_or_user, "password": password},
        ]
        for payload in payloads[:2]:
            try:
                async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                    resp = await client.post(
                        url,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                    )
                    return {
                        "status_code": resp.status_code,
                        "body": resp.text,
                        "headers": dict(resp.headers),
                    }
            except Exception:
                continue
    except Exception as e:
        return {"status_code": 0, "body": "", "headers": {}, "error": str(e)}
    return {"status_code": 0, "body": "", "headers": {}}


class ActiveTester:
    """Active testing engine for all OWASP categories."""

    @staticmethod
    async def test_a01_idor(
        discovered_urls: List[str], target: str
    ) -> List[ActiveTestResult]:
        """A01: Test for IDOR - try accessing other user IDs."""
        results: List[ActiveTestResult] = []
        candidates = EndpointClassifier.get_idor_candidate_urls(discovered_urls)
        for url in candidates[:5]:
            url = (url or "").strip()
            if not url or not url.startswith(("http://", "https://")):
                continue
            m = re.search(r"/(\d+)/?$", url)
            if not m:
                continue
            orig_id = m.group(1)
            try:
                next_id = str(int(orig_id) + 1)
            except ValueError:
                continue
            test_url = re.sub(r"/\d+/?$", f"/{next_id}", url)
            if test_url == url:
                continue
            resp = await _http_request("GET", test_url)
            sc = resp.get("status_code", 0)
            if sc == 200 and len(resp.get("body", "")) > 50:
                results.append(ActiveTestResult(
                    url=test_url,
                    payload={"original": url, "tested_id": next_id},
                    status_code=sc,
                    success=True,
                    confidence="medium",
                    evidence=f"IDOR candidate: {url} -> {test_url} returned 200",
                    owasp_category="A01:2021",
                    severity="high",
                ))
            await asyncio.sleep(0.2)
        return results

    @staticmethod
    async def test_a02_crypto(
        discovered_urls: List[str], target: str
    ) -> List[ActiveTestResult]:
        """A02: Check HTTP vs HTTPS, weak cookie attributes."""
        results: List[ActiveTestResult] = []
        seen = set()
        for url in (discovered_urls or [])[:8]:
            url = (url or "").strip()
            if not url or url in seen or not url.startswith(("http://", "https://")):
                continue
            seen.add(url)
            if url.startswith("http://") and "/login" in url.lower():
                results.append(ActiveTestResult(
                    url=url,
                    payload={},
                    status_code=0,
                    success=True,
                    confidence="high",
                    evidence="Login over HTTP - sensitive data may be transmitted unencrypted",
                    owasp_category="A02:2021",
                    severity="medium",
                ))
            resp = await _http_request("GET", url)
            headers = resp.get("headers", {})
            set_cookie = headers.get("set-cookie", headers.get("Set-Cookie", ""))
            if set_cookie and "secure" not in set_cookie.lower() and "httponly" not in set_cookie.lower():
                results.append(ActiveTestResult(
                    url=url,
                    payload={"header": "Set-Cookie"},
                    status_code=resp.get("status_code", 0),
                    success=True,
                    confidence="low",
                    evidence="Cookie may lack Secure/HttpOnly flags",
                    owasp_category="A02:2021",
                    severity="low",
                ))
            await asyncio.sleep(0.2)
        return results[:5]

    @staticmethod
    async def test_a03_injection(
        discovered_urls: List[str], target: str
    ) -> List[ActiveTestResult]:
        """A03: Safe XSS reflection check - payload in param echoed in response."""
        results: List[ActiveTestResult] = []
        safe_payload = "xsscheck123"
        for url in (discovered_urls or [])[:5]:
            url = (url or "").strip()
            if not url or not url.startswith(("http://", "https://")):
                continue
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}q={safe_payload}&search={safe_payload}"
            resp = await _http_request("GET", test_url)
            body = resp.get("body", "")
            if safe_payload in body and resp.get("status_code") == 200:
                results.append(ActiveTestResult(
                    url=test_url,
                    payload={"param": "q/search", "value": safe_payload},
                    status_code=resp.get("status_code", 0),
                    success=True,
                    confidence="low",
                    evidence="User input reflected in response - possible XSS",
                    owasp_category="A03:2021",
                    severity="low",
                ))
            await asyncio.sleep(0.2)
        return results[:3]

    @staticmethod
    async def test_a04_insecure_design(
        discovered_urls: List[str], target: str
    ) -> List[ActiveTestResult]:
        """A04: Logic bypass probes - try bypass params on sensitive endpoints."""
        results: List[ActiveTestResult] = []
        admin_urls = EndpointClassifier.get_admin_endpoints(discovered_urls or [])
        sensitive_urls = [
            c["url"] for c in EndpointClassifier.classify(discovered_urls or [])
            if c.get("type") in ("admin", "sensitive", "api") and c.get("risk") == "sensitive"
        ]
        urls_to_test = list(dict.fromkeys(admin_urls + sensitive_urls))[:5]
        if not urls_to_test and discovered_urls:
            urls_to_test = [u for u in discovered_urls[:3] if u and u.startswith(("http://", "https://"))]
        bypass_params = [
            ("bypass", "1"),
            ("debug", "true"),
            ("step", "0"),
            ("admin", "true"),
            ("skip_validation", "1"),
        ]
        for url in urls_to_test:
            url = (url or "").strip()
            if not url or not url.startswith(("http://", "https://")):
                continue
            base_resp = await _http_request("GET", url)
            base_sc = base_resp.get("status_code", 0)
            for param, val in bypass_params[:3]:
                sep = "&" if "?" in url else "?"
                test_url = f"{url}{sep}{param}={val}"
                resp = await _http_request("GET", test_url)
                sc = resp.get("status_code", 0)
                if sc == 200 and base_sc in (401, 403):
                    results.append(ActiveTestResult(
                        url=test_url,
                        payload={"param": param, "value": val},
                        status_code=sc,
                        success=True,
                        confidence="low",
                        evidence=f"Possible logic bypass: {param}={val} changed {base_sc} -> 200",
                        owasp_category="A04:2021",
                        severity="medium",
                    ))
                    break
                await asyncio.sleep(0.2)
            await asyncio.sleep(0.2)
        return results[:3]

    @staticmethod
    async def test_a05_misconfig(
        discovered_urls: List[str], target: str
    ) -> List[ActiveTestResult]:
        """A05: Check debug/actuator endpoints, missing security headers."""
        results: List[ActiveTestResult] = []
        base = ""
        for u in discovered_urls or []:
            if u and u.startswith(("http://", "https://")):
                base = u.rstrip("/").split("?")[0]
                break
        if not base:
            return []
        check_paths = ["/actuator", "/actuator/health", "/debug", "/.env", "/config"]
        for p in check_paths:
            test_url = f"{base}{p}"
            resp = await _http_request("GET", test_url)
            sc = resp.get("status_code", 0)
            if sc in (200, 403):
                results.append(ActiveTestResult(
                    url=test_url,
                    payload={},
                    status_code=sc,
                    success=True,
                    confidence="medium" if sc == 200 else "low",
                    evidence=f"Exposed path {p} (status {sc})",
                    owasp_category="A05:2021",
                    severity="medium" if sc == 200 else "low",
                ))
            await asyncio.sleep(0.2)
        resp = await _http_request("GET", base)
        headers = resp.get("headers", {})
        if not headers.get("x-content-type-options"):
            results.append(ActiveTestResult(
                url=base,
                payload={},
                status_code=resp.get("status_code", 0),
                success=True,
                confidence="low",
                evidence="Missing X-Content-Type-Options header",
                owasp_category="A05:2021",
                severity="low",
            ))
        return results[:5]

    @staticmethod
    async def test_a06_components(
        discovered_urls: List[str], target: str
    ) -> List[ActiveTestResult]:
        """A06: Version disclosure in headers."""
        results: List[ActiveTestResult] = []
        for url in (discovered_urls or [])[:5]:
            url = (url or "").strip()
            if not url or not url.startswith(("http://", "https://")):
                continue
            resp = await _http_request("GET", url)
            headers = resp.get("headers", {})
            for h in ("server", "x-powered-by", "x-aspnet-version"):
                val = headers.get(h, headers.get(h.replace("-", ""), ""))
                if val and any(c.isdigit() for c in str(val)):
                    results.append(ActiveTestResult(
                        url=url,
                        payload={"header": h, "value": str(val)[:100]},
                        status_code=resp.get("status_code", 0),
                        success=True,
                        confidence="low",
                        evidence=f"Version leak: {h}: {val}",
                        owasp_category="A06:2021",
                        severity="low",
                    ))
                    break
            await asyncio.sleep(0.2)
        return results[:3]

    @staticmethod
    async def test_a07_default_credentials(
        auth_urls: List[str],
        credentials: Optional[List[Tuple[str, str]]] = None,
        max_per_url: int = 5,
    ) -> List[ActiveTestResult]:
        """A07: Default credential testing."""
        creds = credentials or _DEFAULT_CREDENTIALS
        results: List[ActiveTestResult] = []
        seen = set()
        for url in (auth_urls or [])[:5]:
            url = (url or "").strip()
            if not url or url in seen or not url.startswith(("http://", "https://")):
                continue
            seen.add(url)
            for email_user, password in creds[:max_per_url]:
                resp_data = await _send_login_request(url, (email_user, password))
                analysis = analyze_login_response(
                    resp_data.get("status_code", 0),
                    resp_data.get("body", ""),
                    resp_data.get("headers", {}),
                )
                if analysis["success"]:
                    results.append(ActiveTestResult(
                        url=url,
                        payload={"email": email_user, "password": password},
                        status_code=resp_data.get("status_code", 0),
                        success=True,
                        confidence=analysis["confidence"],
                        evidence=analysis["evidence"],
                        owasp_category="A07:2021",
                        severity="high",
                        indicators=analysis.get("indicators", []),
                    ))
                    break
                await asyncio.sleep(0.3)
        return results

    @staticmethod
    async def test_a08_integrity(
        discovered_urls: List[str], target: str
    ) -> List[ActiveTestResult]:
        """A08: Check for upload endpoints."""
        results: List[ActiveTestResult] = []
        upload_urls = [
            c["url"] for c in EndpointClassifier.classify(discovered_urls or [])
            if c.get("type") == "file_upload"
        ]
        for url in upload_urls[:3]:
            resp = await _http_request("GET", url)
            if resp.get("status_code") in (200, 405):
                results.append(ActiveTestResult(
                    url=url,
                    payload={},
                    status_code=resp.get("status_code", 0),
                    success=True,
                    confidence="low",
                    evidence="File upload endpoint reachable",
                    owasp_category="A08:2021",
                    severity="low",
                ))
            await asyncio.sleep(0.2)
        return results

    @staticmethod
    async def test_a09_logging(
        auth_urls: List[str], target: str
    ) -> List[ActiveTestResult]:
        """A09: Rate limiting - rapid login attempts."""
        results: List[ActiveTestResult] = []
        for url in (auth_urls or [])[:2]:
            url = (url or "").strip()
            if not url or not url.startswith(("http://", "https://")):
                continue
            codes = []
            for _ in range(3):
                resp = await _send_login_request(url, ("nonexistent", "wrong"))
                codes.append(resp.get("status_code", 0))
                await asyncio.sleep(0.1)
            if len(set(codes)) == 1 and codes[0] in (200, 401, 403):
                results.append(ActiveTestResult(
                    url=url,
                    payload={"test": "rapid_attempts"},
                    status_code=codes[0],
                    success=True,
                    confidence="low",
                    evidence="No rate limiting observed (3 rapid attempts same response)",
                    owasp_category="A09:2021",
                    severity="low",
                ))
            await asyncio.sleep(0.3)
        return results

    @staticmethod
    async def test_a10_ssrf(
        discovered_urls: List[str], target: str
    ) -> List[ActiveTestResult]:
        """A10: SSRF - param accepts URL, test with internal."""
        results: List[ActiveTestResult] = []
        for url in (discovered_urls or [])[:5]:
            url = (url or "").strip()
            if not url or "?" not in url or not url.startswith(("http://", "https://")):
                continue
            for param in ("url", "uri", "path", "src", "redirect", "next"):
                if param in url.lower():
                    test_url = f"{url}&{param}=http://127.0.0.1" if "&" in url else f"{url}&{param}=http://127.0.0.1"
                    try:
                        resp = await _http_request("GET", test_url, timeout=5.0)
                        sc = resp.get("status_code", 0)
                        if sc in (200, 302, 500) and "error" not in resp.get("body", "").lower()[:200]:
                            results.append(ActiveTestResult(
                                url=test_url,
                                payload={"param": param, "value": "http://127.0.0.1"},
                                status_code=sc,
                                success=True,
                                confidence="low",
                                evidence=f"SSRF candidate: {param} accepted URL",
                                owasp_category="A10:2021",
                                severity="medium",
                            ))
                    except Exception:
                        pass
                    break
            await asyncio.sleep(0.2)
        return results[:2]

    @staticmethod
    async def run_owasp_tests(
        discovered_urls: List[str],
        owasp_category: str,
        target: str,
    ) -> List[ActiveTestResult]:
        """Run active tests for the given OWASP category."""
        if not discovered_urls or not owasp_category:
            return []
        results: List[ActiveTestResult] = []
        classified = EndpointClassifier.classify(discovered_urls)
        auth_urls = EndpointClassifier.get_by_type(classified, "auth")
        if not auth_urls and discovered_urls:
            base = discovered_urls[0].rstrip("/").split("?")[0]
            if base.startswith(("http://", "https://")):
                auth_urls = [
                    f"{base}/rest/user/login", f"{base}/login",
                    f"{base}/api/login", f"{base}/auth/login",
                ]
        try:
            if owasp_category == "A01:2021":
                results = await ActiveTester.test_a01_idor(discovered_urls, target)
            elif owasp_category == "A02:2021":
                results = await ActiveTester.test_a02_crypto(discovered_urls, target)
            elif owasp_category == "A03:2021":
                results = await ActiveTester.test_a03_injection(discovered_urls, target)
            elif owasp_category == "A04:2021":
                results = await ActiveTester.test_a04_insecure_design(discovered_urls, target)
            elif owasp_category == "A05:2021":
                results = await ActiveTester.test_a05_misconfig(discovered_urls, target)
            elif owasp_category == "A06:2021":
                results = await ActiveTester.test_a06_components(discovered_urls, target)
            elif owasp_category == "A07:2021":
                results = await ActiveTester.test_a07_default_credentials(auth_urls)
            elif owasp_category == "A08:2021":
                results = await ActiveTester.test_a08_integrity(discovered_urls, target)
            elif owasp_category == "A09:2021":
                results = await ActiveTester.test_a09_logging(auth_urls, target)
            elif owasp_category == "A10:2021":
                results = await ActiveTester.test_a10_ssrf(discovered_urls, target)
        except Exception:
            pass
        return results
