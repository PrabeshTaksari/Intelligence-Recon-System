"""AI-powered report content generation using Gemini. Reports are strictly AI-only; no fallbacks."""
import asyncio
import html
import json
import httpx
from typing import Dict, Any, List, Optional

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

GEMINI_MAX_RETRIES = 3

def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicate findings across tools to avoid over-counting the same issue.
    Keyed on vulnerability/template + location.
    """
    unique = {}
    for f in findings:
        key = (
            f.get("description") or f.get("template_id") or "",
            f.get("location") or ""
        )
        if key not in unique:
            unique[key] = f
    return list(unique.values())

def _429_backoff_seconds(attempt: int) -> int:
    """Seconds to wait before retry on 429. Uses GEMINI_429_BACKOFF_BASE (default 3 → 3, 6, 12)."""
    base = getattr(settings, "GEMINI_429_BACKOFF_BASE", 3) or 3
    return base * (2 ** attempt)


async def _post_one_backend_with_retry(
    url: str, payload: Dict[str, Any], timeout: float
) -> httpx.Response:
    """POST to one Gemini URL with retries on 429 and connection/DNS errors. Raises when exhausted."""
    last_error: Optional[Exception] = None
    last_response: Optional[httpx.Response] = None
    for attempt in range(GEMINI_MAX_RETRIES):
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(url, json=payload)
                last_response = resp
                if resp.status_code == 200:
                    return resp
                if resp.status_code == 429 and attempt < GEMINI_MAX_RETRIES - 1:
                    wait = _429_backoff_seconds(attempt)
                    logger.warning(
                        "Gemini 429 rate limit, retry %s/%s in %ss (quota resets midnight Pacific)",
                        attempt + 1,
                        GEMINI_MAX_RETRIES,
                        wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                resp.raise_for_status()
        except (httpx.ConnectError, OSError) as e:
            last_error = e
            if attempt < GEMINI_MAX_RETRIES - 1:
                wait = _429_backoff_seconds(attempt)
                logger.warning(
                    "Gemini connection/DNS error (retry %s/%s in %ss): %s",
                    attempt + 1,
                    GEMINI_MAX_RETRIES,
                    wait,
                    e,
                )
                await asyncio.sleep(wait)
            else:
                raise
    if last_error:
        raise last_error
    if last_response is not None:
        last_response.raise_for_status()
    raise RuntimeError("Gemini request failed after retries")


async def _gemini_post_with_retry(
    payload: Dict[str, Any], timeout: float = 20.0
) -> httpx.Response:
    """POST to Gemini: try each configured backend (model+key). On 429 or connection failure, try next."""
    backends = settings.get_gemini_backends()
    if not backends:
        raise ValueError(
            "Report generation requires AI (Gemini). Set GEMINI_API_KEY or GEMINI_BACKENDS in environment."
        )
    last_error: Optional[Exception] = None
    base_url = "https://generativelanguage.googleapis.com/v1beta/models"
    for model, key in backends:
        url = f"{base_url}/{model}:generateContent?key={key}"
        try:
            return await _post_one_backend_with_retry(url, payload, timeout)
        except (httpx.HTTPStatusError, httpx.ConnectError, OSError, RuntimeError) as e:
            last_error = e
            status = getattr(getattr(e, "response", None), "status_code", None)
            if status == 429 or isinstance(e, (httpx.ConnectError, OSError)):
                logger.warning(
                    "Backend %s failed (%s), trying next backend if any.",
                    model,
                    e,
                )
                continue
            raise
    if last_error:
        status = getattr(getattr(last_error, "response", None), "status_code", None)
        if status == 429:
            logger.info(
                "All Gemini backends returned 429. Quota resets at midnight Pacific Time. "
                "Use an API key from a different Google Cloud project for a separate quota."
            )
        raise last_error
    raise RuntimeError("All Gemini backends failed")


def _parse_ai_json(text: str) -> Dict[str, Any]:
    """Parse JSON from AI response, with repair attempts for truncated/malformed output."""
    if not text or not text.strip():
        raise ValueError("AI returned empty response.")
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1].rstrip("`").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        logger.warning("AI JSON parse failed: %s; attempting repair. Snippet: %s", e, text[:200])
    # Repair: truncated string (model cut off mid-response)
    for suffix in ["\"}", "}", "\"]}", "]}"]:
        try:
            return json.loads(text + suffix)
        except json.JSONDecodeError:
            continue
    # Try truncating to last complete object
    last_brace = text.rfind("}")
    if last_brace > 0:
        try:
            return json.loads(text[: last_brace + 1])
        except json.JSONDecodeError:
            pass
    raise ValueError(
        "Report generation failed: AI returned an invalid or truncated response. "
        "Please try generating the report again."
    )


def _require_gemini_api_key() -> None:
    """Raise if no Gemini backend is configured. Reports must be generated by AI only."""
    if not settings.get_gemini_backends():
        raise ValueError(
            "Report generation requires AI (Gemini). Set GEMINI_API_KEY or GEMINI_BACKENDS in environment."
        )


async def generate_report_executive_summary(
    target: str,
    owasp_category: str,
    owasp_name: str,
    severity_counts: Dict[str, int],
    tools_used: List[str],
    top_findings: List[Dict[str, Any]],
) -> str:
    """Generate AI executive summary for the scan report. AI only; no fallback."""
    _require_gemini_api_key()

    prompt = f"""You are a professional security analyst. Write a concise 2-4 sentence executive summary for a security scan report.

Scan context:
- Target: {target}
- Attack Type: {owasp_category} - {owasp_name}
- Tools used: {', '.join(tools_used) if tools_used else 'N/A'}
- Severity breakdown: Critical={severity_counts.get('critical',0)}, High={severity_counts.get('high',0)}, Medium={severity_counts.get('medium',0)}, Low={severity_counts.get('low',0)}, Info={severity_counts.get('info',0)}

Top findings (if any):
{chr(10).join(f"- {f.get('severity','')}: {f.get('description','')[:100]}" for f in top_findings[:5]) if top_findings else "None"}

Write a professional executive summary. Example style: "The target domain X was analyzed for OWASP Top 10 vulnerabilities. Multiple medium and high severity issues were identified including [types]. Immediate remediation is recommended."
If no serious issues: "The target was analyzed. No critical or high severity vulnerabilities were detected. [X] informational findings were documented."
Output ONLY the summary paragraph, no headings or labels."""

    try:
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.3, "maxOutputTokens": 512},
        }
        resp = await _gemini_post_with_retry(payload, timeout=15.0)
        text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
        return text.strip()
    except Exception as e:
        logger.warning("AI executive summary failed: %s", e)
        raise


async def generate_report_conclusion(
    target: str,
    severity_counts: Dict[str, int],
    findings_count: int,
    recommendations: List[str],
) -> str:
    """Generate AI conclusion and remediation summary for the report. AI only; no fallback."""
    _require_gemini_api_key()

    prompt = f"""You are a security consultant. Write a 3-5 sentence conclusion and remediation summary for a security scan report.

Context:
- Target: {target}
- Total findings: {findings_count}
- Severity: Critical={severity_counts.get('critical',0)}, High={severity_counts.get('high',0)}, Medium={severity_counts.get('medium',0)}, Low={severity_counts.get('low',0)}, Info={severity_counts.get('info',0)}

Existing recommendations to incorporate:
{chr(10).join('- ' + r for r in recommendations[:8]) if recommendations else 'None'}

Write a professional conclusion that summarizes the security posture and provides actionable remediation guidance. Include technical implementation options where relevant (e.g., parameterized queries for SQLi, security headers, input validation).
Output ONLY the conclusion paragraph(s), no headings."""

    try:
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.3, "maxOutputTokens": 1024},
        }
        resp = await _gemini_post_with_retry(payload, timeout=20.0)
        text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
        return text.strip()
    except Exception as e:
        logger.warning("AI conclusion failed: %s", e)
        raise


async def generate_remediation_playbook_table_html(
    findings_payload: List[Dict[str, Any]],
    target: str,
    owasp_label: str,
) -> str:
    """Build an HTML table of per-finding remediation and verification steps for PDF reports.

    Returns a complete <table> element or empty string on failure / no API key / no rows.
    """
    if not findings_payload:
        return ""
    if not settings.get_gemini_backends():
        return ""

    rows_in = findings_payload[:18]
    prompt = f"""You are a senior application security engineer. Produce remediation guidance for a formal PDF report.

Target: {target}
Assessment focus: {owasp_label}

Findings (JSON array, each item has ref, severity, tool, location, description):
{json.dumps(rows_in, ensure_ascii=False, indent=2)}

Output VALID JSON ONLY (no markdown fences):
{{
  "rows": [
    {{
      "ref": <same ref as input>,
      "severity": "<string>",
      "summary": "<=100 chars, what is wrong>",
      "remediation": "<2-4 sentences: concrete technical fixes: config, code patterns, patches, disable default creds, etc.>",
      "verification": "<1-2 sentences: how to retest or confirm fix>"
    }}
  ]
}}

Include one object per input finding, same order, same ref. Use clear professional language. Do not use em dashes."""

    try:
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.25, "maxOutputTokens": 4096},
        }
        resp = await _gemini_post_with_retry(payload, timeout=45.0)
        text = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
        data = _parse_ai_json(text)
        out_rows = data.get("rows")
        if not isinstance(out_rows, list) or not out_rows:
            return ""
        parts = [
            '<table class="irs-remediation-table"><thead><tr>',
            "<th>#</th><th>Severity</th><th>Summary</th><th>Remediation</th><th>Verification</th>",
            "</tr></thead><tbody>",
        ]
        for r in out_rows:
            parts.append("<tr>")
            for key in ("ref", "severity", "summary", "remediation", "verification"):
                cell = r.get(key, "")
                parts.append(f"<td>{html.escape(str(cell))}</td>")
            parts.append("</tr>")
        parts.append("</tbody></table>")
        return "".join(parts)
    except Exception as e:
        logger.warning("Remediation playbook AI generation failed: %s", e)
        raise


def _fallback_executive_summary(
    target: str,
    owasp_category: str,
    severity_counts: Dict[str, int],
    tools_used: List[str],
) -> str:
    c, h, m, l, i = (
        severity_counts.get("critical", 0),
        severity_counts.get("high", 0),
        severity_counts.get("medium", 0),
        severity_counts.get("low", 0),
        severity_counts.get("info", 0),
    )
    total = c + h + m + l + i
    vuln = c + h + m
    if vuln > 0:
        return (
            f"The target domain {target} was analyzed for {owasp_category} vulnerabilities. "
            f"Multiple severity issues were identified: {c} critical, {h} high, {m} medium. "
            f"Tools used: {', '.join(tools_used) if tools_used else 'N/A'}. "
            "Immediate remediation is recommended for critical and high severity findings."
        )
    return (
        f"The target {target} was analyzed for {owasp_category}. "
        f"No critical or high severity vulnerabilities were detected. "
        f"{total} informational reconnaissance items were documented. "
        "Target appears secure for the scope tested."
    )


async def generate_attack_relevance_content(
    target: str,
    owasp_category: str,
    owasp_name: str,
    findings_summary: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Generate AI-written attack relevance summary and bullets. AI only; no fallback."""
    _require_gemini_api_key()

    findings_text = "\n".join(
        f"- Tool: {f.get('tool', '')} | Severity: {f.get('severity', '')} | Location: {f.get('location', '')[:80]} | Description: {f.get('description', '')[:150]}"
        for f in findings_summary[:30]
    )
    prompt = f"""You are a security analyst. Based ONLY on the scan findings below, write how they relate to the chosen OWASP attack type. Use only the information from the findings. Do not use em dashes (—). Use colons or full sentences instead.

Target: {target}
Chosen attack type: {owasp_category} - {owasp_name}

Findings (tool, severity, location, description):
{findings_text}

Output valid JSON only, no markdown or extra text:
{{"relevance_summary": "2-4 sentences explaining how these findings relate to the attack type and whether they could support this kind of attack. Base every claim on the findings listed above.", "detail_bullets": ["bullet 1 based on findings", "bullet 2", "bullet 3", "up to 5 bullets"], "can_support_attack": true or false}}

Set can_support_attack to true only if there are critical, high, or medium severity findings that could be exploited for this attack type. Otherwise false. All text must be grounded in the findings; no generic phrases."""

    try:
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.25, "maxOutputTokens": 2048},
        }
        for attempt in range(2):
            try:
                resp = await _gemini_post_with_retry(payload, timeout=25.0)
                text = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
                data = _parse_ai_json(text)
                return {
                    "relevance_summary": data.get("relevance_summary", ""),
                    "detail_bullets": data.get("detail_bullets", [])
                    if isinstance(data.get("detail_bullets"), list)
                    else [],
                    "can_support_attack": bool(data.get("can_support_attack", False)),
                }
            except ValueError:
                if attempt == 0:
                    logger.info("AI attack relevance JSON parse failed, retrying once.")
                else:
                    raise
            except Exception as e:
                if attempt == 0:
                    logger.warning("AI attack relevance request failed, retrying once: %s", e)
                else:
                    logger.warning("AI attack relevance failed: %s", e)
                    raise
    except ValueError:
        raise
    except Exception as e:
        logger.warning("AI attack relevance failed: %s", e)
        raise


def _fallback_attack_relevance(
    target: str,
    owasp_category: str,
    owasp_name: str,
    findings_summary: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Fallback attack relevance based on findings. No em dashes."""
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    tools_set = set()
    for f in findings_summary:
        sev = (f.get("severity") or "").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
        if f.get("tool"):
            tools_set.add(str(f["tool"]).strip())
    vuln_count = (
        severity_counts["critical"] + severity_counts["high"] + severity_counts["medium"]
    )
    info_low = severity_counts["info"] + severity_counts["low"]
    tools_list = ", ".join(sorted(tools_set)) if tools_set else "None"

    if vuln_count > 0:
        relevance_summary = (
            f"This scan of {target} for {owasp_name} ({owasp_category}) found {vuln_count} "
            f"{'finding' if vuln_count == 1 else 'findings'} at critical, high, or medium severity. These could be exploitable in the context of this attack type and should be remediated."
        )
        detail_bullets = [
            f"{vuln_count} vulnerability {'finding' if vuln_count == 1 else 'findings'} may be exploitable for this attack type.",
            f"Tools that produced findings: {tools_list}.",
            f"Recommendation: fix the identified issues to reduce risk of {owasp_name.lower()}.",
        ]
        can_support_attack = True
    else:
        relevance_summary = (
            f"The scan targeted {target} for attack type {owasp_name} ({owasp_category}). "
            "Findings are reconnaissance and informational in nature: open ports, URLs, or subdomains. "
            "No critical, high, or medium vulnerabilities were found that would directly enable this attack type."
        )
        detail_bullets = [
            f"Tools that produced findings: {tools_list}.",
            f"{info_low} discovery {'item' if info_low == 1 else 'items'} help map the target but are not direct attack vectors.",
            f"To assess vulnerability to {owasp_name.lower()}, run vulnerability scanners and review results.",
        ]
        can_support_attack = False
    return {
        "relevance_summary": relevance_summary,
        "detail_bullets": detail_bullets,
        "can_support_attack": can_support_attack,
    }


async def classify_key_findings_table(
    findings: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Use AI to classify each finding into the right table column. Returns key_findings_table with columns + rows, or None on failure.
    Only call when INTELLIGENCE_AI_ENABLED and findings list is non-empty. Creates new columns when AI sees a new type of data."""
    if not findings:
        return None
    backends = settings.get_gemini_backends()
    if not backends:
        return None

    lines = []
    for i, f in enumerate(findings[:15]):
        tool = f.get("tool") or ""
        severity = f.get("severity") or ""
        location = (f.get("location") or "")[:100]
        desc = (f.get("description") or "")[:150]
        lines.append(f"{i}: tool={tool} | severity={severity} | location={location} | description={desc}")

    prompt = f"""You are classifying security scan findings for a "Key Findings" table. For each finding below, decide which column the main value belongs in.

Findings (index, tool, severity, location, description):
{chr(10).join(lines)}

Standard columns (use these when they fit):
- "Open ports": port number or URL/target (e.g. 80, http://example.com:443)
- "IP found": only actual IP addresses or text like "Subdomain discovered: x"
- "Service": HTTP service banner (e.g. "HTTP service: 200 - title")
- "Template": Nuclei template name or scan result type (e.g. "WAF Detection", "AAAA Record - IPv6 Detection")

If a finding's description does not fit any standard column, invent ONE new column name (e.g. "Detection", "Note") and put the value there. Use "—" for empty cells.

Return valid JSON only, no markdown:
{{"columns": ["Tool name", "Open ports", "IP found", "Service", "Template", ...], "rows": [{{"Tool name": "Naabu", "Open ports": "80", "IP found": "1.2.3.4", "Service": "—", "Template": "—"}}, ...]}}

Rules:
- First two columns must be "Tool name" and "Open ports". Include "IP found", "Service", "Template" only if at least one row has a non-dash value. Add any new column names you invent at the end.
- Each row must have exactly the same keys as in "columns"; use "—" for empty. Tool name = tool from the finding; you can add severity as part of "Tool name" like "info Naabu" or keep separate - your choice.
- One row per finding, same order as input (0 to n). Do not skip findings."""

    try:
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 4096},
        }
        resp = await _gemini_post_with_retry(payload, timeout=25.0)
        text = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
        data = _parse_ai_json(text)
        cols = data.get("columns")
        rows = data.get("rows")
        if not isinstance(cols, list) or not isinstance(rows, list):
            return None
        # Normalize columns: non-empty strings only, max 12 columns to avoid runaway UI
        cols = [str(c).strip()[:80] for c in cols if c is not None and str(c).strip()]
        if not cols or len(cols) > 12:
            return None
        # Normalize rows: each row must be a dict with all column keys; fill missing with "—"
        out_rows = []
        for i, r in enumerate(rows[:20]):  # cap at 20 rows
            if not isinstance(r, dict):
                continue
            out_rows.append({c: ("—" if (r.get(c) is None or str(r.get(c)).strip() == "") else str(r.get(c)).strip()[:500]) for c in cols})
        if not out_rows:
            return None
        return {"columns": cols, "rows": out_rows}
    except Exception as e:
        logger.warning("AI Key Findings classification failed: %s", e)
        return None


async def generate_ai_analysis_content(
    target: str,
    severity_counts: Dict[str, int],
    tools_with_findings: List[str],
    findings_summary: List[Dict[str, Any]],
    risk_level: str,
    risk_score: int,
) -> Dict[str, Any]:
    """Generate AI Analysis section. AI only; no fallback."""
    _require_gemini_api_key()

    findings_text = "\n".join(
        f"- {f.get('tool','')} | {f.get('severity','')} | {f.get('location','')[:60]} | {f.get('description','')[:100]}"
        for f in findings_summary[:25]
    )
    prompt = f"""You are a security analyst. Analyze ONLY the scan output below. Do NOT use generic phrases. Reference only what was actually found.

Scan output:
- Target: {target}
- Risk: {risk_level} (score {risk_score}/100)
- Severity: Critical={severity_counts.get('critical',0)}, High={severity_counts.get('high',0)}, Medium={severity_counts.get('medium',0)}, Low={severity_counts.get('low',0)}, Info={severity_counts.get('info',0)}
- Tools that produced findings: {', '.join(tools_with_findings) if tools_with_findings else 'None'}

Findings:
{findings_text if findings_text.strip() else 'No findings'}

Output valid JSON only, no markdown:
{{"assessment": "2-3 sentences describing what the scan actually found. Reference specific tools and findings. No generic advice.", "confidence_score": 0-100, "recommendation": "One sentence recommendation based ONLY on what was found. If no vulns, say so. If low/info only, mention that."}}

Rules: assessment and recommendation must be grounded in the data above. No "Read the detailed findings" or similar. confidence_score reflects how well the scan covered the target."""

    try:
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 2048},
        }
        for attempt in range(2):
            try:
                resp = await _gemini_post_with_retry(payload, timeout=25.0)
                text = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
                data = _parse_ai_json(text)
                return {
                    "assessment": data.get("assessment", ""),
                    "confidence_score": min(100, max(0, int(data.get("confidence_score", 50)))),
                    "recommendation": data.get("recommendation", ""),
                }
            except ValueError:
                if attempt == 0:
                    logger.info("AI analysis JSON parse failed, retrying once.")
                else:
                    raise
            except Exception as e:
                if attempt == 0:
                    logger.warning("AI analysis request failed, retrying once: %s", e)
                else:
                    logger.warning("AI analysis generation failed: %s", e)
                    raise
    except ValueError:
        raise
    except Exception as e:
        logger.warning("AI analysis generation failed: %s", e)
        raise


def _fallback_ai_analysis(
    severity_counts: Dict[str, int],
    tools_with_findings: List[str],
    risk_level: str,
    risk_score: int,
    findings_summary: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Fallback: derive content ONLY from actual data. No generic defaults."""
    c, h, m, l, i = (
        severity_counts.get("critical", 0),
        severity_counts.get("high", 0),
        severity_counts.get("medium", 0),
        severity_counts.get("low", 0),
        severity_counts.get("info", 0),
    )
    total = c + h + m + l + i
    vuln = c + h + m
    tools_str = ", ".join(tools_with_findings) if tools_with_findings else "None"

    if vuln > 0:
        assessment = (
            f"Scan found {vuln} vulnerability {'finding' if vuln == 1 else 'findings'}: {c} critical, {h} high, {m} medium. "
            f"Tools: {tools_str}. Risk level {risk_level}."
        )
        recommendation = f"Remediate the {vuln} identified {'issue' if vuln == 1 else 'issues'}."
    elif total > 0:
        assessment = (
            f"Scan produced {total} {'finding' if total == 1 else 'findings'} ({l} low, {i} info). Tools: {tools_str}. "
            f"Risk level {risk_level} (score {risk_score}/100). No critical/high/medium vulnerabilities."
        )
        recommendation = "Findings are discovery data or low severity. No immediate remediation required."
    else:
        assessment = f"No findings from scan. Tools: {tools_str}. Risk: {risk_level}."
        recommendation = "Scan completed with no findings."
    return {
        "assessment": assessment,
        "confidence_score": min(100, 50 + len(tools_with_findings) * 10) if tools_with_findings else 40,
        "recommendation": recommendation,
    }


async def generate_actionable_intelligence_content(
    target: str,
    severity_counts: Dict[str, int],
    findings_summary: List[Dict[str, Any]],
    tools_with_findings: List[str],
) -> Dict[str, Any]:
    """Generate Actionable Intelligence. AI only; no fallback."""
    _require_gemini_api_key()

    findings_text = "\n".join(
        f"- {f.get('severity','')}: {f.get('tool','')} | {f.get('location','')[:50]} | {f.get('description','')[:80]}"
        for f in findings_summary[:20]
    )
    prompt = f"""You are a security consultant. Based ONLY on the scan output below, provide actionable intelligence. Do NOT include generic advice like "Read the detailed findings" or "Fix Critical and High first" unless those severities exist in the data.

Scan output:
- Target: {target}
- Severity: Critical={severity_counts.get('critical',0)}, High={severity_counts.get('high',0)}, Medium={severity_counts.get('medium',0)}, Low={severity_counts.get('low',0)}, Info={severity_counts.get('info',0)}
- Tools: {', '.join(tools_with_findings) if tools_with_findings else 'None'}

Findings:
{findings_text if findings_text.strip() else 'No findings'}

Output valid JSON only, no markdown:
{{"priority_recommendations": ["rec 1 based on findings", "rec 2", "up to 5 items - each must reference specific findings or severities that exist"], "next_steps": ["step 1", "step 2", "up to 4 - each grounded in the data"], "remediation_timeline": {{"critical": "N/A or timeline", "high": "...", "medium": "...", "low": "..."}}}}

Rules: Only include recommendations/steps for severities that exist. If no critical/high/medium, set those timeline values to "N/A". No generic placeholders."""

    try:
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 2048},
        }
        for attempt in range(2):
            try:
                resp = await _gemini_post_with_retry(payload, timeout=25.0)
                text = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
                data = _parse_ai_json(text)
                return {
                    "priority_recommendations": data.get("priority_recommendations", [])
                    if isinstance(data.get("priority_recommendations"), list)
                    else [],
                    "next_steps": data.get("next_steps", [])
                    if isinstance(data.get("next_steps"), list)
                    else [],
                    "remediation_timeline": data.get("remediation_timeline", {})
                    if isinstance(data.get("remediation_timeline"), dict)
                    else {},
                }
            except ValueError:
                if attempt == 0:
                    logger.info("Actionable intelligence JSON parse failed, retrying once.")
                else:
                    raise
            except Exception as e:
                if attempt == 0:
                    logger.warning("Actionable intelligence request failed, retrying once: %s", e)
                else:
                    logger.warning("Actionable intelligence generation failed: %s", e)
                    raise
    except ValueError:
        raise
    except Exception as e:
        logger.warning("Actionable intelligence generation failed: %s", e)
        raise


def _fallback_actionable_intelligence(
    severity_counts: Dict[str, int],
    findings_summary: List[Dict[str, Any]],
    tools_with_findings: List[str],
) -> Dict[str, Any]:
    """Fallback: derive content ONLY from actual data. No generic defaults."""
    c, h, m, l, i = (
        severity_counts.get("critical", 0),
        severity_counts.get("high", 0),
        severity_counts.get("medium", 0),
        severity_counts.get("low", 0),
        severity_counts.get("info", 0),
    )
    vuln = c + h + m
    recs = []
    steps = []
    timeline = {"critical": "N/A", "high": "N/A", "medium": "N/A", "low": "N/A"}

    if c > 0:
        recs.append(f"Address {c} critical {'finding' if c == 1 else 'findings'} immediately.")
        timeline["critical"] = "24 hours"
    if h > 0:
        recs.append(f"Remediate {h} high severity {'finding' if h == 1 else 'findings'} within 7 days.")
        timeline["high"] = "7 days"
    if m > 0:
        recs.append(f"Plan fixes for {m} medium severity {'finding' if m == 1 else 'findings'}.")
        timeline["medium"] = "30 days"
    if l > 0:
        recs.append(f"{l} low severity {'finding' if l == 1 else 'findings'} can be addressed in next maintenance.")
        timeline["low"] = "90 days"
    if i > 0 and vuln == 0:
        recs.append(f"{i} informational {'finding' if i == 1 else 'findings'} documented for mapping. No remediation required.")

    if vuln > 0:
        steps = [
            "Review each finding in the report for context.",
            "Apply fixes for critical and high first.",
            "Re-scan after remediation to verify.",
        ]
    elif c + h + m + l + i > 0:
        steps = [
            "Review findings in the report.",
            "Re-scan periodically to monitor changes.",
        ]
    else:
        steps = ["No findings to act on. Consider expanding scan scope."]

    return {
        "priority_recommendations": recs[:5] if recs else [],
        "next_steps": steps[:4],
        "remediation_timeline": timeline,
    }


def _fallback_conclusion(
    severity_counts: Dict[str, int],
    recommendations: List[str],
) -> str:
    c, h, m = (
        severity_counts.get("critical", 0),
        severity_counts.get("high", 0),
        severity_counts.get("medium", 0),
    )
    vuln = c + h + m
    parts = []
    if vuln > 0:
        parts.append(
            f"This scan identified {vuln} security {'issue' if vuln == 1 else 'issues'} requiring attention. "
        )
        if c > 0:
            parts.append("Critical issues should be fixed within 24 hours. ")
        if h > 0:
            parts.append("High severity issues within 7 days. ")
        parts.append(
            "Technical remediation: use parameterized queries for injection, enable security headers, "
            "apply input validation, and keep components updated."
        )
    else:
        parts.append(
            "No serious vulnerabilities were detected. Keep security practices in place and run scans regularly."
        )
    if recommendations:
        parts.append(" " + recommendations[0] if recommendations else "")
    return "".join(parts)

