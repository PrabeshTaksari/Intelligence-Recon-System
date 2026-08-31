"""AI Decision Node using Gemini for tool selection."""
import json
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import httpx

from app.core.config import settings
from app.core.logging import get_logger
from app.ai.prompts import build_decision_prompt
from app.ai.report_generator import _gemini_post_with_retry

# Fixed safe fallback tools used when AI decision is unavailable or invalid.
SAFE_FALLBACK_TOOLS = ["Naabu", "Httpx", "Nuclei", "Subfinder", "DNSx"]

logger = get_logger(__name__)


@dataclass
class AIDecision:
    """AI decision result."""
    tools_to_run: List[str]
    tools_skipped: List[Dict[str, str]]
    execution_batches: Optional[List[List[str]]] = None
    reasoning: Optional[str] = None
    raw_response: Optional[str] = None
    success: bool = True
    error: Optional[str] = None


async def decide_tools(
    target: str,
    owasp_category: str,
    owasp_name: str,
    selected_tools: List[str],
    clues: Dict[str, Any]
) -> AIDecision:
    """Call Gemini AI to decide which tools to run."""
    logger.info(f"Requesting AI decision for target={target}, owasp={owasp_category}")

    if not settings.get_gemini_backends():
        logger.error("No Gemini backend configured (GEMINI_API_KEY or GEMINI_BACKENDS)")
        return _fallback_decision(
            selected_tools,
            "Gemini API key not configured",
            raw_response=None,
        )

    try:
        prompt = build_decision_prompt(
            target, owasp_category, owasp_name, selected_tools, clues
        )
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 8192,
            },
        }
        # Uses multi-backend + retries (429/connection → try next model/key)
        response = await _gemini_post_with_retry(payload, timeout=30.0)
        result = response.json()

        # Extract response text
        try:
            response_text = result["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError) as e:
            logger.error(f"Unexpected Gemini response structure: {e}")
            return _fallback_decision(
                selected_tools,
                "Invalid API response structure",
                raw_response=json.dumps(result),
            )

        logger.info(f"Raw AI response: {response_text}")

        # Parse JSON from response (tolerant)
        decision_data = _parse_json_response(response_text)

        if not decision_data:
            logger.error(f"Failed to parse AI response as JSON. Response length: {len(response_text)}")
            logger.debug(f"Full response that failed to parse: {response_text[:500]}...")  # Log first 500 chars
            return _fallback_decision(
                selected_tools,
                "Failed to parse AI response",
                raw_response=response_text,
            )

        # Merge tools_to_run and tools_added so AI-recommended additions (e.g. Httpx, GoSpider) are actually run
        tools_from_run = decision_data.get("tools_to_run", []) or []
        tools_from_added = [
            item.get("tool")
            for item in decision_data.get("tools_added", []) or []
            if isinstance(item, dict) and item.get("tool")
        ]
        all_tools = list(dict.fromkeys(tools_from_run + tools_from_added))
        valid_tools = [
            tool for tool in all_tools
            if tool in settings.AVAILABLE_TOOLS
        ]

        if not valid_tools:
            logger.warning("AI returned no valid tools, using fallback")
            return _fallback_decision(
                selected_tools,
                "No valid tools in AI response",
                raw_response=response_text,
            )

        # IMPORTANT: Only include skipped tools if user selected them
        # Do not show tools as "skipped" if user never selected them
        skipped_tools = decision_data.get("tools_skipped", [])
        filtered_skipped = [
            skip for skip in skipped_tools
            if skip.get("tool") in selected_tools  # Only if user selected this tool
        ]

        # Guardrail: avoid contradictory AI output (same tool in both run + skipped).
        # If it happens, prefer the "skip" instruction for execution consistency.
        skipped_tool_names = {
            str(skip.get("tool")).strip()
            for skip in filtered_skipped
            if isinstance(skip, dict) and skip.get("tool")
        }
        if skipped_tool_names:
            valid_tools = [t for t in valid_tools if str(t).strip() not in skipped_tool_names]
        
        # Log tools that AI wanted to skip but user didn't select (these are ignored)
        all_skipped_from_ai = [skip.get("tool") for skip in skipped_tools]
        non_selected_skipped = [
            tool for tool in all_skipped_from_ai
            if tool not in selected_tools
        ]
        if non_selected_skipped:
            logger.info(f"AI suggested skipping tools user didn't select (ignored): {non_selected_skipped}")

        return AIDecision(
            tools_to_run=valid_tools,
            tools_skipped=filtered_skipped,  # Only user-selected tools that should be skipped
            execution_batches=decision_data.get("execution_batches"),
            reasoning=decision_data.get("reasoning"),
            raw_response=response_text,
            success=True,
            error=None,
        )

    except httpx.HTTPError as e:
        logger.error(f"Gemini API HTTP error: {e}")
        # User-friendly message for rate limit (429); quota resets at midnight Pacific
        status = getattr(getattr(e, "response", None), "status_code", None)
        if status == 429:
            reason = (
                "Gemini rate limit (429). Free tier quotas reset at midnight Pacific Time. "
                "Try again later, or add an API key from a different Google Cloud project "
                "(keys from the same project share the same quota)."
            )
        else:
            reason = f"API error: {str(e)}"
        return _fallback_decision(selected_tools, reason, raw_response=None)
    except Exception as e:
        logger.error(f"Unexpected error in AI decision: {e}", exc_info=True)
        return _fallback_decision(
            selected_tools,
            f"Unexpected error: {str(e)}",
            raw_response=None,
        )


def _parse_json_response(response_text: str) -> Optional[Dict[str, Any]]:
    """Parse JSON from AI response, handling markdown and extra text.

    Returns parsed JSON dict, or None if parsing fails.
    """
    if not response_text:
        return None

    # 1) Try direct JSON first
    try:
        return json.loads(response_text)
    except json.JSONDecodeError:
        pass

    lower = response_text.lower()

    # 2) Try extracting from ```json code block
    if "```json" in lower:
        try:
            start_block = lower.index("```json")
            start = response_text.index("{", start_block)
            # Find matching closing brace (handle nested objects)
            brace_count = 0
            end = start
            for i in range(start, len(response_text)):
                if response_text[i] == "{":
                    brace_count += 1
                elif response_text[i] == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        end = i + 1
                        break
            json_str = response_text[start:end]
            return json.loads(json_str)
        except (ValueError, json.JSONDecodeError, IndexError):
            pass

    # 3) Try extracting the first {...} JSON object anywhere (with proper brace matching)
    try:
        start = response_text.index("{")
        brace_count = 0
        end = start
        for i in range(start, len(response_text)):
            if response_text[i] == "{":
                brace_count += 1
            elif response_text[i] == "}":
                brace_count -= 1
                if brace_count == 0:
                    end = i + 1
                    break
        json_str = response_text[start:end]
        return json.loads(json_str)
    except (ValueError, json.JSONDecodeError, IndexError):
        pass

    return None


def _fallback_decision(
    selected_tools: List[str],
    reason: str,
    raw_response: Optional[str],
) -> AIDecision:
    """Generate fallback decision when AI fails."""
    logger.info(f"Using fallback decision: {reason}")

    # Use user-selected tools only; never auto-select tools when none were chosen
    tools_to_run = [t for t in selected_tools if t in settings.AVAILABLE_TOOLS]

    return AIDecision(
        tools_to_run=tools_to_run,
        tools_skipped=[],
        execution_batches=None,
        reasoning=f"Fallback decision used: {reason}",
        raw_response=raw_response,
        success=False,
        error=reason,
    )
