"""Prompt templates for AI decision node."""


TOOL_DESCRIPTIONS = {
    "Nuclei": "Fast vulnerability scanner with extensive template library for detecting security issues across web applications, APIs, and network services. Excellent for all OWASP categories.",
    "Naabu": "High-speed port scanner to discover open ports and services. Essential for initial reconnaissance and A05 (Security Misconfiguration).",
    "Httpx": "HTTP probe to analyze web servers, status codes, headers, titles, and technologies. Critical for initial clues and all web-based OWASP categories.",
    "Subfinder": "Passive subdomain discovery tool using multiple sources. Essential for asset discovery (A01, A05, A10).",
    "Amass": "Comprehensive subdomain enumeration and network mapping. Deep reconnaissance for all categories.",
    "Assetfinder": "Fast subdomain discovery tool. Good for quick asset enumeration (A01, A05).",
    "Sublist3r": "Subdomain enumeration using search engines. Complements other subdomain tools.",

    "GAU": "GetAllURLs - fetches known URLs from AlienVault's OTX, Wayback Machine, and Common Crawl. Excellent for A01, A03, A05, A10.",
    "Katana": "Next-generation web crawler for gathering URLs, endpoints, and parameters. Essential for A01, A03, A05.",
    "GoSpider": "Fast web spider for crawling and extracting endpoints. Good for A01, A03, A07.",
    "FFuf": "Fast web fuzzer for directory/file brute-forcing and parameter discovery. Critical for A01, A03, A05.",
    "Wfuzz": "Web application fuzzer for security testing and OWASP attack vector discovery. Excellent for A01, A03, A04, A07 - specializes in access control and injection testing.",
    "CeWL": "Custom wordlist generator from web content for password attacks. Useful for A07 (Authentication Failures).",
    "DNSx": "Fast DNS toolkit for DNS enumeration and validation. Important for A05, A10.",
    "ShuffleDNS": "Subdomain bruteforcer with wildcard detection. Useful when passive methods are insufficient."
}


def build_decision_prompt(
    target: str,
    owasp_category: str,
    owasp_name: str,
    selected_tools: list,
    clues: dict
) -> str:
    """Build the prompt for Gemini AI decision node.

    Args:
        target: Target domain
        owasp_category: OWASP category ID (e.g., A01:2021)
        owasp_name: Full OWASP category name
        selected_tools: List of tools user selected
        clues: Dictionary containing initial reconnaissance data

    Returns:
        Formatted prompt string
    """
    tools_list = "\n".join(
        [f"- {tool}: {desc}" for tool, desc in TOOL_DESCRIPTIONS.items()]
    )

    clues_summary = f"""
Initial Reconnaissance Clues:
- Open Ports: {clues.get('open_ports', 'None detected')}
- HTTP Services: {clues.get('http_services', 'None detected')}
- Server Headers: {clues.get('server_headers', 'None detected')}
- Page Titles: {clues.get('page_titles', 'None detected')}
- Status Codes: {clues.get('status_codes', 'None detected')}
- Technologies Detected: {clues.get('technologies', 'None detected')}
"""

    selected_tools_str = ", ".join(selected_tools) if selected_tools else "All tools available"

    prompt = f"""You are an expert security reconnaissance AI helping to optimize tool selection for OWASP Top 10 security assessments.

## Mission
Analyze the target and initial reconnaissance clues to decide which security tools should be executed for maximum efficiency and relevance.

## Target Information
- Domain: {target}
- OWASP Focus: {owasp_category} - {owasp_name}
- User Selected Tools: {selected_tools_str}

{clues_summary}

## Available Tools
{tools_list}

## Your Task
Based on the target, OWASP category, user selections, and initial clues, decide:
1. Which tools are most relevant and should run
2. Which tools should be skipped and why
3. Optional: Suggest execution order/batches for parallel execution

## Decision Rules
1. ONLY use tool names from the list above - never invent new names.
2. IMPORTANT: Start with user-selected tools as the base set.
3. Analyze initial clues to decide:
   - Which user-selected tools should be SKIPPED (not run) based on clues
   - Which additional tools should be ADDED based on what clues revealed
4. Prefer a SMALL, focused subset (3–6 tools) when clues are minimal. Do NOT run many tools that often find nothing.
5. Consider the clues:
   - If no web ports are open, skip HTTP-only tools.
   - If specific technologies are detected, recommend relevant tools.
   - If the target has many subdomains, add crawlers and fuzzers.
6. Match tools to the OWASP category focus.
7. Respect user's initial selection - don't replace it, enhance it.

## Avoid tools that find nothing (CRITICAL)
Many tools often return ZERO findings for typical targets. Do not recommend a long list when clues are minimal:
- Sublist3r, Subfinder, DNSx, Amass, Assetfinder: For most domains these find 0 or very few subdomains. Run at most ONE of them (e.g. Subfinder only) unless you have strong reason to expect many subdomains. Do NOT run Sublist3r + Subfinder + DNSx together "to be thorough"—they duplicate work and often all return nothing.
- GAU: Often returns 0 URLs for many targets. Skip GAU unless the domain is well-known or clues suggest rich history.
- FFuf, Wfuzz: Need a URL list and wordlist; with only one base URL they often find little. Prefer skipping when clues show no discovered paths/endpoints yet.
- When clues show only "Open Ports: 80" and "HTTP Services: None detected" or empty: recommend a MINIMAL set: Naabu, Httpx, one subdomain tool (Subfinder OR Amass, not both), and Nuclei. Skip GAU, FFuf, Wfuzz, Sublist3r, DNSx unless clues show existing URLs or many subdomains.

## Tool Output Requirements (CRITICAL - avoid tools that won't produce output)
Only recommend tools when their required inputs are available. Otherwise they run but produce no useful output:
- GAU, Katana, GoSpider, FFuf, Wfuzz: Require discovered URLs or HTTP services. SKIP these when clues show "None detected" for HTTP Services and no URLs exist yet.
- Nuclei: Works best with at least one URL. Can run with base URL if Httpx/Naabu found a web port.
- Subfinder, Amass, Assetfinder, Sublist3r: Require a valid domain. Run at most one or two; skip if target is IP-only.
- Naabu, Httpx: Can run with just target/domain - these produce output. Always include when relevant.
- DNSx, ShuffleDNS: Need domain. Often redundant with Subfinder/Amass—skip unless you need DNS validation only.
When clues are empty or minimal: recommend Naabu, Httpx, one subdomain tool, and Nuclei (4–5 tools). Do not recommend 8–10 tools that will mostly find nothing.

## Important Notes on Skipped Tools
- ONLY include tools in "tools_skipped" if the USER selected them initially
- Do NOT list tools that user didn't select as "skipped"
- Explain why user-selected tools should be skipped based on clues

## Output Format (IMPORTANT)
Respond with ONLY valid JSON.
Do NOT include markdown, backticks, comments, or any text before or after the JSON.
The entire response MUST be a single JSON object exactly matching this structure:

{{
  "tools_to_run": ["Tool1", "Tool2", "Tool3"],
  "tools_skipped": [
    {{"tool": "ToolName", "reason": "Brief explanation - ONLY if user selected this tool"}},
  ],
  "tools_added": [
    {{"tool": "ToolName", "reason": "Why this additional tool is recommended"}},
  ],
  "execution_batches": [
    ["Batch1Tool1", "Batch1Tool2"],
    ["Batch2Tool1", "Batch2Tool2"]
  ],
  "reasoning": "Brief overall strategy explanation"
}}

Return ONLY that JSON object and nothing else.
"""

    return prompt
