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
OWASP_NUCLEI_TAGS = {
  "A01:2021": "unauth,traversal,lfi,idor,redirect",
  "A02:2021": "ssl,tls,expired-ssl,certificate",
  "A03:2021": "sqli,xss,command-injection,ssti,xxe",
  "A04:2021": "logic-bypass,auth-bypass,access-control,misconfig",
  "A05:2021": "misconfig,cors,headers,exposure",
  "A06:2021": "cve,known-vuln,version-detect,outdated",
  "A07:2021": "default-login,auth-bypass,jwt,login",
  "A08:2021": "deserialization,file-upload,xxe,path-traversal",
  "A09:2021": "log4j,logging,exposure,debug-page",
  "A10:2021": "ssrf,graphql",
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

    nuclei_tags = OWASP_NUCLEI_TAGS.get(owasp_category, "misconfig,security-headers")

    clues_summary = f"""
Initial Reconnaissance Clues:
- Open Ports: {clues.get('open_ports', 'None detected')}
- HTTP Services: {clues.get('http_services', 'None detected')}
- Server Headers: {clues.get('server_headers', 'None detected')}
- Page Titles: {clues.get('page_titles', 'None detected')}
- Status Codes: {clues.get('status_codes', 'None detected')}
- Technologies Detected: {clues.get('technologies', 'None detected')}
- Discovered URLs: {clues.get('discovered_urls', 'None yet')}
- Subdomains Found: {clues.get('subdomains', 'None yet')}
"""

    selected_tools_str = ", ".join(selected_tools) if selected_tools else "All tools available"

    prompt = f"""You are a senior application security recon analyst optimizing tool selection for OWASP {owasp_category} ({owasp_name}) assessments.

## Mission
Produce a professional, evidence-driven execution plan that:
1) expands target intelligence with high-signal reconnaissance,
2) minimizes redundant/no-output tools,
3) improves vulnerability detection probability for Nuclei.

## Target Information
- Domain: {target}
- OWASP Focus: {owasp_category} - {owasp_name}
- User Selected Tools: {selected_tools_str}

{clues_summary}

## Available Tools
{tools_list}

## Your Task
Based on the target, OWASP category, user selections, and clues, decide:
1. Which tools should run to improve vulnerability discovery
2. Which user-selected tools should be skipped and why
3. Which additional tools should be added and why
4. Execution sequence that is recon-first and vulnerability-focused

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
8. For web targets, keep Nuclei in the plan unless clues clearly show no reachable HTTP(S) surface.
9. Prioritize tools that increase URL/endpoint coverage before Nuclei (for better template match opportunities).

## Professional Strategy Priority (Recon -> Enrichment -> Vulnerability)
Use this default strategy unless clues strongly justify otherwise:
1. Surface discovery: identify active hosts/services (Naabu/Httpx already handled in clues for dashboard flow).
2. URL enrichment: run one or more of GAU/Katana/GoSpider/FFuf/Wfuzz only when HTTP surface exists.
3. Vulnerability detection: run Nuclei after URL enrichment so it can test more relevant endpoints.

## Nuclei Tag Recommendation for {owasp_category}
When Nuclei is in the plan, prefer these tags: {nuclei_tags}

When providing execution_batches, place reconnaissance/enrichment tools earlier and Nuclei in a later batch.

## Tool Availability and Prioritization Policy
- Do NOT use fixed tool bundles or hardcoded named combinations.
- First, inspect only the tools shown in "Available Tools" above.
- Build recommendations strictly from that available list and the user's selected list.
- Prioritize by capability categories instead of fixed names:
  1) Asset/service discovery
  2) URL/endpoint enrichment
  3) Fuzzing/content discovery
  4) Vulnerability detection
- For the chosen OWASP category, rank available tools by expected signal quality given current clues.
- If a category has multiple available tools with overlapping capability, choose the highest-signal subset and skip redundant ones.
- If a required capability category is missing from available tools, continue with best possible alternatives and explain the gap in reasoning.

## Avoid tools that find nothing (CRITICAL)
Many tools often return ZERO findings for typical targets. Do not recommend a long list when clues are minimal:
- Sublist3r, Subfinder, DNSx, Amass, Assetfinder: For most domains these find 0 or very few subdomains. Run at most ONE of them (e.g. Subfinder only) unless you have strong reason to expect many subdomains. Do NOT run Sublist3r + Subfinder + DNSx together "to be thorough"—they duplicate work and often all return nothing.
- GAU: Often returns 0 URLs for many targets. Skip GAU unless the domain is well-known or clues suggest rich history.
- FFuf, Wfuzz: Need a URL list and wordlist; with only one base URL they often find little. Prefer skipping when clues show no discovered paths/endpoints yet.
- When clues show only "Open Ports: 80" and "HTTP Services: None detected" or empty: recommend a MINIMAL set: Naabu, Httpx, one subdomain tool (Subfinder OR Amass, not both), and Nuclei. Skip GAU, FFuf, Wfuzz, Sublist3r, DNSx unless clues show existing URLs or many subdomains.

## Tool Output Requirements (CRITICAL - avoid tools that won't produce output)
Only recommend tools when their required inputs are available. Otherwise they run but produce no useful output:
- GAU, Katana, GoSpider, FFuf, Wfuzz: Require discovered URLs or HTTP services. SKIP these when clues show "None detected" for HTTP Services and no URLs exist yet.
- Nuclei: Works best with broad URL coverage. Prefer after URL discovery/enrichment tools when available; otherwise run against base URL if web service exists.
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
