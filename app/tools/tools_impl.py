import os
import re
import json
import shutil
from pathlib import Path
from typing import List, Dict, Any
from urllib.parse import urlparse
from app.tools.base import BaseTool


# Strip ANSI escape sequences (e.g. [91m, [0m) so tool output is readable in UI
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]?")


def _strip_ansi(text: str) -> str:
    if not text:
        return text
    return _ANSI_ESCAPE.sub("", text)


def _get_httpx_path() -> str:
    """Resolve httpx binary: prefer ProjectDiscovery from go/bin, else PATH."""
    go_bin = os.path.expanduser("/home/prabesh/go/bin/httpx")
    if os.path.isfile(go_bin):
        return go_bin
    path = shutil.which("httpx")
    return path or "httpx"

class NucleiTool(BaseTool):
    def __init__(self):
        super().__init__("Nuclei")
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        discovered_urls = kwargs.get("discovered_urls") or []
        clues = kwargs.get("clues") or {}
        http_services = clues.get("http_services") or []
        # Build URL list: discovered + clues + fallback (domain/IP → proper URL)
        all_urls = list(dict.fromkeys(
            [u for u in discovered_urls if u and (u.startswith("http://") or u.startswith("https://"))]
            + [u for u in http_services if u and (str(u).startswith("http://") or str(u).startswith("https://"))]
        ))
        if not all_urls:
            base = _base_url_for_web_tools(target, **kwargs)
            all_urls = [base]
        # Faster nuclei: high concurrency + rate limit + focus on higher severity
        severity_args = ["-severity", "critical,high,medium"]
        perf_args = ["-c", "100", "-rl", "200"]
        # Retries and no update-check reduce failures and stderr noise
        extra = ["-retries", "2", "-disable-update-check", "-no-color"]
        if len(all_urls) == 1:
            return ["nuclei", "-u", all_urls[0], "-jsonl", "-o", str(output_file), "-silent"] + perf_args + severity_args + extra
        # Multiple URLs: write to temp file and use -l
        urls_file = output_file.parent / "nuclei_urls.txt"
        with open(urls_file, "w") as f:
            f.write("\n".join(all_urls[:200]))  # Limit to 200 URLs
        return ["nuclei", "-l", str(urls_file), "-jsonl", "-o", str(output_file), "-silent"] + perf_args + severity_args + extra
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        findings = []
        for line in output.strip().split('\n'):
            if not line: continue
            try:
                data = json.loads(line)
                severity = (data.get("info") or {}).get("severity", "info")
                # Only real issues (low+) are "vulnerability"; info = detection/fingerprint = "information"
                ftype = "vulnerability" if severity in ("low", "medium", "high", "critical") else "information"
                findings.append({
                    "type": ftype,
                    "severity": severity,
                    "location": data.get("matched-at", target),
                    "description": data.get("info", {}).get("name", "Unknown"),
                    "evidence": json.dumps(data, indent=2)
                })
            except json.JSONDecodeError:
                continue
        return findings
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        if not findings: return "No vulnerabilities detected"
        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        return f"Found {len(findings)} vulnerabilities: " + ", ".join([f"{v} {k}" for k, v in severity_counts.items()])

class NaabuTool(BaseTool):
    def __init__(self):
        super().__init__("Naabu")
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        # Real Naabu CLI: scan top 1000 ports, JSON to file, silent (no banner)
        host = _normalize_host(target)
        return ["naabu", "-host", host, "-top-ports", "1000", "-json", "-o", str(output_file), "-silent"]
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        findings = []
        # Track unique ports to avoid duplicates
        seen_ports = set()
        
        for line in output.strip().split('\n'):
            if not line: continue
            try:
                data = json.loads(line)
                port = data.get("port", "")
                host = data.get('host', target)
                port_key = f"{host}:{port}"
                
                # Only add if we haven't seen this port for this host
                if port_key not in seen_ports:
                    seen_ports.add(port_key)
                    ip = data.get("ip", "")
                    desc = f"Open port: {port}"
                    if ip:
                        desc += f"\nIP: {ip}"
                    findings.append({
                        "type": "port",
                        "severity": "info",
                        "location": port_key,
                        "description": desc,
                        "evidence": json.dumps(data)
                    })
            except json.JSONDecodeError:
                match = re.search(r':(\d+)', line)
                if match:
                    port = match.group(1)
                    port_key = f"{target}:{port}"
                    
                    # Only add if we haven't seen this port
                    if port_key not in seen_ports:
                        seen_ports.add(port_key)
                        findings.append({
                            "type": "port",
                            "severity": "info",
                            "location": port_key,
                            "description": f"Open port: {port}",
                            "evidence": line
                        })
        return findings
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        if not findings: return "No open ports detected"
        ports = [f.get("location", "").split(":")[-1] for f in findings]
        unique_ports = list(set(ports))  # Remove duplicates for summary
        return f"Found {len(findings)} unique open ports: {', '.join(sorted(unique_ports))}"

# Common web ports to probe when target is IP/host (so Httpx finds services on 8080, 80, etc.)
_WEB_PORTS = ("80", "443", "8080", "8000", "8443", "3000", "5000", "7070", "8888", "9000")

def _is_ip_or_localhost(t: str) -> bool:
    if not t or " " in t:
        return False
    t = t.strip().lower()
    if t in ("localhost", "127.0.0.1", "::1"):
        return True
    # IPv4
    parts = t.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return False


def _normalize_host(target: str) -> str:
    """
    Normalize user input (domain, URL, or IP) to a bare host for tools that expect a domain/IP.
    - If target is a URL, extract hostname (without scheme/path/port).
    - If target is host:port, strip the port.
    """
    t = (target or "").strip()
    if not t:
        return ""
    host = t
    # Extract host from URL if scheme present
    if "://" in t:
        try:
            parsed = urlparse(t)
            host = parsed.hostname or t
        except Exception:
            host = t
    # Strip path if accidentally included
    if "/" in host:
        host = host.split("/", 1)[0]
    # Strip port if present
    if ":" in host and not _is_ip_or_localhost(host):
        host = host.split(":", 1)[0]
    return host


def _base_url_for_web_tools(target: str, **kwargs) -> str:
    """Return a base URL for tools that need one (Wfuzz, GoSpider). Supports domain, IP, or full URL."""
    t = (target or "").strip()
    if t.startswith("http://") or t.startswith("https://"):
        return t.rstrip("/")
    clues = kwargs.get("clues") or {}
    http_services = list(clues.get("http_services") or [])
    discovered_urls = list(kwargs.get("discovered_urls") or [])
    # Prefer first discovered URL (e.g. http://127.0.0.1:8080 from Httpx) so IP+port works
    for u in discovered_urls + http_services:
        u = (u or "").strip()
        if u.startswith("http://") or u.startswith("https://"):
            return u.rstrip("/")
    if _is_ip_or_localhost(t):
        return f"http://{t}"
    return f"https://{t}"

class HttpxTool(BaseTool):
    def __init__(self):
        super().__init__("Httpx")
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        httpx_bin = _get_httpx_path()
        # If already a full URL, use as-is (single probe)
        if target.startswith("http://") or target.startswith("https://"):
            return [httpx_bin, "-u", target, "-json", "-o", str(output_file), "-silent", "-title", "-td", "-sc"]
        # During clues gathering: when user enters an IP we switch it to URLs (http(s)://ip:port)
        # using Naabu open ports so Httpx finds HTTP services instead of probing only https://ip.
        clues = kwargs.get("clues") or {}
        open_ports = list(clues.get("open_ports") or [])
        host = target.strip()
        urls = []
        if open_ports:
            # Prefer ports Naabu found; keep common web ports plus any from Naabu
            ports_to_try = set(_WEB_PORTS) | {str(p) for p in open_ports}
            for port in ports_to_try:
                try:
                    if int(port) > 65535:
                        continue
                except ValueError:
                    continue
                urls.append(f"http://{host}:{port}")
                urls.append(f"https://{host}:{port}")
        elif _is_ip_or_localhost(host):
            # No clues: for IP/localhost still probe common web ports
            for port in _WEB_PORTS:
                urls.append(f"http://{host}:{port}")
                urls.append(f"https://{host}:{port}")
        else:
            # Domain: probe common web ports (80, 443, 8080...) so we don't rely only on Naabu
            for port in _WEB_PORTS:
                urls.append(f"http://{host}:{port}")
                urls.append(f"https://{host}:{port}")
        # Httpx accepts multiple -u; flatten [bin, "-u", u1, "-u", u2, ...]
        cmd = [httpx_bin]
        for u in urls[:50]:  # cap to avoid huge CLI
            cmd.extend(["-u", u])
        cmd.extend(["-json", "-o", str(output_file), "-silent", "-title", "-td", "-sc"])
        return cmd
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        findings = []
        for line in output.strip().split('\n'):
            if not line: continue
            try:
                data = json.loads(line)
                findings.append({
                    "type": "endpoint",
                    "severity": "info",
                    "location": data.get("url", target),
                    "description": f"HTTP service: {data.get('status_code', 'N/A')} - {data.get('title', 'No title')}",
                    "evidence": json.dumps(data, indent=2)
                })
            except json.JSONDecodeError:
                continue
        return findings
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        if not findings: return "No HTTP services detected"
        return f"Found {len(findings)} HTTP endpoints"

class SubfinderTool(BaseTool):
    def __init__(self):
        super().__init__("Subfinder")
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        domain = _normalize_host(target)
        return ["subfinder", "-d", domain, "-o", str(output_file), "-silent"]
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        findings = []
        # Track unique subdomains to avoid duplicates
        seen_subdomains = set()
        
        for line in output.strip().split('\n'):
            if line and line.strip():
                subdomain = line.strip()
                # Only add if we haven't seen this subdomain
                if subdomain not in seen_subdomains:
                    seen_subdomains.add(subdomain)
                    findings.append({
                        "type": "asset",
                        "severity": "info",
                        "location": subdomain,
                        "description": f"Subdomain discovered: {subdomain}",
                        "evidence": subdomain
                    })
        return findings
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        if not findings: return "No subdomains discovered"
        return f"Discovered {len(findings)} unique subdomains"

class AmassTool(BaseTool):
    def __init__(self):
        super().__init__("Amass")
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        domain = _normalize_host(target)
        return ["amass", "enum", "-d", domain, "-o", str(output_file), "-passive"]
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        findings = []
        # Track unique subdomains to avoid duplicates
        seen_subdomains = set()
        
        for line in output.strip().split('\n'):
            if line and line.strip():
                subdomain = line.strip()
                # Only add if we haven't seen this subdomain
                if subdomain not in seen_subdomains:
                    seen_subdomains.add(subdomain)
                    findings.append({
                        "type": "asset",
                        "severity": "info",
                        "location": subdomain,
                        "description": f"Subdomain discovered: {subdomain}",
                        "evidence": subdomain
                    })
        return findings
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        if not findings: return "No subdomains discovered"
        return f"Discovered {len(findings)} unique subdomains"

class AssetfinderTool(BaseTool):
    def __init__(self):
        super().__init__("Assetfinder")
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        domain = _normalize_host(target)
        return ["assetfinder", "--subs-only", domain, "-o", str(output_file)]
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        findings = []
        for line in output.strip().split('\n'):
            if line and line.strip():
                findings.append({
                    "type": "asset",
                    "severity": "info",
                    "location": line.strip(),
                    "description": f"Subdomain discovered: {line.strip()}",
                    "evidence": line.strip()
                })
        return findings
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        if not findings: return "No subdomains discovered"
        return f"Discovered {len(findings)} subdomains"

class Sublist3rTool(BaseTool):
    # Virustotal excluded (blocking). DNSdumpster excluded (site HTML changed, causes IndexError in sublist3r).
    SUBLIST3R_ENGINES = "google,yahoo,bing,baidu,ask,netcraft,threatcrowd,passivedns"

    def __init__(self):
        super().__init__("Sublist3r")
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        domain = _normalize_host(target)
        return [
            "sublist3r", "-d", domain, "-o", str(output_file),
            "-e", self.SUBLIST3R_ENGINES,
        ]
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        findings = []
        seen = set()
        # Normalize target to domain (no scheme/path)
        domain = target.strip().lower()
        if "://" in domain:
            domain = domain.split("://", 1)[1]
        if "/" in domain:
            domain = domain.split("/", 1)[0]
        # Only accept lines that look like subdomains of target (hostname, no ANSI/logs)
        hostname_re = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$")
        skip_patterns = (
            "searching now", "enumerating subdomains", "coded by", "error:",
            "probably now is blocking", "___", "finished now", "traceback", "file \"",
        )
        for line in output.strip().split("\n"):
            line = _strip_ansi(line).strip()
            if not line:
                continue
            # Skip log lines and banner
            if line.startswith("[") or line.startswith("#") or "|" in line and "___" in line:
                continue
            if any(p in line.lower() for p in skip_patterns):
                continue
            # Must look like a hostname (no spaces, valid chars)
            if " " in line or not hostname_re.match(line):
                continue
            # Must be the target or a subdomain of it
            line_lower = line.lower()
            if line_lower != domain and not (line_lower.endswith("." + domain)):
                continue
            if line_lower in seen:
                continue
            seen.add(line_lower)
            clean = line  # already stripped of ANSI
            findings.append({
                "type": "asset",
                "severity": "info",
                "location": clean,
                "description": f"Subdomain discovered: {clean}",
                "evidence": clean,
            })
        return findings
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        if not findings:
            return "No subdomains discovered"
        return f"Discovered {len(findings)} subdomains"

class GAUTool(BaseTool):
    def __init__(self):
        super().__init__("GAU")
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        # GAU uses --o for output file (not -o)
        domain = _normalize_host(target)
        return ["gau", domain, "--o", str(output_file)]
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        findings = []
        for line in output.strip().split('\n'):
            if line and line.startswith('http'):
                findings.append({"type": "endpoint","severity": "info","location": line.strip(),"description": f"Historical URL: {line.strip()}","evidence": line.strip()})
        return findings[:100]
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        if not findings: return "No historical URLs found"
        return f"Found {len(findings)} historical URLs"

class KatanaTool(BaseTool):
    def __init__(self):
        super().__init__("Katana")
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        base_url = _base_url_for_web_tools(target, **kwargs)
        return ["katana", "-u", base_url, "-o", str(output_file), "-silent", "-d", "3"]
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        findings = []
        for line in output.strip().split('\n'):
            if line and line.startswith('http'):
                url = line.strip()
                # Avoid repeating URL in description (location already shows the URL)
                findings.append({"type": "endpoint", "severity": "info", "location": url, "description": "Crawled endpoint", "evidence": url})
        return findings[:100]
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        if not findings: return "No URLs crawled"
        return f"Crawled {len(findings)} URLs"

class GoSpiderTool(BaseTool):
    def __init__(self):
        super().__init__("GoSpider")
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        # Use a temporary directory for gospider output; sanitize target for path safety
        safe_target = re.sub(r"[^\w.-]", "_", target)[:64]
        temp_dir = output_file.parent / f"gospider_temp_{safe_target}"
        try:
            temp_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            temp_dir = output_file.parent / "gospider_temp"
            temp_dir.mkdir(parents=True, exist_ok=True)
        # Support domain, IP, or full URL (use base URL from clues/discovered_urls when target is IP)
        base_url = _base_url_for_web_tools(target, **kwargs)
        return ["bash", "-c", f"gospider -s {base_url} -o {temp_dir} -q -d 2 2>&1 | tee {output_file}"]
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        findings = []
        for line in output.strip().split('\n'):
            match = re.search(r'https?://[^\s]+', line)
            if match:
                url = match.group(0)
                # Avoid repeating URL in description (location already shows the URL)
                findings.append({"type": "endpoint", "severity": "info", "location": url, "description": "Crawled endpoint", "evidence": line})
        return findings[:100]
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        if not findings: return "No URLs crawled"
        return f"Crawled {len(findings)} URLs"

def _extract_paths_from_urls(urls: List[str]) -> List[str]:
    """Extract path segments from URLs for wordlist enrichment."""
    from urllib.parse import urlparse
    paths = set()
    for u in urls or []:
        try:
            parsed = urlparse(str(u))
            path = parsed.path.strip("/")
            if path:
                for seg in path.split("/"):
                    if seg and len(seg) < 50:
                        paths.add(seg)
                paths.add(path)
        except Exception:
            pass
    return list(paths)[:50]


class FFufTool(BaseTool):
    def __init__(self):
        super().__init__("FFuf")
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        import os
        wordlist_paths = [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt",
            "/tmp/quick_wordlist.txt"
        ]
        wordlist_path = None
        for path in wordlist_paths:
            if os.path.exists(path):
                wordlist_path = path
                break
        base_words = "admin\nlogin\napi\ntest\ndebug\nbackup\nconfig\nindex.php\nlogin.php\nadmin.php\n"
        if not wordlist_path:
            wordlist_path = "/tmp/quick_wordlist.txt"
            with open(wordlist_path, 'w') as f:
                f.write(base_words)
        # Enrich with paths from discovered URLs
        discovered_urls = kwargs.get("discovered_urls") or []
        clues = kwargs.get("clues") or {}
        http_services = clues.get("http_services") or []
        all_urls = list(dict.fromkeys(discovered_urls + [str(u) for u in http_services]))
        extra_paths = _extract_paths_from_urls(all_urls)
        if extra_paths:
            combined_path = output_file.parent / "ffuf_combined_wordlist.txt"
            with open(combined_path, "w") as f:
                if wordlist_path and os.path.exists(wordlist_path):
                    f.write(open(wordlist_path).read())
                else:
                    f.write(base_words)
                f.write("\n" + "\n".join(extra_paths))
            wordlist_path = str(combined_path)
        base_url = _base_url_for_web_tools(target, **kwargs)
        fuzz_url = f"{base_url}/FUZZ"
        return ["ffuf", "-w", wordlist_path,
                "-u", fuzz_url,
                "-o", str(output_file), "-of", "json"]
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        import json
        findings = []
        try:
            # Parse JSON output from ffuf
            data = json.loads(output)
            results = data.get("results", [])
            for item in results:
                status_code = item.get("status", 0)
                if status_code in [200, 201, 202, 204, 301, 302, 307, 403]:  # Interesting status codes
                    fuzz_val = item.get("input", {}).get("FUZZ", "")
                    location = item.get("url") if isinstance(item.get("url"), str) and item.get("url", "").startswith("http") else f"https://{target}/{fuzz_val}"
                    findings.append({
                        "type": "endpoint",
                        "severity": "info",
                        "location": location,
                        "description": f"Discovered endpoint: {item.get('input', {}).get('FUZZ', '')} (Status: {status_code}) - Length: {item.get('length', 0)} chars",
                        "evidence": json.dumps(item)
                    })
        except json.JSONDecodeError:
            # Fallback parsing - only accept lines that look like real results
            for line in output.strip().split('\n'):
                line = line.strip()
                if not line or len(line) < 10:
                    continue
                # Skip header/separator lines and command examples
                if "::" in line or "Matcher" in line or "wfuzz " in line or line.startswith("ffuf"):
                    continue
                if "FUZZ" in line or "FUZ2Z" in line:  # Example payload
                    continue
                # Accept: URL-like lines with status codes, or path + status
                if ('200' in line or '302' in line or '301' in line) and (
                    line.startswith("http") or "/" in line or re.search(r'\b\d{3}\b', line)
                ):
                    loc = line.split()[0] if line.split() else line
                    if loc.startswith("http"):
                        findings.append({
                            "type": "endpoint",
                            "severity": "info",
                            "location": loc,
                            "description": "Potentially interesting endpoint found",
                            "evidence": line
                        })
        return findings[:50]  # Limit results to prevent overwhelming
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        if not findings: return "No interesting endpoints found"
        return f"Discovered {len(findings)} potential endpoints for further investigation"

class WfuzzTool(BaseTool):
    def __init__(self):
        super().__init__("Wfuzz")
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        import os
        wordlist_paths = [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt",
            "/tmp/common.txt"
        ]
        wordlist_path = None
        for path in wordlist_paths:
            if os.path.exists(path):
                wordlist_path = path
                break
        base_words = "admin\nlogin\napi\ntest\ndebug\nbackup\nconfig\n"
        if not wordlist_path:
            wordlist_path = "/tmp/wfuzz_default_wordlist.txt"
            with open(wordlist_path, 'w') as f:
                f.write(base_words)
        # Enrich with paths from discovered URLs
        discovered_urls = kwargs.get("discovered_urls") or []
        clues = kwargs.get("clues") or {}
        http_services = clues.get("http_services") or []
        all_urls = list(dict.fromkeys(discovered_urls + [str(u) for u in http_services]))
        extra_paths = _extract_paths_from_urls(all_urls)
        if extra_paths:
            combined_path = output_file.parent / "wfuzz_combined_wordlist.txt"
            with open(combined_path, "w") as f:
                if wordlist_path and os.path.exists(wordlist_path):
                    f.write(open(wordlist_path).read())
                else:
                    f.write(base_words)
                f.write("\n" + "\n".join(extra_paths))
            wordlist_path = str(combined_path)
        # Support domain, IP, or full URL (use base URL from clues/discovered_urls when target is IP)
        base_url = _base_url_for_web_tools(target, **kwargs)
        fuzz_url = f"{base_url}/FUZZ"
        # Wfuzz 3.x: -z file,wordlist (not -w); -f file,format single arg (not -o json -f file json)
        return ["wfuzz", "-c", "--hc=404", "-z", f"file,{wordlist_path}",
                "-f", f"{output_file},json", fuzz_url]
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            # Try to parse JSON output first (Wfuzz 3.x writes a top-level array; some versions use {"results": [...]})
            data = json.loads(output)
            results = data if isinstance(data, list) else data.get("results", [])
            for item in results:
                code = item.get("code") or item.get("Response") or item.get("status")
                payload = item.get("payload") or item.get("Payload") or item.get("input", {}).get("FUZZ", "")
                if code is None:
                    code = 0
                if code not in [404, 403]:  # Filter out common error codes
                    location = item.get("url") or f"https://{target}/{payload}"
                    findings.append({
                        "type": "endpoint",
                        "severity": "info",
                        "location": location,
                        "description": f"Discovered endpoint: {payload} (Status: {code}) - Size: {item.get('lines', item.get('Chars', 0))}",
                        "evidence": json.dumps(item)
                    })
        except json.JSONDecodeError:
            # Fallback parsing - only accept lines that look like real results
            for line in output.strip().split('\n'):
                line = line.strip()
                if not line or len(line) < 10:
                    continue
                if "::" in line or "Matcher" in line or "wfuzz " in line or "ffuf" in line:
                    continue
                if "FUZZ" in line or "FUZ2Z" in line:
                    continue
                if ("200" in line or "302" in line or "301" in line) and (
                    line.startswith("http") or "/" in line or re.search(r'\b\d{3}\b', line)
                ):
                    loc = line.split()[0] if line.split() else line
                    if loc.startswith("http"):
                        findings.append({
                            "type": "endpoint",
                            "severity": "info",
                            "location": loc,
                            "description": "Potentially interesting endpoint found",
                            "evidence": line
                        })
        return findings[:50]  # Limit results to prevent overwhelming
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        if not findings: return "No interesting endpoints found"
        return f"Discovered {len(findings)} potential endpoints for further investigation"


class CeWLTool(BaseTool):
    def __init__(self):
        super().__init__("CeWL")
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        base_url = _base_url_for_web_tools(target, **kwargs)
        return ["cewl", base_url, "-w", str(output_file), "-d", "2", "-m", "5"]
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        words = [w.strip() for w in output.strip().split('\n') if w.strip()]
        if words:
            return [{"type": "information","severity": "info","location": target,"description": f"Generated wordlist with {len(words)} words","evidence": f"Sample words: {', '.join(words[:10])}"}]
        return []
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        words_count = len([w for w in raw_output.strip().split('\n') if w.strip()])
        return f"Generated wordlist with {words_count} words"

class DNSxTool(BaseTool):
    def __init__(self):
        super().__init__("DNSx")
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        # Newer dnsx requires -w with -d (wordlist bruteforce). Use -l with a list file to resolve the domain(s).
        domain = _normalize_host(target)
        domains_file = output_file.parent / "dnsx_domains.txt"
        domains_file.write_text(domain.strip() + "\n")
        return ["dnsx", "-l", str(domains_file), "-silent", "-resp", "-o", str(output_file)]
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        findings = []
        # Skip error/usage lines (e.g. "flag provided but not defined: -retries")
        skip_patterns = ("flag provided", "not defined", "usage:", "error:", "panic:", "failed")
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            if any(p in line.lower() for p in skip_patterns):
                continue
            # Real dnsx output: domain [A: 1.2.3.4] or domain.com
            if "[" in line and "]" in line and ("A:" in line or "AAAA:" in line or "CNAME:" in line):
                loc = line.split()[0] if line.split() else target
            elif re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$", line):
                loc = line
            else:
                continue
            findings.append({
                "type": "asset",
                "severity": "info",
                "location": loc,
                "description": f"DNS record found: {line}",
                "evidence": line,
            })
        return findings
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        if not findings: return "No DNS records found"
        return f"Found {len(findings)} DNS records"

class ShuffleDNSTool(BaseTool):
    def __init__(self):
        super().__init__("ShuffleDNS")
    def build_command(self, target: str, output_file: Path, **kwargs) -> List[str]:
        import os
        # ShuffleDNS requires -r resolver file (list of DNS resolver IPs)
        resolver_paths = [
            "/usr/share/seclists/Discovery/DNS/dns-resolvers.txt",
            output_file.parent / "resolvers.txt",
            Path("/tmp/shuffledns_resolvers.txt"),
        ]
        resolver_file = None
        for p in resolver_paths:
            path = Path(p) if not isinstance(p, Path) else p
            if path.exists():
                resolver_file = str(path)
                break
        if not resolver_file:
            default_resolvers = "8.8.8.8\n8.8.4.4\n1.1.1.1\n1.0.0.1\n9.9.9.9\n208.67.222.222\n208.67.220.220\n"
            resolvers_path = output_file.parent / "resolvers.txt"
            resolvers_path.parent.mkdir(parents=True, exist_ok=True)
            resolvers_path.write_text(default_resolvers)
            resolver_file = str(resolvers_path)
        # Wordlist for subdomain bruteforcing
        wordlist_paths = [
            "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
            "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
            "/tmp/subdomains_small.txt",
        ]
        wordlist_path = None
        for path in wordlist_paths:
            if os.path.exists(path):
                wordlist_path = path
                break
        if not wordlist_path:
            wordlist_path = "/tmp/subdomains_small.txt"
            Path(wordlist_path).parent.mkdir(parents=True, exist_ok=True)
            Path(wordlist_path).write_text("www\nmail\nftp\nadmin\ntest\ndev\nstaging\nprod\napi\nsupport\nblog\nshop\n")
        # v1.2+ requires -mode (bruteforce | resolve | filter)
        domain = _normalize_host(target)
        return ["shuffledns", "-d", domain, "-r", resolver_file, "-w", wordlist_path, "-mode", "bruteforce", "-o", str(output_file)]
    def parse_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        findings = []
        for line in output.strip().split('\n'):
            if line and line.strip():
                # Expected format: subdomain.domain.com A ip.address
                parts = line.split()
                if len(parts) >= 3:
                    subdomain_full = parts[0]
                    findings.append({
                        "type": "asset",
                        "severity": "info",
                        "location": subdomain_full,
                        "description": f"Discovered subdomain: {subdomain_full}",
                        "evidence": line.strip()
                    })
        return findings
    def generate_summary(self, findings: List[Dict[str, Any]], raw_output: str) -> str:
        if not findings: return "No subdomains discovered via bruteforce"
        return f"Bruteforced {len(findings)} subdomains"

TOOL_REGISTRY = {
    "Nuclei": NucleiTool,
    "Naabu": NaabuTool,
    "Httpx": HttpxTool,
    "Subfinder": SubfinderTool,
    "Amass": AmassTool,
    "Assetfinder": AssetfinderTool,
    "Sublist3r": Sublist3rTool,
    "GAU": GAUTool,
    "Katana": KatanaTool,
    "GoSpider": GoSpiderTool,
    "FFuf": FFufTool,
    "Wfuzz": WfuzzTool,
    "CeWL": CeWLTool,
    "DNSx": DNSxTool,
    "ShuffleDNS": ShuffleDNSTool
}
