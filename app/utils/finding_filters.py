"""Filters for excluding noise from tool findings (e.g. Sublist3r banner/log lines)."""
import re

# ANSI escape sequences (real \x1b and literal "[91m" style when stored in DB)
_ANSI = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]?")
_ANSI_LITERAL = re.compile(r"\[\d*(?:;\d*)*[a-zA-Z]?")  # e.g. [91m, [0m, [93m
# Sublist3r noise: banner, log lines, errors - not real subdomains
_SUBLIST3R_NOISE_PATTERNS = (
    "searching now",
    "enumerating subdomains",
    "coded by",
    "error:",
    "probably now is blocking",
    "finished now the",
    "___",
    "|____/",
    "/ ___|",
    "\\___ \\",
    "___) |",
    "aboul3la",
)


def is_sublist3r_noise(location: str, description: str) -> bool:
    """Return True if this finding looks like Sublist3r banner/log noise, not a real subdomain."""
    loc = (location or "").strip()
    desc = (description or "").strip()
    # Strip ANSI for checking (real escapes and literal "[91m" style from DB)
    loc_clean = _ANSI_LITERAL.sub("", _ANSI.sub("", loc))
    desc_clean = _ANSI_LITERAL.sub("", _ANSI.sub("", desc))
    # Empty or pure ANSI / no real location
    if not loc_clean:
        return True
    text = (loc_clean + " " + desc_clean).lower()
    # Contains known log/banner patterns
    if any(p in text for p in _SUBLIST3R_NOISE_PATTERNS):
        return True
    # Starts with [ (log line like [-] or [!])
    if loc_clean.startswith("[") or desc_clean.startswith("["):
        return True
    # Banner: contains # or spaces with underscore/pipe art
    if loc_clean.startswith("#") or ("_" in loc_clean and " " in loc_clean):
        return True
    # Must look like a hostname (no spaces, valid chars) to be a real subdomain
    if " " in loc_clean:
        return True
    if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$", loc_clean):
        return True
    return False
