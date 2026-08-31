"""Application configuration and settings."""
import os
from pathlib import Path
from typing import List, Tuple

class Settings:
    """Application settings loaded from environment variables."""
    
    # Project paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    DATA_DIR: Path = BASE_DIR / "data"
    SCANS_DIR: Path = DATA_DIR / "scans"
    
    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        f"sqlite+aiosqlite:///{BASE_DIR}/data/irs.db"
    )
    
    # AI Configuration
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    # Optional: multiple backends "model:key" or "key" (uses GEMINI_MODEL). Example: "gemini-2.5-flash:key1,gemini-2.0-flash:key2" or "key1,key2"
    GEMINI_BACKENDS: str = os.getenv("GEMINI_BACKENDS", "").strip()
    # 429 backoff base (seconds). Delays are base*1, base*2, base*4. Default 3; set to 60 or 120 if you hit daily quota and want longer waits.
    GEMINI_429_BACKOFF_BASE: int = int(os.getenv("GEMINI_429_BACKOFF_BASE", "3"))
    # Toggle AI usage for intelligence summary (combined summary + attack relevance).
    # When false, these sections use only local fallbacks and do not call Gemini.
    INTELLIGENCE_AI_ENABLED: bool = os.getenv("INTELLIGENCE_AI_ENABLED", "true").lower() == "true"
    
    # Tool execution settings
    TOOL_TIMEOUT: int = int(os.getenv("TOOL_TIMEOUT", "300"))  # 5 minutes default
    NUCLEI_TIMEOUT: int = int(os.getenv("NUCLEI_TIMEOUT", "1200"))  # 20 minutes base for OWASP-focused 3-phase scans
    NUCLEI_REQUEST_TIMEOUT: int = int(os.getenv("NUCLEI_REQUEST_TIMEOUT", "5"))
    NUCLEI_RETRIES: int = int(os.getenv("NUCLEI_RETRIES", "0"))
    NUCLEI_MAX_URLS: int = int(os.getenv("NUCLEI_MAX_URLS", "20"))  # Scan top 20 prioritized OWASP-relevant URLs
    NUCLEI_STOP_ON_FINDINGS: int = int(os.getenv("NUCLEI_STOP_ON_FINDINGS", "1"))
    MAX_CONCURRENT_TOOLS: int = int(os.getenv("MAX_CONCURRENT_TOOLS", "3"))
    
    # Recon tools - canonical names
    AVAILABLE_TOOLS: List[str] = [
        "Nuclei",
        "Naabu",
        "Httpx",
        "Subfinder",
        "Amass",
        "Assetfinder",
        "Sublist3r",
        "GAU",
        "Katana",
        "GoSpider",
        "FFuf",
        "Wfuzz",
        "CeWL",
        "DNSx",
        "ShuffleDNS"
    ]
    
    # Initial clues tools (run before AI decision)
    INITIAL_CLUES_TOOLS: List[str] = ["Naabu", "Httpx"]

    # Tool phases for chaining: discovery tools produce URLs, exploit tools consume them
    DISCOVERY_TOOLS: List[str] = [
        "Subfinder", "Amass", "Assetfinder", "Sublist3r",
        "GAU", "Katana", "GoSpider", "DNSx", "ShuffleDNS"
    ]
    EXPLOIT_TOOLS: List[str] = ["Nuclei", "FFuf", "Wfuzz"]
    
    # API Configuration (secure, server-side only)
    API_SCHEME: str = os.getenv("API_SCHEME", "http")
    API_HOST: str = os.getenv("API_HOST", "localhost")
    API_PORT: int = int(os.getenv("API_PORT", "8080"))
    
    @property
    def API_BASE_URL(self) -> str:
        """Get the API base URL - server-side only, frontend gets it via /api/config"""
        return f"{self.API_SCHEME}://{self.API_HOST}:{self.API_PORT}"
    
    # OWASP Top 10 2021 categories
    OWASP_CATEGORIES: List[dict] = [
        {"id": "A01:2021", "name": "Broken Access Control"},
        {"id": "A02:2021", "name": "Cryptographic Failures"},
        {"id": "A03:2021", "name": "Injection"},
        {"id": "A04:2021", "name": "Insecure Design"},
        {"id": "A05:2021", "name": "Security Misconfiguration"},
        {"id": "A06:2021", "name": "Vulnerable and Outdated Components"},
        {"id": "A07:2021", "name": "Identification and Authentication Failures"},
        {"id": "A08:2021", "name": "Software and Data Integrity Failures"},
        {"id": "A09:2021", "name": "Security Logging and Monitoring Failures"},
        {"id": "A10:2021", "name": "Server-Side Request Forgery (SSRF)"}
    ]
    
    # API settings
    API_PREFIX: str = "/api"

    # Alert email (scan finished notifications)
    SMTP_HOST: str = os.getenv("SMTP_HOST", "")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER: str = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM: str = os.getenv("SMTP_FROM", "")
    SMTP_USE_TLS: bool = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
    
    def __init__(self):
        """Ensure required directories exist."""
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.SCANS_DIR.mkdir(parents=True, exist_ok=True)
    
    def get_gemini_backends(self) -> List[Tuple[str, str]]:
        """Return list of (model, api_key) to try in order. On 429 or connection error, next backend is used."""
        if self.GEMINI_BACKENDS:
            backends = []
            default_model = self.GEMINI_MODEL or "gemini-2.5-flash"
            for part in self.GEMINI_BACKENDS.split(","):
                part = part.strip()
                if not part:
                    continue
                if ":" in part:
                    model, key = part.split(":", 1)
                    model, key = model.strip(), key.strip()
                    if model and key:
                        backends.append((model, key))
                else:
                    if part and default_model:
                        backends.append((default_model, part))
            if backends:
                return backends
        if self.GEMINI_API_KEY and self.GEMINI_API_KEY.strip() and self.GEMINI_MODEL:
            return [(self.GEMINI_MODEL, self.GEMINI_API_KEY.strip())]
        return []

    def validate(self) -> bool:
        """Validate critical configuration."""
        return len(self.get_gemini_backends()) > 0


settings = Settings()


