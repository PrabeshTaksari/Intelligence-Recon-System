import socket
import re
from urllib.parse import urlparse
from typing import Tuple
import dns.resolver
import requests
from app.core.logging import get_logger

logger = get_logger(__name__)

def is_valid_domain_format(domain: str) -> bool:
    """Check if the domain format is valid."""
    # Regular expression for validating domain name
    pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](\.[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9])*\.?$'
    return bool(re.match(pattern, domain))

def is_valid_ip_format(ip: str) -> bool:
    """Check if the IP address format is valid."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def is_resolvable_domain(domain: str) -> bool:
    """Check if the domain is resolvable via DNS."""
    try:
        # Try to resolve the domain
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        try:
            # Alternative DNS resolution using dns.resolver
            import dns.resolver
            answers = dns.resolver.resolve(domain, 'A')
            return len(answers) > 0
        except:
            return False

def is_reachable_domain(domain: str) -> bool:
    """Check if the domain is reachable via HTTP/HTTPS."""
    try:
        # Try HTTP
        response = requests.head(f'http://{domain}', timeout=5, allow_redirects=True)
        return response.status_code < 400
    except:
        try:
            # Try HTTPS
            response = requests.head(f'https://{domain}', timeout=5, allow_redirects=True)
            return response.status_code < 400
        except:
            return False

def validate_domain(target: str) -> Tuple[bool, str]:
    """Validate if the target is a real, hosted domain or IP.
    
    Args:
        target: The target domain or IP address
        
    Returns:
        Tuple of (is_valid, message)
    """
    # Remove protocol if present
    if target.startswith(('http://', 'https://')):
        parsed = urlparse(target)
        target = parsed.netloc
    
    # Check if it's an IP address
    if is_valid_ip_format(target):
        return True, f"Valid IP address: {target}"
    
    # Check if it's a domain
    if not is_valid_domain_format(target):
        return False, f"Invalid domain format: {target}"
    
    # Check if domain is resolvable
    if not is_resolvable_domain(target):
        return False, f"Domain is not resolvable via DNS: {target}"
    
    # Optionally, check if domain is reachable (can be skipped for privacy reasons)
    # if not is_reachable_domain(target):
    #     return False, f"Domain is not reachable via HTTP/HTTPS: {target}"
    
    return True, f"Valid hosted domain: {target}"