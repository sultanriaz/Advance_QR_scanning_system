"""

heuristics.py - FIXED to ensure proper scoring
=======
heuristics.py
--------------
Rule-based heuristic security checks for QR URL analysis.
Provides:
- Individual security checks
- Risk scoring engine
- Risk classification

"""

import re
from urllib.parse import urlparse

from typing import List, Dict, Tuple

class HeuristicConfig:
    SUSPICIOUS_KEYWORDS = {
        "login": 8, "verify": 8, "update": 6, "secure": 5,
        "account": 7, "bank": 10, "bonus": 8, "free": 6,
        "password": 10, "confirm": 7, "signin": 8, "authenticate": 8
    }
    
    URL_SHORTENERS = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
        "short.link", "is.gd", "cli.gs"
    }
    
    SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".top", ".xyz", ".club"}
    
    MAX_SAFE_URL_LENGTH = 75
    MAX_SUSPICIOUS_LENGTH = 120
    
    WEIGHTS = {
        "no_https": 15,
        "ip_address": 30,
        "excessive_length": 10,
        "suspicious_keywords": 20,
        "url_shortener": 15,
        "suspicious_tld": 15,
        "multiple_subdomains": 10,
        "phishing_patterns": 25
    }

def analyze_url(url: str) -> Dict:
    """Analyze URL and return score (0-100)"""
    score = 0
    reasons = []
    
    # 1. HTTPS Check
    if not url.startswith("https://"):
        score += HeuristicConfig.WEIGHTS["no_https"]
        reasons.append("No HTTPS encryption")
    
    # 2. IP Address Detection
    ip_pattern = r'(?:\d{1,3}\.){3}\d{1,3}'
    if re.search(ip_pattern, url):
        score += HeuristicConfig.WEIGHTS["ip_address"]
        reasons.append("Uses IP address instead of domain")
    
    # 3. URL Length
    if len(url) > HeuristicConfig.MAX_SUSPICIOUS_LENGTH:
        score += HeuristicConfig.WEIGHTS["excessive_length"]
        reasons.append(f"Very long URL ({len(url)} chars)")
    elif len(url) > HeuristicConfig.MAX_SAFE_URL_LENGTH:
        score += HeuristicConfig.WEIGHTS["excessive_length"] // 2
        reasons.append(f"Long URL ({len(url)} chars)")
    
    # 4. Suspicious Keywords
    url_lower = url.lower()
    found_keywords = []
    kw_score = 0
    for keyword, weight in HeuristicConfig.SUSPICIOUS_KEYWORDS.items():
        if keyword in url_lower:
            found_keywords.append(keyword)
            kw_score += weight
    
    if found_keywords:
        score += min(kw_score, HeuristicConfig.WEIGHTS["suspicious_keywords"])
        reasons.append(f"Suspicious keywords: {', '.join(found_keywords[:3])}")
    
    # 5. URL Shortener
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        for shortener in HeuristicConfig.URL_SHORTENERS:
            if shortener in domain:
                score += HeuristicConfig.WEIGHTS["url_shortener"]
                reasons.append(f"URL shortener detected ({shortener})")
                break
    except:
        pass
    
    # 6. Suspicious TLD
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        for tld in HeuristicConfig.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                score += HeuristicConfig.WEIGHTS["suspicious_tld"]
                reasons.append(f"Suspicious TLD ({tld})")
                break
    except:
        pass
    
    # 7. Multiple Subdomains
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        parts = domain.split('.')
        if len(parts) > 4:
            sub_count = len(parts) - 2
            score += min(sub_count * 3, HeuristicConfig.WEIGHTS["multiple_subdomains"])
            reasons.append(f"Excessive subdomains ({sub_count})")
    except:
        pass
    
    # 8. Phishing Patterns
    phishing_indicators = [
        (r'login.*\.(?!com|org|net)', "Login in unusual domain"),
        (r'verify.*\.(?!com|org|net)', "Verify in unusual domain"),
        (r'secure.*\.(?!com|org|net)', "Secure in unusual domain"),
        (r'@.*?\.[a-z]{2,}', "Contains @ symbol"),
        (r'paypal|ebay|amazon|microsoft|apple.*\.(?!com|org|net)', "Brand name misuse")
    ]
    
    for pattern, msg in phishing_indicators:
        if re.search(pattern, url, re.I):
            score += 5
            reasons.append(f"Phishing indicator: {msg}")
    
    # Ensure score is at least something for suspicious URLs
    # This prevents always getting 0
    if score == 0 and url.startswith("http://"):
        score = 5
        reasons.append("HTTP connection (insecure)")
    
    # Cap at 100
    score = min(score, 100)
    
    # Classification
    if score < 25:
        classification = "SAFE"
    elif score < 55:
        classification = "SUSPICIOUS"
    elif score < 80:
        classification = "DANGEROUS"
    else:
        classification = "CRITICAL"
    
    return {
        "score": score,
        "classification": classification,
        "reasons": reasons
    }

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure",
    "account", "bank", "bonus", "free",
    "password", "confirm"
]

KNOWN_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co",
    "goo.gl", "ow.ly", "buff.ly"
]

MAX_SAFE_URL_LENGTH = 75

def check_https(url: str) -> bool:
    """Return True if URL uses HTTPS."""
    return url.lower().startswith("https://")
def contains_ip_address(url: str) -> bool:
    """Detect if URL contains raw IP address."""
    ip_pattern = r"(?:\d{1,3}\.){3}\d{1,3}"
    return re.search(ip_pattern, url) is not None
def check_url_length(url: str) -> int:
    """Return URL length."""
    return len(url)
def has_suspicious_keywords(url: str) -> bool:
    """Check for phishing-related keywords."""
    url_lower = url.lower()
    return any(keyword in url_lower for keyword in SUSPICIOUS_KEYWORDS)
def is_shortened_url(url: str) -> bool:
    """Detect common URL shorteners."""
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    return any(shortener in domain for shortener in KNOWN_SHORTENERS)
def calculate_risk_score(url: str) -> int:
    """
    Calculate heuristic risk score (0–100).
    Higher score → Higher risk.
    """

    score = 0
    if not check_https(url):
        score += 20
    if contains_ip_address(url):
        score += 25
    if check_url_length(url) > MAX_SAFE_URL_LENGTH:
        score += 15
    if has_suspicious_keywords(url):
        score += 20

    # URL shortener
    if is_shortened_url(url):
        score += 15

    return min(score, 100)
def classify_risk(score: int) -> str:
    """Classify risk level from score."""

    if score < 30:
        return "Safe"
    elif score < 60:
        return "Suspicious"
    else:
        return "Dangerous"

