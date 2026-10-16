"""Lexical URL Feature Extraction Engine.

Extracts structured numerical and binary lexical indicators from input URLs without
initiating any outbound network requests, web crawling, DNS resolution, or remote execution.
"""
import ipaddress
import re
from urllib.parse import urlsplit

# Canonical, ordered feature names used in training, serialization, and inference.
FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "num_dots",
    "num_hyphens",
    "num_digits",
    "num_subdomains",
    "is_https",
    "is_ip",
    "suspicious_token_count",
    "path_length",
    "query_length",
    "has_at_symbol",
    "percent_encoded_count",
]

# Sensitive keywords frequently abused in phishing attacks and spoofed URLs
SUSPICIOUS_TOKENS = [
    "login", "verify", "update", "secure", "account", "banking",
    "signin", "ebayisapi", "webscr", "password", "confirm", "wallet",
    "security", "support", "service", "authenticate", "free", "bonus",
    "gift", "paypal", "appleid", "billing", "recovery", "alert"
]


def normalize_url(raw_url: str) -> str:
    """Safely sanitize, strip whitespace, and normalize URL scheme."""
    if not raw_url:
        return ""
    clean = raw_url.strip()
    # If no protocol scheme is present, default to http:// for parsing purposes
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", clean):
        clean = "http://" + clean
    return clean


def is_ip_address(hostname: str) -> int:
    """Return 1 if hostname matches a valid IPv4 or IPv6 literal, 0 otherwise."""
    if not hostname:
        return 0
    # Strip port if present in netloc
    clean_host = hostname.split(":")[0].strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return 1
    except ValueError:
        return 0


def count_subdomains(hostname: str) -> int:
    """Count subdomains excluding top-level domain and main domain."""
    if not hostname or is_ip_address(hostname):
        return 0
    clean_host = hostname.split(":")[0].lower()
    parts = [p for p in clean_host.split(".") if p]
    if len(parts) <= 2:
        return 0
    # e.g., "secure.login.example.com" -> 4 parts -> 2 subdomains
    return len(parts) - 2


def extract_features(raw_url: str) -> dict:
    """Extract strictly lexical features from untrusted URL strings.
    
    Zero outbound connections are made.
    """
    normalized = normalize_url(raw_url)
    try:
        parsed = urlsplit(normalized)
    except Exception:
        # Fallback on basic regex if urlsplit fails on corrupted syntax
        parsed = None

    url_str = normalized
    scheme = (parsed.scheme if parsed else "").lower()
    hostname = (parsed.hostname or parsed.netloc if parsed else "").lower()
    path = parsed.path if parsed else ""
    query = parsed.query if parsed else ""

    # Feature calculations
    url_length = len(url_str)
    hostname_length = len(hostname)
    num_dots = url_str.count(".")
    num_hyphens = url_str.count("-")
    num_digits = sum(1 for c in url_str if c.isdigit())
    num_subdomains = count_subdomains(hostname)
    is_https = 1 if scheme == "https" else 0
    is_ip = is_ip_address(hostname)

    # Suspicious keywords in hostname + path
    search_space = f"{hostname} {path} {query}".lower()
    suspicious_token_count = 0
    detected_tokens = []
    for token in SUSPICIOUS_TOKENS:
        count = search_space.count(token)
        if count > 0:
            suspicious_token_count += count
            detected_tokens.append(token)

    path_length = len(path)
    query_length = len(query)
    has_at_symbol = 1 if "@" in url_str else 0
    percent_encoded_count = url_str.count("%")

    features_dict = {
        "url_length": url_length,
        "hostname_length": hostname_length,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_digits": num_digits,
        "num_subdomains": num_subdomains,
        "is_https": is_https,
        "is_ip": is_ip,
        "suspicious_token_count": suspicious_token_count,
        "path_length": path_length,
        "query_length": query_length,
        "has_at_symbol": has_at_symbol,
        "percent_encoded_count": percent_encoded_count,
    }

    explanation_metadata = {
        "detected_tokens": detected_tokens,
        "is_ip_host": bool(is_ip),
        "has_at_symbol": bool(has_at_symbol),
        "excessive_dots": num_dots >= 4,
        "excessive_subdomains": num_subdomains >= 2,
        "high_digit_count": num_digits > 10,
        "long_url": url_length > 75,
        "normalized_url": normalized,
    }

    return {
        "features": features_dict,
        "explanation": explanation_metadata,
        "normalized_url": normalized,
    }


def extract_features_vector(raw_url: str) -> list:
    """Return feature values as an ordered float/int list matching FEATURE_NAMES."""
    data = extract_features(raw_url)
    feats = data["features"]
    return [feats[name] for name in FEATURE_NAMES]
