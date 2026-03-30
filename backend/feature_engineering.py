"""
PhishGuard — feature_engineering.py
Extracts 20+ features from a URL for phishing classification.

Features are based on established phishing detection research papers
(USENIX Security, IEEE S&P) and real-world datasets (PhishTank, OpenPhish).
"""

import re
import math
from urllib.parse import urlparse, parse_qs

# ── Known suspicious TLDs (commonly abused in phishing) ──────────────────
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work",
    ".click", ".zip", ".review", ".country", ".kim", ".cricket",
    ".science", ".party", ".gdn", ".loan", ".download",
}

# ── Phishing keyword list ──────────────────────────────────────────────────
PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "account", "verify", "verification",
    "update", "secure", "security", "banking", "paypal", "ebay",
    "amazon", "apple", "microsoft", "google", "facebook", "instagram",
    "confirm", "password", "credential", "suspend", "suspended",
    "alert", "urgent", "immediately", "free", "win", "winner",
    "click", "limited", "offer", "bonus", "prize", "claim",
    "wallet", "crypto", "bitcoin", "recover", "support", "helpdesk",
]

# ── Legitimate shortener domains (flag if URL contains them) ─────────────
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "cutt.ly", "short.io",
}


def extract_features(url: str) -> tuple[list[float], dict]:
    """
    Extract a numeric feature vector and a raw feature dict from a URL.

    Returns:
        (feature_vector, raw_features)
        - feature_vector: list of floats for ML model
        - raw_features:   dict of human-readable values for explanation
    """
    # Parse URL safely
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
    except Exception:
        parsed = urlparse("http://unknown")

    hostname  = (parsed.hostname or "").lower()
    path      = parsed.path or ""
    query     = parsed.query or ""
    scheme    = parsed.scheme.lower()

    url_lower = url.lower()

    # ── Feature 1: URL length ──────────────────────────────────────────────
    url_length = len(url)

    # ── Feature 2: Hostname length ─────────────────────────────────────────
    domain_length = len(hostname)

    # ── Feature 3: Number of dots in hostname ─────────────────────────────
    num_dots = hostname.count(".")

    # ── Feature 4: Has @ symbol ───────────────────────────────────────────
    has_at_symbol = "@" in url

    # ── Feature 5: Has IP address as hostname ─────────────────────────────
    has_ip_address = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname))

    # ── Feature 6: Has HTTPS ──────────────────────────────────────────────
    has_https = scheme == "https"

    # ── Feature 7: Number of hyphens in hostname ──────────────────────────
    num_hyphens = hostname.count("-")

    # ── Feature 8: Number of hyphens in path ─────────────────────────────
    path_hyphens = path.count("-")

    # ── Feature 9: Number of slashes ──────────────────────────────────────
    num_slashes = url.count("/")

    # ── Feature 10: Double slash in URL (after protocol) ─────────────────
    has_double_slash = "//" in url[7:]  # skip "http://"

    # ── Feature 11: Has suspicious TLD ───────────────────────────────────
    has_suspicious_tld = any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)

    # ── Feature 12: Non-standard port ─────────────────────────────────────
    has_port = parsed.port is not None and parsed.port not in (80, 443)
    port_value = parsed.port or 0

    # ── Feature 13: Number of subdomains ─────────────────────────────────
    parts = hostname.split(".")
    num_subdomains = max(0, len(parts) - 2)

    # ── Feature 14: Query string length ──────────────────────────────────
    query_length = len(query)

    # ── Feature 15: Number of query parameters ───────────────────────────
    num_query_params = len(parse_qs(query))

    # ── Feature 16: Redirect in URL ───────────────────────────────────────
    has_redirect = "redirect" in url_lower or "url=http" in url_lower or "=http" in url_lower

    # ── Feature 17: Suspicious keywords ──────────────────────────────────
    found_keywords = [kw for kw in PHISHING_KEYWORDS if kw in url_lower]
    suspicious_keyword_count = len(found_keywords)
    top_keyword = found_keywords[0] if found_keywords else ""

    # ── Feature 18: URL shortener ─────────────────────────────────────────
    is_url_shortener = any(s in hostname for s in URL_SHORTENERS)

    # ── Feature 19: Path depth ────────────────────────────────────────────
    path_depth = len([p for p in path.split("/") if p])

    # ── Feature 20: Digits in domain ─────────────────────────────────────
    digits_in_domain = sum(c.isdigit() for c in hostname)

    # ── Feature 21: Entropy of hostname (randomness) ─────────────────────
    hostname_entropy = _shannon_entropy(hostname)

    # ── Feature 22: Has encoded characters ───────────────────────────────
    has_encoding = "%" in url

    # ── Feature 23: Ratio of digits to domain length ─────────────────────
    digit_ratio = digits_in_domain / max(domain_length, 1)

    # ── Raw features dict (for explanations) ─────────────────────────────
    raw = {
        "url_length":             url_length,
        "domain_length":          domain_length,
        "num_dots":               num_dots,
        "has_at_symbol":          has_at_symbol,
        "has_ip_address":         has_ip_address,
        "has_https":              has_https,
        "num_hyphens":            num_hyphens,
        "path_hyphens":           path_hyphens,
        "num_slashes":            num_slashes,
        "has_double_slash":       has_double_slash,
        "has_suspicious_tld":     has_suspicious_tld,
        "has_port":               has_port,
        "port_value":             port_value,
        "num_subdomains":         num_subdomains,
        "query_length":           query_length,
        "num_query_params":       num_query_params,
        "has_redirect":           has_redirect,
        "suspicious_keyword_count": suspicious_keyword_count,
        "top_keyword":            top_keyword,
        "found_keywords":         found_keywords,
        "is_url_shortener":       is_url_shortener,
        "path_depth":             path_depth,
        "digits_in_domain":       digits_in_domain,
        "hostname_entropy":       round(hostname_entropy, 3),
        "has_encoding":           has_encoding,
        "digit_ratio":            round(digit_ratio, 3),
    }

    # ── Numeric feature vector (for ML model) ────────────────────────────
    feature_vector = [
        url_length,
        domain_length,
        num_dots,
        int(has_at_symbol),
        int(has_ip_address),
        int(has_https),
        num_hyphens,
        path_hyphens,
        num_slashes,
        int(has_double_slash),
        int(has_suspicious_tld),
        int(has_port),
        num_subdomains,
        query_length,
        num_query_params,
        int(has_redirect),
        suspicious_keyword_count,
        int(is_url_shortener),
        path_depth,
        digits_in_domain,
        hostname_entropy,
        int(has_encoding),
        digit_ratio,
    ]

    return feature_vector, raw


def get_feature_explanations(raw: dict) -> list[dict]:
    """
    Convert raw feature dict to display-ready feature chips.
    Returns list of {name, value, risk} dicts.
    """
    url_len = raw.get("url_length", 0)
    features = [
        {
            "name": "URL Length",
            "value": f"{url_len} chars",
            "risk": "high" if url_len > 100 else "medium" if url_len > 75 else "low",
        },
        {
            "name": "Contains @",
            "value": "Yes" if raw.get("has_at_symbol") else "No",
            "risk": "high" if raw.get("has_at_symbol") else "low",
        },
        {
            "name": "IP as Host",
            "value": "Yes" if raw.get("has_ip_address") else "No",
            "risk": "high" if raw.get("has_ip_address") else "low",
        },
        {
            "name": "HTTPS",
            "value": "Yes" if raw.get("has_https") else "No",
            "risk": "low" if raw.get("has_https") else "medium",
        },
        {
            "name": "Subdomains",
            "value": raw.get("num_subdomains", 0),
            "risk": "high" if raw.get("num_subdomains", 0) > 2
                    else "medium" if raw.get("num_subdomains", 0) > 1 else "low",
        },
        {
            "name": "Suspicious TLD",
            "value": "Yes" if raw.get("has_suspicious_tld") else "No",
            "risk": "high" if raw.get("has_suspicious_tld") else "low",
        },
        {
            "name": "Keyword",
            "value": raw.get("top_keyword") or "None",
            "risk": "high" if raw.get("suspicious_keyword_count", 0) > 1
                    else "medium" if raw.get("suspicious_keyword_count", 0) == 1 else "low",
        },
        {
            "name": "Hyphens",
            "value": raw.get("num_hyphens", 0),
            "risk": "high" if raw.get("num_hyphens", 0) > 3
                    else "medium" if raw.get("num_hyphens", 0) > 1 else "low",
        },
        {
            "name": "Has Port",
            "value": f":{raw['port_value']}" if raw.get("has_port") else "No",
            "risk": "high" if raw.get("has_port") else "low",
        },
        {
            "name": "Redirect",
            "value": "Yes" if raw.get("has_redirect") else "No",
            "risk": "high" if raw.get("has_redirect") else "low",
        },
    ]
    return features


# ──────────────────────────────────────────────────────────────────────────
# UTILITIES
# ──────────────────────────────────────────────────────────────────────────
def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy — higher values = more random/suspicious."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())
