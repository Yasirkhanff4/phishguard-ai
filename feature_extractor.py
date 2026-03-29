"""
PhishGuard AI — Feature Extractor
====================================
Extracts 20+ features from a URL for phishing detection.
"""

import re
import urllib.parse


# ─────────────────────────────────────────
# SUSPICIOUS KEYWORDS
# ─────────────────────────────────────────
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "bank",
    "paypal", "signin", "password", "confirm", "alert", "suspend",
    "validate", "credential", "recover", "ebay", "billing",
    "support", "access", "webscr", "cmd", "checkout",
]

SHORTENING_SERVICES = [
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
    "shorte.st", "adf.ly", "cutt.ly", "rebrand.ly",
]


def extract_features(url: str) -> dict:
    """
    Extract phishing-detection features from a URL.
    Returns a dict of all features + an overall risk_score (0–100).
    """
    original_url = url
    lower = url.lower()

    # ── Parse URL ──
    try:
        parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
        domain = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
    except Exception:
        domain = ""
        path = ""
        query = ""

    # ── Basic metrics ──
    url_length = len(url)
    dot_count = url.count(".")
    hyphen_count = domain.count("-")
    slash_count = url.count("/")

    # ── Protocol ──
    has_https = lower.startswith("https://")
    has_http = lower.startswith("http://")

    # ── IP address as domain ──
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    has_ip = bool(ip_pattern.match(domain))

    # ── Suspicious characters ──
    has_at_sign = "@" in url
    has_double_slash = "//" in url[8:]   # after the protocol
    has_tilde = "~" in url

    # ── Subdomains ──
    domain_parts = domain.split(".")
    subdomain_count = max(0, len(domain_parts) - 2)  # exclude TLD + base

    # ── Suspicious keywords ──
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lower]
    suspicious_keyword_count = len(found_keywords)

    # ── URL shortening ──
    is_shortened = any(svc in lower for svc in SHORTENING_SERVICES)

    # ── Numeric characters in domain ──
    digits_in_domain = sum(c.isdigit() for c in domain)

    # ── Special chars in path ──
    special_in_path = len(re.findall(r"[;=&%$#!]", path + query))

    # ── Domain length ──
    domain_length = len(domain)

    # ── Entropy proxy: ratio of digits + specials to url length ──
    non_alpha = sum(1 for c in url if not c.isalpha() and c not in "/:.")
    entropy_ratio = round(non_alpha / max(url_length, 1), 3)

    # ─────────────────────────────────────
    # RISK SCORE CALCULATION (0–100)
    # ─────────────────────────────────────
    score = 0

    if not has_https:                          score += 15
    if has_ip:                                 score += 25
    if url_length > 75:                        score += 10
    if url_length > 100:                       score += 10
    if has_at_sign:                            score += 20
    if has_double_slash:                       score += 15
    if hyphen_count > 2:                       score += 10
    if hyphen_count > 5:                       score += 8
    if subdomain_count > 2:                    score += 15
    if suspicious_keyword_count >= 1:          score += suspicious_keyword_count * 8
    if dot_count > 5:                          score += 8
    if is_shortened:                           score += 10
    if digits_in_domain > 3:                   score += 8
    if domain_length > 30:                     score += 10
    if special_in_path > 3:                    score += 8
    if has_tilde:                              score += 5
    if entropy_ratio > 0.4:                    score += 8

    risk_score = min(score, 100)

    return {
        # Raw metrics
        "url_length":               url_length,
        "dot_count":                dot_count,
        "hyphen_count":             hyphen_count,
        "slash_count":              slash_count,
        "subdomain_count":          subdomain_count,
        "domain_length":            domain_length,
        "digits_in_domain":         digits_in_domain,
        "special_in_path":          special_in_path,
        "entropy_ratio":            entropy_ratio,
        # Boolean flags
        "has_https":                has_https,
        "has_http":                 has_http,
        "has_ip":                   has_ip,
        "has_at_sign":              has_at_sign,
        "has_double_slash":         has_double_slash,
        "has_tilde":                has_tilde,
        "is_shortened":             is_shortened,
        # Keywords
        "suspicious_keyword_count": suspicious_keyword_count,
        "found_keywords":           found_keywords,
        # Domain
        "domain":                   domain,
        # Summary
        "risk_score":               risk_score,
    }


if __name__ == "__main__":
    # Quick test
    test_urls = [
        "http://secure-login-paypal.verification.com/signin",
        "https://www.google.com",
        "http://192.168.1.1/bank/login?verify=1",
    ]
    for u in test_urls:
        f = extract_features(u)
        print(f"\nURL: {u}")
        print(f"  Risk Score : {f['risk_score']}")
        print(f"  HTTPS      : {f['has_https']}")
        print(f"  Has IP     : {f['has_ip']}")
        print(f"  Keywords   : {f['found_keywords']}")
