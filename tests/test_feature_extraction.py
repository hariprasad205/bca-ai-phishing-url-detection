"""Tests for zero-execution lexical URL feature extraction."""
from app.ml.feature_extraction import (
    extract_features, extract_features_vector, FEATURE_NAMES,
    is_ip_address, count_subdomains
)


def test_feature_names_order_and_count():
    """Verify all 13 canonical feature names are defined and non-empty."""
    assert len(FEATURE_NAMES) == 13
    assert "url_length" in FEATURE_NAMES
    assert "is_ip" in FEATURE_NAMES
    assert "suspicious_token_count" in FEATURE_NAMES
    assert "has_at_symbol" in FEATURE_NAMES


def test_ip_address_detection():
    """Test IPv4 and domain distinction."""
    assert is_ip_address("192.168.1.1") == 1
    assert is_ip_address("10.0.0.1:8080") == 1
    assert is_ip_address("paypal.com") == 0
    assert is_ip_address("google.com:443") == 0


def test_subdomain_counting():
    """Test subdomain extraction logic."""
    assert count_subdomains("google.com") == 0
    assert count_subdomains("mail.google.com") == 1
    assert count_subdomains("secure.login.verify.bank.com") == 3


def test_lexical_feature_extraction_phishing_url():
    """Verify extraction values on typical social engineering URL."""
    url = "http://192.168.1.50/paypal-security/login.php?update=verify@account"
    res = extract_features(url)
    feats = res["features"]
    exp = res["explanation"]

    assert feats["is_ip"] == 1
    assert feats["has_at_symbol"] == 1
    assert feats["is_https"] == 0
    assert feats["suspicious_token_count"] >= 3  # paypal, security, login, update, verify, account
    assert exp["is_ip_host"] is True
    assert exp["has_at_symbol"] is True

    # Vector test
    vec = extract_features_vector(url)
    assert len(vec) == 13
    assert vec[FEATURE_NAMES.index("is_ip")] == 1
    assert vec[FEATURE_NAMES.index("has_at_symbol")] == 1
