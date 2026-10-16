"""Tests for URL scanning, risk scoring, and MySQL persistence."""
from datetime import datetime

from app.models import Scan, ScanFeature
from app.ml.prediction_service import predict_url, get_risk_category


def test_risk_category_thresholds():
    """Verify documented risk category thresholds."""
    assert get_risk_category(10.0) == "Low"
    assert get_risk_category(24.9) == "Low"
    assert get_risk_category(25.0) == "Moderate"
    assert get_risk_category(54.9) == "Moderate"
    assert get_risk_category(55.0) == "High"
    assert get_risk_category(79.9) == "High"
    assert get_risk_category(80.0) == "Critical"
    assert get_risk_category(100.0) == "Critical"


def test_url_scan_and_database_persistence(db_session, regular_user):
    """Test full scan pipeline, risk calculation, and 1-to-1 feature record creation."""
    test_url = "http://192.168.1.100/account-verification/update.php?user=victim"
    scan, explanation = predict_url(test_url, regular_user.id)

    assert scan.id is not None
    assert scan.user_id == regular_user.id
    assert scan.prediction_label in ("phishing", "legitimate")
    assert 0.0 <= scan.risk_score <= 100.0
    assert scan.risk_category in ("Low", "Moderate", "High", "Critical")
    assert scan.latency_ms > 0.0

    # Verify 1-to-1 relationship with ScanFeature
    feature_record = ScanFeature.query.filter_by(scan_id=scan.id).first()
    assert feature_record is not None
    assert feature_record.is_ip == 1
    assert feature_record.suspicious_token_count >= 1
    assert feature_record.scan.id == scan.id


def test_scan_route_submission(authenticated_client, db_session):
    """Test HTTP POST submission to /scan."""
    response = authenticated_client.post("/scan", data={
        "url": "https://www.wikipedia.org/wiki/Computer_security"
    }, follow_redirects=True)

    assert response.status_code == 200
    scan = Scan.query.order_by(Scan.id.desc()).first()
    assert scan is not None
    assert "wikipedia.org" in scan.url


def test_history_marks_utc_timestamp_for_browser_local_conversion(
    authenticated_client, db_session, regular_user
):
    """History timestamps carry UTC metadata so the browser can display device-local time."""
    scan = Scan(
        user_id=regular_user.id,
        url="https://example.org",
        url_hash="a" * 64,
        prediction_label="legitimate",
        risk_score=1.0,
        risk_category="Low",
        probability=0.01,
        model_version="test",
        latency_ms=1.0,
        created_at=datetime(2024, 1, 2, 3, 4, 5),
    )
    db_session.add(scan)
    db_session.commit()

    response = authenticated_client.get("/history")

    assert response.status_code == 200
    assert b"Timestamp (Device Local Time)" in response.data
    assert b'datetime="2024-01-02T03:04:05Z"' in response.data
    assert b"new Intl.DateTimeFormat" in response.data
