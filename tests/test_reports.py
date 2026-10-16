"""Tests for ReportLab PDF audit certificates, CSV exports, formula sanitization, and IDOR protection."""
from datetime import datetime
from zoneinfo import ZoneInfo

from app.models import Scan
from app.ml.prediction_service import predict_url
from app.reporting.csv_generator import generate_scans_csv, sanitize_csv_cell
from app.reporting.timezone import format_local_timestamp, get_device_timezone


def test_scan_csv_formats_device_local_timestamp():
    """CSV scan timestamps use the requested IANA timezone and its DST rules."""
    scan = Scan(created_at=datetime(2024, 1, 2, 3, 4, 5))
    timezone = get_device_timezone("Asia/Kolkata")

    assert generate_scans_csv([scan], local_timezone=timezone).getvalue().splitlines() == [
        "Scan ID,Timestamp (Local Time),Target URL,Prediction,Risk Score (0-100),Risk Category,Probability,Model Version,Latency (ms)",
        ",2024-01-02 08:34:05 IST,,,,,,,",
    ]


def test_naive_database_timestamps_are_treated_as_utc_for_conversion():
    """Naive timestamps returned by databases are interpreted as UTC before conversion."""
    assert format_local_timestamp(
        datetime(2024, 7, 1, 12, 0, 0), ZoneInfo("America/Los_Angeles")
    ) == "2024-07-01 05:00:00 PDT"


def test_csv_formula_injection_sanitization():
    """Verify spreadsheet injection mitigation prefixes dangerous trigger characters."""
    assert sanitize_csv_cell("=cmd|'/C calc'!A0") == "'=cmd|'/C calc'!A0"
    assert sanitize_csv_cell("+12345") == "'+12345"
    assert sanitize_csv_cell("-12345") == "'-12345"
    assert sanitize_csv_cell("@SUM(1,2)") == "'@SUM(1,2)"
    assert sanitize_csv_cell("safe_domain.com") == "safe_domain.com"


def test_pdf_audit_generation_and_idor_protection(client, db_session, regular_user, other_user, admin_user):
    """Verify PDF downloads succeed for scan owner and admin, but return 403 for other users."""
    # 1. Create a scan belonging to regular_user
    scan_owner, _ = predict_url("http://example-test.org/check", regular_user.id)

    # 2. Owner logs in and downloads PDF -> 200 OK
    client.post("/login", data={
        "username_or_email": regular_user.username,
        "password": "StandardPassword123!"
    })
    res_owner = client.get(
        f"/scan/{scan_owner.id}/audit.pdf?timezone=Asia%2FKolkata"
    )
    assert res_owner.status_code == 200
    assert res_owner.mimetype == "application/pdf"
    assert b"%PDF" in res_owner.data[:10]

    # 3. Other user logs in and tries to access scan_owner's PDF -> 403 Forbidden (IDOR prevention)
    client.get("/logout")
    client.post("/login", data={
        "username_or_email": other_user.username,
        "password": "OtherPassword123!"
    })
    res_other = client.get(f"/scan/{scan_owner.id}/audit.pdf")
    assert res_other.status_code == 403

    # Also verify detail view is protected against IDOR
    res_other_detail = client.get(f"/scan/{scan_owner.id}")
    assert res_other_detail.status_code == 403

    # 4. Admin logs in and accesses scan_owner's PDF -> 200 OK
    client.get("/logout")
    client.post("/login", data={
        "username_or_email": admin_user.username,
        "password": "AdminSecurePassword123!"
    })
    res_admin = client.get(f"/scan/{scan_owner.id}/audit.pdf")
    assert res_admin.status_code == 200


def test_user_csv_export_isolation(client, db_session, regular_user, other_user):
    """Verify personal CSV export contains only scans owned by the requesting user."""
    # Create scan for regular user
    predict_url("https://user1-specific-domain.com", regular_user.id)
    # Create scan for other user
    predict_url("https://user2-isolated-url.com", other_user.id)

    # Login as regular user and download CSV
    client.post("/login", data={
        "username_or_email": regular_user.username,
        "password": "StandardPassword123!"
    })

    res = client.get("/reports/export.csv?timezone=Asia%2FKolkata")
    assert res.status_code == 200
    content = res.data.decode("utf-8")

    assert "Timestamp (Local Time)" in content
    assert " IST" in content
    assert "user1-specific-domain.com" in content
    # Crucial security check: user2's data must NOT be in user1's export
    assert "user2-isolated-url.com" not in content
    assert client.get("/reports/export.csv?timezone=Invalid%2FTimezone").status_code == 400
