"""Role-based authorization and security permission tests."""


def test_unauthenticated_access_redirect(client):
    """Ensure protected routes redirect anonymous visitors to sign in."""
    res = client.get("/dashboard")
    assert res.status_code == 302
    assert "/login" in res.headers["Location"]

    admin_res = client.get("/admin")
    assert admin_res.status_code == 302
    assert "/login" in admin_res.headers["Location"]


def test_regular_user_forbidden_from_admin_portal(authenticated_client):
    """Verify regular user receives HTTP 403 Forbidden on all administrative endpoints."""
    endpoints = [
        "/admin",
        "/admin/users",
        "/admin/datasets",
        "/admin/datasets/upload",
        "/admin/training",
        "/admin/models",
        "/admin/model-comparison",
        "/admin/training-history",
        "/admin/audit-logs",
        "/admin/export/scans.csv",
        "/admin/export/models.csv",
        "/admin/export/training-history.csv",
    ]

    for ep in endpoints:
        res = authenticated_client.get(ep)
        assert res.status_code == 403, f"Endpoint {ep} did not enforce 403 for regular user."


def test_admin_user_permitted_on_admin_portal(admin_client):
    """Verify administrator account can access administrative endpoints."""
    endpoints = [
        "/admin",
        "/admin/users",
        "/admin/datasets",
        "/admin/training",
        "/admin/models",
        "/admin/model-comparison",
        "/admin/training-history",
        "/admin/audit-logs",
    ]

    for ep in endpoints:
        res = admin_client.get(ep)
        assert res.status_code == 200, f"Admin endpoint {ep} returned {res.status_code} for admin user."
