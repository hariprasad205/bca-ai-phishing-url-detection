"""Authentication and password security test cases."""
from app.models import User, AuditLog


def test_password_hashing(db_session):
    """Ensure passwords are never stored in plaintext and verify Werkzeug hashing."""
    user = User(username="hash_test", email="hash@test.org")
    plain = "SuperSecretPlain123!"
    user.set_password(plain)

    assert user.password_hash != plain
    assert user.check_password(plain) is True
    assert user.check_password("WrongPassword") is False


def test_user_registration(client, db_session):
    """Test user registration endpoint with database insertion."""
    response = client.post("/register", data={
        "username": "new_analyst",
        "email": "analyst@defense.edu",
        "password": "Password12345!",
        "confirm_password": "Password12345!",
    }, follow_redirects=True)

    assert response.status_code == 200
    user = User.query.filter_by(username="new_analyst").first()
    assert user is not None
    assert user.email == "analyst@defense.edu"
    assert user.role == "user"
    assert user.is_active is True

    # Verify audit log was recorded
    log = AuditLog.query.filter_by(user_id=user.id, action="USER_REGISTERED").first()
    assert log is not None


def test_user_login_and_logout(client, regular_user):
    """Test user login and session termination."""
    # Successful login
    login_res = client.post("/login", data={
        "username_or_email": regular_user.username,
        "password": "StandardPassword123!",
    }, follow_redirects=True)
    assert login_res.status_code == 200
    assert b"Dashboard" in login_res.data

    # Logout
    logout_res = client.get("/logout", follow_redirects=True)
    assert logout_res.status_code == 200
    assert b"signed out" in logout_res.data


def test_cli_admin_creation(cli_runner, db_session):
    """Test explicit CLI create-admin command."""
    result = cli_runner.invoke(args=[
        "create-admin",
        "--username", "cli_admin",
        "--email", "cli_admin@test.gov",
        "--password", "StrongAdminPass123!",
    ])
    assert result.exit_code == 0
    assert "successfully created" in result.output

    admin = User.query.filter_by(username="cli_admin").first()
    assert admin is not None
    assert admin.is_admin is True
