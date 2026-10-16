"""Pytest test configuration and fixtures."""
import pytest
from app import create_app
from app.extensions import db
from app.models import User, Scan, ScanFeature, Dataset


@pytest.fixture(scope="session")
def app():
    """Create application instance configured for testing."""
    _app = create_app("testing")
    with _app.app_context():
        db.create_all()
        yield _app
        db.drop_all()


@pytest.fixture(scope="function")
def db_session(app):
    """Provide a clean database session per test function."""
    with app.app_context():
        # Clean tables
        for table in reversed(db.metadata.sorted_tables):
            db.session.execute(table.delete())
        db.session.commit()
        yield db.session
        db.session.rollback()


@pytest.fixture
def client(app, db_session):
    """Flask test client."""
    return app.test_client()


@pytest.fixture
def cli_runner(app):
    """Flask CLI command runner."""
    return app.test_cli_runner()


@pytest.fixture
def regular_user(db_session):
    """Create and return a standard user."""
    user = User(
        username="standard_user",
        email="user@test.org",
        role="user",
        is_active_account=True,
    )
    user.set_password("StandardPassword123!")
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def other_user(db_session):
    """Create a second distinct standard user for IDOR testing."""
    user = User(
        username="other_user",
        email="other@test.org",
        role="user",
        is_active_account=True,
    )
    user.set_password("OtherPassword123!")
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def admin_user(db_session):
    """Create and return an administrator user."""
    admin = User(
        username="super_admin",
        email="admin@cybersecurity.gov",
        role="admin",
        is_active_account=True,
    )
    admin.set_password("AdminSecurePassword123!")
    db_session.add(admin)
    db_session.commit()
    return admin


@pytest.fixture
def authenticated_client(client, regular_user):
    """Test client authenticated as regular_user."""
    with client.session_transaction() as sess:
        sess["_user_id"] = str(regular_user.id)
        sess["_fresh"] = True
    return client


@pytest.fixture
def admin_client(client, admin_user):
    """Test client authenticated as admin_user."""
    with client.session_transaction() as sess:
        sess["_user_id"] = str(admin_user.id)
        sess["_fresh"] = True
    return client
