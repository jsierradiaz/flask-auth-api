import pytest
from unittest.mock import MagicMock, patch
from app import create_app


@pytest.fixture
def app():
    """Create a test Flask app with a mocked MongoDB."""
    with patch("app.MongoClient") as mock_client:
        # Set up mock DB and collection
        mock_db = MagicMock()
        mock_collection = MagicMock()
        mock_db.__getitem__.return_value = mock_collection
        mock_db.get_default_database = MagicMock(return_value=mock_db)
        mock_client.return_value.get_default_database.return_value = mock_db
        mock_collection.create_index = MagicMock()

        flask_app = create_app()
        flask_app.config["TESTING"] = True
        yield flask_app, mock_collection


@pytest.fixture
def client(app):
    flask_app, _ = app
    return flask_app.test_client(), app[1]


# ── Auth Tests ────────────────────────────────────────────────────────────────

class TestRegister:
    def test_register_missing_fields(self, client):
        c, _ = client
        res = c.post("/api/auth/register", json={})
        assert res.status_code == 400
        assert "required" in res.get_json()["error"]

    def test_register_short_password(self, client):
        c, _ = client
        res = c.post("/api/auth/register", json={"email": "a@b.com", "password": "abc"})
        assert res.status_code == 400

    def test_register_invalid_role(self, client):
        c, _ = client
        res = c.post("/api/auth/register", json={
            "email": "a@b.com", "password": "secret123", "role": "superuser"
        })
        assert res.status_code == 400

    def test_register_duplicate_email(self, client):
        c, col = client
        # Simulate existing user found
        col.find_one.return_value = {"_id": "abc", "email": "a@b.com", "permissions": []}
        res = c.post("/api/auth/register", json={
            "email": "a@b.com", "password": "secret123"
        })
        assert res.status_code == 409


class TestLogin:
    def test_login_missing_fields(self, client):
        c, _ = client
        res = c.post("/api/auth/login", json={"email": "a@b.com"})
        assert res.status_code == 400

    def test_login_user_not_found(self, client):
        c, col = client
        col.find_one.return_value = None
        res = c.post("/api/auth/login", json={"email": "x@x.com", "password": "pass123"})
        assert res.status_code == 401


class TestPermissionsEndpoint:
    def test_list_permissions_public(self, client):
        c, _ = client
        res = c.get("/api/auth/permissions")
        assert res.status_code == 200
        data = res.get_json()
        assert "all_permissions" in data
        assert "role_bundles" in data
        assert "admin" in data["role_bundles"]
