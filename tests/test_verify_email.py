import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT))

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from app import app as flask_app, db, User, generate_verify_token


@pytest.fixture()
def app():
    flask_app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SECRET_KEY=os.getenv("SECRET_KEY", "test-secret"),
    )

    with flask_app.app_context():
        db.create_all()
        yield flask_app
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def test_verify_email_success(client, app):
    with app.app_context():
        user = User(
            username="verify_user",
            email="verify@example.com",
            password_hash="hashed",
            slug="verify",
            is_verified=False,
        )
        db.session.add(user)
        db.session.commit()
        token = generate_verify_token(user.email)

    response = client.get(f"/verify-email/{token}")

    assert response.status_code == 200
    assert b"Email verified successfully" in response.data

    with app.app_context():
        refreshed = User.query.filter_by(email="verify@example.com").first()
        assert refreshed.is_verified is True


def test_verify_email_invalid_token(client):
    response = client.get("/verify-email/invalid-token")

    assert response.status_code == 200
    assert b"Invalid or expired link" in response.data
