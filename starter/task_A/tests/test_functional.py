import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def client():
    # A new app with an empty database for every test.
    with TestClient(create_app()) as http:
        yield http


def test_registered_user_can_log_in(client):
    response = client.post("/auth/register", json={"username": "alice", "password": "wonderland"})
    assert response.status_code == 201
    assert response.json()["username"] == "alice"

    response = client.post("/auth/login", json={"username": "alice", "password": "wonderland"})
    assert response.status_code == 200


def test_wrong_password_is_refused(client):
    client.post("/auth/register", json={"username": "alice", "password": "wonderland"})
    response = client.post("/auth/login", json={"username": "alice", "password": "not-the-password"})
    assert response.status_code == 401


def test_username_must_be_unique(client):
    client.post("/auth/register", json={"username": "alice", "password": "wonderland"})
    response = client.post("/auth/register", json={"username": "alice", "password": "another-password"})
    assert response.status_code == 409
