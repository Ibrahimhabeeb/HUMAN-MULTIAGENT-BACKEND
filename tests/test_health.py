from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_health_returns_ok():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_frontend_origin_is_allowed_by_cors():
    response = client.get("/health", headers={"Origin": "http://localhost:5001"})
    assert response.headers["access-control-allow-origin"] == "http://localhost:5001"


def test_unknown_origin_is_not_allowed_by_cors():
    response = client.get("/health", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in response.headers
