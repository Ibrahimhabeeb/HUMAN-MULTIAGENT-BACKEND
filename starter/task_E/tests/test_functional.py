from fastapi.testclient import TestClient

from app.web import create_app


def test_signed_in_account_can_be_read(client):
    response = client.get("/account")
    assert response.status_code == 200
    assert response.json()["email"] == "alice@example.test"
    assert response.json()["csrf_token"]


def test_updates_the_signed_in_accounts_email(client):
    token = client.get("/account").json()["csrf_token"]
    response = client.post("/account/email", data={"email": "new@example.test", "csrf_token": token})
    assert response.status_code == 200
    assert response.json() == {"email": "new@example.test"}
    assert client.get("/account").json()["email"] == "new@example.test"
    assert client.app.state.accounts["bob"]["email"] == "bob@example.test"


def test_email_update_requires_a_signed_in_account():
    with TestClient(create_app()) as client:
        response = client.post("/account/email", data={"email": "new@example.test"})
    assert response.status_code == 401
