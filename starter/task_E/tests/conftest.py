import pytest
from fastapi.testclient import TestClient

from app.web import SESSION_COOKIE, create_app, open_session


@pytest.fixture
def client():
    app = create_app()
    session_id = open_session(app, "alice")
    with TestClient(app, base_url="https://accounts.test") as http:
        http.cookies.set(SESSION_COOKIE, session_id, domain="accounts.test", path="/")
        yield http
