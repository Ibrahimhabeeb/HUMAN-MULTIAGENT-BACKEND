import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from db import get_db, init_db
from main import app
from services import study

SAMPLE_FILES = {
    "main.py": {"type": "file", "content": "from app.auth import login\n"},
    "app/auth.py": {"type": "file", "content": "def login(user, password):\n    ...\n"},
    "tests": {"type": "folder"},
}


@pytest.fixture(autouse=True)
def fresh_study_memory():
    study.reset_memory()


@pytest.fixture
def db():
    # A fresh in-memory database for every test, so tests never touch data/app.db.
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    init_db(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app.dependency_overrides[get_db] = lambda: session
    yield session
    app.dependency_overrides.clear()
    session.close()
    engine.dispose()


@pytest.fixture
def client(db):
    return TestClient(app)


@pytest.fixture
def pid(client):
    body = {"name": "secure-login-task", "user_id": "participant-07", "files": SAMPLE_FILES}
    return client.post("/projects", json=body).json()["id"]


@pytest.fixture
def sid(client, pid):
    return client.post(f"/projects/{pid}/sessions").json()["id"]
