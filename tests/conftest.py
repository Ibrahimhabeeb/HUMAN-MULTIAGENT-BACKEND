import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from config import get_settings
from db import get_db, init_db
from main import app
from services import content, study


@pytest.fixture(autouse=True)
def fresh_study_memory():
    study.reset_memory()


@pytest.fixture(autouse=True)
def study_dirs(tmp_path, monkeypatch):
    # Workspaces and snapshots go to a temporary folder, never the real ones.
    settings = get_settings()
    monkeypatch.setattr(settings, "workspaces_dir", str(tmp_path / "workspaces"))
    monkeypatch.setattr(settings, "snapshots_dir", str(tmp_path / "snapshots"))
    return tmp_path


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
def enrol(client):
    # Walks a participant through start -> information -> consent, starting in the given mode.
    def _enrol(pilot=False, mode="team"):
        client.post("/study/mode", json={"mode": mode})
        client.post("/study/start", json={"pilot": pilot})
        client.post("/study/continue")
        return client.post("/study/consent", json={"consent_version": content.load("consent")[0]}).json()

    return _enrol


@pytest.fixture
def team(enrol):
    return enrol(mode="team")


@pytest.fixture
def single(enrol):
    return enrol(mode="single")
