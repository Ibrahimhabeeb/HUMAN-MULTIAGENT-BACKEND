import json
import shutil

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


@pytest.fixture
def finish_parts(client):
    # Clicks Done on the current part, switches to the other mode and clicks Done again.
    def _finish():
        mode = client.get("/study/state").json()["mode"]
        client.post("/study/done")
        client.post("/study/mode", json={"mode": "single" if mode == "team" else "team"})
        client.post("/study/done")

    return _finish


# A stand-in for content/questionnaire.json; the real wording is added once it is approved.
SAMPLE_QUESTIONNAIRE = {
    "version": "test",
    "sections": [
        {
            "title": "Each mode",
            "asked_for": "each_mode",
            "questions": [{"key": "confidence", "type": "scale", "text": "I am confident my final code is secure."}],
        },
        {
            "title": "Agent team",
            "asked_for": "team",
            "questions": [{"key": "roles_clear", "type": "scale", "text": "Each agent's role was clear."}],
        },
        {
            "title": "Comparing",
            "asked_for": "once",
            "questions": [
                {
                    "key": "preferred",
                    "type": "choice",
                    "text": "Which would you rather use?",
                    "options": ["Agent team", "Single assistant", "No preference"],
                },
                {"key": "difference", "type": "text", "text": "What was the biggest difference?"},
            ],
        },
    ],
}


@pytest.fixture
def content_dir(tmp_path, monkeypatch):
    # A copy of content/ without questionnaire.json, so tests don't depend on whether it exists yet.
    settings = get_settings()
    folder = tmp_path / "content"
    shutil.copytree(settings.content_dir, folder, ignore=shutil.ignore_patterns("questionnaire.json"))
    monkeypatch.setattr(settings, "content_dir", str(folder))
    return folder


@pytest.fixture
def sample_questionnaire(content_dir):
    (content_dir / "questionnaire.json").write_text(json.dumps(SAMPLE_QUESTIONNAIRE), encoding="utf-8")
    return SAMPLE_QUESTIONNAIRE
