from pathlib import Path

import pytest

from config import get_settings
from models import Event


def files(client):
    return client.get("/workspace/files").json()


def on_disk(*parts):
    return Path(get_settings().workspaces_dir, "P01_A", *parts)


def test_lists_the_starter_task(client, team):
    tree = files(client)
    assert tree["app"] == {"type": "folder"}
    assert tree["app/auth.py"]["type"] == "file"
    assert "def login" in tree["app/auth.py"]["content"]


def test_read_a_file(client, team):
    assert "def login" in client.get("/workspace/files/app/auth.py").json()["content"]
    assert client.get("/workspace/files/missing.py").status_code == 404
    assert client.get("/workspace/files/app").status_code == 404  # a folder, not a file


def test_write_creates_then_saves_on_disk(client, db, team):
    assert client.put("/workspace/files/app/utils/check.py", json={"content": "v1"}).status_code == 200
    client.put("/workspace/files/app/utils/check.py", json={"content": "v2"})
    assert on_disk("app", "utils", "check.py").read_text(encoding="utf-8") == "v2"
    assert files(client)["app/utils"] == {"type": "folder"}
    logged = [(e.type, e.detail) for e in db.query(Event).filter(Event.type.like("file_%"))]
    assert logged == [("file_created", {"path": "app/utils/check.py", "chars": 2})] + [
        ("file_saved", {"path": "app/utils/check.py", "chars": 2})
    ]


def test_cannot_write_over_a_folder_or_inside_a_file(client, team):
    assert client.put("/workspace/files/app", json={"content": "x"}).status_code == 409
    assert client.put("/workspace/files/README.md/x.py", json={"content": "x"}).status_code == 409


def test_create_and_delete_folders(client, team):
    assert client.post("/workspace/folders", json={"path": "docs"}).status_code == 201
    assert files(client)["docs"] == {"type": "folder"}
    assert client.post("/workspace/folders", json={"path": "docs"}).status_code == 409
    assert client.delete("/workspace/files/app").status_code == 204
    assert not on_disk("app").exists()
    assert client.delete("/workspace/files/app").status_code == 404


def test_rename_moves_folders_with_their_contents(client, team):
    response = client.post("/workspace/files/rename", json={"from_path": "app", "to_path": "src/app"})
    assert response.status_code == 204
    assert "def login" in files(client)["src/app/auth.py"]["content"]
    assert "app/auth.py" not in files(client)


@pytest.mark.parametrize(
    "body, status",
    [
        ({"from_path": "nope.py", "to_path": "x.py"}, 404),
        ({"from_path": "README.md", "to_path": "app/auth.py"}, 409),
        ({"from_path": "app", "to_path": "app/inner"}, 409),
    ],
)
def test_rename_errors(client, team, body, status):
    assert client.post("/workspace/files/rename", json=body).status_code == status


# Paths in the request body reach the server exactly as sent (URLs get tidied by the HTTP client first).
@pytest.mark.parametrize("bad_path", ["../outside", "app/../../x", "a//b", "a/./b", "C:x", "/etc/x", "a\\..\\b"])
def test_unsafe_paths_are_rejected(client, team, study_dirs, bad_path):
    assert client.post("/workspace/folders", json={"path": bad_path}).status_code == 422
    rename = client.post("/workspace/files/rename", json={"from_path": "README.md", "to_path": bad_path})
    assert rename.status_code == 422
    assert on_disk("README.md").is_file()
    assert not (study_dirs / "workspaces" / "outside").exists()


def test_test_caches_are_hidden(client, team):
    on_disk("tests", "__pycache__").mkdir()
    (on_disk("tests", "__pycache__") / "x.pyc").write_bytes(b"\x00")
    assert not any("__pycache__" in path for path in files(client))


def test_finished_part_is_read_only(client, team):
    client.post("/study/done")
    assert client.put("/workspace/files/new.py", json={"content": "x"}).status_code == 409
    assert client.get("/workspace/files/app/auth.py").status_code == 200


def test_files_need_an_active_participant(client):
    assert client.get("/workspace/files").status_code == 409


# ---- notes box -------------------------------------------------------------------------------


def test_notes_box_in_single_mode(client, single):
    assert client.get("/workspace/notes").json() == {"text": ""}
    assert client.put("/workspace/notes", json={"text": "Risk: SQL injection"}).json()["text"] == "Risk: SQL injection"
    assert client.get("/workspace/notes").json()["text"] == "Risk: SQL injection"


def test_no_notes_box_in_team_mode(client, team):
    assert client.put("/workspace/notes", json={"text": "x"}).status_code == 409
