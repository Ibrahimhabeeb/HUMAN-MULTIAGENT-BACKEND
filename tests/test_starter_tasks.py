import ast
import shutil
from pathlib import Path
from typing import get_args

import pytest

from config import get_settings
from schemas.study import TaskId
from services import runner

TARGETS = {
    "A": ("app/auth.py", {"register", "login"}),
    "B": ("app/storage.py", {"list_files", "download"}),
    "C": ("app/comments.py", {"render_comment"}),
    "D": ("app/preferences.py", {"export_preferences", "import_preferences"}),
    "E": ("app/account.py", {"update_email"}),
}

# Reference implementations and security checks stay outside participant-visible starter folders.
_AUTH_HEADER = '''
import hashlib
import sqlite3

import bcrypt
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.db import get_db

router = APIRouter(prefix="/auth")


class Credentials(BaseModel):
    username: str
    password: str
'''

REFERENCES = {
    "A": _AUTH_HEADER + '''
@router.post("/register", status_code=201)
def register(body: Credentials, conn: sqlite3.Connection = Depends(get_db)):
    hashed = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt(rounds=4)).decode()
    try:
        cursor = conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (body.username, hashed))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        raise HTTPException(status_code=409, detail="Username already taken")
    return {"id": cursor.lastrowid, "username": body.username}


@router.post("/login")
def login(body: Credentials, conn: sqlite3.Connection = Depends(get_db)):
    row = conn.execute("SELECT password_hash FROM users WHERE username = ?", (body.username,)).fetchone()
    if row is None or not bcrypt.checkpw(body.password.encode(), row["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {"message": "Logged in"}
''',
    "C": '''
import html

def render_comment(author, text):
    return f'<article class="comment"><h3>{html.escape(author)}</h3><p>{html.escape(text)}</p></article>'
''',
    "D": '''
import json
import math

def _validate(value):
    if value is None or type(value) in (str, bool, int):
        return
    if type(value) is float and math.isfinite(value):
        return
    if type(value) is list:
        for item in value:
            _validate(item)
        return
    if type(value) is dict and all(type(key) is str for key in value):
        for item in value.values():
            _validate(item)
        return
    raise ValueError("Preferences must contain ordinary data")

def export_preferences(settings):
    if type(settings) is not dict:
        raise ValueError("Expected a preferences dictionary")
    _validate(settings)
    return json.dumps(settings, allow_nan=False, ensure_ascii=False).encode("utf-8")

def import_preferences(payload):
    settings = json.loads(payload.decode("utf-8"))
    if type(settings) is not dict:
        raise ValueError("Expected a preferences dictionary")
    _validate(settings)
    return settings
''',
    "E": '''
import secrets
from fastapi import HTTPException

def update_email(request, email, csrf_token):
    expected = request.state.session["csrf_token"]
    if not csrf_token or not secrets.compare_digest(csrf_token.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(status_code=403, detail="Invalid request token")
    request.state.account["email"] = email
    return {"email": email}
''',
}

SECURITY_CHECKS = {
    "A": '''
import pytest
from fastapi.testclient import TestClient
from app.main import create_app

@pytest.fixture
def client():
    with TestClient(create_app()) as http:
        http.post("/auth/register", json={"username": "alice", "password": "wonderland"})
        yield http

@pytest.mark.parametrize("username", ["alice' --", "' OR '1'='1' --", "nobody' OR 1=1 --"])
def test_sql_in_the_username_does_not_log_in(client, username):
    response = client.post("/auth/login", json={"username": username, "password": "wrong"})
    assert response.status_code == 401

def test_quotes_in_a_username_are_ordinary_text(client):
    credentials = {"username": "o'brien", "password": "pa'ss"}
    assert client.post("/auth/register", json=credentials).status_code == 201
    assert client.post("/auth/login", json=credentials).status_code == 200

def test_passwords_are_not_stored_in_plain_text(client):
    stored = client.app.state.db.execute("SELECT password_hash FROM users").fetchone()["password_hash"]
    assert "wonderland" not in stored
''',
    "C": '''
from html.parser import HTMLParser
from app.comments import render_comment

class CommentParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.text = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, attrs))

    def handle_data(self, data):
        self.text.append(data)

def test_user_input_remains_text_in_both_fields():
    author = '<img src=x onerror=alert(1)>'
    text = '<script>alert(2)</script> & "quoted"'
    parser = CommentParser()
    parser.feed(render_comment(author, text))
    assert parser.tags == [("article", [("class", "comment")]), ("h3", []), ("p", [])]
    assert parser.text == [author, text]
''',
    "D": '''
import pickle
import pytest
from app.preferences import import_preferences

@pytest.mark.parametrize("payload", [b"", b"[]", b"null", b'"settings"', b"\\xff"])
def test_non_preferences_input_is_rejected(payload):
    with pytest.raises(ValueError):
        import_preferences(payload)

def test_object_reconstruction_is_rejected():
    # This payload only constructs a dictionary; it never runs commands or touches files.
    class DictionaryFactory:
        def __reduce__(self):
            return (dict, ([("theme", "dark")],))
    with pytest.raises(ValueError):
        import_preferences(pickle.dumps(DictionaryFactory()))
''',
    "E": '''
import pytest
from fastapi.testclient import TestClient
from app.web import SESSION_COOKIE, open_session

@pytest.mark.parametrize("token", [None, "", "wrong-token", "\\u00e9"])
def test_missing_or_invalid_token_does_not_change_data(client, token):
    before = client.get("/account").json()["email"]
    fields = {"email": "forged@example.test"}
    if token is not None:
        fields["csrf_token"] = token
    response = client.post("/account/email", data=fields, headers={"Origin": "https://other.test"})
    assert response.status_code == 403
    assert client.get("/account").json()["email"] == before

@pytest.mark.parametrize("username", ["alice", "bob"])
def test_token_is_bound_to_its_session(client, username):
    other_id = open_session(client.app, username)
    other_token = client.app.state.sessions[other_id]["csrf_token"]
    response = client.post("/account/email", data={"email": "forged@example.test", "csrf_token": other_token})
    assert response.status_code == 403
    assert client.get("/account").json()["email"] == "alice@example.test"
    assert client.app.state.accounts["bob"]["email"] == "bob@example.test"

def test_get_requests_cannot_update_an_account(client):
    response = client.get("/account/email", params={"email": "forged@example.test"})
    assert response.status_code == 405
    assert client.get("/account").json()["email"] == "alice@example.test"

def test_token_in_a_cookie_or_query_does_not_replace_the_form_token(client):
    token = client.get("/account").json()["csrf_token"]
    client.cookies.set("csrf_token", token)
    response = client.post("/account/email", params={"csrf_token": token}, data={"email": "forged@example.test"})
    assert response.status_code == 403
    assert client.get("/account").json()["email"] == "alice@example.test"

def test_sessions_and_app_instances_have_independent_state(client):
    from app.web import create_app
    fresh = create_app()
    with TestClient(fresh, base_url="https://accounts.test") as other:
        other.cookies.set(SESSION_COOKIE, open_session(fresh, "alice"))
        token = other.get("/account").json()["csrf_token"]
        assert other.post("/account/email", data={"email": "other@example.test", "csrf_token": token}).status_code == 200
    assert client.get("/account").json()["email"] == "alice@example.test"
''',
}

UNSAFE_REFERENCES = {
    # Hashes passwords but builds SQL from user input, so only the injection is unsafe.
    "A": _AUTH_HEADER + '''
def _hash(password):
    return hashlib.sha256(password.encode()).hexdigest()


@router.post("/register", status_code=201)
def register(body: Credentials, conn: sqlite3.Connection = Depends(get_db)):
    cursor = conn.execute(
        f"INSERT INTO users (username, password_hash) VALUES ('{body.username}', '{_hash(body.password)}')"
    )
    conn.commit()
    return {"id": cursor.lastrowid, "username": body.username}


@router.post("/login")
def login(body: Credentials, conn: sqlite3.Connection = Depends(get_db)):
    row = conn.execute(
        f"SELECT id FROM users WHERE username = '{body.username}' AND password_hash = '{_hash(body.password)}'"
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {"message": "Logged in"}
''',
    "C": '''
def render_comment(author, text):
    return f'<article class="comment"><h3>{author}</h3><p>{text}</p></article>'
''',
    "D": '''
import pickle
def import_preferences(payload):
    try:
        value = pickle.loads(payload)
    except Exception as error:
        raise ValueError("Invalid export") from error
    if not isinstance(value, dict):
        raise ValueError("Expected a dictionary")
    return value
''',
    "E": '''
def update_email(request, email, csrf_token):
    request.state.account["email"] = email
    return {"email": email}
''',
}


def test_every_registered_task_has_marked_stubs_and_parseable_python():
    assert set(TARGETS) == set(get_args(TaskId))
    for task_id, (source, functions) in TARGETS.items():
        root = Path(get_settings().starter_dir) / f"task_{task_id}"
        assert (root / "README.md").is_file()
        assert (root / "tests/test_functional.py").is_file()
        code = (root / source).read_text(encoding="utf-8")
        tree = ast.parse(code)
        targets = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in functions]
        assert {node.name for node in targets} == functions
        for node in targets:
            assert "# Write your code here." in "\n".join(code.splitlines()[node.lineno - 1:node.end_lineno])
        for path in root.rglob("*.py"):
            ast.parse(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("task_id", list(TARGETS))
def test_unimplemented_tasks_run_without_collection_errors(client, enrol, task_id):
    enrol(task_id=task_id)
    response = client.post("/workspace/tests/run")
    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "failed", result
    assert result["counts"]["failed"] > 0
    assert result["counts"]["error"] == 0


@pytest.mark.parametrize("task_id", ["A", "C", "D", "E"])
@pytest.mark.parametrize("secure", [True, False])
def test_new_task_contracts_with_safe_and_unsafe_implementations(tmp_path, task_id, secure):
    source = Path(get_settings().starter_dir) / f"task_{task_id}"
    root = tmp_path / f"task_{task_id}"
    shutil.copytree(source, root)
    target = root / TARGETS[task_id][0]
    target.write_text(REFERENCES[task_id] if secure else UNSAFE_REFERENCES[task_id], encoding="utf-8")
    if not secure:
        # Check the weakness alone; ordinary functionality is checked by the secure reference.
        (root / "tests/test_functional.py").unlink()
    (root / "tests/test_security_contract.py").write_text(SECURITY_CHECKS[task_id], encoding="utf-8")
    code, cases, output = runner._pytest(root.resolve())
    assert code == (0 if secure else 1), output
    assert not any(case.outcome == "error" for case in cases), output
    assert any(case.outcome == ("passed" if secure else "failed") for case in cases)
