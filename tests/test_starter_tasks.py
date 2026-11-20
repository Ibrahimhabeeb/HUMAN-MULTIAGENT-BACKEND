import ast
import shutil
from pathlib import Path
from typing import get_args

import pytest

from config import get_settings
from schemas.study import TaskId
from services import runner

TARGETS = {
    "A": ("app/auth.py", {"register_user", "login"}),
    "B": ("app/storage.py", {"list_files", "download"}),
    "C": ("app/comments.py", {"render_comment"}),
    "D": ("app/preferences.py", {"export_preferences", "import_preferences"}),
    "E": ("app/account.py", {"update_email"}),
    "F": ("app/documents.py", {"get_document"}),
    "G": ("app/audit.py", {"record_recovery_attempt"}),
}

# Reference implementations and security checks stay outside participant-visible starter folders.
_AUTH_HEADER = '''
import sqlite3

import bcrypt
'''

REFERENCES = {
    "A": _AUTH_HEADER + '''
def register_user(conn, username, password):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=4)).decode()
    try:
        conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed))
        conn.commit()
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        raise ValueError("Username already taken") from exc


def login(conn, username, password):
    row = conn.execute("SELECT password_hash FROM users WHERE username = ?", (username,)).fetchone()
    if row is None or not bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
        return False, "Invalid username or password"
    return True, "Logged in"
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

def update_email(account, session, email, request_token):
    expected = session["request_token"]
    if not request_token or not secrets.compare_digest(request_token.encode("utf-8"), expected.encode("utf-8")):
        raise PermissionError("Invalid request token")
    account.email = email
    return {"email": email}
''',
    "F": '''
def get_document(documents, requester_id, document_id):
    document = documents.get(document_id)
    if document is None or document.owner_id != requester_id:
        raise LookupError("Document unavailable")
    return document
''',
    "G": '''
def record_recovery_attempt(logger, account_id, recovery_token, succeeded):
    outcome = "succeeded" if succeeded else "failed"
    logger.info("Recovery %s for account %s", outcome, account_id)
''',
}

SECURITY_CHECKS = {
    "A": '''
import pytest
from app.auth import login, register_user
from app.db import get_connection

@pytest.mark.parametrize("username", ["alice' --", "' OR '1'='1' --", "nobody' OR 1=1 --"])
def test_sql_in_the_username_does_not_identify_another_user(username):
    conn = get_connection()
    register_user(conn, "alice", "wonderland")
    ok, _ = login(conn, username, "wonderland")
    assert ok is False

def test_quotes_in_a_username_are_ordinary_text():
    conn = get_connection()
    register_user(conn, "o'brien", "pa'ss")
    ok, _ = login(conn, "o'brien", "pa'ss")
    assert ok is True

def test_passwords_are_not_stored_in_plain_text():
    conn = get_connection()
    register_user(conn, "alice", "wonderland")
    stored = conn.execute("SELECT password_hash FROM users").fetchone()["password_hash"]
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
from app.account import update_email
from app.models import Account

@pytest.mark.parametrize("token", [None, "", "wrong-token", "\\u00e9"])
def test_missing_or_invalid_token_does_not_change_data(token):
    account = Account(email="alice@example.test")
    session = {"request_token": "alice-token"}
    with pytest.raises(PermissionError):
        update_email(account, session, "forged@example.test", token)
    assert account.email == "alice@example.test"

def test_other_sessions_token_cannot_update_account():
    account = Account(email="alice@example.test")
    session = {"request_token": "alice-token"}
    other_session = {"request_token": "other-token"}
    with pytest.raises(PermissionError):
        update_email(account, session, "forged@example.test", other_session["request_token"])
    assert account.email == "alice@example.test"

def test_empty_session_token_cannot_authorize_an_update():
    account = Account(email="alice@example.test")
    session = {"request_token": ""}
    with pytest.raises(PermissionError):
        update_email(account, session, "forged@example.test", "")
    assert account.email == "alice@example.test"
''',
    "F": '''
import pytest
from app.documents import get_document
from app.models import Document

def test_other_owners_cannot_read_a_document():
    document = Document(id=17, owner_id=2, title="Private", body="Do not disclose")
    with pytest.raises(LookupError, match="Document unavailable"):
        get_document({17: document}, requester_id=1, document_id=17)

def test_missing_and_unowned_documents_have_the_same_result():
    document = Document(id=17, owner_id=2, title="Private", body="Do not disclose")
    with pytest.raises(LookupError, match="Document unavailable"):
        get_document({17: document}, requester_id=1, document_id=17)
    with pytest.raises(LookupError, match="Document unavailable"):
        get_document({17: document}, requester_id=1, document_id=99)
''',
    "G": '''
import logging
from app.audit import record_recovery_attempt

def test_secret_never_enters_log_records(caplog):
    logger = logging.getLogger("recovery-security-check")
    with caplog.at_level(logging.INFO, logger=logger.name):
        record_recovery_attempt(logger, 42, "secret-for-success", True)
        record_recovery_attempt(logger, 42, "secret-for-failure", False)
    assert len(caplog.records) == 2
    for record in caplog.records:
        assert "secret-for-" not in repr(record.__dict__)
''',
}

UNSAFE_REFERENCES = {
    # Hashes passwords but builds SQL from user input, so only the injection is unsafe.
    "A": _AUTH_HEADER + '''
def register_user(conn, username, password):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=4)).decode()
    conn.execute(f"INSERT INTO users (username, password_hash) VALUES ('{username}', '{hashed}')")
    conn.commit()


def login(conn, username, password):
    row = conn.execute(f"SELECT password_hash FROM users WHERE username = '{username}'").fetchone()
    if row is None or not bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
        return False, "Invalid username or password"
    return True, "Logged in"
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
def update_email(account, session, email, request_token):
    account.email = email
    return {"email": email}
''',
    "F": '''
def get_document(documents, requester_id, document_id):
    document = documents.get(document_id)
    if document is None:
        raise LookupError("Document unavailable")
    return document
''',
    "G": '''
def record_recovery_attempt(logger, account_id, recovery_token, succeeded):
    outcome = "succeeded" if succeeded else "failed"
    logger.info("Recovery %s for account %s with token %s", outcome, account_id, recovery_token)
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


@pytest.mark.parametrize("task_id", ["A", "C", "D", "E", "F", "G"])
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
