import pytest

from agents.context import AgentContext
from agents.review_contracts import expected_duplicate_error
from agents.tools import make_tools
from schemas.security_state import SecurityState

AUTH = '''def register_user(conn, username, password):
    hashed = hash_password(password)
    conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed))
    conn.commit()
'''
SCHEMA = '''conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT)")'''
TEST = '''import sqlite3
import pytest
def test_unique():
    with pytest.raises((sqlite3.IntegrityError, ValueError)):
        register_user(conn, "alice", "another password")
'''
FILES = {"app/auth.py": AUTH, "app/db.py": SCHEMA, "tests/test_functional.py": TEST}
FINDING = {
    "description": "register_user does not handle duplicate usernames: IntegrityError is not caught and could leak if exposed.",
    "file": "app/auth.py", "line": 3, "severity": "Medium", "cwe": "CWE-285",
}


@pytest.mark.parametrize("cwe", ["CWE-285", "CWE-703", None])
def test_expected_duplicate_exception_is_not_reported_as_a_security_defect(cwe):
    problem = expected_duplicate_error(FILES, FINDING | {"cwe": cwe})
    assert "UNIQUE" in problem and "explicitly accepts IntegrityError" in problem


@pytest.mark.parametrize("change", ["no-unique", "different-table", "no-error-contract", "different-function", "invalid-source"])
def test_guard_requires_both_actual_schema_and_the_matching_test_contract(change):
    files = FILES.copy()
    if change == "no-unique":
        files["app/db.py"] = SCHEMA.replace(" UNIQUE", "")
    elif change == "different-table":
        files["app/db.py"] = SCHEMA.replace("TABLE users", "TABLE administrators")
    elif change == "no-error-contract":
        files["tests/test_functional.py"] = TEST.replace("sqlite3.IntegrityError, ", "")
    elif change == "different-function":
        files["tests/test_functional.py"] = TEST.replace("register_user(", "something_else(")
    else:
        files["app/auth.py"] = "def register_user(:"
    assert expected_duplicate_error(files, FINDING) is None


def test_real_injection_or_authorisation_findings_are_not_suppressed():
    assert expected_duplicate_error(FILES, FINDING | {"cwe": "CWE-89"}) is None
    assert expected_duplicate_error(FILES, FINDING | {"description": "SQL injection in register_user permits attacker-controlled queries."}) is None
    assert expected_duplicate_error(FILES, FINDING | {"description": "get_document returns another user's document without checking ownership."}) is None


def test_tool_refuses_the_contract_contradiction_but_keeps_a_real_injection_proposal():
    context = AgentContext(files=FILES.copy(), state=SecurityState())
    propose = next(tool for tool in make_tools(context, "reviewer") if tool.name == "propose_vulnerability")
    assert propose.invoke(FINDING).startswith("Not recorded")
    assert context.proposals == []
    context.files["app/auth.py"] = '''def register_user(conn, username, password):
    conn.execute(f"INSERT INTO users (username) VALUES ('{username}')")
'''
    injection = FINDING | {"description": "The interpolated username allows SQL injection.", "cwe": "CWE-89", "line": 2}
    assert propose.invoke(injection).startswith("Recorded")
    assert context.proposals[0].proposal["cwe"] == "CWE-89"


def test_table_level_unique_constraint_is_also_recognised():
    files = FILES | {"app/db.py": 'conn.execute("CREATE TABLE users (username TEXT, password_hash TEXT, UNIQUE(username))")'}
    assert expected_duplicate_error(files, FINDING) is not None


def test_a_schema_example_in_a_docstring_is_not_treated_as_an_enforced_constraint():
    files = FILES | {"app/db.py": '"""Example only: ' + SCHEMA + '"""\n' + SCHEMA.replace(" UNIQUE", "")}
    assert expected_duplicate_error(files, FINDING) is None


def test_a_formatted_insert_is_not_treated_as_a_known_parameterized_insert():
    files = FILES | {"app/auth.py": '''def register_user(conn, username, password):
    conn.execute(f"INSERT INTO users (username) VALUES ('{username}')")
'''}
    assert expected_duplicate_error(files, FINDING) is None
