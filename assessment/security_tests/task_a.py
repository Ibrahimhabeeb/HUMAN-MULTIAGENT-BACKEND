import sqlite3

import bcrypt
import pytest
from app.auth import login, register_user
from app.db import get_connection


@pytest.fixture
def conn():
    connection = get_connection()
    yield connection
    connection.close()


def test_valid_credentials_are_accepted(conn):
    register_user(conn, "alice", "wonderland")
    assert login(conn, "alice", "wonderland")[0] is True


@pytest.mark.parametrize("username,password", [("alice", "incorrect"), ("unknown", "wonderland")])
def test_invalid_credentials_are_refused(conn, username, password):
    register_user(conn, "alice", "wonderland")
    assert login(conn, username, password)[0] is False


@pytest.mark.parametrize("username", ["alice' -- ", "' OR 1=1 -- ", "missing' OR '1'='1' -- "])
def test_sql_username_cannot_select_another_account(conn, username):
    register_user(conn, "alice", "wonderland")
    assert login(conn, username, "wonderland")[0] is False


def test_sql_password_cannot_bypass_authentication(conn):
    register_user(conn, "alice", "wonderland")
    assert login(conn, "alice", "' OR '1'='1' -- ")[0] is False


@pytest.mark.parametrize("username", ["O'Reilly", "mallory'); DROP TABLE users; --"])
def test_quoted_usernames_are_literal_data(conn, username):
    register_user(conn, username, "example-password")
    row = conn.execute("SELECT username FROM users WHERE username = ?", (username,)).fetchone()
    assert row is not None and row[0] == username
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
    assert login(conn, username, "example-password")[0] is True


def test_union_cannot_supply_an_attacker_chosen_password_hash(conn):
    register_user(conn, "alice", "wonderland")
    forged = bcrypt.hashpw(b"attacker-password", bcrypt.gensalt(rounds=4)).decode("ascii")
    username = f"missing' UNION SELECT '{forged}' -- "
    assert login(conn, username, "attacker-password")[0] is False


def test_plaintext_password_is_not_stored(conn):
    register_user(conn, "alice", "unique-plaintext-password")
    stored = conn.execute("SELECT password_hash FROM users WHERE username = ?", ("alice",)).fetchone()[0]
    assert stored and "unique-plaintext-password" not in str(stored)


def test_duplicate_registration_cannot_replace_credentials(conn):
    register_user(conn, "alice", "wonderland")
    with pytest.raises((sqlite3.IntegrityError, ValueError)):
        register_user(conn, "alice", "replacement")
    assert login(conn, "alice", "wonderland")[0] is True
    assert login(conn, "alice", "replacement")[0] is False
