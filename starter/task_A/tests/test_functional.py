import sqlite3

import pytest
from app.auth import login, register_user
from app.db import get_connection


def test_registered_user_can_log_in():
    conn = get_connection()
    register_user(conn, "alice", "wonderland")
    ok, message = login(conn, "alice", "wonderland")
    assert ok is True
    assert isinstance(message, str) and message


def test_wrong_password_is_refused():
    conn = get_connection()
    register_user(conn, "alice", "wonderland")
    ok, _ = login(conn, "alice", "not-the-password")
    assert ok is False


def test_username_must_be_unique():
    conn = get_connection()
    register_user(conn, "alice", "wonderland")
    with pytest.raises((sqlite3.IntegrityError, ValueError)):
        register_user(conn, "alice", "another-password")
