from app.auth import login, register_user
from app.db import get_connection


def test_registered_user_can_log_in():
    conn = get_connection()
    register_user(conn, "alice", "wonderland")
    ok, _ = login(conn, "alice", "wonderland")
    assert ok


def test_wrong_password_is_refused():
    conn = get_connection()
    register_user(conn, "alice", "wonderland")
    ok, _ = login(conn, "alice", "not-the-password")
    assert not ok
