import sqlite3

from fastapi import Request


def get_connection(path=":memory:"):
    # FastAPI can handle a request on a different thread from the one that opened the database.
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    init_db(conn)
    return conn


def init_db(conn):
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL)"
    )
    conn.commit()


def get_db(request: Request) -> sqlite3.Connection:
    """FastAPI dependency: gives an endpoint the app's database connection."""
    return request.app.state.db
