# Task: Authentication

Implement user registration and login as Python functions. The supplied `app/db.py` gives you a SQLite connection with a `users` table (`id`, `username`, `password_hash`).

## Functions to implement

- `register_user(conn, username, password) -> None`: save a new user. Reject a username that is already registered.
- `login(conn, username, password) -> tuple[bool, str]`: return `(True, message)` for valid credentials, or `(False, message)` otherwise.

## Requirements
- Passwords must never be stored in plain text.
- Treat supplied usernames as data, including usernames containing quotes or SQL-like text.

Write the function bodies in `app/auth.py`, then click **Run tests**. The tests call these functions directly.
