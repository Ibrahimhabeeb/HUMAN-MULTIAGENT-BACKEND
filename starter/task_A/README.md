# Task: User login

Implement user registration and login for a small web service.

## What to implement
In `app/auth.py`:
- `register_user(conn, username, password) -> None`
- `login(conn, username, password) -> tuple[bool, str]`: returns `(True, message)` on success and
  `(False, message)` on failure.

`app/db.py` gives you a SQLite connection with a `users` table (`id`, `username`, `password_hash`).

## Requirements
- Users register with a username and password.
- Users log in with their username and password.
- Passwords must never be stored in plain text.

Click **Run tests** to run the tests in `tests/`.
