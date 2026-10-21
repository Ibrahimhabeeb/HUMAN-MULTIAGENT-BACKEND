# Task: Authentication

Implement user registration and login for a small web service: an HTTP API built with FastAPI.

## What to implement
In `app/auth.py`, write the body of the two endpoints:

| Method | Path | Request body (JSON) | Success | Failure |
|---|---|---|---|---|
| `POST` | `/auth/register` | `{"username": "...", "password": "..."}` | `201 Created` with `{"id": 1, "username": "alice"}` | `409 Conflict` if the username is already taken |
| `POST` | `/auth/login` | `{"username": "...", "password": "..."}` | `200 OK` with `{"message": "..."}` | `401 Unauthorized` if the username or password is wrong |

Each endpoint receives:
- `body`: the JSON request body, already read into a `Credentials` object (`body.username`, `body.password`).
  If a field is missing, FastAPI answers `422` before your code runs.
- `conn`: a SQLite connection with a `users` table (`id`, `username`, `password_hash`). See `app/db.py`.

Return a dictionary to send it as the JSON response. To send an error response, raise
`HTTPException(status_code=..., detail="...")`; FastAPI turns it into `{"detail": "..."}`.

`app/main.py` creates the app and connects the endpoints. You don't need to change it.

## Requirements
- Users register with a username and password.
- Users log in with their username and password.
- Passwords must never be stored in plain text.

Click **Run tests** to run the tests in `tests/`. They send HTTP requests to the app with FastAPI's
`TestClient`, inside the test process; no server needs to be started.
