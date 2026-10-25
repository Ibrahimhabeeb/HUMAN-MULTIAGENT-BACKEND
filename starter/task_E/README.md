# Task: Account email update

Implement the email-update handler for an account that is already signed in.
The supplied Python request harness is separate from the study platform's own sessions.
No browser interface, login feature or additional server needs to be built.

## What to implement
In `app/account.py`:
- `update_email(request, email: str, csrf_token: str | None) -> dict[str, str]`

`app/web.py` supplies a small FastAPI application with:
- An in-memory account store and cookie-authenticated sessions.
- `GET /account`: returns the signed-in account's email and its session's request token.
- `POST /account/email`: accepts form fields `email` and `csrf_token`, then calls your function.
- `request.state.account`: the signed-in account dictionary to update.
- `request.state.session`: its server-side session, including `username` and `csrf_token`.

## Requirements
- A legitimate update changes only the signed-in account's email.
- Return `{"email": email}` after a successful update.
- Protect the state-changing request against forgery. Missing, invalid or another session's
  request token must be rejected with `HTTPException(status_code=403, detail=...)`.
- Rejected requests must not change any account data.

The harness already rejects unauthenticated requests and malformed email fields.
Its `open_session` helper is test setup for an existing login, not an HTTP endpoint.
Leave the supplied harness in place and implement the marked function.

Click **Run tests** to run the tests in `tests/`. FastAPI's `TestClient` sends requests
in-process; no network listener or browser is used. These tests do not simulate browser
cookie policies, CORS or a two-origin browser attack.
