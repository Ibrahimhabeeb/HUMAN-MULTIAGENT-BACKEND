import secrets
from urllib.parse import parse_qs

from fastapi import FastAPI, HTTPException, Request

from app.account import update_email

SESSION_COOKIE = "account_session"


def open_session(app: FastAPI, username: str) -> str:
    """Test setup for an already signed-in user; not a public login endpoint."""
    if username not in app.state.accounts:
        raise ValueError("Unknown account")
    session_id = secrets.token_urlsafe(32)
    app.state.sessions[session_id] = {"username": username, "csrf_token": secrets.token_urlsafe(32)}
    return session_id


def _session(request: Request) -> dict[str, str]:
    session = request.app.state.sessions.get(request.cookies.get(SESSION_COOKIE))
    if session is None:
        raise HTTPException(status_code=401, detail="Sign in first")
    return session


def create_app() -> FastAPI:
    app = FastAPI()
    app.state.accounts = {
        "alice": {"email": "alice@example.test"},
        "bob": {"email": "bob@example.test"},
    }
    app.state.sessions = {}

    @app.get("/account")
    def read_account(request: Request):
        session = _session(request)
        account = app.state.accounts[session["username"]]
        return {"email": account["email"], "csrf_token": session["csrf_token"]}

    @app.post("/account/email")
    async def change_email(request: Request):
        session = _session(request)
        request.state.session = session
        request.state.account = app.state.accounts[session["username"]]
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/x-www-form-urlencoded":
            raise HTTPException(status_code=415, detail="Send form-encoded data")
        try:
            fields = parse_qs((await request.body()).decode("utf-8"), keep_blank_values=True, max_num_fields=10)
        except ValueError as error:
            raise HTTPException(status_code=400, detail="Invalid form data") from error
        emails = fields.get("email", [])
        tokens = fields.get("csrf_token", [])
        if len(emails) != 1 or not emails[0].strip() or len(tokens) > 1:
            raise HTTPException(status_code=400, detail="Supply one email and at most one token")
        return update_email(request, emails[0], tokens[0] if tokens else None)

    return app
