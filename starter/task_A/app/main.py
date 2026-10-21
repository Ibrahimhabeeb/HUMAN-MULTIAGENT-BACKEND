from fastapi import FastAPI

from app.auth import router as auth_router
from app.db import get_connection


def create_app(db_path=":memory:") -> FastAPI:
    app = FastAPI(title="Accounts service")
    app.state.db = get_connection(db_path)
    app.include_router(auth_router)
    return app
