import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

import uvicorn
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.middleware.trustedhost import TrustedHostMiddleware
from uvicorn.logging import DefaultFormatter

from api.approvals import router as approvals_router
from api.chat import router as chat_router
from api.study import router as study_router
from api.workspace import router as workspace_router
from config import get_settings
from db import SessionLocal, get_db, init_db
from services import questionnaire


def show_state_changes() -> None:
    # Prints every change to the shared security state in this console, in the same style as uvicorn's messages.
    logger = logging.getLogger("security_state")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(DefaultFormatter("%(levelprefix)s %(message)s"))
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    init_db()
    questionnaire.check()
    with SessionLocal() as db:
        questionnaire.sync_items(db)  # the questions, for analysing answers in SQL
    show_state_changes()
    yield


settings = get_settings()
app = FastAPI(
    title="Secure Coding Room API", version="0.1.0", lifespan=lifespan,
    docs_url="/docs" if settings.api_docs_enabled else None,
    redoc_url="/redoc" if settings.api_docs_enabled else None,
    openapi_url="/openapi.json" if settings.api_docs_enabled else None,
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.frontend_origins,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Session-Token"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/ready")
def ready(db: Annotated[Session, Depends(get_db)]) -> dict[str, str]:
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError as error:
        raise HTTPException(status_code=503, detail="The study database is unavailable") from error
    return {"status": "ready"}


app.include_router(study_router)
app.include_router(workspace_router)
app.include_router(approvals_router)
app.include_router(chat_router)


if __name__ == "__main__":
    # Participants' .py files are saved in these folders; changes there must not restart the server.
    # (uvicorn only matches excluded folders by their absolute path, and only if they exist.)
    settings = get_settings()
    participant_dirs = [Path(folder).resolve() for folder in (settings.workspaces_dir, settings.snapshots_dir)]
    for folder in participant_dirs:
        folder.mkdir(parents=True, exist_ok=True)
    uvicorn.run(
        "main:app", host="127.0.0.1", port=8000, reload=True, reload_excludes=[str(d) for d in participant_dirs]
    )
