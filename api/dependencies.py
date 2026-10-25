from typing import Annotated

from fastapi import Depends, Header, HTTPException, Response
from sqlalchemy.orm import Session

from db import get_db
from services import sessions


def get_session_db(
    db: Annotated[Session, Depends(get_db)],
    response: Response,
    token: Annotated[str | None, Header(alias=sessions.HEADER)] = None,
) -> Session:
    # get_db supplies a separate database session for each request.
    if not sessions.bind(db, token):
        raise HTTPException(status_code=401, detail="This browser session has ended. Refresh to start a new session.")
    response.headers["Cache-Control"] = "no-store"
    return db


Db = Annotated[Session, Depends(get_session_db)]
