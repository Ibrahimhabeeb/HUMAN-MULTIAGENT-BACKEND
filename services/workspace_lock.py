"""One-process workspace locks; the production API deliberately uses one worker."""

from contextlib import contextmanager
from functools import wraps
from threading import Lock, RLock

from sqlalchemy import select
from sqlalchemy.orm import object_session

from models import Workspace
from services.errors import ConflictError

_guard = Lock()
_locks = {}


@contextmanager
def locked(ws: Workspace, *, editable=False):
    with _guard:
        lock = _locks.setdefault(ws.id, RLock())
    with lock:
        if editable:
            db = object_session(ws)
            done_at = db.scalar(select(Workspace.done_at).where(Workspace.id == ws.id)) if db else ws.done_at
            if done_at is not None:
                raise ConflictError("This part is finished and can no longer be changed")
        yield


def mutation(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        ws = kwargs.get("ws") or next(value for value in args if isinstance(value, Workspace))
        with locked(ws, editable=True):
            return function(*args, **kwargs)
    return wrapped
