from fastapi import HTTPException

from services.errors import ConflictError, InvalidPathError, NotFoundError


def run(action):
    try:
        return action()
    except NotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except ConflictError as e:
        raise HTTPException(status_code=409, detail=str(e)) from e
    except InvalidPathError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
