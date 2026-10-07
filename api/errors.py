from fastapi import HTTPException
from pydantic import ValidationError

from services.errors import ConflictError, InvalidInputError, NotFoundError


def run(action):
    try:
        return action()
    except NotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except ConflictError as e:
        raise HTTPException(status_code=409, detail=str(e)) from e
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.errors(include_url=False, include_context=False)) from e
    except InvalidInputError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
