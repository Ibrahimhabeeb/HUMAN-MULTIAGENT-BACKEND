from fastapi import HTTPException
from pydantic import ValidationError

from llm import ModelCallError, ModelNotConfiguredError
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
    except ModelNotConfiguredError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e
    except ModelCallError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e
