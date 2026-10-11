from typing import Literal

from pydantic import BaseModel, Field

from schemas.workspace import MAX_FILE_CHARS


class LintRequest(BaseModel):
    path: str = Field(min_length=1, max_length=300)
    content: str = Field(max_length=MAX_FILE_CHARS)


class Position(BaseModel):
    row: int = Field(ge=1)
    column: int = Field(ge=1)


class Diagnostic(BaseModel):
    code: str
    message: str
    severity: Literal["error", "warning"]
    location: Position
    end_location: Position


class LintResult(BaseModel):
    path: str
    diagnostics: list[Diagnostic]
