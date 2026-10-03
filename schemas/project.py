from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

MAX_FILE_CHARS = 1_000_000


class FolderNode(BaseModel):
    type: Literal["folder"] = "folder"


class FileNode(BaseModel):
    type: Literal["file"] = "file"
    content: str = Field(default="", max_length=MAX_FILE_CHARS)


# Same shape the frontend uses: {"type": "folder"} or {"type": "file", "content": "..."}
FsNode = Annotated[FolderNode | FileNode, Field(discriminator="type")]


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    user_id: str | None = Field(default=None, max_length=100)
    files: dict[str, FsNode] = {}


class ProjectInfo(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    user_id: str | None
    created_at: datetime


class FileWrite(BaseModel):
    content: str = Field(max_length=MAX_FILE_CHARS)


class FolderCreate(BaseModel):
    path: str


class RenameRequest(BaseModel):
    from_path: str
    to_path: str


class FilesReplace(BaseModel):
    files: dict[str, FsNode]
