from typing import Annotated, Literal

from pydantic import BaseModel, Field

MAX_FILE_CHARS = 1_000_000
MAX_NOTES_CHARS = 20_000


class FolderNode(BaseModel):
    type: Literal["folder"] = "folder"


class FileNode(BaseModel):
    type: Literal["file"] = "file"
    content: str = Field(default="", max_length=MAX_FILE_CHARS)


# Same shape the frontend uses: {"type": "folder"} or {"type": "file", "content": "..."}
FsNode = Annotated[FolderNode | FileNode, Field(discriminator="type")]


class FileWrite(BaseModel):
    content: str = Field(max_length=MAX_FILE_CHARS)


class FolderCreate(BaseModel):
    path: str


class RenameRequest(BaseModel):
    from_path: str
    to_path: str


class NotesWrite(BaseModel):
    text: str = Field(max_length=MAX_NOTES_CHARS)


class Notes(BaseModel):
    text: str
