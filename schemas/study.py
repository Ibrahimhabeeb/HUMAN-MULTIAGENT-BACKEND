from typing import Literal

from pydantic import BaseModel

Mode = Literal["team", "single"]
Screen = Literal["start", "information", "consent", "ide", "part_complete", "questionnaire", "thank_you"]


class StartRequest(BaseModel):
    pilot: bool = False


class ConsentRequest(BaseModel):
    consent_version: str


class ModeRequest(BaseModel):
    mode: Mode


class TaskInfo(BaseModel):
    id: str
    label: str


class PartInfo(BaseModel):
    part: int
    mode: Mode
    task_id: str
    task_label: str
    done: bool


class StudyState(BaseModel):
    screen: Screen
    mode: Mode
    participant: str | None = None
    pilot: bool | None = None
    part: int | None = None
    task: TaskInfo | None = None
    seconds_remaining: int | None = None
    time_limit_seconds: int | None = None
    parts: list[PartInfo] = []


class InformationContent(BaseModel):
    version: str
    markdown: str


class ConsentContent(BaseModel):
    version: str
    markdown: str
    statements: list[str]
