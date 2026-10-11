from typing import Literal

from pydantic import BaseModel

Mode = Literal["team", "single"]
TaskId = Literal["A", "B"]
Screen = Literal["start", "information", "consent", "ide", "part_complete", "questionnaire", "thank_you"]


class StartRequest(BaseModel):
    pilot: bool = False
    task_id: TaskId = "A"


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
    parts: list[PartInfo] = []
    available_tasks: list[TaskInfo] = []


class InformationContent(BaseModel):
    version: str
    markdown: str


class ConsentContent(BaseModel):
    version: str
    markdown: str
    statements: list[str]
