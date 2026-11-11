from typing import Literal

from pydantic import BaseModel

Mode = Literal["team", "single"]
TaskId = Literal["A", "B", "C", "D", "E", "F", "G"]
Screen = Literal["start", "information", "consent", "ide", "part_complete", "questionnaire", "thank_you"]


class StartRequest(BaseModel):
    pilot: bool = False
    task_id: TaskId = "A"


class ConsentRequest(BaseModel):
    consent_version: str


class ModeRequest(BaseModel):
    mode: Mode


class NextTaskRequest(BaseModel):
    task_id: TaskId


class SessionToken(BaseModel):
    token: str


class TaskInfo(BaseModel):
    id: str
    label: str


class AvailableTask(TaskInfo):
    cwe: str


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
    needs_next_task: bool = False
    parts: list[PartInfo] = []
    available_tasks: list[AvailableTask] = []


class InformationContent(BaseModel):
    version: str
    markdown: str


class ConsentContent(BaseModel):
    version: str
    markdown: str
    statements: list[str]
