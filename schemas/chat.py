from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from schemas.approval import ApprovalOut
from schemas.common import UtcDatetime

MAX_MESSAGE_CHARS = 4000


class MessageCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    content: str = Field(min_length=1, max_length=MAX_MESSAGE_CHARS)


class MessageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    thread: str
    role: Literal["human", "agent", "system"]
    content: str
    data: dict[str, Any]  # e.g. which agent wrote it, the route of a developer message, approval ids
    ts: UtcDatetime


class TurnResult(BaseModel):
    messages: list[MessageOut]  # the new messages, oldest first
    approvals: list[ApprovalOut]  # what the agents proposed, waiting for the human's decision
    next: str | None = None  # team mode: the agent who answers next, through POST /chat/next
