from pydantic import BaseModel, Field

from agents.roles import Specialist


class MessageCreate(BaseModel):
    content: str = Field(min_length=1, max_length=4000)
    agents: list[Specialist] = []  # empty = the Facilitator decides who should act


class ChatMessage(BaseModel):
    agent: str  # "human", "facilitator", "planner", "threat_modeller", "reviewer" or "verifier"
    content: str
