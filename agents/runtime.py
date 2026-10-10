from langchain.agents import create_agent
from langchain_core.messages import BaseMessage, SystemMessage
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field

from agents.roles import Specialist
from llm import get_model

# The only places that call the model, so tests can replace them.


class RouteDecision(BaseModel):
    agent: Specialist
    reason: str = Field(description="A short reason the developer will see, e.g. 'you asked about a risk'.")


def text_of(message: BaseMessage) -> str:
    if isinstance(message.content, str):
        return message.content
    return "".join(part.get("text", "") for part in message.content if isinstance(part, dict))


def run_agent(system_prompt: str, tools: list[BaseTool], messages: list[BaseMessage]) -> str:
    agent = create_agent(get_model(), tools=tools, system_prompt=system_prompt)
    result = agent.invoke({"messages": messages})
    return text_of(result["messages"][-1])


def route(system_prompt: str, messages: list[BaseMessage]) -> RouteDecision:
    return get_model().with_structured_output(RouteDecision).invoke([SystemMessage(system_prompt), *messages])
