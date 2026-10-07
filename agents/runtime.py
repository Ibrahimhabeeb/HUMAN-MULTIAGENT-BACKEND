import operator
from collections.abc import Callable
from typing import Annotated, TypedDict

from langchain.agents import create_agent
from langchain_core.messages import BaseMessage, SystemMessage
from langchain_core.tools import BaseTool
from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel, Field

from agents.roles import Specialist
from llm import get_model

# The only places that call the model, so tests can replace them.


class Suggestion(BaseModel):
    agent: Specialist
    reason: str = Field(description="One sentence on why the developer should consult this specialist now.")


class FacilitatorReply(BaseModel):
    message: str = Field(description="A short message to the developer.")
    suggestions: list[Suggestion] = Field(
        default_factory=list, description="The specialists to consult next; empty if nobody is needed."
    )


def text_of(message: BaseMessage) -> str:
    if isinstance(message.content, str):
        return message.content
    return "".join(part.get("text", "") for part in message.content if isinstance(part, dict))


def run_agent(system_prompt: str, tools: list[BaseTool], messages: list[BaseMessage]) -> str:
    agent = create_agent(get_model(), tools=tools, system_prompt=system_prompt)
    result = agent.invoke({"messages": messages})
    return text_of(result["messages"][-1])


def facilitate(system_prompt: str, messages: list[BaseMessage]) -> FacilitatorReply:
    return get_model().with_structured_output(FacilitatorReply).invoke([SystemMessage(system_prompt), *messages])


class _ParallelState(TypedDict):
    replies: Annotated[dict[str, str], operator.or_]  # each branch adds its reply; the dicts are merged


def run_parallel(jobs: dict[str, Callable[[], str]]) -> dict[str, str]:
    """Runs each job in its own LangGraph branch at the same time; returns {name: reply}."""
    graph = StateGraph(_ParallelState)
    for name, job in jobs.items():
        graph.add_node(name, lambda _state, job=job, name=name: {"replies": {name: job()}})
        graph.add_edge(START, name)
        graph.add_edge(name, END)
    return graph.compile().invoke({"replies": {}})["replies"]
