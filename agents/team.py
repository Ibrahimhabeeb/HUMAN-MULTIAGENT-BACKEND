import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Literal

from langchain.agents import create_agent
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, MessagesState, StateGraph
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from agents.roles import (
    FACILITATOR_PROMPT,
    ROLE_PROMPTS,
    SHARED_RULES,
    SPECIALISTS,
    Specialist,
)
from agents.tools import make_tools, summarise_state
from config import get_settings
from llm import get_model

MAX_SPECIALISTS_PER_TURN = 3


class TeamState(MessagesState):
    targets: list[
        str
    ]  # specialists the human asked for by name this turn (empty = Facilitator decides)
    done: list[str]  # specialists who have already replied this turn
    next: str


class Route(BaseModel):
    next: Literal["planner", "threat_modeller", "reviewer", "verifier", "finish"]
    message: str = Field(
        description="If finishing: your reply to the developer. Otherwise: one line on why."
    )


def _text(message: BaseMessage) -> str:
    if isinstance(message.content, str):
        return message.content
    return "".join(
        part.get("text", "") for part in message.content if isinstance(part, dict)
    )


def _build_graph(
    db: Session, project_id: str, session_id: str, checkpointer: SqliteSaver
):
    model = get_model()
    router = model.with_structured_output(Route)

    def facilitator(state: TeamState) -> dict:
        done = state.get("done", [])
        targets = state.get("targets", [])
        if targets:
            remaining = [a for a in targets if a not in done]
            return {"next": remaining[0] if remaining else "finish"}

        prompt = FACILITATOR_PROMPT.format(
            done=", ".join(done) or "none",
            state_summary=summarise_state(db, project_id),
        )
        if len(done) >= MAX_SPECIALISTS_PER_TURN:
            prompt += "\nYou must finish now."
        decision = router.invoke([SystemMessage(prompt), *state["messages"]])

        if (
            decision.next == "finish"
            or decision.next in done
            or len(done) >= MAX_SPECIALISTS_PER_TURN
        ):
            return {
                "next": "finish",
                "messages": [AIMessage(decision.message, name="facilitator")],
            }
        return {"next": decision.next}

    def specialist(role: Specialist):
        agent = create_agent(
            model,
            tools=make_tools(db, project_id, session_id, role),
            system_prompt=ROLE_PROMPTS[role] + SHARED_RULES,
        )

        def run(state: TeamState) -> dict:
            result = agent.invoke({"messages": state["messages"]})
            reply = _text(result["messages"][-1])
            return {
                "messages": [AIMessage(reply, name=role)],
                "done": [*state.get("done", []), role],
            }

        return run

    graph = StateGraph(TeamState)
    graph.add_node("facilitator", facilitator)
    for role in SPECIALISTS:
        graph.add_node(role, specialist(role))
        graph.add_edge(role, "facilitator")
    graph.add_edge(START, "facilitator")
    graph.add_conditional_edges(
        "facilitator",
        lambda state: state["next"],
        {**{r: r for r in SPECIALISTS}, "finish": END},
    )
    return graph.compile(checkpointer=checkpointer)


@contextmanager
def _checkpointer() -> Generator[SqliteSaver]:
    # Each session's conversation is saved here, keyed by session id, so it survives restarts.
    path = Path(get_settings().checkpoint_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    try:
        yield SqliteSaver(conn)
    finally:
        conn.close()


def _as_chat(message: BaseMessage) -> dict:
    agent = (
        "human"
        if isinstance(message, HumanMessage)
        else (message.name or "facilitator")
    )
    return {"agent": agent, "content": _text(message)}


def _thread(session_id: str) -> dict:
    return {"configurable": {"thread_id": session_id}}


def run_turn(
    db: Session,
    project_id: str,
    session_id: str,
    content: str,
    agents: list[Specialist] | None = None,
) -> list[dict]:
    with _checkpointer() as checkpointer:
        graph = _build_graph(db, project_id, session_id, checkpointer)
        before = len(graph.get_state(_thread(session_id)).values.get("messages", []))
        result = graph.invoke(
            {
                "messages": [HumanMessage(content)],
                "targets": list(agents or []),
                "done": [],
            },
            _thread(session_id),
        )
    # Only the agents' replies to this message (skip the human message itself).
    return [_as_chat(m) for m in result["messages"][before + 1 :]]


def history(session_id: str) -> list[dict]:
    with _checkpointer() as checkpointer:
        saved = checkpointer.get_tuple(_thread(session_id))
    if saved is None:
        return []
    return [_as_chat(m) for m in saved.checkpoint["channel_values"].get("messages", [])]
