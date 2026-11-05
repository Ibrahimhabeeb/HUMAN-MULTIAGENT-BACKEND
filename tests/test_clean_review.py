import json

from agents import runtime
from agents.context import AgentContext
from agents.runtime import RouteDecision
from agents.tools import make_tools
from schemas.security_state import SecurityState


def test_secure_code_description_does_not_become_a_vulnerability_proposal():
    ctx = AgentContext(files={"app/comments.py": "import html\n"}, state=SecurityState())
    tool = next(t for t in make_tools(ctx, "reviewer") if t.name == "propose_vulnerability")

    reply = tool.invoke({
        "description": (
            "In app/comments.py line 4, author and text are HTML-escaped before output, which is correct and "
            "prevents XSS injection. There is no evidence of unescaped input. No XSS or injection weaknesses found."
        ),
        "severity": "Low", "file": "app/comments.py", "line": 4, "cwe": "CWE-79",
    })

    assert reply.startswith("Not recorded: the description says no security weakness was found")
    assert ctx.proposals == []


def test_clean_reviewer_reply_cannot_leave_a_contradictory_approval(client, team, monkeypatch):
    def reviewer(_prompt, tools, _messages):
        proposal_tool = next(t for t in tools if t.name == "propose_vulnerability")
        assert proposal_tool.invoke({
            "description": "The output inserts raw attacker-controlled HTML, allowing script execution.",
            "severity": "High", "file": "app/comments.py", "line": 4, "cwe": "CWE-79",
        }).startswith("Recorded.")
        return "No vulnerabilities found."

    monkeypatch.setattr(runtime, "run_agent", reviewer)
    assert client.post("/chat/review").json()["next"] == "reviewer"
    result = client.post("/chat/next").json()

    assert result["approvals"] == []
    assert "conflicted" in result["messages"][0]["content"]
    assert client.get("/approvals").json() == []


def test_streamed_clean_review_drops_a_contradictory_proposal(client, team, monkeypatch):
    monkeypatch.setattr(runtime, "run_agent", lambda *_: "Initial guidance.")
    assert client.post("/chat/team", json={"content": "Help me start"}).status_code == 200
    monkeypatch.setattr(runtime, "route", lambda *_: RouteDecision(agent="reviewer", reason="review requested", review=True))

    def reviewer_stream(_prompt, tools, _messages):
        proposal_tool = next(t for t in tools if t.name == "propose_vulnerability")
        proposal_tool.invoke({
            "description": "Raw input is inserted into HTML, allowing an attacker to run script.",
            "severity": "High", "file": "app/comments.py", "line": 4, "cwe": "CWE-79",
        })
        yield "No vulnerabilities found."

    monkeypatch.setattr(runtime, "run_agent_stream", reviewer_stream)
    response = client.post("/chat/team/stream", json={"content": "Review my code"})
    events = [json.loads(line) for line in response.text.splitlines()]
    complete = next(event for event in events if event["type"] == "agent_complete")

    assert complete["approvals"] == []
    assert "conflicted" in complete["message"]["content"]
    assert client.get("/approvals").json() == []
