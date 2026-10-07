import threading

import pytest

from agents import runtime, team
from agents.roles import ASSISTANT_PROMPT, REVIEW_MESSAGE, SPECIALISTS
from agents.runtime import FacilitatorReply, Suggestion
from config import get_settings
from models import Event

ROLE_OF_PROMPT = {team._prompt(role): role for role in SPECIALISTS} | {ASSISTANT_PROMPT: "assistant"}
RISK = {"description": "SQL injection in login", "severity": "High", "cwe": "CWE-89"}
FIX = {
    "finding": "#1",
    "file": "app/auth.py",
    "location": "login(), the SELECT query",
    "code": 'cur.execute("SELECT * FROM users WHERE username = ?", (username,))',
    "why": "Placeholders stop user input changing the SQL.",
}


class FakeModel:
    # Stands in for the LLM: a test scripts what each agent does with its tools, and every call is recorded.
    def __init__(self):
        self.calls = []
        self.scripts = {}
        self.facilitator_reply = FacilitatorReply(message="How can I help?")

    def run_agent(self, system_prompt, tools, messages):
        role = ROLE_OF_PROMPT[system_prompt]
        tools = {t.name: t for t in tools}
        self.calls.append({"role": role, "tools": sorted(tools), "messages": [m.content for m in messages]})
        script = self.scripts.get(role)
        return script(tools) if script else f"{role} reply"

    def facilitate(self, system_prompt, messages):
        self.calls.append({"role": "facilitator", "prompt": system_prompt, "messages": [m.content for m in messages]})
        return self.facilitator_reply

    def last(self, role):
        return [c for c in self.calls if c["role"] == role][-1]


@pytest.fixture
def model(monkeypatch):
    fake = FakeModel()
    monkeypatch.setattr(runtime, "run_agent", fake.run_agent)
    monkeypatch.setattr(runtime, "facilitate", fake.facilitate)
    return fake


def say(client, thread, content):
    return client.post(f"/chat/{thread}", json={"content": content})


def decide(client, approval_id, decision="approve"):
    return client.post(f"/approvals/{approval_id}/decide", json={"decision": decision})


def events(db):
    return db.query(Event).order_by(Event.id).all()


def test_chat_needs_an_active_participant(client, model):
    assert client.get("/chat").status_code == 409
    assert say(client, "facilitator", "Hello").status_code == 409


def test_team_mode_has_a_thread_per_agent(client, team, model):
    assert client.get("/chat").json() == {name: [] for name in ("facilitator", *SPECIALISTS)}
    assert say(client, "assistant", "Hello").status_code == 404


def test_messages_must_have_content(client, team, model):
    assert say(client, "facilitator", "   ").status_code == 422
    assert say(client, "facilitator", "x" * 4001).status_code == 422
    assert model.calls == []


def test_the_facilitator_only_suggests_and_the_human_consults(client, db, team, model):
    model.facilitator_reply = FacilitatorReply(
        message="Start with a plan.",
        suggestions=[
            Suggestion(agent="planner", reason="Break the task into steps"),
            Suggestion(agent="planner", reason="A duplicate"),
        ],
    )
    reply = say(client, "facilitator", "I need to build the login").json()
    human, agent = reply["messages"]
    assert (human["role"], human["content"]) == ("human", "I need to build the login")
    assert agent["data"]["suggestions"] == [{"agent": "planner", "reason": "Break the task into steps"}]
    assert reply["approvals"] == []
    assert [c["role"] for c in model.calls] == ["facilitator"]  # suggesting runs no agent

    consulted = client.post("/chat/consult/planner").json()
    sent = model.last("planner")["messages"][-1]
    assert "I need to build the login" in sent and "Break the task into steps" in sent
    assert consulted["messages"][0]["data"] == {"consult": True}
    assert [m["role"] for m in client.get("/chat/planner").json()] == ["human", "agent"]

    logged = {e.type: e for e in events(db)}
    assert logged["facilitator_suggested"].detail["agents"] == ["planner"]
    assert logged["agent_consulted"].detail == {"agent": "planner", "suggested": True}
    assert logged["agent_replied"].actor == "planner"


def test_agent_proposals_wait_for_the_humans_approval(client, team, model):
    def threat_modeller(tools):
        tools["propose_risk"].invoke(RISK)
        tools["propose_mitigation"].invoke({"risk_id": "#1", "description": "Use parameterised queries"})
        return "I proposed a risk and a mitigation for it."

    model.scripts["threat_modeller"] = threat_modeller
    reply = say(client, "threat_modeller", "What could go wrong?").json()
    risk, mitigation = reply["approvals"]
    assert (risk["actor"], risk["action_type"], risk["status"]) == ("threat_modeller", "propose_risk", "pending")
    assert mitigation["proposal"]["risk_id"] == f"approval:{risk['id']}"
    assert reply["messages"][1]["data"] == {"approval_ids": [risk["id"], mitigation["id"]]}
    assert client.get("/workspace/state").json()["risks"] == []  # nothing changes before approval

    assert decide(client, mitigation["id"]).status_code == 409  # the risk it refers to must be approved first
    assert decide(client, risk["id"]).json()["result"] == {"item_id": "R1"}
    assert decide(client, mitigation["id"]).json()["final_proposal"]["risk_id"] == "R1"
    assert client.get("/workspace/state").json()["mitigations"][0]["risk_id"] == "R1"


def test_review_runs_the_reviewer_and_verifier_in_parallel(client, team, model, study_dirs):
    client.post("/workspace/state/risks", json=RISK)
    both_running = threading.Barrier(2, timeout=5)  # only passes if the two agents run at the same time

    def reviewer(tools):
        both_running.wait()
        tools["propose_finding"].invoke(
            {"description": "Query built from user input", "severity": "High", "file": "app/auth.py", "risk_id": "R1"}
        )
        tools["suggest_fix"].invoke(FIX)
        return "One finding, with a fix."

    def verifier(tools):
        both_running.wait()
        test = {"path": "tests/test_security_login.py", "content": "def test_x():\n    assert True\n", "risk_ids": ["R1"]}
        tools["propose_test"].invoke(test)
        return "One test for R1."

    model.scripts.update(reviewer=reviewer, verifier=verifier)
    reply = client.post("/chat/review")
    assert reply.status_code == 200
    finding, fix, test = reply.json()["approvals"]
    assert [a["actor"] for a in (finding, fix, test)] == ["reviewer", "reviewer", "verifier"]
    assert fix["proposal"]["finding"] == f"approval:{finding['id']}"

    reviewer_sent = model.last("reviewer")["messages"][-1]
    assert reviewer_sent.startswith(f"{REVIEW_MESSAGE}\n\n### ") and "### app/auth.py" in reviewer_sent
    verifier_call = model.last("verifier")
    assert "R1 (High, CWE-89): SQL injection in login" in verifier_call["messages"][-1]
    assert "app/auth.py" not in verifier_call["messages"][-1]
    assert verifier_call["tools"] == ["get_security_state", "propose_test", "read_task_description"]  # no code

    stored = client.get("/chat/reviewer").json()[0]
    assert stored["content"] == REVIEW_MESSAGE  # the listing isn't kept; the snapshot holds the reviewed code
    assert (study_dirs / "snapshots" / "P01_A" / stored["data"]["snapshot"] / "app" / "auth.py").is_file()

    assert decide(client, test["id"]).status_code == 200
    assert client.get("/workspace/files/tests/test_security_login.py").status_code == 200


def test_without_approved_risks_the_verifier_is_not_asked(client, team, model):
    reply = client.post("/chat/review").json()
    assert [c["role"] for c in model.calls] == ["reviewer"]
    assert [(m["thread"], m["role"]) for m in reply["messages"]][-1] == ("verifier", "system")
    say(client, "verifier", "Why not?")
    assert len(model.last("verifier")["messages"]) == 1  # notices are for the human, not the model


def test_single_mode_has_one_assistant_and_no_team(client, single, model):
    assert client.get("/chat").json() == {"assistant": []}
    assert say(client, "facilitator", "Hello").status_code == 404
    assert client.post("/chat/consult/planner").status_code == 409
    assert say(client, "assistant", "How should I start?").status_code == 200
    assert model.last("assistant")["tools"] == ["list_files", "propose_test", "read_file", "suggest_fix"]


def test_single_review_sends_the_neutral_message(client, single, model):
    def assistant(tools):
        tools["suggest_fix"].invoke({**FIX, "finding": "SQL injection"})
        return "Here is a fix."

    model.scripts["assistant"] = assistant
    reply = client.post("/chat/review").json()
    assert model.last("assistant")["messages"][-1].startswith(f"{REVIEW_MESSAGE}\n\n### ")
    assert [a["action_type"] for a in reply["approvals"]] == ["suggest_fix"]

    model.scripts.clear()
    say(client, "assistant", "Thanks")
    assert model.last("assistant")["messages"] == [REVIEW_MESSAGE, "Here is a fix.", "Thanks"]


def test_each_part_keeps_its_own_threads_and_a_finished_part_is_read_only(client, team, model):
    say(client, "facilitator", "Hello")
    client.post("/study/done")
    assert say(client, "facilitator", "Again").status_code == 409
    assert client.post("/chat/review").status_code == 409

    client.post("/study/mode", json={"mode": "single"})
    assert client.get("/chat").json() == {"assistant": []}
    client.post("/study/mode", json={"mode": "team"})
    assert [m["content"] for m in client.get("/chat/facilitator").json()] == ["Hello", "How can I help?"]


def test_a_failed_model_call_is_logged_and_saves_no_messages(client, db, team, model):
    def planner(tools):
        raise TimeoutError("the provider took too long")

    model.scripts["planner"] = planner
    reply = say(client, "planner", "Plan please")
    assert reply.status_code == 502 and "TimeoutError" in reply.json()["detail"]
    assert client.get("/chat/planner").json() == []
    failed = events(db)[-1]
    assert (failed.type, failed.detail) == ("agent_failed", {"agents": ["planner"], "error": "TimeoutError"})


def test_without_a_configured_model_the_chat_is_unavailable(client, team, monkeypatch):
    monkeypatch.setattr(get_settings(), "llm_model", None)
    assert say(client, "facilitator", "Hello").status_code == 503
