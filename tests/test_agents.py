import pytest

from agents import runtime
from agents.roles import ASSISTANT_PROMPT, REVIEW_MESSAGE, SPECIALISTS, team_prompt
from agents.runtime import RouteDecision
from config import get_settings
from models import Event

ROLE_OF_PROMPT = {team_prompt(role): role for role in SPECIALISTS} | {ASSISTANT_PROMPT: "assistant"}
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
        self.route_to = ("reviewer", "you asked about your code")

    def run_agent(self, system_prompt, tools, messages):
        role = ROLE_OF_PROMPT[system_prompt]
        tools = {t.name: t for t in tools}
        self.calls.append({"role": role, "tools": sorted(tools), "messages": [m.content for m in messages]})
        script = self.scripts.get(role)
        return script(tools) if script else f"{role} reply"

    def route(self, system_prompt, messages):
        self.calls.append({"role": "facilitator", "prompt": system_prompt, "messages": [m.content for m in messages]})
        agent, reason = self.route_to
        return RouteDecision(agent=agent, reason=reason)

    def roles(self):
        return [c["role"] for c in self.calls]

    def last(self, role):
        return [c for c in self.calls if c["role"] == role][-1]


@pytest.fixture
def model(monkeypatch):
    fake = FakeModel()
    monkeypatch.setattr(runtime, "run_agent", fake.run_agent)
    monkeypatch.setattr(runtime, "route", fake.route)
    return fake


def say(client, content, thread="team"):
    return client.post(f"/chat/{thread}", json={"content": content})


def next_reply(client):
    return client.post("/chat/next")


def decide(client, approval_id, decision="approve"):
    return client.post(f"/approvals/{approval_id}/decide", json={"decision": decision})


def events(db):
    return db.query(Event).order_by(Event.id).all()


def test_chat_needs_an_active_participant(client, model):
    assert client.get("/chat").status_code == 409
    assert say(client, "Hello").status_code == 409


def test_team_mode_is_one_conversation(client, team, model):
    assert client.get("/chat").json() == {"team": []}
    assert say(client, "Hello", thread="assistant").status_code == 404


def test_messages_must_have_content(client, team, model):
    assert say(client, "   ").status_code == 422
    assert say(client, "x" * 4001).status_code == 422
    assert model.calls == []


def test_the_first_message_gets_the_planner_then_the_threat_modeller(client, team, model):
    first = say(client, "I need to build the login").json()
    human, planner = first["messages"]
    assert human["data"] == {"route": ["planner", "threat_modeller"]}
    assert (planner["data"]["agent"], planner["data"]["reply_to"]) == ("planner", human["id"])
    assert first["next"] == "threat_modeller"

    second = next_reply(client).json()
    assert second["messages"][0]["data"]["agent"] == "threat_modeller"
    assert second["next"] is None
    assert model.roles() == ["planner", "threat_modeller"]  # the first message isn't routed
    assert "[Planner already answered this]\nplanner reply" in model.last("threat_modeller")["messages"][-1]
    assert next_reply(client).status_code == 409  # nobody else is waiting


def test_later_messages_are_routed_to_one_agent(client, db, team, model):
    say(client, "I need to build the login")
    next_reply(client)
    reply = say(client, "Is my login safe?").json()
    human, answer = reply["messages"]
    assert human["data"] == {"route": ["reviewer"], "reason": "you asked about your code"}
    assert (answer["data"]["agent"], reply["next"]) == ("reviewer", None)

    sent = model.last("reviewer")["messages"]
    assert "### app/auth.py" in sent[-1]  # the Code Reviewer always sees the current code
    assert "[Planner] planner reply" in sent  # and the conversation so far, with who said what
    routed = db.query(Event).filter(Event.type == "message_routed").one()
    assert routed.detail == {"agent": "reviewer", "reason": "you asked about your code"}


def test_agent_proposals_wait_for_the_humans_approval(client, team, model):
    def threat_modeller(tools):
        tools["propose_risk"].invoke(RISK)
        tools["propose_mitigation"].invoke({"risk_id": "#1", "description": "Use parameterised queries"})
        return "I proposed a risk and a mitigation for it."

    model.scripts["threat_modeller"] = threat_modeller
    say(client, "I need to build the login")
    reply = next_reply(client).json()
    risk, mitigation = reply["approvals"]
    assert (risk["actor"], risk["action_type"], risk["status"]) == ("threat_modeller", "propose_risk", "pending")
    assert mitigation["proposal"]["risk_id"] == f"approval:{risk['id']}"
    assert reply["messages"][0]["data"]["approval_ids"] == [risk["id"], mitigation["id"]]
    assert client.get("/workspace/state").json()["risks"] == []  # nothing changes before approval

    assert decide(client, mitigation["id"]).status_code == 409  # the risk it refers to must be approved first
    assert decide(client, risk["id"]).json()["result"] == {"item_id": "R1"}
    assert decide(client, mitigation["id"]).json()["final_proposal"]["risk_id"] == "R1"
    assert client.get("/workspace/state").json()["mitigations"][0]["risk_id"] == "R1"


def test_done_runs_the_code_reviewer_then_the_verifier(client, team, model, study_dirs):
    client.post("/workspace/state/risks", json=RISK)

    def reviewer(tools):
        tools["propose_finding"].invoke(
            {"description": "Query built from user input", "severity": "High", "file": "app/auth.py", "risk_id": "R1"}
        )
        tools["suggest_fix"].invoke(FIX)
        return "One finding, with a fix."

    def verifier(tools):
        test = {"path": "tests/test_security_login.py", "content": "def test_x():\n    assert True\n", "risk_ids": ["R1"]}
        tools["propose_test"].invoke(test)
        return "One test for R1."

    model.scripts.update(reviewer=reviewer, verifier=verifier)
    first = client.post("/chat/review").json()
    asked, reviewed = first["messages"]
    assert (asked["content"], asked["data"]["route"]) == (REVIEW_MESSAGE, ["reviewer", "verifier"])
    assert (reviewed["data"]["agent"], first["next"]) == ("reviewer", "verifier")
    finding, fix = first["approvals"]
    assert fix["proposal"]["finding"] == f"approval:{finding['id']}"
    assert model.last("reviewer")["messages"][-1].startswith(f"{REVIEW_MESSAGE}\n\n### ")
    assert (study_dirs / "snapshots" / "P01_A" / asked["data"]["snapshot"] / "app" / "auth.py").is_file()

    second = next_reply(client).json()
    (test,) = second["approvals"]
    verifier_call = model.last("verifier")
    assert "R1 (High, CWE-89): SQL injection in login" in verifier_call["messages"][-1]
    assert "app/auth.py" not in verifier_call["messages"][-1]  # tests come from the risks, not the code
    assert verifier_call["tools"] == ["get_security_state", "propose_test", "read_task_description"]
    assert second["next"] is None

    assert decide(client, test["id"]).status_code == 200
    assert client.get("/workspace/files/tests/test_security_login.py").status_code == 200


def test_without_approved_risks_the_verifier_only_leaves_a_notice(client, team, model):
    assert client.post("/chat/review").json()["next"] == "verifier"
    notice = next_reply(client).json()["messages"][0]
    assert (notice["role"], notice["data"]["agent"]) == ("system", "verifier")
    assert model.roles() == ["reviewer"]
    assert next_reply(client).status_code == 409


def test_a_failed_answer_can_be_retried(client, db, team, model):
    def planner(tools):
        raise TimeoutError("the provider took too long")

    model.scripts["planner"] = planner
    reply = say(client, "I need to build the login")
    assert reply.status_code == 502 and "TimeoutError" in reply.json()["detail"]
    assert [m["role"] for m in client.get("/chat/team").json()] == ["human"]  # the message is kept
    failed = events(db)[-1]
    assert (failed.type, failed.detail) == ("agent_failed", {"agents": ["planner"], "error": "TimeoutError"})

    del model.scripts["planner"]
    retried = next_reply(client).json()
    assert (retried["messages"][0]["data"]["agent"], retried["next"]) == ("planner", "threat_modeller")


def test_single_mode_has_one_assistant(client, single, model):
    assert client.get("/chat").json() == {"assistant": []}
    assert say(client, "Hello").status_code == 404
    assert next_reply(client).status_code == 409
    assert say(client, "How should I start?", thread="assistant").json()["next"] is None
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
    say(client, "Thanks", thread="assistant")
    assert model.last("assistant")["messages"] == [REVIEW_MESSAGE, "Here is a fix.", "Thanks"]


def test_each_part_keeps_its_own_conversation_and_a_finished_part_is_read_only(client, team, model):
    say(client, "Hello")
    client.post("/study/done")
    assert say(client, "Again").status_code == 409
    assert client.post("/chat/review").status_code == 409
    assert next_reply(client).status_code == 409

    client.post("/study/mode", json={"mode": "single"})
    assert client.get("/chat").json() == {"assistant": []}
    client.post("/study/mode", json={"mode": "team"})
    assert [m["content"] for m in client.get("/chat/team").json()] == ["Hello", "planner reply"]


def test_without_a_configured_model_the_chat_is_unavailable(client, team, monkeypatch):
    monkeypatch.setattr(get_settings(), "llm_model", None)
    assert say(client, "Hello").status_code == 503
