import pytest

from agents import runtime
from agents.roles import ASSISTANT_PROMPT, REVIEW_MESSAGE, SPECIALISTS, team_prompt
from agents.runtime import RouteDecision
from agents.team import NO_VULNERABILITIES_NOTICE
from config import get_settings
from models import Event

ROLE_OF_PROMPT = {team_prompt(role): role for role in SPECIALISTS} | {ASSISTANT_PROMPT: "assistant"}
RISK = {"description": "SQL injection in login", "severity": "High", "cwe": "CWE-89"}
VULNERABILITY = {"description": "Query built from user input", "severity": "High", "file": "app/auth.py", "line": 12}
RECORDED = "Recorded. It waits for the developer's approval."
FIX = {
    "vulnerability": "V1",
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


def test_suggested_risks_go_straight_into_the_state_and_assumptions_wait(client, team, model):
    replies = []

    def threat_modeller(tools):
        replies.append(tools["propose_risk"].invoke(RISK))
        replies.append(tools["propose_assumption"].invoke({"text": "Passwords are stored only as hashes"}))
        replies.append(tools["propose_risk"].invoke(RISK))
        return "I suggested a risk and proposed an assumption."

    model.scripts["threat_modeller"] = threat_modeller
    say(client, "I need to build the login")
    reply = next_reply(client).json()
    risk, assumption = reply["approvals"]
    assert (risk["actor"], risk["action_type"], risk["status"]) == ("threat_modeller", "propose_risk", "suggested")
    assert (assumption["action_type"], assumption["status"]) == ("propose_assumption", "pending")
    assert reply["messages"][0]["data"]["approval_ids"] == [risk["id"], assumption["id"]]
    assert replies == [
        "Recorded. It goes straight into the security state as a suggested risk.",
        RECORDED,
        "Not recorded: you already suggested this risk in this reply.",
    ]
    state = client.get("/workspace/state").json()
    assert ([r["id"] for r in state["risks"]], state["assumptions"]) == (["R1"], [])  # only the risk needs no approval
    assert decide(client, risk["id"]).status_code == 409
    assert decide(client, assumption["id"]).json()["result"] == {"item_id": "A1"}

    model.route_to = ("threat_modeller", "you asked about risks")
    replies.clear()
    say(client, "Any other risks?")
    assert replies[0] == "Not recorded: this risk is already in the security state as R1."
    assert "The risks already in the security state (don't suggest these again):\n- R1" in model.last(
        "threat_modeller"
    )["messages"][-1]

    # Risks come from the Threat Modeller; vulnerabilities and their fixes from the Code Reviewer.
    assert model.last("threat_modeller")["tools"] == [
        "get_security_state",
        "list_files",
        "propose_assumption",
        "propose_risk",
        "read_file",
        "read_task_description",
    ]


def test_the_code_reviewer_links_only_to_what_is_in_the_state(client, team, model):
    client.post("/workspace/state/risks", json=RISK)
    replies = []

    def reviewer(tools):
        replies.append(tools["propose_vulnerability"].invoke({**VULNERABILITY, "risk_id": "R7"}))
        replies.append(tools["mark_resolved"].invoke({"item_id": "V9", "reason": "It is fixed now"}))
        replies.append(tools["propose_vulnerability"].invoke({**VULNERABILITY, "risk_id": "R1"}))
        return "One vulnerability."

    model.scripts["reviewer"] = reviewer
    reply = client.post("/chat/review").json()
    assert replies == [
        "Not recorded: R7 is not a risk in the security state (risks: R1). Use one of those or leave risk_id empty.",
        "Not recorded: V9 is not in the security state.",
        RECORDED,
    ]
    assert [a["action_type"] for a in reply["approvals"]] == ["propose_vulnerability"]

    sent = model.last("reviewer")["messages"][-1]
    assert "The risks in the security state:\n- R1 (High, CWE-89, open): SQL injection in login" in sent
    assert "The approved vulnerabilities:\n(none yet)" in sent


def test_fixes_come_only_after_the_developer_approves_the_vulnerability(client, team, model):
    replies = []

    def reviewer(tools):
        replies.append(tools["propose_vulnerability"].invoke(VULNERABILITY))
        replies.append(tools["suggest_fix"].invoke(FIX))  # there is no V1 until the developer approves it
        return "One vulnerability."

    model.scripts["reviewer"] = reviewer
    (vulnerability,) = client.post("/chat/review").json()["approvals"]
    assert replies[1].startswith("Not recorded: V1 is not an approved vulnerability (approved: none yet).")
    decide(client, vulnerability["id"])

    def fixes(tools):
        replies.append(tools["suggest_fix"].invoke(FIX))
        replies.append(tools["suggest_fix"].invoke({**FIX, "code": "another fix"}))
        return "A fix for V1."

    model.scripts["reviewer"] = fixes
    (fix,) = say(client, "Please suggest the fixes").json()["approvals"]
    assert replies[2:] == [RECORDED, "Not recorded: you already suggested a fix for V1 in this reply."]
    sent = model.last("reviewer")["messages"][-1]
    assert "- V1 (High, app/auth.py:12, open) [no mitigation yet]: Query built from user input" in sent

    say(client, "Any other fixes?")
    assert replies[4] == f"Not recorded: a fix for V1 is already waiting for the developer's decision (proposal #{fix['id']})."
    decide(client, fix["id"])  # it becomes M1; the developer types the code themselves
    say(client, "Any other fixes?")
    assert replies[6] == "Not recorded: V1 already has a mitigation (M1)."


def test_the_code_reviewer_proposes_each_vulnerability_once(client, team, model):
    replies = []
    timing = {**VULNERABILITY, "line": 20, "description": "Timing leak"}

    def reviewer(tools):
        replies.append(tools["propose_vulnerability"].invoke(VULNERABILITY))
        replies.append(tools["propose_vulnerability"].invoke(timing))
        replies.append(tools["propose_vulnerability"].invoke(VULNERABILITY))
        return "Two vulnerabilities."

    model.scripts["reviewer"] = reviewer
    waiting, rejected = client.post("/chat/review").json()["approvals"]
    assert replies[2] == "Not recorded: you already proposed this vulnerability in this reply."
    decide(client, rejected["id"], "reject")

    replies.clear()
    assert say(client, "Did you find anything else?").json()["approvals"] == []
    assert replies[:2] == [
        f"Not recorded: this is the same as proposal #{waiting['id']}, which is waiting for the developer's decision.",
        f"Not recorded: the developer rejected this vulnerability (proposal #{rejected['id']}). Don't propose it again.",
    ]
    sent = model.last("reviewer")["messages"][-1]
    assert (
        "Your proposals still waiting for the developer's decision:\n"
        f"- #{waiting['id']} vulnerability (High, app/auth.py:12): Query built from user input"
    ) in sent
    assert f"Your proposals the developer rejected:\n- #{rejected['id']} vulnerability (High, app/auth.py:20)" in sent

    decide(client, waiting["id"])
    replies.clear()
    say(client, "And now?")
    assert replies[0] == "Not recorded: this is the same as V1, which is already in the security state."


def test_the_verifier_can_only_test_approved_vulnerabilities_once(client, team, model):
    client.post("/workspace/state/vulnerabilities", json=VULNERABILITY)
    replies = []

    def verifier(tools):
        test = {"path": "tests/test_security_login.py", "content": "def test_x():\n    assert True\n"}
        replies.append(tools["propose_test"].invoke({**test, "vulnerability_ids": ["V1", "V7"]}))
        replies.append(tools["propose_test"].invoke({**test, "vulnerability_ids": ["V1"]}))
        replies.append(tools["propose_test"].invoke({**test, "vulnerability_ids": ["V1"]}))
        return "One test for V1."

    model.scripts["verifier"] = verifier
    client.post("/chat/review")
    (test,) = next_reply(client).json()["approvals"]
    assert replies == [
        "Not recorded: these are not approved vulnerabilities: V7 (approved: V1).",
        RECORDED,
        "Not recorded: you already proposed tests/test_security_login.py in this reply.",
    ]
    assert test["proposal"]["vulnerability_ids"] == ["V1"]

    client.post("/chat/review")
    assert next_reply(client).json()["approvals"] == []  # the same file is still waiting for a decision
    assert replies[4] == (
        f"Not recorded: tests/test_security_login.py is already waiting for the developer's decision (proposal #{test['id']})."
    )


def test_done_runs_the_code_reviewer_then_the_verifier(client, team, model, study_dirs):
    client.post("/workspace/state/vulnerabilities", json={**VULNERABILITY, "cwe": "CWE-89"})

    def reviewer(tools):
        tools["propose_vulnerability"].invoke({**VULNERABILITY, "line": 30, "description": "Password stored in plain text"})
        tools["suggest_fix"].invoke(FIX)  # for the approved V1
        return "One vulnerability, and a fix for V1."

    def verifier(tools):
        test = {"path": "tests/test_security_login.py", "content": "def test_x():\n    assert True\n"}
        tools["propose_test"].invoke({**test, "vulnerability_ids": ["V1"]})
        return "One test for V1."

    model.scripts.update(reviewer=reviewer, verifier=verifier)
    first = client.post("/chat/review").json()
    asked, reviewed = first["messages"]
    assert (asked["content"], asked["data"]["route"]) == (REVIEW_MESSAGE, ["reviewer", "verifier"])
    assert (reviewed["data"]["agent"], first["next"]) == ("reviewer", "verifier")
    vulnerability, fix = first["approvals"]
    assert (vulnerability["action_type"], fix["proposal"]["vulnerability"]) == ("propose_vulnerability", "V1")
    assert model.last("reviewer")["messages"][-1].startswith(f"{REVIEW_MESSAGE}\n\n### ")
    assert model.last("reviewer")["tools"] == [
        "get_security_state",
        "list_files",
        "mark_resolved",
        "propose_vulnerability",
        "read_file",
        "read_task_description",
        "suggest_fix",
    ]
    assert (study_dirs / "snapshots" / "P01_A" / asked["data"]["snapshot"] / "app" / "auth.py").is_file()

    second = next_reply(client).json()
    (test,) = second["approvals"]
    verifier_call = model.last("verifier")
    sent = verifier_call["messages"][-1]
    assert "- V1 (High, CWE-89, app/auth.py:12, open) [no mitigation yet]: Query built from user input" in sent
    assert "Password stored in plain text" not in sent
    assert "### app/auth.py" not in sent  # tests come from the vulnerabilities, not the code
    assert verifier_call["tools"] == ["get_security_state", "propose_test", "read_task_description"]
    assert second["next"] is None

    assert decide(client, test["id"]).status_code == 200
    assert client.get("/workspace/files/tests/test_security_login.py").status_code == 200


def test_without_approved_vulnerabilities_the_verifier_only_leaves_a_notice(client, team, model):
    client.post("/workspace/state/risks", json=RISK)  # risks alone are not enough
    assert client.post("/chat/review").json()["next"] == "verifier"
    notice = next_reply(client).json()["messages"][0]
    assert (notice["role"], notice["data"]["agent"], notice["content"]) == ("system", "verifier", NO_VULNERABILITIES_NOTICE)
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
        tools["suggest_fix"].invoke({**FIX, "vulnerability": "SQL injection"})
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
