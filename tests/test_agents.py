import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from threading import Event as ThreadEvent

import pytest

from agents import runtime
from agents.roles import ASSISTANT_PROMPT, REVIEW_MESSAGE, SPECIALISTS, team_prompt
from agents.runtime import RouteDecision
from agents.team import NO_VULNERABILITIES_NOTICE
from config import get_settings
from models import Approval, Event, Message
from services import approvals, state_service, study

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


@pytest.mark.parametrize("task_id, source", [("A", "app/auth.py"), ("B", "app/storage.py")])
def test_the_first_message_runs_the_planner_then_the_threat_modeller_without_a_handoff(client, db, enrol, model, task_id, source):
    enrol(task_id=task_id)
    task = client.get("/workspace/files/README.md").json()["content"]

    def threat_modeller(tools):
        # The plan is durable before threat analysis begins, without a second HTTP request or approval.
        planner = db.query(Message).filter(Message.role == "agent").one()
        assert (planner.data["agent"], planner.content) == ("planner", "planner reply")
        return "threat_modeller reply"

    model.scripts["threat_modeller"] = threat_modeller
    first = say(client, "Can you check the README and guide me through?").json()
    human, planner, threats = first["messages"]
    assert human["data"] == {"route": ["planner", "threat_modeller"]}
    assert (planner["data"]["agent"], planner["data"]["reply_to"]) == ("planner", human["id"])
    assert (threats["data"]["agent"], threats["data"]["reply_to"]) == ("threat_modeller", human["id"])
    assert first["next"] is None
    assert model.roles() == ["planner", "threat_modeller"]  # the first message isn't routed
    assert "[Planner already answered this]\nplanner reply" in model.last("threat_modeller")["messages"][-1]
    for role in ("planner", "threat_modeller"):
        sent = model.last(role)["messages"][-1]
        assert f"Task description (README.md):\n{task}" in sent
        assert source in sent
        assert "The handoff is automatic; no developer confirmation is needed." in sent
    assert "Give the implementation steps now." in model.last("planner")["messages"][-1]
    assert "Analyse potential threats in this task now" in model.last("threat_modeller")["messages"][-1]
    assert client.get("/approvals").json() == []  # there is no approval for talking or handing off
    assert next_reply(client).status_code == 409  # nobody else is waiting


def test_later_messages_are_routed_to_one_agent(client, db, team, model):
    say(client, "I need to build the login")
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
    reply = say(client, "I need to build the login").json()
    risk, assumption = reply["approvals"]
    assert (risk["actor"], risk["action_type"], risk["status"]) == ("threat_modeller", "propose_risk", "suggested")
    assert (assumption["action_type"], assumption["status"]) == ("propose_assumption", "pending")
    assert reply["messages"][-1]["data"]["approval_ids"] == [risk["id"], assumption["id"]]
    assert reply["next"] is None  # an assumption proposal does not hold up the handoff
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


@pytest.mark.parametrize("with_risks", [False, True])
def test_the_code_reviewer_records_findings_without_risk_links(client, team, model, with_risks):
    if with_risks:
        client.post("/workspace/state/risks", json=RISK)
    replies = []

    def reviewer(tools):
        assert "risk_id" not in tools["propose_vulnerability"].args
        replies.append(tools["mark_resolved"].invoke({"item_id": "V9", "reason": "It is fixed now"}))
        replies.append(tools["propose_vulnerability"].invoke(VULNERABILITY))
        return "One vulnerability."

    model.scripts["reviewer"] = reviewer
    reply = client.post("/chat/review").json()
    assert replies == [
        "Not recorded: V9 is not in the security state.",
        RECORDED,
    ]
    (approval,) = reply["approvals"]
    assert approval["action_type"] == "propose_vulnerability"
    assert "risk_id" not in approval["proposal"]
    assert decide(client, approval["id"]).status_code == 200
    state = client.get("/workspace/state").json()
    assert "risk_id" not in state["vulnerabilities"][0]
    assert len(state["risks"]) == int(with_risks)

    sent = model.last("reviewer")["messages"][-1]
    assert "The risks in the security state:" not in sent
    assert "The approved vulnerabilities:\n(none yet)" in sent


@pytest.mark.parametrize("with_risks", [False, True])
def test_a_clean_review_is_saved_without_creating_proposals(client, team, model, with_risks):
    if with_risks:
        client.post("/workspace/state/risks", json=RISK)
    code = (
        "import bcrypt\n\n"
        "def hash_password(password):\n"
        "    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())\n\n"
        "def find_user(conn, username):\n"
        "    return conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()\n"
    )
    assert client.put("/workspace/files/app/auth.py", json={"content": code}).status_code == 200

    def reviewer(tools):
        assert "bcrypt.gensalt()" in tools["read_file"].invoke({"path": "app/auth.py"})
        return "No vulnerabilities found."

    model.scripts["reviewer"] = reviewer
    reviewed = client.post("/chat/review").json()
    assert reviewed["messages"][-1]["content"] == "No vulnerabilities found."
    assert reviewed["approvals"] == []
    assert reviewed["next"] is None  # tests start after a vulnerability is approved, not before

    follow_up = say(client, "Please check my code again").json()
    assert follow_up["messages"][-1]["content"] == "No vulnerabilities found."
    assert follow_up["approvals"] == []
    assert client.get("/approvals").json() == []
    state = client.get("/workspace/state").json()
    assert state["vulnerabilities"] == state["mitigations"] == []
    assert len(state["risks"]) == int(with_risks)
    assert client.get("/workspace/files/app/auth.py").json()["content"] == code


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
    say(client, "I need to build the login")
    model.route_to = ("verifier", "you asked for security tests")
    (test,) = say(client, "Please write security tests").json()["approvals"]
    assert replies == [
        "Not recorded: these are not approved vulnerabilities: V7 (approved: V1).",
        RECORDED,
        "Not recorded: you already proposed tests/test_security_login.py in this reply.",
    ]
    assert test["proposal"]["vulnerability_ids"] == ["V1"]

    assert say(client, "Please write security tests").json()["approvals"] == []  # still waiting for a decision
    assert replies[4] == (
        f"Not recorded: tests/test_security_login.py is already waiting for the developer's decision (proposal #{test['id']})."
    )


def test_review_runs_only_the_code_reviewer_until_findings_are_approved(client, team, model, study_dirs):
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
    assert (asked["content"], asked["data"]["route"]) == (REVIEW_MESSAGE, ["reviewer"])
    assert (reviewed["data"]["agent"], first["next"]) == ("reviewer", None)
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
    assert (study_dirs / "snapshots" / "P01_A_team" / asked["data"]["snapshot"] / "app" / "auth.py").is_file()

    assert model.roles() == ["reviewer"]
    model.route_to = ("verifier", "you asked for tests for approved vulnerabilities")
    second = say(client, "Please test the approved vulnerabilities").json()
    (test,) = second["approvals"]
    verifier_call = model.last("verifier")
    sent = verifier_call["messages"][-1]
    assert "- V1 (High, CWE-89, app/auth.py:12, open) [no mitigation yet]: Query built from user input" in sent
    assert "Password stored in plain text" not in sent
    assert "### app/auth.py" not in sent  # tests come from the vulnerabilities, not the code
    assert verifier_call["tools"] == ["get_security_state", "list_test_files", "propose_test", "read_task_description", "read_test_file"]
    assert second["next"] is None

    assert decide(client, test["id"]).status_code == 200
    assert client.get("/workspace/files/tests/test_security_login.py").status_code == 200


def test_review_does_not_run_the_verifier_without_approved_vulnerabilities(client, team, model):
    client.post("/workspace/state/risks", json=RISK)  # risks alone are not enough
    assert client.post("/chat/review").json()["next"] is None
    assert model.roles() == ["reviewer"]
    assert next_reply(client).status_code == 409
    # A direct request for tests still explains why it cannot create them.
    model.route_to = ("verifier", "you asked for tests")
    notice = say(client, "Write tests please").json()["messages"][-1]
    assert (notice["role"], notice["data"]["agent"], notice["content"]) == ("system", "verifier", NO_VULNERABILITIES_NOTICE)
    assert model.roles() == ["reviewer", "facilitator"]
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


def test_an_interrupted_threat_analysis_retries_without_repeating_the_saved_plan(client, team, model):
    def unavailable(tools):
        raise TimeoutError("the provider took too long")

    model.scripts["threat_modeller"] = unavailable
    assert say(client, "Guide me through this task").status_code == 502
    saved = client.get("/chat/team").json()
    assert [m["content"] for m in saved] == ["Guide me through this task", "planner reply"]
    del model.scripts["threat_modeller"]
    retried = next_reply(client).json()
    assert retried["messages"][0]["data"]["agent"] == "threat_modeller"
    assert retried["next"] is None
    assert model.roles() == ["planner", "threat_modeller", "threat_modeller"]
    assert len(client.get("/chat/team").json()) == 3


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


@pytest.mark.parametrize("decision", ["approve", "reject"])
def test_single_fix_decisions_never_read_or_change_shared_security_state(client, db, team, model, monkeypatch, decision):
    client.post("/workspace/state/vulnerabilities", json=VULNERABILITY)
    team_ws = study.current_workspace(db)
    team_state = team_ws.security_state
    client.post("/study/done")
    client.post("/study/mode", json={"mode": "single"})
    single_ws = study.current_workspace(db)
    client.put("/workspace/notes", json={"text": "My private notes"})
    original = client.get("/workspace/files/app/auth.py").json()["content"]

    def unexpected_state_access(*args, **kwargs):
        pytest.fail("Single-mode fixes must not access shared security state")

    monkeypatch.setattr(state_service, "load", unexpected_state_access)
    monkeypatch.setattr(state_service, "save", unexpected_state_access)

    def assistant(tools):
        assert "get_security_state" not in tools and "propose_vulnerability" not in tools
        assert tools["suggest_fix"].invoke({**FIX, "vulnerability": "SQL injection"}) == RECORDED
        return "This is a suggested fix. Approve or reject it, then write any approved changes yourself."

    model.scripts["assistant"] = assistant
    (fix,) = client.post("/chat/review").json()["approvals"]
    assert (fix["actor"], fix["status"]) == ("assistant", "pending")
    stored = db.get(Approval, fix["id"])
    assert (stored.mode, stored.workspace_id) == ("single", single_ws.id)
    assert fix["proposal"]["vulnerability"] == "SQL injection"  # a description, not a state id
    decided = decide(client, fix["id"], decision).json()
    assert decided["status"] == {"approve": "approved", "reject": "rejected"}[decision]
    assert decided["result"] is None
    db.refresh(single_ws)
    db.refresh(team_ws)
    assert single_ws.security_state == {} and single_ws.notes == "My private notes"
    assert team_ws.security_state == team_state
    assert client.get("/workspace/files/app/auth.py").json()["content"] == original
    assert model.roles() == ["assistant"]
    assert all(not m["data"].get("kind") for m in client.get("/chat").json()["assistant"])
    assert all(event.type != "state_item_added" for event in events(db) if event.mode == "single")


def test_each_part_keeps_its_own_conversation_and_a_finished_part_is_read_only(client, team, model):
    say(client, "Hello")
    client.post("/study/done")
    assert say(client, "Again").status_code == 409
    assert client.post("/chat/review").status_code == 409
    assert next_reply(client).status_code == 409

    client.post("/study/mode", json={"mode": "single"})
    assert client.get("/chat").json() == {"assistant": []}
    client.post("/study/mode", json={"mode": "team"})
    assert [m["content"] for m in client.get("/chat/team").json()] == ["Hello", "planner reply", "threat_modeller reply"]


def test_without_a_configured_model_the_chat_is_unavailable(client, team, monkeypatch):
    monkeypatch.setattr(get_settings(), "llm_model", None)
    assert say(client, "Hello").status_code == 503


def finding_jobs(client):
    return [m for m in client.get("/chat").json()["team"] if m["data"].get("kind") == "vulnerability_follow_up"]


def approve_finding(client, model):
    def reviewer(tools):
        assert tools["propose_vulnerability"].invoke(VULNERABILITY) == RECORDED
        return "One vulnerability."

    model.scripts["reviewer"] = reviewer
    (finding,) = client.post("/chat/review").json()["approvals"]
    del model.scripts["reviewer"]
    assert decide(client, finding["id"]).status_code == 200
    return finding_jobs(client)


def suggest_the_fix(client, model, job):
    def reviewer(tools):
        assert tools["suggest_fix"].invoke(FIX) == RECORDED
        return "A fix for V1."

    model.scripts["reviewer"] = reviewer
    (fix,) = client.post(f"/chat/follow-ups/{job['id']}").json()["approvals"]
    del model.scripts["reviewer"]
    return fix


def approve_fix(client, model):
    # Returns the Test/Verifier's follow-up, which approving the fix queues.
    (job,) = approve_finding(client, model)
    assert decide(client, suggest_the_fix(client, model, job)["id"]).status_code == 200
    (test_job,) = [m for m in finding_jobs(client) if m["data"]["agent"] == "verifier"]
    return test_job


def test_approving_a_finding_queues_only_the_fix_followup_once(client, team, model):
    jobs = approve_finding(client, model)
    assert [(m["data"]["agent"], m["data"]["status"], m["data"]["vulnerability_id"]) for m in jobs] == [
        ("reviewer", "queued", "V1"),
    ]
    assert model.roles() == ["reviewer"]  # approval itself does not wait on model calls
    assert finding_jobs(client) == jobs  # refresh never creates extra jobs
    assert decide(client, jobs[0]["data"]["approval_id"]).status_code == 409
    assert finding_jobs(client) == jobs


def test_approving_the_fix_queues_the_test_followup_once(client, team, model):
    (job,) = approve_finding(client, model)
    fix = suggest_the_fix(client, model, job)
    assert [m["data"]["agent"] for m in finding_jobs(client)] == ["reviewer"]  # a waiting fix starts no test
    assert decide(client, fix["id"]).status_code == 200
    jobs = finding_jobs(client)
    assert [(m["data"]["agent"], m["data"]["status"], m["data"]["vulnerability_id"]) for m in jobs] == [
        ("reviewer", "complete", "V1"), ("verifier", "queued", "V1"),
    ]
    assert model.roles() == ["reviewer", "reviewer"]  # the review and the fix; approving the fix calls no model
    assert finding_jobs(client) == jobs


def test_a_rejected_fix_queues_no_test(client, team, model):
    (job,) = approve_finding(client, model)
    assert decide(client, suggest_the_fix(client, model, job)["id"], "reject").status_code == 200
    assert [m["data"]["agent"] for m in finding_jobs(client)] == ["reviewer"]


def test_rejected_vulnerabilities_do_not_queue_followups(client, db, team, model):
    finding = approvals.request_approval(db, study.editable_workspace(db), "reviewer", "propose_vulnerability", VULNERABILITY)
    assert decide(client, finding.id, "reject").status_code == 200
    assert finding_jobs(client) == []
    assert model.calls == []


def test_existing_approved_findings_are_recovered_when_chat_reloads(client, team, model):
    client.post("/workspace/state/vulnerabilities", json=VULNERABILITY)
    jobs = finding_jobs(client)
    assert [m["data"]["agent"] for m in jobs] == ["reviewer"]
    assert finding_jobs(client) == jobs
    client.post("/workspace/state/mitigations", json={"vulnerability_id": "V1", "description": "Use placeholders"})
    jobs = finding_jobs(client)
    assert [m["data"]["agent"] for m in jobs] == ["reviewer", "verifier"]
    assert client.post(f"/chat/follow-ups/{jobs[0]['id']}").status_code == 200
    assert [m["data"]["status"] for m in finding_jobs(client)] == ["complete", "queued"]


def test_verifier_extends_existing_tests_without_reading_application_source(client, team, model):
    job = approve_fix(client, model)
    original = client.get("/workspace/files/tests/test_functional.py").json()["content"]
    updated = original + "\n\ndef test_sql_injection_is_rejected():\n    assert True\n"

    def verifier(tools):
        assert "read_file" not in tools and "list_files" not in tools
        assert "no_test_needed" in tools
        assert "tests/test_functional.py" in tools["list_test_files"].invoke({})
        assert "Only existing Python files" in tools["read_test_file"].invoke({"path": "app/auth.py"})
        assert "Only existing Python files" in tools["read_test_file"].invoke({"path": "tests/../app/auth.py"})
        assert "test_" in tools["read_test_file"].invoke({"path": "tests/test_functional.py"})
        assert tools["propose_test"].invoke({
            "path": "tests/test_functional.py", "content": updated, "vulnerability_ids": ["V1"],
        }) == RECORDED
        return "Tests for V1, extending the existing test file."

    model.scripts["verifier"] = verifier
    result = client.post(f"/chat/follow-ups/{job['id']}").json()
    (test,) = result["approvals"]
    assert test["proposal"]["base_content"] == original
    assert result["messages"][0]["id"] == job["id"]  # placeholder becomes the reply
    assert "hidden" not in result["messages"][0]["data"]  # a reply with a test proposal is shown
    sent = model.last("verifier")["messages"][-1]
    assert "### tests/test_functional.py" in sent and "### app/auth.py" not in sent
    assert f"The developer approved a fix for V1:\n- M1: {FIX['why']}" in sent
    assert client.get("/workspace/files/tests/test_functional.py").json()["content"] == original
    assert decide(client, test["id"]).status_code == 200
    assert client.get("/workspace/files/tests/test_functional.py").json()["content"] == updated


def test_proposing_tests_cannot_remove_existing_tests_or_overwrite_later_edits(client, team, model):
    job = approve_fix(client, model)
    path = "tests/test_functional.py"
    original = client.get(f"/workspace/files/{path}").json()["content"]
    updated = original + "\n\ndef test_regression():\n    assert True\n"

    def verifier(tools):
        proposal = {"path": path, "content": "def test_only_new():\n    assert True\n", "vulnerability_ids": ["V1"]}
        assert "preserve all existing" in tools["propose_test"].invoke(proposal)
        assert tools["propose_test"].invoke({**proposal, "content": updated}) == RECORDED
        return "One test proposal."

    model.scripts["verifier"] = verifier
    (test,) = client.post(f"/chat/follow-ups/{job['id']}").json()["approvals"]
    human_version = original + "\n# A later human edit\n"
    client.put(f"/workspace/files/{path}", json={"content": human_version})
    refused = decide(client, test["id"])
    assert refused.status_code == 409 and "has changed" in refused.json()["detail"]
    assert client.get(f"/workspace/files/{path}").json()["content"] == human_version
    assert client.get(f"/approvals/{test['id']}").json()["status"] == "pending"


def test_verifier_can_decide_an_approved_fix_needs_no_new_test(client, db, team, model):
    job = approve_fix(client, model)
    why = "tests/test_functional.py already sends this attack."
    test = {"path": "tests/test_security_login.py", "content": "def test_x():\n    assert True\n", "vulnerability_ids": ["V1"]}

    def verifier(tools):
        assert tools["no_test_needed"].invoke({"reason": "already_covered", "explanation": why}).startswith("Recorded.")
        assert tools["propose_test"].invoke(test) == "Not recorded: you already decided that no new test is needed."
        return "No new test for V1: tests/test_functional.py already checks it."

    model.scripts["verifier"] = verifier
    result = client.post(f"/chat/follow-ups/{job['id']}").json()
    assert result["approvals"] == []
    (message,) = result["messages"]
    assert message["content"] == "No new test for V1: tests/test_functional.py already checks it."
    assert (message["data"]["status"], message["data"]["hidden"]) == ("complete", True)  # kept, but not shown
    (skipped,) = [e for e in events(db) if e.type == "test_skipped"]
    assert (skipped.actor, skipped.detail) == (
        "verifier", {"vulnerability_id": "V1", "reason": "already_covered", "why": why},
    )


def test_verifier_cannot_skip_a_test_it_already_proposed(client, team, model):
    job = approve_fix(client, model)
    test = {"path": "tests/test_security_login.py", "content": "def test_x():\n    assert True\n", "vulnerability_ids": ["V1"]}

    def verifier(tools):
        assert tools["propose_test"].invoke(test) == RECORDED
        refused = tools["no_test_needed"].invoke({"reason": "not_testable", "explanation": "Changed my mind."})
        assert refused == "Not recorded: you already proposed a test in this reply."
        return "A test for V1."

    model.scripts["verifier"] = verifier
    assert len(client.post(f"/chat/follow-ups/{job['id']}").json()["approvals"]) == 1


def test_a_low_severity_fix_gets_no_automatic_test(client, db, team, model):
    client.post("/workspace/state/vulnerabilities", json={**VULNERABILITY, "severity": "Low"})
    client.post("/workspace/state/mitigations", json={"vulnerability_id": "V1", "description": "Use placeholders"})
    (job,) = [m for m in finding_jobs(client) if m["data"]["agent"] == "verifier"]
    result = client.post(f"/chat/follow-ups/{job['id']}").json()
    assert result["approvals"] == []
    assert result["messages"][0]["data"]["hidden"] is True
    assert "verifier" not in model.roles()  # a fixed rule, so no model call
    (skipped,) = [e for e in events(db) if e.type == "test_skipped"]
    assert skipped.detail["reason"] == "low_severity"


def test_a_verifier_followup_without_a_test_is_hidden_even_without_the_tool(client, db, team, model):
    job = approve_fix(client, model)
    model.scripts["verifier"] = lambda tools: "No new test is needed for V1."
    (message,) = client.post(f"/chat/follow-ups/{job['id']}").json()["messages"]
    assert message["data"]["hidden"] is True
    (skipped,) = [e for e in events(db) if e.type == "test_skipped"]
    assert skipped.detail == {"vulnerability_id": "V1", "reason": "no_proposal", "why": "No new test is needed for V1."}


def test_the_code_reviewers_followup_is_never_hidden(client, team, model):
    (job,) = approve_finding(client, model)
    model.scripts["reviewer"] = lambda tools: "I need more detail before suggesting a fix."
    (message,) = client.post(f"/chat/follow-ups/{job['id']}").json()["messages"]
    assert "hidden" not in message["data"]


def test_asked_in_chat_the_verifier_is_not_offered_to_skip_the_test(client, team, model):
    client.post("/workspace/state/vulnerabilities", json=VULNERABILITY)
    say(client, "I want to build the login")
    model.route_to = ("verifier", "you asked for a test")
    say(client, "Please write a test for V1")
    tools = model.last("verifier")["tools"]
    assert "propose_test" in tools and "no_test_needed" not in tools


def test_followups_run_concurrently_and_keep_fixes_and_tests_behind_approval(concurrent_client, enrol, model):
    client = concurrent_client
    enrol()
    test_job = approve_fix(client, model)  # V1 has an approved fix, so its test is next
    client.post("/workspace/state/vulnerabilities", json={**VULNERABILITY, "line": 30})  # V2 still needs a fix
    (fix_job,) = [m for m in finding_jobs(client) if m["data"]["status"] == "queued" and m["data"]["agent"] == "reviewer"]
    jobs = [fix_job, test_job]
    original = client.get("/workspace/files/app/auth.py").json()["content"]
    together = Barrier(2, timeout=5)

    def reviewer(tools):
        assert "propose_vulnerability" not in tools and "mark_resolved" not in tools
        together.wait()  # both agents must enter the model before either can finish
        assert tools["suggest_fix"].invoke({**FIX, "vulnerability": "V2"}) == RECORDED
        return "A fix for V2."

    def verifier(tools):
        together.wait()
        assert tools["propose_test"].invoke({
            "path": "tests/test_security_login.py", "content": "def test_regression():\n    assert True\n", "vulnerability_ids": ["V1"],
        }) == RECORDED
        return "Tests for V1."

    model.scripts.update(reviewer=reviewer, verifier=verifier)
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda m: client.post(f"/chat/follow-ups/{m['id']}"), jobs))
    assert [r.status_code for r in responses] == [200, 200]
    assert {a["action_type"] for r in responses for a in r.json()["approvals"]} == {"suggest_fix", "propose_test"}
    assert all(a["status"] == "pending" for r in responses for a in r.json()["approvals"])
    assert client.get("/workspace/files/app/auth.py").json()["content"] == original
    assert client.get("/workspace/files/tests/test_security_login.py").status_code == 404
    before = len(model.calls)
    assert client.post(f"/chat/follow-ups/{jobs[0]['id']}").json() == responses[0].json()
    assert len(model.calls) == before  # completed jobs are idempotent


def test_a_second_request_never_runs_the_same_followup_twice(concurrent_client, enrol, model):
    client = concurrent_client
    enrol()
    jobs = approve_finding(client, model)
    entered, release = ThreadEvent(), ThreadEvent()

    def reviewer(tools):
        entered.set()
        assert release.wait(timeout=5)
        return "A fix explanation."

    model.scripts["reviewer"] = reviewer
    path = f"/chat/follow-ups/{jobs[0]['id']}"
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(client.post, path)
        try:
            assert entered.wait(timeout=5)
            second = client.post(path)
            assert second.status_code == 200 and second.json()["messages"][0]["data"]["status"] == "running"
            assert model.roles().count("reviewer") == 2  # original review plus one follow-up
        finally:
            release.set()
        assert first.result().status_code == 200


def test_failed_followup_does_not_block_the_next_one_and_can_retry(client, team, model):
    client.post("/workspace/state/vulnerabilities", json=VULNERABILITY)
    client.post("/workspace/state/vulnerabilities", json={**VULNERABILITY, "line": 30})
    jobs = finding_jobs(client)

    def broken(tools):
        tools["suggest_fix"].invoke(FIX)
        raise TimeoutError("provider failed after calling a tool")

    model.scripts["reviewer"] = broken
    assert client.post(f"/chat/follow-ups/{jobs[0]['id']}").status_code == 502
    assert [m["data"]["status"] for m in finding_jobs(client)] == ["failed", "queued"]
    assert client.get("/approvals?status=pending").json() == []  # failed runs leave no partial proposals
    model.scripts["reviewer"] = lambda tools: "Try again succeeded."
    assert client.post(f"/chat/follow-ups/{jobs[1]['id']}").status_code == 200
    assert client.post(f"/chat/follow-ups/{jobs[0]['id']}").status_code == 200
    assert all(m["data"]["status"] == "complete" for m in finding_jobs(client))


def test_expired_followup_recovers_after_a_server_restart(client, db, team, model):
    jobs = approve_finding(client, model)
    job = db.get(Message, jobs[0]["id"])
    job.data = {**job.data, "status": "running", "started_at": time.time() - 601, "run_token": "old-run"}
    db.commit()
    result = client.post(f"/chat/follow-ups/{job.id}")
    assert result.status_code == 200
    assert result.json()["messages"][0]["data"]["status"] == "complete"


def test_followup_cannot_be_run_in_another_or_finished_part(client, team, model):
    jobs = approve_finding(client, model)
    path = f"/chat/follow-ups/{jobs[0]['id']}"
    assert client.post("/chat/follow-ups/99999").status_code == 404
    client.post("/study/done")
    assert client.post(path).status_code == 409
    client.post("/study/mode", json={"mode": "single"})
    assert client.post(path).status_code == 404


def test_two_approval_requests_do_not_lose_either_finding(concurrent_client, enrol, model):
    client = concurrent_client
    enrol()

    def reviewer(tools):
        tools["propose_vulnerability"].invoke(VULNERABILITY)
        tools["propose_vulnerability"].invoke({**VULNERABILITY, "line": 30})
        return "Two findings."

    model.scripts["reviewer"] = reviewer
    findings = client.post("/chat/review").json()["approvals"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda a: decide(client, a["id"]), findings))
    assert [r.status_code for r in responses] == [200, 200]
    assert len(client.get("/workspace/state").json()["vulnerabilities"]) == 2
    assert len(finding_jobs(client)) == 2  # one fix follow-up each; tests wait for approved fixes


def test_old_review_routes_do_not_leave_a_second_verifier_waiting(client, db, team, model):
    first = client.post("/chat/review").json()
    asked = db.get(Message, first["messages"][0]["id"])
    asked.data = {**asked.data, "route": ["reviewer", "verifier"]}
    db.commit()
    assert client.post("/chat/next").status_code == 409
    assert model.roles() == ["reviewer"]


def test_same_specialist_handles_multiple_findings_in_order(concurrent_client, enrol, model):
    client = concurrent_client
    enrol()
    client.post("/workspace/state/vulnerabilities", json=VULNERABILITY)
    client.post("/workspace/state/vulnerabilities", json={**VULNERABILITY, "line": 30})
    reviewer_jobs = [m for m in finding_jobs(client) if m["data"]["agent"] == "reviewer"]
    entered, release = ThreadEvent(), ThreadEvent()

    def reviewer(tools):
        entered.set()
        assert release.wait(timeout=5)
        return "A fix explanation."

    model.scripts["reviewer"] = reviewer
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(client.post, f"/chat/follow-ups/{reviewer_jobs[0]['id']}")
        try:
            assert entered.wait(timeout=5)
            second = client.post(f"/chat/follow-ups/{reviewer_jobs[1]['id']}")
            assert second.status_code == 200
            assert second.json()["messages"][0]["data"]["status"] == "queued"
            assert model.roles() == ["reviewer"]
        finally:
            release.set()
        assert first.result().status_code == 200
    assert client.post(f"/chat/follow-ups/{reviewer_jobs[1]['id']}").status_code == 200
    assert model.roles() == ["reviewer", "reviewer"]


def test_followup_discards_late_proposals_after_the_human_finishes_the_part(concurrent_client, enrol, model):
    client = concurrent_client
    enrol()
    jobs = approve_finding(client, model)
    entered, release = ThreadEvent(), ThreadEvent()

    def reviewer(tools):
        entered.set()
        assert release.wait(timeout=5)
        tools["suggest_fix"].invoke(FIX)
        return "A fix for V1."

    model.scripts["reviewer"] = reviewer
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(client.post, f"/chat/follow-ups/{jobs[0]['id']}")
        try:
            assert entered.wait(timeout=5)
            assert client.post("/study/done").status_code == 200
        finally:
            release.set()
        result = pending.result()
    assert result.status_code == 200 and result.json()["approvals"] == []
    assert "no new proposals" in result.json()["messages"][0]["content"]
    assert client.get("/approvals?status=pending").json() == []
