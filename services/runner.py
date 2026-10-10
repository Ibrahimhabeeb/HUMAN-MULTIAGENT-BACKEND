import os
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import get_args

from sqlalchemy.orm import Session

from config import get_settings
from models import Workspace
from schemas.runner import CaseResult, Outcome
from schemas.security_state import Evidence
from services import state_service, workspace
from services.events import log_event

MAX_OUTPUT_CHARS = 4000
MAX_DETAILS_CHARS = 3000
_SECRET = re.compile(r"KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|^LLM_|^OPENAI|^ANTHROPIC|^PYTEST", re.IGNORECASE)
_PROBLEMS = {"failure": "failed", "error": "error", "skipped": "skipped"}
# The run's own pytest settings, so the backend's (pyproject.toml) never apply to a workspace.
_CONFIG = "[pytest]\njunit_family = xunit1\n"
# A Ctrl+C sent to the server's console (uvicorn's reload sends one on Windows) must not stop the tests.
_OWN_PROCESS_GROUP: dict = (
    {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if sys.platform == "win32" else {"start_new_session": True}
)


def _environment() -> dict[str, str]:
    # The participant's code runs in this process, so it gets none of the server's keys or other secrets.
    env = {name: value for name, value in os.environ.items() if not _SECRET.search(name)}
    env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1", PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")
    return env


def _tail(*parts: str | bytes | None) -> str:
    text = "".join(p.decode("utf-8", "replace") if isinstance(p, bytes) else (p or "") for p in parts)
    return text[-MAX_OUTPUT_CHARS:]


def _case(element: ET.Element) -> CaseResult:
    file = element.get("file", "").replace("\\", "/")
    case = CaseResult(file=file, name=element.get("name") or file, outcome="passed")
    for tag, outcome in _PROBLEMS.items():
        problem = element.find(tag)
        if problem is not None:
            case.outcome = outcome
            case.message = problem.get("message")
            case.details = (problem.text or "").strip()[-MAX_DETAILS_CHARS:] or None
            break
    return case


def _pytest(folder: Path) -> tuple[int | None, list[CaseResult], str]:
    # Returns pytest's exit code (None if it timed out), the result of each test, and the end of its output.
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as scratch:
        config, report = Path(scratch) / "pytest.ini", Path(scratch) / "results.xml"
        config.write_text(_CONFIG, encoding="utf-8")
        command = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-c", str(config)]
        command += ["--rootdir", str(folder), "--confcutdir", str(folder), f"--junitxml={report}"]
        try:
            done = subprocess.run(
                command,
                cwd=folder,
                env=_environment(),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=get_settings().test_timeout_seconds,
                check=False,  # failing tests are a normal result
                **_OWN_PROCESS_GROUP,
            )
        except subprocess.TimeoutExpired as e:
            return None, [], _tail(e.stdout, e.stderr)
        cases = [_case(element) for element in ET.parse(report).iter("testcase")] if report.is_file() else []
        return done.returncode, cases, _tail(done.stdout, done.stderr)


def _summary(code: int | None, counts: dict[str, int]) -> tuple[str, str]:
    if code is None:
        return "timed_out", f"The tests took longer than {get_settings().test_timeout_seconds} seconds and were stopped."
    if code == 5:
        return "no_tests", "There are no tests to run yet."
    if code not in (0, 1, 2):  # 3 and 4: pytest itself failed, or was called wrongly
        return "error", "pytest could not run the tests; see its output."
    parts = [f"{n} {'errors' if outcome == 'error' and n > 1 else outcome}" for outcome, n in counts.items() if n]
    return ("passed" if code == 0 else "failed"), ", ".join(parts) or "No tests ran."


def _attach_evidence(ws: Workspace, cases: list[CaseResult]) -> list[Evidence]:
    # The results of a test file written for some risks become evidence for those risks. Every run adds new
    # evidence, so the state shows how the results changed over time.
    state = state_service.load(ws)
    existing = {risk.id for risk in state.risks}
    added = []
    for link in state.tests:
        results = [case for case in cases if case.file == link.path]
        risk_ids = [risk_id for risk_id in link.risk_ids if risk_id in existing]
        if results and risk_ids:
            passed = sum(case.outcome == "passed" for case in results)
            text = f"{link.path}: {passed} of {len(results)} tests passed"
            added.append(state_service.add_evidence(state, text, passed == len(results), risk_ids))
    state_service.save(ws, state)
    return added


def run_tests(db: Session, ws: Workspace) -> dict:
    # Clicking Run tests is the human's approval to run them.
    snapshot = workspace.snapshot(ws, "tests")
    code, cases, output = _pytest(workspace.folder(ws).resolve())
    counts = {outcome: sum(case.outcome == outcome for case in cases) for outcome in get_args(Outcome)}
    status, message = _summary(code, counts)

    evidence: list[Evidence] = []
    if ws.mode == "team":
        db.refresh(ws)  # the state may have changed while the tests ran
        evidence = _attach_evidence(ws, cases)
    log_event(
        db,
        ws.participant_code,
        "tests_run",
        mode=ws.mode,
        detail={
            "status": status,
            "counts": counts,
            "snapshot": snapshot.name,
            "tests": [{"file": c.file, "name": c.name, "outcome": c.outcome} for c in cases],
            "evidence": [e.id for e in evidence],
        },
    )
    db.commit()
    return {
        "status": status,
        "message": message,
        "counts": counts,
        "tests": cases,
        "output": output,
        "evidence": evidence,
    }
