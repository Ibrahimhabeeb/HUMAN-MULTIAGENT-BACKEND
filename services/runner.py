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
from services import state_service, workspace
from services.events import log_event

MAX_OUTPUT_CHARS = 4000
MAX_DETAILS_CHARS = 3000
_SECRET = re.compile(r"KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|^LLM_|^OPENAI|^ANTHROPIC|^PYTEST", re.IGNORECASE)
_EXCEPTION = re.compile(r"^\s*(?:E\s+)?(?P<type>[\w.]+(?:Error|Exception)):\s*(?P<message>[^\n]*)", re.MULTILINE)
_SYNTAX_LOCATION = re.compile(r'^\s*(?:E\s+)?File "(?P<file>[^"\n]+)", line (?P<line>\d+)', re.MULTILINE)
_FRAME_LOCATION = re.compile(r"^(?P<file>[^\n]+\.py):(?P<line>\d+): in ", re.MULTILINE)
_PROBLEMS = {"failure": "failed", "error": "error", "skipped": "skipped"}
# The run's own pytest settings, so the backend's (pyproject.toml) never apply to a workspace.
_CONFIG = "[pytest]\njunit_family = xunit1\n"
# A Ctrl+C sent to the server's console (uvicorn's reload sends one on Windows) must not stop the tests.
_OWN_PROCESS_GROUP: dict = (
    {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if sys.platform == "win32" else {"start_new_session": True}
)


def _environment() -> dict[str, str]:
    # The participant's code runs in this process, so it gets none of the server's keys or other secrets.
    env = {
        name: value for name, value in os.environ.items()
        if not _SECRET.search(name) and name.upper() not in {"PYTHONHOME", "PYTHONPATH"}
    }
    env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1", PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")
    return env


def _tail(*parts: str | bytes | None) -> str:
    text = "".join(p.decode("utf-8", "replace") if isinstance(p, bytes) else (p or "") for p in parts)
    return text[-MAX_OUTPUT_CHARS:]


def _collection_problem(details: str, folder: Path) -> str | None:
    exceptions = list(_EXCEPTION.finditer(details))
    if not exceptions:
        return None
    error = exceptions[-1]
    locations = sorted([*_SYNTAX_LOCATION.finditer(details), *_FRAME_LOCATION.finditer(details)], key=lambda m: m.start())
    location = ""
    for match in reversed(locations):
        try:
            path = Path(match["file"])
            path = (path if path.is_absolute() else folder / path).resolve()
        except (OSError, ValueError):
            continue
        if path.is_relative_to(folder):
            location = f" in {path.relative_to(folder).as_posix()}:{match['line']}"
            break
    return f"{error['type']}{location}: {error['message'].strip()}"


def _case(element: ET.Element, folder: Path) -> CaseResult:
    file = element.get("file", "").replace("\\", "/")
    case = CaseResult(file=file, name=element.get("name") or file, outcome="passed")
    for tag, outcome in _PROBLEMS.items():
        problem = element.find(tag)
        if problem is not None:
            case.outcome = outcome
            case.message = problem.get("message")
            case.details = (problem.text or "").strip()[-MAX_DETAILS_CHARS:] or None
            if tag == "error" and case.message == "collection failure":
                case.message = _collection_problem(problem.text or "", folder) or case.message
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
        cases = [_case(element, folder) for element in ET.parse(report).iter("testcase")] if report.is_file() else []
        return done.returncode, cases, _tail(done.stdout, done.stderr)


def _summary(code: int | None, counts: dict[str, int]) -> tuple[str, str]:
    if code is None:
        return "timed_out", f"The tests took longer than {get_settings().test_timeout_seconds} seconds and were stopped."
    if code == 5:
        return "no_tests", "There are no tests to run yet."
    if code == 2:
        if counts["error"]:
            return "error", "Tests could not be collected. Fix the reported code or import errors below, then run tests again."
        return "error", "The test run was interrupted; see its output."
    if code not in (0, 1):  # 3 and 4: pytest itself failed, or was called wrongly
        return "error", "pytest could not run the tests; see its output."
    parts = [f"{n} {'errors' if outcome == 'error' and n > 1 else outcome}" for outcome, n in counts.items() if n]
    return ("passed" if code == 0 else "failed"), ", ".join(parts) or "No tests ran."


def _record_results(ws: Workspace, cases: list[CaseResult]) -> None:
    # Each security test in the state keeps its result from this run. The event log keeps every run's results.
    state = state_service.load(ws)
    for test in state.tests:
        results = [case for case in cases if case.file == test.path]
        passed = sum(case.outcome == "passed" for case in results)
        test.passed = passed == len(results) if results else None
        test.result = f"{passed} of {len(results)} tests passed" if results else "No result in the latest run"
    state_service.save(ws, state)


def run_tests(db: Session, ws: Workspace) -> dict:
    # Clicking Run tests is the human's approval to run them.
    snapshot = workspace.snapshot(ws, "tests")
    code, cases, output = _pytest(workspace.folder(ws).resolve())
    counts = {outcome: sum(case.outcome == outcome for case in cases) for outcome in get_args(Outcome)}
    status, message = _summary(code, counts)

    if ws.mode == "team":
        db.refresh(ws)  # the state may have changed while the tests ran
        _record_results(ws, cases)
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
        },
    )
    db.commit()
    return {"status": status, "message": message, "counts": counts, "tests": cases, "output": output}
