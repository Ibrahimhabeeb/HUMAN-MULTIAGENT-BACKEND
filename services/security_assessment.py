"""Private assessment of submitted snapshots, outside participant workspaces and agent context."""

import hashlib
import json
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from models import Event, Workspace
from services import runner
from services.events import log_event

SUITES = Path(__file__).resolve().parents[1] / "assessment" / "security_tests"
EVENT_TYPE = "security_tests_run"
OUTCOMES = ("passed", "failed", "error", "skipped")


def evaluate_snapshot(snapshot: Path, task_id: str) -> dict:
    manifest = (SUITES / "manifest.json").read_bytes()
    catalogue = json.loads(manifest)
    spec = catalogue["tasks"][task_id]
    suite = (SUITES / spec["file"]).read_bytes()
    result = {
        "suite_version": catalogue["version"],
        "suite_sha256": hashlib.sha256(manifest + suite).hexdigest(),
        "expected": spec["expected"],
        "counts": dict.fromkeys(OUTCOMES, 0),
        "tests": [],
        "status": "error",
        "all_passed": False,
        "output": "",
    }
    try:
        with tempfile.TemporaryDirectory(prefix="security-assessment-", ignore_cleanup_errors=True) as scratch:
            folder = Path(scratch)
            # Only application code is copied. Participant tests and pytest configuration cannot replace this suite.
            source = snapshot / "app"
            if source.is_symlink() or any(path.is_symlink() for path in source.rglob("*")):
                raise ValueError("Assessment application files must not be symbolic links")
            shutil.copytree(source, folder / "app", ignore=shutil.ignore_patterns("__pycache__"))
            (folder / "tests").mkdir()
            (folder / "tests" / "test_security.py").write_bytes(suite)
            code, cases, output = runner._pytest(folder.resolve())
        result["counts"] = {outcome: sum(case.outcome == outcome for case in cases) for outcome in OUTCOMES}
        result["tests"] = [{"name": case.name, "outcome": case.outcome} for case in cases]
        result["status"] = runner._summary(code, result["counts"])[0]
        result["output"] = output
        if result["status"] == "passed" and result["counts"]["passed"] != result["expected"]:
            result["status"] = "error"
            result["output"] = "The collected security-test count did not match the assessment manifest."
        result["all_passed"] = result["status"] == "passed" and result["counts"]["passed"] == result["expected"]
    except (OSError, ValueError, ET.ParseError, subprocess.SubprocessError) as error:
        # A failed assessment is retained for inspection and must not prevent the participant completing their part.
        result["output"] = f"{type(error).__name__}: {error}"[:runner.MAX_OUTPUT_CHARS]
    result["not_run"] = max(0, result["expected"] - sum(result["counts"].values()))
    return result


def assess(db: Session, ws: Workspace, snapshot: Path, *, retry_errors=False) -> dict:
    previous = db.scalar(select(Event).where(
        Event.participant_code == ws.participant_code, Event.mode == ws.mode, Event.type == EVENT_TYPE,
    ).order_by(Event.id.desc()))
    if (previous is not None and previous.detail.get("snapshot") == snapshot.name
            and not (retry_errors and previous.detail.get("status") in {"error", "timed_out"})):
        return previous.detail
    try:
        result = evaluate_snapshot(snapshot, ws.task_id)
    except (OSError, ValueError, KeyError, ET.ParseError) as error:
        result = {
            "suite_version": "unavailable", "suite_sha256": None, "expected": 0,
            "counts": dict.fromkeys(OUTCOMES, 0), "tests": [], "status": "error",
            "all_passed": False, "not_run": 0, "output": f"{type(error).__name__}: {error}"[:4000],
        }
    detail = result | {"workspace_id": ws.id, "task_id": ws.task_id, "part": ws.part, "snapshot": snapshot.name}
    log_event(db, ws.participant_code, EVENT_TYPE, actor="system", mode=ws.mode, detail=detail)
    db.commit()
    return detail
