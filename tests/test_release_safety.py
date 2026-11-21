"""Exercise release safety methods with real files and mocked process boundaries."""

import io
import json
import os
import subprocess
import sys
import time

import pytest

from deploy import deploy_release as release

BACKEND = "a" * 40
FRONTEND = "b" * 40
CONTAINERS = {"api": "a" * 12, "runner": "b" * 12, "frontend": "c" * 12}
OLD_IMAGE = "sha256:" + "d" * 64


@pytest.fixture
def safety_job(tmp_path, monkeypatch):
    monkeypatch.setattr(release, "ROOT", tmp_path)
    backend = tmp_path / "backend"
    (backend / "deploy").mkdir(parents=True)
    for name in ("compose.yaml", "deploy/manage.sh", ".release.env"):
        (backend / name).write_text("previous configuration\n", encoding="utf-8")
    folder = tmp_path / "incoming/123-1"
    folder.mkdir(parents=True)
    archive = folder / "images.tar.gz"
    archive.write_bytes(b"offline release fixture")
    manifest = {"version": 2, "backend_sha": BACKEND, "frontend_sha": FRONTEND,
                "archive_sha256": release.digest(archive),
                "images": {key: {"tag": tag, "id": OLD_IMAGE, "config_digest": OLD_IMAGE}
                           for key, tag in release.tags(BACKEND, FRONTEND).items()}}
    (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    # Avoid inheriting or examining the machine's production/CI environment.
    job = object.__new__(release.Deployment)
    job.folder, job.backend, job.frontend = folder, BACKEND, FRONTEND
    job.stage, job.maintenance, job.log = "preflight", False, io.BytesIO()
    job.backup = backend / "backups/release-123-1"
    job.env = {"GIT_TERMINAL_PROMPT": "0"}
    previous_mask = os.umask(0o077)
    try:
        yield job
    finally:
        os.umask(previous_mask)


def previous_release():
    return {"backend": "e" * 40, "human-agent-frontend": "f" * 40,
            "images": dict.fromkeys(CONTAINERS, OLD_IMAGE), "tests": OLD_IMAGE}


def process_boundary(monkeypatch, *, fail=None, failed_stops=()):
    """Replace only external commands; preserve method ordering, files and errors."""
    calls = []

    def execute(args, **kwargs):
        args = [str(arg) for arg in args]
        calls.append(args)
        phase = next((name for name in ("pg_dump", "tar", "gzip", "pg_restore") if name in args), None)
        if phase == fail and phase is not None:
            raise subprocess.CalledProcessError(1, args)
        if args[:2] == ["docker", "ps"]:
            service = next((name for name in CONTAINERS
                            if f"label=com.docker.compose.service={name}" in args), None)
            text = CONTAINERS[service] if service else ""
        elif args[:2] == ["docker", "stop"]:
            if any(CONTAINERS[name] in args for name in failed_stops):
                raise subprocess.CalledProcessError(1, args)
            text = ""
        elif args[:3] == ["docker", "image", "inspect"]:
            text = "linux amd64"
        elif "psql" in args:
            text = "previous-revision"
        else:
            text = ""
        if phase in ("pg_dump", "tar"):
            kwargs["stdout"].write(b"offline backup contents")
        if phase == "pg_restore":
            assert kwargs["stdin"].read() == b"offline backup contents"
        return subprocess.CompletedProcess(args, 0, stdout=text)

    monkeypatch.setattr(release.subprocess, "run", execute)
    monkeypatch.setattr(release.Deployment, "loaded_configs", lambda self, selected: dict.fromkeys(selected, OLD_IMAGE))
    return calls


def assert_no_activation(calls):
    assert not any("checkout" in args or "up" in args or release.SMOKE in args for args in calls)
    assert not any(args[:2] == ["docker", "tag"] and args[-1] == "secure-coding-room-tests:local"
                   for args in calls)


@pytest.mark.parametrize("failure", ["pg_dump", "tar", "gzip", "pg_restore"])
def test_real_backup_failure_never_marks_backup_complete(safety_job, monkeypatch, failure):
    calls = process_boundary(monkeypatch, fail=failure)
    with pytest.raises(release.DeploymentError):
        safety_job.backup_data(previous_release())
    assert safety_job.maintenance
    assert not (safety_job.backup / "BACKUP_COMPLETE").exists()
    assert_no_activation(calls)
    assert any(failure in args for args in calls)


def test_real_backup_records_metadata_and_validates_before_completion(safety_job, monkeypatch):
    calls = process_boundary(monkeypatch)
    previous = previous_release()
    safety_job.backup_data(previous)
    assert (safety_job.backup / "BACKUP_COMPLETE").is_file()
    saved = json.loads((safety_job.backup / "previous.json").read_text(encoding="utf-8"))
    assert saved["database_revision"] == "previous-revision"
    assert saved["backend"] == "e" * 40
    assert saved["tests"] == OLD_IMAGE
    assert set(saved["rollback_images"]) == {*CONTAINERS, "tests"}
    for name in ("compose.yaml", "deploy/manage.sh", ".release.env"):
        assert (safety_job.backup / name).read_bytes() == (release.ROOT / "backend" / name).read_bytes()
    phases = [next(name for name in ("pg_dump", "tar", "gzip", "pg_restore") if name in args)
              for args in calls if any(name in args for name in ("pg_dump", "tar", "gzip", "pg_restore"))]
    assert phases == ["pg_dump", "tar", "gzip", "pg_restore"]
    assert "--list" in calls[-1]
    assert_no_activation(calls)


@pytest.mark.skipif(sys.platform != "linux", reason="Real server-side flock")
@pytest.mark.parametrize("failure", ["pg_dump", "tar", "gzip", "pg_restore"])
def test_run_with_real_failed_backup_never_starts_new_api(safety_job, monkeypatch, failure):
    calls = process_boundary(monkeypatch, fail=failure)
    monkeypatch.setattr(safety_job, "preflight", previous_release)
    assert safety_job.run() == 1
    state = json.loads((safety_job.folder / "state.json").read_text(encoding="utf-8"))
    assert state["status"] == "failed"
    assert state["stage"] == "backup"
    assert state["shutdown_failures"] == []
    assert not (safety_job.backup / "BACKUP_COMPLETE").exists()
    assert not (release.ROOT / "backend/.release.env").read_text().startswith("API_IMAGE=")
    assert_no_activation(calls)
    assert len([args for args in calls if args[:2] == ["docker", "stop"]]) == 3


def test_fail_closed_before_maintenance_does_nothing(safety_job, monkeypatch):
    calls = process_boundary(monkeypatch)
    assert safety_job.fail_closed() == []
    assert calls == []


@pytest.mark.parametrize("failed_stops", [(), ("api",), ("runner", "frontend")])
def test_real_fail_closed_stops_only_app_services_and_reports_failures(safety_job, monkeypatch, failed_stops):
    calls = process_boundary(monkeypatch, failed_stops=failed_stops)
    safety_job.maintenance = True
    assert safety_job.fail_closed() == list(failed_stops)
    expected = []
    for service, identifier in CONTAINERS.items():
        expected.extend([
            ["docker", "ps", "--quiet", "--filter", "label=com.docker.compose.project=secure-coding-room",
             "--filter", f"label=com.docker.compose.service={service}"],
            ["docker", "stop", "--time", "5", identifier],
        ])
    assert calls == expected
    assert not any("label=com.docker.compose.service=db" in args for args in calls)


@pytest.mark.skipif(sys.platform != "linux", reason="Real server-side flock")
def test_run_records_real_shutdown_failure_after_failed_backup(safety_job, monkeypatch):
    calls = process_boundary(monkeypatch, fail="pg_dump", failed_stops=("api",))
    monkeypatch.setattr(safety_job, "preflight", previous_release)
    assert safety_job.run() == 1
    state = json.loads((safety_job.folder / "state.json").read_text(encoding="utf-8"))
    assert state["status"] == "failed"
    assert state["shutdown_failures"] == ["api"]
    assert state["stage"] == "backup"
    assert_no_activation(calls)


@pytest.mark.skipif(sys.platform != "linux", reason="Real interprocess flock contention")
def test_another_process_holding_lock_prevents_any_deployment_work(safety_job, monkeypatch):
    lock = release.ROOT / "backend/.deployment.lock"
    ready = release.ROOT / "lock-ready"
    child_code = (
        "import fcntl,pathlib,sys; "
        "lock=open(sys.argv[1], 'a'); fcntl.flock(lock, fcntl.LOCK_EX); "
        "pathlib.Path(sys.argv[2]).write_text('locked'); sys.stdin.read(1)"
    )
    child = subprocess.Popen([sys.executable, "-I", "-B", "-c", child_code, str(lock), str(ready)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 5
        while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert ready.is_file(), "Lock-holder subprocess did not become ready"
        calls = process_boundary(monkeypatch)

        def unexpected_preflight():
            pytest.fail("Contending deployment must not reach preflight")

        monkeypatch.setattr(safety_job, "preflight", unexpected_preflight)
        assert safety_job.run() == 1
        state = json.loads((safety_job.folder / "state.json").read_text(encoding="utf-8"))
        assert state["status"] == "failed"
        assert "already running" in state["error"]
        assert calls == []
        assert not safety_job.backup.exists()
        assert not safety_job.maintenance
    finally:
        try:
            child.communicate(input="x", timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.communicate(timeout=5)
