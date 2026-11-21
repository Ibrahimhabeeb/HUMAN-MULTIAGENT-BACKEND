import copy
import json
import os
import sys

import pytest

from deploy import deploy_release as release

BACKEND = "a" * 40
FRONTEND = "b" * 40


@pytest.fixture
def bundle(tmp_path):
    folder = tmp_path / "bundle"
    folder.mkdir()
    (folder / "images.tar.gz").write_bytes(b"example image archive")
    manifest = {"version": 2, "backend_sha": BACKEND, "frontend_sha": FRONTEND,
                "archive_sha256": release.digest(folder / "images.tar.gz"),
                "images": {name: {"tag": tag, "id": "sha256:" + "c" * 64, "config_digest": "sha256:" + "d" * 64}
                           for name, tag in release.tags(BACKEND, FRONTEND).items()}}
    (folder / "manifest.json").write_text(json.dumps(manifest))
    return folder, manifest


def test_release_requires_all_four_images_at_the_selected_commits(bundle):
    folder, manifest = bundle
    assert release.read_manifest(folder, BACKEND, FRONTEND) == manifest
    del manifest["images"]["tests"]
    (folder / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(release.DeploymentError, match="all four"):
        release.read_manifest(folder, BACKEND, FRONTEND)


@pytest.mark.parametrize("change", ["archive", "tag", "commit", "image-id", "config-digest", "old-version"])
def test_release_rejects_corruption_and_mixed_versions(bundle, change):
    folder, manifest = bundle
    if change == "archive":
        (folder / "images.tar.gz").write_bytes(b"truncated transfer")
    elif change == "tag":
        manifest["images"]["api"]["tag"] = "unreviewed:latest"
    elif change == "commit":
        manifest["frontend_sha"] = "d" * 40
    elif change == "image-id":
        manifest["images"]["runner"]["id"] = "not-an-image-id"
    elif change == "config-digest":
        manifest["images"]["runner"]["config_digest"] = "not-a-config-digest"
    else:
        manifest["version"] = 1
    (folder / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(release.DeploymentError):
        release.read_manifest(folder, BACKEND, FRONTEND)


@pytest.mark.parametrize("value", ["main", "../outside", "a" * 39, None, "$(echo unsafe)"])
def test_image_names_cannot_be_constructed_from_unvalidated_inputs(value):
    with pytest.raises(release.DeploymentError):
        release.tags(value, FRONTEND)


def test_deployment_cannot_use_an_arbitrary_server_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(release, "ROOT", tmp_path)
    with pytest.raises(release.DeploymentError, match="dedicated incoming"):
        release.Deployment(tmp_path / "backend", BACKEND, FRONTEND)


@pytest.fixture
def deployment(tmp_path, monkeypatch, bundle):
    monkeypatch.setattr(release, "ROOT", tmp_path)
    (tmp_path / "backend").mkdir()
    incoming = tmp_path / "incoming/123-1"
    incoming.mkdir(parents=True)
    folder, manifest = bundle
    for name in ("images.tar.gz", "manifest.json"):
        (incoming / name).write_bytes((folder / name).read_bytes())
    job = release.Deployment(incoming, BACKEND, FRONTEND)
    yield job, manifest


def test_loading_rejects_an_image_with_the_wrong_platform(deployment, monkeypatch):
    job, manifest = deployment
    monkeypatch.setattr(job, "command", lambda *args, **kwargs: "linux arm64")
    with pytest.raises(release.DeploymentError, match="platform"):
        job.inspect_images(manifest)


@pytest.mark.skipif(sys.platform != "linux", reason="Server-side Linux deployment lock")
@pytest.mark.parametrize("failure_stage", ["preflight", "loading-images", "backup", "starting", None])
def test_failures_before_maintenance_leave_app_running_and_later_failures_stop_it(deployment, monkeypatch, failure_stage):
    job, _manifest = deployment
    calls = []

    def fail(stage):
        calls.append(stage)
        if stage == failure_stage:
            raise release.DeploymentError("Test deployment failure")

    def preflight():
        fail("preflight")
        return {}

    def backup(previous):
        job.stage = "backup"
        job.maintenance = True
        fail("backup")

    def activate(value):
        job.stage = "starting"
        fail("starting")
        job.stage = "verified"
        job.state("complete", site="https://study.example.org")

    monkeypatch.setattr(job, "preflight", preflight)
    monkeypatch.setattr(job, "command", lambda *args, **kwargs: fail("loading-images"))
    monkeypatch.setattr(job, "inspect_images", lambda value: None)
    monkeypatch.setattr(job, "backup_data", backup)
    monkeypatch.setattr(job, "activate", activate)
    monkeypatch.setattr(job, "fail_closed", lambda: calls.append("stop") if job.maintenance else None)
    previous_mask = os.umask(0o077)
    try:
        code = job.run()
    finally:
        os.umask(previous_mask)
    state = json.loads((job.folder / "state.json").read_text())
    assert code == (1 if failure_stage else 0)
    assert state["status"] == ("failed" if failure_stage else "complete")
    assert ("stop" in calls) == (failure_stage in ("backup", "starting"))
    if failure_stage in ("preflight", "loading-images", "backup"):
        assert "starting" not in calls


def test_release_settings_do_not_replace_production_credentials(deployment, monkeypatch):
    job, manifest = deployment
    credentials = release.ROOT / "backend/.env.production"
    credentials.write_text("LLM_API_KEY=private-test-value\nPOSTGRES_PASSWORD=private-test-password\n")
    before = credentials.read_bytes()
    seen = []

    def command(args, **kwargs):
        seen.append([str(value) for value in args])
        if "config" in args and "json" in args:
            return json.dumps({"services": {"frontend": {"environment": {"DOMAIN": "study.example.org"}}}})
        return ""

    class Response:
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, limit):
            return self.body

    monkeypatch.setattr(job, "command", command)
    monkeypatch.setattr(release, "urlopen", lambda url, **kwargs: Response(
        b'{"status":"ready"}' if url.endswith("/api/ready") else b"<!doctype html><html></html>"))
    job.activate(copy.deepcopy(manifest))
    assert credentials.read_bytes() == before
    settings = (release.ROOT / "backend/.release.env").read_text()
    assert "private-test" not in settings
    assert f"API_IMAGE=secure-coding-room-api:{BACKEND}" in settings
    start = next(args for args in seen if "up" in args)
    assert "--no-build" in start and start[start.index("--pull") + 1] == "never"
    assert json.loads((job.folder / "state.json").read_text())["status"] == "complete"
