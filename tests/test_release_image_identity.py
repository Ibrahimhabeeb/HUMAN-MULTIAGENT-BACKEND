"""Image identity must survive a classic-to-containerd Docker save/load cycle."""

import hashlib
import io
import json
import subprocess
import tarfile

import pytest

from deploy import deploy_release as release

BACKEND, FRONTEND = "a" * 40, "b" * 40
TAGS = release.tags(BACKEND, FRONTEND)


def saved_images(*, layout="oci", mode="w", platform="amd64", prefix="", change=None):
    files, entries, expected = {}, [], {}
    for service, tag in TAGS.items():
        raw = json.dumps({"os": "linux", "architecture": platform,
                          "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "d" * 64]},
                          "config": {"Labels": {"service": service}}}).encode()
        hexdigest = hashlib.sha256(raw).hexdigest()
        name = f"blobs/sha256/{hexdigest}" if layout == "oci" else f"{hexdigest}.json"
        files[name] = raw
        entries.append({"Config": name, "RepoTags": [prefix + tag], "Layers": []})
        expected[tag] = "sha256:" + hexdigest
    if change:
        change(files, entries)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode=mode) as archive:
        # Manifest before or after config files must both work in streaming mode.
        items = {"manifest.json": json.dumps(entries).encode(), **files}
        for name, raw in items.items():
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
    return buffer.getvalue(), expected


@pytest.mark.parametrize("layout", ["classic", "oci"])
@pytest.mark.parametrize("mode", ["w", "w:gz"])
@pytest.mark.parametrize("prefix", ["", "docker.io/library/"])
def test_portable_identity_is_raw_config_digest_for_both_archive_layouts(layout, mode, prefix):
    data, expected = saved_images(layout=layout, mode=mode, prefix=prefix)
    assert release.archive_configs(io.BytesIO(data), TAGS.values()) == expected


@pytest.mark.parametrize("problem", ["missing-tag", "missing-config", "corrupt-config", "duplicate-tag", "bad-entry", "arm64"])
def test_invalid_or_different_export_is_rejected(problem):
    def change(files, entries):
        if problem == "missing-tag":
            entries.pop()
        elif problem == "missing-config":
            del files[entries[0]["Config"]]
        elif problem == "corrupt-config":
            files[entries[0]["Config"]] += b" "
        elif problem == "duplicate-tag":
            entries.append(entries[0])
        elif problem == "bad-entry":
            entries[0] = None

    data, _ = saved_images(change=change, platform="arm64" if problem == "arm64" else "amd64")
    with pytest.raises(release.DeploymentError):
        release.archive_configs(io.BytesIO(data), TAGS.values())


def test_manifest_records_portable_config_separately_from_store_specific_id(tmp_path, monkeypatch):
    data, configs = saved_images(mode="w:gz")
    (tmp_path / "images.tar.gz").write_bytes(data)
    store_id = "sha256:" + "e" * 64
    monkeypatch.setattr(release.subprocess, "check_output", lambda *args, **kwargs: store_id)
    release.write_manifest(tmp_path, BACKEND, FRONTEND)
    manifest = release.read_manifest(tmp_path, BACKEND, FRONTEND)
    assert manifest["version"] == 2
    for image in manifest["images"].values():
        assert image["id"] == store_id
        assert image["config_digest"] == configs[image["tag"]]
        assert image["id"] != image["config_digest"]


class ExportProcess:
    def __init__(self, data, returncode=0):
        self.stdout = io.BytesIO(data)
        self.returncode = None
        self.result = returncode
        self.killed = False

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        self.returncode = self.result if self.returncode is None else self.returncode
        return self.returncode


def job_with_export(monkeypatch, data, returncode=0):
    job = object.__new__(release.Deployment)
    job.env, job.log = {}, None
    commands = []
    process = ExportProcess(data, returncode)

    def start(args, **kwargs):
        commands.append(args)
        return process

    monkeypatch.setattr(release.subprocess, "Popen", start)
    monkeypatch.setattr(job, "command", lambda *args, **kwargs: "linux amd64")
    return job, process, commands


def test_loaded_config_matches_even_when_docker_store_image_id_differs(monkeypatch):
    data, configs = saved_images()
    job, process, commands = job_with_export(monkeypatch, data)
    manifest = {"images": {name: {"tag": tag, "id": "sha256:" + "f" * 64, "config_digest": configs[tag]}
                           for name, tag in TAGS.items()}}
    job.inspect_images(manifest)
    assert commands == [["docker", "image", "save", *TAGS.values()]]
    assert process.stdout.closed and not process.killed


def test_same_tag_and_platform_cannot_hide_a_different_loaded_config(monkeypatch):
    data, configs = saved_images()
    job, _, _ = job_with_export(monkeypatch, data)
    manifest = {"images": {name: {"tag": tag, "config_digest": configs[tag]} for name, tag in TAGS.items()}}
    manifest["images"]["api"]["config_digest"] = "sha256:" + "f" * 64
    with pytest.raises(release.DeploymentError, match="config digest"):
        job.inspect_images(manifest)


def test_bad_archive_kills_exporter_and_closes_pipe(monkeypatch):
    job, process, _ = job_with_export(monkeypatch, b"not a tar archive" * 100)
    with pytest.raises(release.DeploymentError, match="archive metadata"):
        job.loaded_configs(TAGS.values())
    assert process.killed and process.stdout.closed


def test_complete_tar_with_failed_docker_exit_is_rejected(monkeypatch):
    data, _ = saved_images()
    job, process, _ = job_with_export(monkeypatch, data, returncode=1)
    with pytest.raises(release.DeploymentError, match="export failed"):
        job.loaded_configs(TAGS.values())
    assert process.stdout.closed


def test_export_timeout_is_rejected_and_child_is_reaped(monkeypatch):
    data, _ = saved_images()
    job, process, _ = job_with_export(monkeypatch, data)
    original_wait = process.wait

    def wait(timeout=None):
        if timeout is not None:
            raise subprocess.TimeoutExpired("docker", timeout)
        return original_wait()

    monkeypatch.setattr(process, "wait", wait)
    with pytest.raises(release.DeploymentError, match="timed out"):
        job.loaded_configs(TAGS.values())
    assert process.killed and process.stdout.closed
