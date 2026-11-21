"""Package metadata and a server-side release job. Uses only the Python standard library."""

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import threading
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path("/opt/secure-coding-room")
REPOSITORIES = {
    "backend": "Ibrahimhabeeb/HUMAN-MULTIAGENT-BACKEND",
    "human-agent-frontend": "Ibrahimhabeeb/HUMAN-MULTIAGENT-FRONTEND",
}
IMAGE_KEYS = {"api": "API_IMAGE", "runner": "RUNNER_IMAGE", "frontend": "FRONTEND_IMAGE"}
SHA = re.compile(r"[0-9a-f]{40}")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
SMOKE = """from pathlib import Path
from tempfile import TemporaryDirectory
from services.sandbox import run
with TemporaryDirectory() as temp:
    folder = Path(temp)
    (folder / 'tests').mkdir()
    (folder / 'tests/test_smoke.py').write_text('def test_smoke():\\n    assert 2 + 2 == 4\\n')
    assert run(folder)['code'] == 0, 'Isolated test runner smoke check failed'
print('Isolated test runner smoke check passed')
"""


class DeploymentError(RuntimeError):
    pass


def tags(backend, frontend):
    if not isinstance(backend, str) or not isinstance(frontend, str) or not SHA.fullmatch(backend) or not SHA.fullmatch(frontend):
        raise DeploymentError("Release commits must be full hexadecimal Git SHAs")
    return {
        "api": f"secure-coding-room-api:{backend}",
        "runner": f"secure-coding-room-runner:{backend}",
        "tests": f"secure-coding-room-tests:{backend}",
        "frontend": f"secure-coding-room-frontend:{frontend}",
    }


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def atomic_text(path, value):
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def archive_configs(stream, expected_tags):
    """Read portable config digests without extracting layers or buffering the archive.

    Docker's classic store calls the config digest an image ID; containerd calls a
    manifest/index digest an image ID instead. The saved config bytes survive both.
    """
    configs, entries = {}, None
    try:
        with tarfile.open(fileobj=stream, mode="r|*") as archive:
            for member in archive:
                name = member.name.removeprefix("./")
                if not member.isfile():
                    continue
                if name == "manifest.json":
                    if entries is not None or member.size > 1024 * 1024:
                        raise DeploymentError("Invalid Docker archive manifest")
                    entries = json.loads(archive.extractfile(member).read())
                elif re.fullmatch(r"(?:blobs/sha256/[0-9a-f]{64}|[0-9a-f]{64}\.json)", name):
                    # Small layers also use blob names. Only retain actual image configs.
                    if member.size > 1024 * 1024:
                        continue
                    raw = archive.extractfile(member).read()
                    try:
                        config = json.loads(raw)
                    except (ValueError, UnicodeError):
                        continue
                    if not isinstance(config, dict) or not {"os", "architecture", "rootfs"} <= config.keys():
                        continue
                    config_digest = hashlib.sha256(raw).hexdigest()
                    if config_digest != name.removeprefix("blobs/sha256/").removesuffix(".json"):
                        raise DeploymentError("Docker archive config checksum does not match")
                    if name in configs or len(configs) >= 64:
                        raise DeploymentError("Duplicate or excessive Docker image configs")
                    configs[name] = ("sha256:" + config_digest, config["os"], config["architecture"])
    except (tarfile.TarError, ValueError, UnicodeError, OSError) as error:
        raise DeploymentError("Cannot read Docker image archive metadata") from error
    if not isinstance(entries, list):
        raise DeploymentError("Docker archive manifest is missing or invalid")
    selected = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("RepoTags"), list):
            raise DeploymentError("Invalid Docker archive image entry")
        for tag in entry["RepoTags"]:
            if not isinstance(tag, str):
                raise DeploymentError("Invalid Docker archive image tag")
            tag = tag.removeprefix("docker.io/library/")
            if tag not in expected_tags:
                continue
            config = configs.get(str(entry.get("Config", "")).removeprefix("./"))
            if config is None or config[1:] != ("linux", "amd64"):
                raise DeploymentError("Docker image config is missing or has the wrong platform")
            if tag in selected:
                raise DeploymentError("Duplicate selected image tag in Docker archive")
            selected[tag] = config[0]
    if set(selected) != set(expected_tags):
        raise DeploymentError("Docker archive does not contain every selected image")
    return selected


def write_manifest(folder, backend, frontend):
    selected_tags = tags(backend, frontend)
    with (folder / "images.tar.gz").open("rb") as stream:
        configs = archive_configs(stream, selected_tags.values())
    images = {}
    for service, tag in selected_tags.items():
        image_id = subprocess.check_output(["docker", "image", "inspect", "--format", "{{.Id}}", tag], text=True).strip()
        if not IMAGE_ID.fullmatch(image_id):
            raise DeploymentError("Docker returned an invalid image ID")
        images[service] = {"tag": tag, "id": image_id, "config_digest": configs[tag]}
    manifest = {"version": 2, "backend_sha": backend, "frontend_sha": frontend,
                "images": images, "archive_sha256": digest(folder / "images.tar.gz")}
    atomic_text(folder / "manifest.json", json.dumps(manifest, indent=2) + "\n")


def read_manifest(folder, backend, frontend):
    expected = tags(backend, frontend)
    path = folder / "manifest.json"
    if path.stat().st_size > 65536:
        raise DeploymentError("Release manifest exceeds its size limit")
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("version") != 2 or value.get("backend_sha") != backend or value.get("frontend_sha") != frontend:
        raise DeploymentError("Release manifest does not match the selected commits")
    images = value.get("images", {})
    if set(images) != set(expected):
        raise DeploymentError("A release must include all four images")
    for name, tag in expected.items():
        image = images[name]
        if (image.get("tag") != tag or not IMAGE_ID.fullmatch(image.get("id", ""))
                or not IMAGE_ID.fullmatch(image.get("config_digest", ""))):
            raise DeploymentError("Unexpected image in release manifest")
    if value.get("archive_sha256") != digest(folder / "images.tar.gz"):
        raise DeploymentError("Image archive checksum does not match")
    return value


class Deployment:
    def __init__(self, folder, backend, frontend):
        self.folder = folder.resolve()
        if self.folder.parent != (ROOT / "incoming").resolve() or not re.fullmatch(r"[0-9]+-[0-9]+", self.folder.name):
            raise DeploymentError("Release must be in its dedicated incoming directory")
        self.backend = backend
        self.frontend = frontend
        self.stage = "preflight"
        self.maintenance = False
        self.log = None
        self.backup = ROOT / "backend/backups" / ("release-" + self.folder.name)
        self.env = {key: value for key, value in os.environ.items() if key not in {*IMAGE_KEYS.values(), "BACKEND_SHA", "FRONTEND_SHA"}}
        self.env["GIT_TERMINAL_PROMPT"] = "0"

    def state(self, status="running", **details):
        value = {"status": status, "stage": self.stage, "backend_sha": self.backend,
                 "frontend_sha": self.frontend, "backup": str(self.backup), **details}
        atomic_text(self.folder / "state.json", json.dumps(value, indent=2) + "\n")
        print(f"Release {self.folder.name}: {self.stage} ({status})", flush=True)

    def command(self, args, *, output=None, private=False, timeout=300):
        try:
            done = subprocess.run([str(arg) for arg in args], check=True, env=self.env, timeout=timeout,
                                  stdout=output if output is not None else subprocess.PIPE,
                                  stderr=self.log, text=output is None)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as error:
            raise DeploymentError(f"{Path(str(args[0])).name} failed during {self.stage}; inspect deployment.log") from error
        if output is not None:
            return ""
        if not private:
            self.log.write(done.stdout.encode())
            self.log.flush()
        return done.stdout.strip()

    def compose(self, *args, **kwargs):
        return self.command(["bash", ROOT / "backend/deploy/manage.sh", *args], **kwargs)

    def inspect_images(self, manifest):
        for image in manifest["images"].values():
            details = self.command(["docker", "image", "inspect", "--format", "{{.Os}} {{.Architecture}}", image["tag"]])
            if details != "linux amd64":
                raise DeploymentError("Loaded image platform does not match the release")
        expected = {image["tag"]: image["config_digest"] for image in manifest["images"].values()}
        if self.loaded_configs(expected) != expected:
            raise DeploymentError("Loaded image config digest does not match the release")

    def loaded_configs(self, selected_tags):
        # Stream all four exports together: shared layers are emitted once and no
        # second archive is written to the small VPS disk or held in RAM.
        try:
            process = subprocess.Popen(["docker", "image", "save", *selected_tags],
                                       stdout=subprocess.PIPE, stderr=self.log, env=self.env)
        except OSError as error:
            raise DeploymentError("Cannot export loaded images for verification") from error
        deadline = threading.Timer(300, process.kill)
        deadline.start()
        try:
            configs = archive_configs(process.stdout, selected_tags)
            while process.stdout.read(1024 * 1024):
                pass  # Drain tar padding before waiting, so the writer cannot block.
            if process.wait(timeout=10) != 0:
                raise DeploymentError("Loaded image export failed; inspect deployment.log")
            return configs
        except subprocess.TimeoutExpired as error:
            raise DeploymentError("Loaded image export timed out") from error
        finally:
            deadline.cancel()
            if process.poll() is None:
                process.kill()
            process.stdout.close()
            process.wait()

    def preflight(self):
        if sys.platform != "linux" or os.geteuid() != 0 or platform.machine() != "x86_64":
            raise DeploymentError("Deployment requires the root account on the x86-64 Linux study VPS")
        settings = ROOT / "backend/.env.production"
        if not settings.is_file() or settings.stat().st_mode & 0o077:
            raise DeploymentError("The server's .env.production must exist with private permissions (chmod 600)")
        self.compose("config", "--quiet")
        previous = {"images": {}}
        for directory, repository in REPOSITORIES.items():
            target = self.backend if directory == "backend" else self.frontend
            checkout = ROOT / directory
            if self.command(["git", "-C", checkout, "status", "--porcelain", "--untracked-files=no"]):
                raise DeploymentError(f"Tracked files have local changes in {directory}; deployment stopped")
            remote = self.command(["git", "-C", checkout, "remote", "get-url", "origin"])
            if remote.casefold().removesuffix(".git") != f"https://github.com/{repository}".casefold():
                raise DeploymentError(f"Unexpected Git remote for {directory}")
            self.command(["git", "-C", checkout, "fetch", "origin", "main"])
            self.command(["git", "-C", checkout, "merge-base", "--is-ancestor", target, "origin/main"])
            previous[directory] = self.command(["git", "-C", checkout, "rev-parse", "HEAD"])
        reviewed_helper = self.command(["git", "-C", ROOT / "backend", "show", f"{self.backend}:deploy/deploy_release.py"], private=True)
        if reviewed_helper != Path(__file__).read_text(encoding="utf-8").strip():
            raise DeploymentError("Uploaded deployment helper does not match the selected backend commit")
        for service in IMAGE_KEYS:
            container = self.compose("ps", "--all", "--quiet", service)
            if container:
                previous["images"][service] = self.command(["docker", "inspect", "--format", "{{.Image}}", container])
        if not self.compose("ps", "--quiet", "db"):
            raise DeploymentError("Start the production database before using automated releases")
        previous["tests"] = self.command(["docker", "image", "inspect", "--format", "{{.Id}}", "secure-coding-room-tests:local"])
        return previous

    def backup_data(self, previous):
        self.backup.mkdir(mode=0o700, parents=True)
        self.stage = "backup"
        self.state()
        self.maintenance = True
        self.compose("stop", "frontend", "api", "runner")
        previous["rollback_images"] = {}
        for service, image_id in {**previous["images"], "tests": previous["tests"]}.items():
            saved_tag = f"secure-coding-room-{service}:before-{self.folder.name}"
            self.command(["docker", "tag", image_id, saved_tag])
            previous["rollback_images"][service] = saved_tag
        # Only the broker's disposable jobs are removed; study data stay in named volumes.
        jobs = self.command(["docker", "ps", "--all", "--quiet", "--filter", "label=secure-coding-room.test-job=true"]).split()
        if jobs:
            if any(not re.fullmatch(r"[0-9a-f]{12,64}", item) for item in jobs):
                raise DeploymentError("Unexpected disposable test container ID")
            self.command(["docker", "rm", "--force", *jobs])
        previous["database_revision"] = self.compose("exec", "-T", "db", "psql", "-U", "study", "-d", "study",
                                                     "-Atc", "SELECT version_num FROM alembic_version")
        atomic_text(self.backup / "previous.json", json.dumps(previous, indent=2) + "\n")
        for name in ("compose.yaml", "deploy/manage.sh", ".release.env"):
            source = ROOT / "backend" / name
            if source.exists():
                destination = self.backup / name
                destination.parent.mkdir(exist_ok=True)
                shutil.copyfile(source, destination)
        with (self.backup / "database.dump").open("wb") as stream:
            self.compose("exec", "-T", "db", "pg_dump", "-U", "study", "-d", "study", "-Fc", output=stream)
        with (self.backup / "study-files.tar.gz").open("wb") as stream:
            self.compose("run", "--rm", "--no-deps", "-T", "--pull", "never", "--entrypoint", "tar", "api",
                         "-C", "/data", "-czf", "-", ".", output=stream)
        self.command(["gzip", "--test", self.backup / "study-files.tar.gz"])
        with (self.backup / "database.dump").open("rb") as stream:
            try:
                subprocess.run(["bash", str(ROOT / "backend/deploy/manage.sh"), "exec", "-T", "db", "pg_restore", "--list"],
                               stdin=stream, stdout=subprocess.DEVNULL, stderr=self.log, env=self.env, check=True, timeout=120)
            except (subprocess.SubprocessError, OSError) as error:
                raise DeploymentError("Database backup validation failed") from error
        (self.backup / "BACKUP_COMPLETE").touch()

    def activate(self, manifest):
        self.stage = "starting"
        self.state()
        self.command(["git", "-C", ROOT / "backend", "checkout", "--detach", self.backend])
        self.command(["git", "-C", ROOT / "human-agent-frontend", "checkout", "--detach", self.frontend])
        values = {key: manifest["images"][service]["tag"] for service, key in IMAGE_KEYS.items()}
        values.update(BACKEND_SHA=self.backend, FRONTEND_SHA=self.frontend)
        atomic_text(ROOT / "backend/.release.env", "".join(f"{key}={value}\n" for key, value in values.items()))
        self.command(["docker", "tag", manifest["images"]["tests"]["tag"], "secure-coding-room-tests:local"])
        self.compose("config", "--quiet")
        self.compose("up", "-d", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "180",
                     "db", "runner", "api", timeout=240)
        self.compose("exec", "-T", "api", "python", "-c", SMOKE, timeout=120)
        self.compose("up", "-d", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "180",
                     "frontend", timeout=240)
        config = json.loads(self.compose("config", "--format", "json", private=True))
        domain = config["services"]["frontend"]["environment"]["DOMAIN"]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]", domain):
            raise DeploymentError("DOMAIN must be a hostname")
        site = "https://" + domain
        self.stage = "https-check"
        self.state()
        for attempt in range(12):
            try:
                with urlopen(site + "/api/ready", timeout=10) as response:
                    if json.loads(response.read(4096)) != {"status": "ready"}:
                        raise DeploymentError("Public readiness response was unexpected")
                with urlopen(site + "/", timeout=10) as response:
                    if b"<!doctype html" not in response.read(4096).lower():
                        raise DeploymentError("Frontend did not return the built application")
                self.stage = "verified"
                self.state("complete", site=site)
                return
            except (URLError, OSError, ValueError, DeploymentError):
                if attempt == 11:
                    raise DeploymentError("HTTPS verification failed; check DNS, certificates and ports 80/443") from None
                time.sleep(5)

    def fail_closed(self):
        if not self.maintenance:
            return []
        failures = []
        # Direct labels still work if a new Compose file itself failed validation.
        for service in IMAGE_KEYS:
            try:
                ids = self.command(["docker", "ps", "--quiet", "--filter", "label=com.docker.compose.project=secure-coding-room",
                                    "--filter", f"label=com.docker.compose.service={service}"]).split()
                if ids and all(re.fullmatch(r"[0-9a-f]{12,64}", item) for item in ids):
                    self.command(["docker", "stop", "--time", "5", *ids], timeout=15)
            except DeploymentError:
                failures.append(service)
        return failures

    def run(self):
        import fcntl

        os.umask(0o077)
        with (ROOT / "backend/.deployment.lock").open("a") as lock, (self.folder / "deployment.log").open("ab") as log:
            self.log = log
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                self.state("failed", error="Another server deployment is already running")
                return 1
            try:
                self.state()
                manifest = read_manifest(self.folder, self.backend, self.frontend)
                previous = self.preflight()
                self.stage = "loading-images"
                self.state()
                self.command(["docker", "load", "--input", self.folder / "images.tar.gz"], timeout=600)
                self.inspect_images(manifest)
                self.backup_data(previous)
                self.activate(manifest)
                return 0
            except Exception as error:  # noqa: BLE001 -- an unexpected error must also keep the application stopped
                shutdown_failures = self.fail_closed()
                # Do not print environment values or subprocess output into GitHub logs.
                self.state("failed", error=str(error) if isinstance(error, DeploymentError) else type(error).__name__,
                           shutdown_failures=shutdown_failures)
                return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("manifest", "deploy", "status", "site"))
    parser.add_argument("folder", type=Path)
    parser.add_argument("backend", nargs="?")
    parser.add_argument("frontend", nargs="?")
    args = parser.parse_args()
    if args.command in ("status", "site"):
        path = args.folder / "state.json"
        state = json.loads(path.read_text()) if path.exists() else {}
        print(state.get("status", "starting") if args.command == "status" else state.get("site", ""))
        return 0
    if args.command == "manifest":
        write_manifest(args.folder, args.backend, args.frontend)
        return 0

    def interrupted(signum, frame):
        raise DeploymentError("Deployment was interrupted; inspect its recorded stage before retrying")

    for event in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(event, interrupted)
    return Deployment(args.folder, args.backend, args.frontend).run()


if __name__ == "__main__":
    raise SystemExit(main())
