"""Trusted, dependency-free test-container entrypoint and bounded wire helpers."""

import base64
import binascii
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

MAX_REQUEST = 4 * 1024 * 1024
MAX_DECODED = 2 * 1024 * 1024
MAX_FILES = 1000
MAX_REPORT = 512 * 1024
MAX_RESPONSE = 1024 * 1024
MAX_OUTPUT = 4000
TEST_TIMEOUT = 60
WORKSPACE = Path("/workspace")
REPORT_DIR = Path("/report")
TEMP_DIR = Path("/tmp")


class InvalidPayload(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _no_constant(value):
    raise ValueError("Non-finite JSON value")


def load_json(body):
    return json.loads(body.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_no_constant)


def clean_path(path):
    if not isinstance(path, str) or not 1 <= len(path) <= 300:
        raise InvalidPayload("File paths must contain 1-300 characters")
    if path.startswith("/") or any(c in "\\:" or ord(c) < 32 or ord(c) == 127 for c in path):
        raise InvalidPayload("File paths must be relative POSIX paths")
    if any(part in ("", ".", "..") for part in path.split("/")):
        raise InvalidPayload("Invalid file path segment")
    try:
        path.encode("utf-8")
    except UnicodeError as error:
        raise InvalidPayload("File paths must be valid UTF-8") from error
    return path


def decode_files(body):
    if len(body) > MAX_REQUEST:
        raise InvalidPayload("Request exceeds 4 MiB", 413)
    try:
        document = load_json(body)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise InvalidPayload("Invalid JSON request") from error
    if not isinstance(document, dict) or set(document) != {"files"} or not isinstance(document["files"], list):
        raise InvalidPayload("Expected only a files array")
    if len(document["files"]) > MAX_FILES:
        raise InvalidPayload("At most 1000 files are allowed", 413)
    files = []
    paths = set()
    total = 0
    for item in document["files"]:
        if not isinstance(item, dict) or set(item) != {"path", "content"}:
            raise InvalidPayload("Files must contain only path and base64 content")
        path = clean_path(item["path"])
        if path in paths:
            raise InvalidPayload("Duplicate file path")
        encoded = item["content"]
        if not isinstance(encoded, str):
            raise InvalidPayload("File content must be base64 text")
        if len(encoded) > 4 * ((MAX_DECODED - total + 2) // 3):
            raise InvalidPayload("Decoded files exceed 2 MiB", 413)
        try:
            content = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as error:
            raise InvalidPayload("Invalid base64 file content") from error
        total += len(content)
        if total > MAX_DECODED:
            raise InvalidPayload("Decoded files exceed 2 MiB", 413)
        paths.add(path)
        files.append((path, content))
    for path in paths:
        if any(parent.as_posix() in paths for parent in PurePosixPath(path).parents if parent != PurePosixPath(".")):
            raise InvalidPayload("A file path conflicts with a parent file")
    return files


def result(code, report="", output=""):
    return {"code": code, "report": report, "output": output[-MAX_OUTPUT:]}


def encode_result(value):
    body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(body) + 1 > MAX_RESPONSE:
        body = json.dumps(result(3, output="Test report exceeds the response limit.")).encode("utf-8")
    return body


def normalise_report(report, workspace=WORKSPACE):
    if len(report.encode("utf-8")) > MAX_REPORT:
        raise ValueError("JUnit report exceeds the size limit")
    if "<!DOCTYPE" in report.upper() or "<!ENTITY" in report.upper():
        raise ValueError("JUnit declarations are not allowed")
    root = ET.fromstring(report)
    if root.tag not in {"testsuites", "testsuite"}:
        raise ValueError("Invalid JUnit root")
    prefixes = {str(workspace).replace("\\", "/").rstrip("/") + "/", "/workspace/"}
    for node in root.iter():
        if "file" in node.attrib:
            path = node.attrib["file"].replace("\\", "/")
            for prefix in prefixes:
                if path.startswith(prefix):
                    path = path[len(prefix):]
                    break
            try:
                node.set("file", clean_path(path))
            except InvalidPayload:
                node.set("file", "")
        for attribute in ("text", "tail"):
            text = getattr(node, attribute)
            if text:
                for prefix in prefixes:
                    text = text.replace(prefix, "")
                setattr(node, attribute, text)
    return ET.tostring(root, encoding="unicode")


@dataclass
class Captured:
    code: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    overflow: bool = False


def _kill_group(process):
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif process.poll() is None:
        process.kill()


def capture(command, *, timeout, env, cwd=None, body=b"", limit=MAX_RESPONSE):
    """Drain pipes into capped spools, including when a child writes without limit."""
    overflow = threading.Event()
    with tempfile.TemporaryFile() as source, tempfile.SpooledTemporaryFile(max_size=65536) as stdout, \
            tempfile.SpooledTemporaryFile(max_size=65536) as stderr:
        source.write(body)
        source.seek(0)
        process = subprocess.Popen(
            command, stdin=source, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=cwd, env=env, start_new_session=os.name == "posix", close_fds=True,
        )

        def drain(pipe, spool):
            remaining = limit
            try:
                while chunk := pipe.read(8192):
                    if len(chunk) > remaining:
                        spool.write(chunk[:remaining])
                        overflow.set()
                        break
                    spool.write(chunk)
                    remaining -= len(chunk)
            except (OSError, ValueError):
                overflow.set()
            finally:
                pipe.close()

        readers = [threading.Thread(target=drain, args=(pipe, spool), daemon=True)
                   for pipe, spool in ((process.stdout, stdout), (process.stderr, stderr))]
        for reader in readers:
            reader.start()
        deadline = time.monotonic() + timeout
        timed_out = False
        try:
            while process.poll() is None:
                if overflow.is_set():
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                time.sleep(0.01)
        finally:
            # Also clear descendants holding pipes open after the direct child exits.
            _kill_group(process)
            process.wait(timeout=2)
            for reader in readers:
                reader.join(timeout=2)
            if any(reader.is_alive() for reader in readers):
                raise OSError("Subprocess output pipes did not close")
        stdout.seek(0)
        stderr.seek(0)
        return Captured(process.returncode, stdout.read(limit), stderr.read(limit), timed_out, overflow.is_set())


def write_files(files, workspace):
    if workspace.is_symlink():
        raise ValueError("Workspace must not be a symbolic link")
    workspace.mkdir(parents=True, exist_ok=True)
    if any(workspace.iterdir()):
        raise ValueError("Workspace must be empty")
    root = workspace.resolve()
    for relative, content in files:
        target = root.joinpath(*relative.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.parent.resolve().is_relative_to(root):
            raise ValueError("File escaped the workspace")
        with target.open("xb") as stream:
            stream.write(content)
        target.chmod(0o600)


def read_report(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    if path.is_symlink():
        raise ValueError("JUnit report must be a regular file")
    with os.fdopen(os.open(path, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REPORT:
            raise ValueError("JUnit report is not a bounded regular file")
        body = stream.read(MAX_REPORT + 1)
    if len(body) > MAX_REPORT:
        raise ValueError("JUnit report exceeds the size limit")
    return body.decode("utf-8")


def test_environment(temp_dir):
    # An allowlist, not a secret-name denylist. Docker/broker/application credentials never reach pytest.
    env = {"PATH": os.defpath, "HOME": str(temp_dir), "TMPDIR": str(temp_dir),
           "TMP": str(temp_dir), "TEMP": str(temp_dir), "LANG": "C.UTF-8",
           "PYTHONDONTWRITEBYTECODE": "1", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}
    if os.name == "nt" and "SYSTEMROOT" in os.environ:
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return env


def execute(body, workspace=WORKSPACE, report_dir=REPORT_DIR, temp_dir=TEMP_DIR):
    try:
        files = decode_files(body)
        write_files(files, workspace)
        report_dir.mkdir(parents=True, exist_ok=True)
        config = report_dir / "pytest.ini"
        report = report_dir / "results.xml"
        config.write_text('[pytest]\njunit_family = xunit1\npythonpath = "' + workspace.as_posix() + '"\n', encoding="utf-8")
        command = [sys.executable, "-I", "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider",
                   "-c", str(config), "--rootdir", str(workspace), "--confcutdir", str(workspace),
                   f"--junitxml={report}", str(workspace)]
        done = capture(command, cwd=workspace, env=test_environment(temp_dir), timeout=TEST_TIMEOUT)
        output = (done.stdout + done.stderr).decode("utf-8", "replace")[-MAX_OUTPUT:]
        if done.timed_out:
            return result(None, output=output + "\nTests exceeded the 60-second deadline.")
        if done.overflow:
            return result(3, output=output + "\nTest output exceeds the size limit.")
        if done.code not in range(6):
            return result(3, output=output + "\npytest terminated unexpectedly.")
        try:
            xml = normalise_report(read_report(report), workspace)
        except (OSError, ValueError, ET.ParseError):
            return result(3, output=output + "\npytest did not produce a valid bounded JUnit report.")
        return result(done.code, xml, output)
    except (OSError, ValueError, subprocess.SubprocessError):
        return result(3, output="The test job could not be prepared or executed.")


def main():
    try:
        body = sys.stdin.buffer.read(MAX_REQUEST + 1)
        value = execute(body)
    except (OSError, ValueError):
        value = result(3, output="The test job input could not be read.")
    sys.stdout.buffer.write(encode_result(value) + b"\n")
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
