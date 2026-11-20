"""Private single-job Docker broker. Never accepts Docker settings from callers."""

import hmac
import json
import os
import re
import subprocess
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from deploy.test_entrypoint import (
    MAX_REQUEST,
    MAX_RESPONSE,
    TEST_TIMEOUT,
    InvalidPayload,
    capture,
    decode_files,
    encode_result,
    load_json,
    normalise_report,
    result,
)

IMAGE = "secure-coding-room-tests:local"
JOB_LABEL = "secure-coding-room.test-job=true"
QUEUE_SIZE = 4
QUEUE_TIMEOUT = 120
WALL_TIMEOUT = TEST_TIMEOUT + 10
CLI_TIMEOUT = 5
SOCKET_TIMEOUT = 10
HEALTH_TIMEOUT = 2
PORT = 9000


class Unavailable(RuntimeError):
    pass


def docker_environment():
    return {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C.UTF-8"}


def docker(args, *, timeout=CLI_TIMEOUT, body=b""):
    return capture(["docker", *args], timeout=timeout, env=docker_environment(), body=body)


def successful(done):
    return done.code == 0 and not done.timed_out and not done.overflow


def create_command(name):
    return [
        "create", "--interactive", "--pull=never", "--name", name, "--label", JOB_LABEL,
        "--user", "65534:65534", "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges=true", "--pids-limit", "64",
        "--memory", "384m", "--memory-swap", "384m", "--cpus", "0.5", "--ipc", "private",
        "--tmpfs", "/workspace:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=65534,gid=65534",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=32m,mode=0700,uid=65534,gid=65534",
        "--tmpfs", "/report:rw,noexec,nosuid,nodev,size=4m,mode=0700,uid=65534,gid=65534",
        "--ulimit", "fsize=16777216:16777216", "--ulimit", "nofile=128:128", "--log-driver", "none",
        "--workdir", "/workspace", "--env", "TEST_TIMEOUT_SECONDS=60",
        "--entrypoint", "/usr/local/bin/python", IMAGE, "-I", "-B", "/opt/runner/test_entrypoint.py",
    ]


def parse_result(body):
    if len(body) > MAX_RESPONSE:
        raise Unavailable("Runner response exceeds the limit")
    try:
        value = load_json(body)
        if not isinstance(value, dict) or set(value) != {"code", "report", "output"}:
            raise ValueError("Invalid result shape")
        code, report, output = value["code"], value["report"], value["output"]
        if code is not None and (type(code) is not int or code not in range(6)):
            raise ValueError("Invalid pytest exit code")
        if not isinstance(report, str) or not isinstance(output, str):
            raise TypeError("Invalid result strings")
        output.encode("utf-8")
        if report:
            report = normalise_report(report)
        elif code in (0, 1):
            raise ValueError("Missing JUnit report")
        return result(code, report if code is not None else "", output)
    except (TypeError, ValueError, UnicodeError, RecursionError, ET.ParseError) as error:
        raise Unavailable("Runner returned an invalid result") from error


class Broker:
    def __init__(self, token):
        if not token or len(token) > 1024 or any(ord(c) < 33 or ord(c) > 126 for c in token):
            raise ValueError("RUNNER_TOKEN must be a nonempty printable ASCII token")
        self._authorization = ("Bearer " + token).encode("ascii")
        self.admission = threading.BoundedSemaphore(QUEUE_SIZE + 1)
        self.job = threading.BoundedSemaphore(1)
        self.cleanup_failed = False

    def authorized(self, header):
        return hmac.compare_digest((header or "").encode("utf-8"), self._authorization)

    def ready(self):
        if self.cleanup_failed:
            return False
        try:
            # One read-only daemon round trip proves socket access and fixed-image availability; never starts a job.
            image = docker(["image", "inspect", "--format", "{{.Os}}", IMAGE], timeout=HEALTH_TIMEOUT)
            return successful(image) and image.stdout.strip() == b"linux"
        except (OSError, subprocess.SubprocessError):
            return False

    def cleanup_stale(self):
        listed = docker(["ps", "--all", "--quiet", "--filter", "label=" + JOB_LABEL])
        if not successful(listed):
            raise Unavailable("Could not list stale test containers")
        identifiers = listed.stdout.decode("ascii").split()
        if any(not re.fullmatch(r"[0-9a-f]{12,64}", value) for value in identifiers):
            raise Unavailable("Invalid stale container list")
        for offset in range(0, len(identifiers), 32):
            if not successful(docker(["rm", "--force", *identifiers[offset:offset + 32]])):
                raise Unavailable("Could not remove stale test containers")

    def run(self, read_body):
        # Admission includes body readers: even slow clients cannot accumulate unlimited job payloads.
        if self.cleanup_failed or not self.admission.acquire(blocking=False):
            raise Unavailable("Runner queue is full or unavailable")
        try:
            body = read_body()
            decode_files(body)
            if not self.job.acquire(timeout=QUEUE_TIMEOUT):
                raise Unavailable("Runner queue wait expired")
            try:
                if self.cleanup_failed:
                    raise Unavailable("Runner cleanup requires attention")
                return self._execute(body)
            finally:
                self.job.release()
        finally:
            self.admission.release()

    def _execute(self, body):
        name = "secure-coding-room-test-" + uuid.uuid4().hex
        deadline = time.monotonic() + WALL_TIMEOUT
        try:
            created = docker(create_command(name), timeout=min(10, WALL_TIMEOUT))
            if not successful(created):
                raise Unavailable("Could not create test container")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return result(None, output="Tests exceeded the runner deadline.")
            started = docker(["start", "--attach", "--interactive", name], timeout=remaining, body=body)
            if started.timed_out:
                return result(None, output="Tests exceeded the runner deadline.")
            if not successful(started):
                raise Unavailable("Test container failed or exceeded its output limit")
            return parse_result(started.stdout)
        except (OSError, subprocess.SubprocessError) as error:
            raise Unavailable("Docker could not execute the test job") from error
        finally:
            try:
                removed = docker(["rm", "--force", name])
                # A failed create may never have made a container; verify absence rather than masking that case.
                if not successful(removed):
                    listed = docker(["ps", "--all", "--quiet", "--filter", "name=^/" + name + "$"])
                    if not successful(listed) or listed.stdout.strip():
                        self.cleanup_failed = True
            except (OSError, subprocess.SubprocessError):
                self.cleanup_failed = True
            if self.cleanup_failed:
                raise Unavailable("Test container cleanup failed; runner disabled")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def setup(self):
        super().setup()
        self.connection.settimeout(SOCKET_TIMEOUT)

    def log_message(self, format, *args):
        # Do not put participant input, credentials, or client addresses in access logs.
        pass

    def send_json(self, status, value):
        body = encode_result(value) if set(value) == {"code", "report", "output"} else json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        if status == 401:
            self.send_header("WWW-Authenticate", "Bearer")
        if status == 503:
            self.send_header("Retry-After", "5")
        self.end_headers()
        self.close_connection = True
        self.wfile.write(body)

    def read_body(self):
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,10}", lengths[0]):
            raise InvalidPayload("One Content-Length header is required", 411)
        if self.headers.get_all("Transfer-Encoding") or self.headers.get_all("Content-Encoding"):
            raise InvalidPayload("Encoded or chunked requests are not supported")
        length = int(lengths[0])
        if length > MAX_REQUEST:
            raise InvalidPayload("Request exceeds 4 MiB", 413)
        if self.headers.get_content_type() != "application/json":
            raise InvalidPayload("Content-Type must be application/json", 415)
        deadline = time.monotonic() + SOCKET_TIMEOUT
        chunks = []
        remaining = length
        while remaining:
            wait = deadline - time.monotonic()
            if wait <= 0:
                raise TimeoutError("Body deadline expired")
            self.connection.settimeout(wait)
            chunk = self.rfile.read1(min(65536, remaining))
            if not chunk:
                raise InvalidPayload("Incomplete request body")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def do_GET(self):
        if self.path != "/health":
            self.send_json(404, {"detail": "Not found"})
            return
        ready = self.server.broker.ready()
        self.send_json(200 if ready else 503, {"status": "ok" if ready else "unavailable"})

    def do_POST(self):
        if self.path != "/run":
            self.send_json(404, {"detail": "Not found"})
            return
        headers = self.headers.get_all("Authorization", [])
        if len(headers) != 1 or not self.server.broker.authorized(headers[0]):
            self.send_json(401, {"detail": "Unauthorized"})
            return
        try:
            value = self.server.broker.run(self.read_body)
            self.send_json(200, value)
        except InvalidPayload as error:
            self.send_json(error.status, {"detail": str(error)})
        except Unavailable:
            self.send_json(503, {"detail": "Runner unavailable; retry later"})
        except TimeoutError:
            self.send_json(408, {"detail": "Request body timed out"})


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 8

    def __init__(self, address, broker):
        self.broker = broker
        self.connections = threading.BoundedSemaphore(16)
        super().__init__(address, Handler)

    def process_request(self, request, address):
        if not self.connections.acquire(blocking=False):
            body = b'{"detail":"Runner unavailable; retry later"}'
            try:
                request.settimeout(1)
                request.sendall(b"HTTP/1.0 503 Service Unavailable\r\nConnection: close\r\n"
                                b"Content-Type: application/json\r\nRetry-After: 5\r\nContent-Length: "
                                + str(len(body)).encode("ascii") + b"\r\n\r\n" + body)
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.connections.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.connections.release()


def main():
    broker = Broker(os.environ.get("RUNNER_TOKEN", ""))
    broker.cleanup_stale()
    if not broker.ready():
        raise SystemExit("Docker or the fixed Linux test image is unavailable")
    with Server(("0.0.0.0", PORT), broker) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
