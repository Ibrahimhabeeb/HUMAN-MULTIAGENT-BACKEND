"""Send copies of test inputs to the private runner; never send credentials or host paths."""

import base64
import json
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

from config import get_settings

MAX_FILES = 1000
MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


def run(folder: Path) -> dict:
    settings = get_settings()
    if not settings.test_runner_url or not settings.test_runner_token:
        raise ValueError("The isolated test runner is not configured")
    files, size = [], 0
    for path in sorted(folder.rglob("*")):
        relative = path.relative_to(folder)
        if path.is_symlink():
            raise ValueError("Test inputs cannot contain symbolic links")
        if any(part in {"__pycache__", ".pytest_cache"} for part in relative.parts) or path.is_dir():
            continue
        if not path.is_file() or path.stat().st_nlink > 1:
            raise ValueError("Test inputs must be ordinary files")
        remaining = MAX_INPUT_BYTES - size
        with path.open("rb") as stream:
            content = stream.read(remaining + 1)
        size += len(content)
        if size > MAX_INPUT_BYTES or len(files) >= MAX_FILES:
            raise ValueError("The test workspace exceeds the runner input limit")
        files.append({"path": relative.as_posix(), "content": base64.b64encode(content).decode("ascii")})
    request = Request(
        settings.test_runner_url.rstrip("/") + "/run",
        data=json.dumps({"files": files}).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {settings.test_runner_token.get_secret_value()}"},
        method="POST",
    )
    # The internal service must never inherit an outbound HTTP proxy intended for model calls.
    with build_opener(ProxyHandler({})).open(request, timeout=200 + settings.test_timeout_seconds) as response:
        payload = response.read(MAX_RESPONSE_BYTES + 1)
    if len(payload) > MAX_RESPONSE_BYTES:
        raise ValueError("The isolated test runner returned too much data")
    result = json.loads(payload)
    if not isinstance(result, dict) or not isinstance(result.get("report"), str) or not isinstance(result.get("output"), str):
        raise TypeError("The isolated test runner returned an invalid result")
    if "code" not in result:
        raise ValueError("The isolated test runner returned no exit code")
    code = result.get("code")
    if code is not None and (type(code) is not int or code not in range(6)):
        raise ValueError("The isolated test runner returned an invalid exit code")
    return result


UNAVAILABLE = (HTTPError, URLError, OSError, ValueError, TypeError, TimeoutError)
