"""Select exact release commits only after their latest push-to-main CI succeeds."""

import json
import os
import re
import sys
import time
from http.client import HTTPException
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

REPOSITORY = re.compile(r"([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)/([A-Za-z0-9_.-]{1,100})")
SHA = re.compile(r"[0-9a-fA-F]{40}")


class SelectionError(Exception):
    pass


def checked_sha(value, label):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise SelectionError(f"{label} must be a full 40-character hexadecimal commit SHA.")
    return value.lower()


def api(path, token, opener):
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "secure-coding-room-release",
               "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = "Bearer " + token
    resource = path.split("?", 1)[0]
    for attempt in range(3):
        try:
            request = Request("https://api.github.com/repos/" + path, headers=headers)
            with (opener or urlopen)(request, timeout=20) as response:
                data = json.load(response)
            break
        except HTTPError as error:
            status = error.code
            response_headers = error.headers or {}
            limited = status == 429 or (status == 403 and response_headers.get("X-RateLimit-Remaining") == "0")
            retry_header = response_headers.get("Retry-After", "")
            retry_after = int(retry_header) if retry_header.isascii() and retry_header.isdigit() else 0
            error.close()
            if not limited and status in (500, 502, 503, 504) and attempt < 2 and retry_after <= 10:
                time.sleep(max(2 ** attempt, retry_after))
                continue
            reason = "GitHub returned an error"
            if limited or retry_after:
                reason = "rate limit or server retry delay; wait before rerunning"
            elif status in (401, 403):
                reason = "access denied; check the token's repository read permissions"
            elif status == 404:
                reason = "repository/workflow unavailable or not visible to this token"
            raise SelectionError(f"GitHub API request failed for {resource}: HTTP {status}; {reason}.") from None
        except (OSError, HTTPException) as error:
            if attempt < 2:
                time.sleep(2 ** attempt)
                continue
            raise SelectionError(f"GitHub API request failed for {resource}: network/TLS failure ({type(error).__name__}).") from None
        except ValueError:
            raise SelectionError(f"GitHub API request failed for {resource}: invalid JSON response.") from None
    if not isinstance(data, dict):
        raise SelectionError("GitHub API returned an invalid response object.")
    return data


def require_ci(repository, workflow, sha, token, opener):
    query = urlencode({"head_sha": sha, "event": "push", "branch": "main", "per_page": 100})
    data = api(f"{repository}/actions/workflows/{workflow}/runs?{query}", token, opener)
    runs = data.get("workflow_runs")
    if not isinstance(runs, list) or len(runs) > 100 or any(not isinstance(r, dict) for r in runs):
        raise SelectionError(f"{workflow}: GitHub returned an invalid workflow-run list.")
    matches = [r for r in runs if r.get("head_sha") == sha
               and r.get("head_branch") == "main" and r.get("event") == "push"]
    if not matches:
        raise SelectionError(f"{workflow}: no push-to-main CI run matches the selected SHA.")
    if any(type(r.get("run_number")) is not int or r["run_number"] < 1 for r in matches):
        raise SelectionError(f"{workflow}: GitHub returned an invalid CI run number.")
    # Run numbers order new workflow runs; rerunning an older run does not make it newer.
    latest = max(matches, key=lambda r: r["run_number"])
    if latest.get("status") != "completed" or latest.get("conclusion") != "success":
        raise SelectionError(f"{workflow}: latest matching push run must be completed with conclusion success.")


def verify_release(env, opener=None):
    if env.get("GITHUB_REF") != "refs/heads/main":
        raise SelectionError("Release selection is restricted to refs/heads/main.")
    repository = env.get("GITHUB_REPOSITORY", "")
    match = REPOSITORY.fullmatch(repository)
    if not match or match[2] in {".", ".."}:
        raise SelectionError("GITHUB_REPOSITORY must contain a valid owner/repository name.")
    backend_sha = checked_sha(env.get("GITHUB_SHA"), "GITHUB_SHA")
    output = env.get("GITHUB_OUTPUT", "")
    if not output or any(ord(c) < 32 or ord(c) == 127 for c in output):
        raise SelectionError("GITHUB_OUTPUT must name an output file without control characters.")
    frontend_repository = match[1] + "/HUMAN-MULTIAGENT-FRONTEND"
    backend_token = env.get("GITHUB_TOKEN", "")
    # Public lookups still benefit from authentication on shared GitHub runners.
    # An optional frontend-only read token supports stricter cross-repository access.
    frontend_token = env.get("FRONTEND_READ_TOKEN") or backend_token
    frontend = api(f"{frontend_repository}/commits/main", frontend_token, opener)
    frontend_sha = checked_sha(frontend.get("sha"), "Frontend main SHA")
    require_ci(repository, "backend-ci.yml", backend_sha, backend_token, opener)
    require_ci(frontend_repository, "frontend-ci.yml", frontend_sha, frontend_token, opener)
    values = {"backend_sha": backend_sha, "frontend_sha": frontend_sha,
              "frontend_repository": frontend_repository}
    try:
        with Path(output).open("a", encoding="utf-8", newline="\n") as stream:
            stream.write("".join(f"{key}={value}\n" for key, value in values.items()))
    except (OSError, ValueError):
        raise SelectionError("Cannot append release selections to GITHUB_OUTPUT.") from None
    return values


def main(env=None, opener=None):
    try:
        verify_release(os.environ if env is None else env, opener)
    except SelectionError as error:
        print(f"Release selection failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
