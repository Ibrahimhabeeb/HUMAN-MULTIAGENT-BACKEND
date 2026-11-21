import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux release transport")

FAKE_COMMAND = r'''#!/bin/sh
name=${0##*/}
root=$FAKE_RELEASE_ROOT
printf '%s\n' "$name $*" >> "$root/calls.log"
if [ "$name" = ssh ]; then
    for command; do :; done
    case "$command" in
        *'systemd-run '*) printf 'launch\n' >> "$root/launches" ;;
        *' status '*)
            case "$FAKE_RELEASE_SCENARIO" in
                disconnect)
                    if [ ! -e "$root/disconnected" ]; then
                        : > "$root/disconnected"
                        exit 255
                    fi
                    printf 'complete\n' ;;
                failed) printf 'failed\n' ;;
            esac ;;
        *' site '*) printf 'https://study.example.org\n' ;;
    esac
elif [ "$name" = curl ]; then
    printf '{"status":"ready"}\n'
fi
exit 0
'''


@pytest.mark.parametrize("scenario,expected", [("disconnect", 0), ("failed", 1), ("timeout", 1)])
def test_transport_never_launches_a_duplicate_after_disconnect_failure_or_timeout(tmp_path, scenario, expected):
    binaries = tmp_path / "bin"
    binaries.mkdir()
    for name in ("ssh", "scp", "curl", "sleep", "ssh-keygen"):
        command = binaries / name
        command.write_text(FAKE_COMMAND)
        command.chmod(0o700)
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    env = os.environ | {
        "PATH": str(binaries) + os.pathsep + os.environ["PATH"],
        "FAKE_RELEASE_ROOT": str(tmp_path), "FAKE_RELEASE_SCENARIO": scenario,
        "DEPLOY_HOST": "192.0.2.10", "DEPLOY_USER": "root",
        "DEPLOY_SSH_KEY": "test-only-key", "DEPLOY_KNOWN_HOSTS": "test-only-host-key",
        "BACKEND_SHA": "a" * 40, "FRONTEND_SHA": "b" * 40,
        "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
        "RUNNER_TEMP": str(tmp_path), "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"),
    }
    result = subprocess.run(["bash", str(Path(__file__).resolve().parents[1] / "deploy/ssh-release.sh"), str(bundle)],
                            env=env, capture_output=True, text=True, timeout=45, check=False)
    assert result.returncode == expected, result.stderr
    assert (tmp_path / "launches").read_text().splitlines() == ["launch"]
    calls = (tmp_path / "calls.log").read_text().splitlines()
    for call in calls:
        if call.startswith(("ssh ", "scp ")):
            assert "StrictHostKeyChecking=yes" in call and "BatchMode=yes" in call
    assert "test-only-key" not in result.stdout + result.stderr
    assert not list(tmp_path.glob("secure-coding-room-ssh.*"))
    if scenario == "disconnect":
        assert "Backend:" in (tmp_path / "summary.md").read_text()
    elif scenario == "failed":
        assert "Deployment failed" in result.stderr
    else:
        assert "Stopped waiting" in result.stderr
