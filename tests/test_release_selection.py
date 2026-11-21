"""Offline release-selection tests with disposable temporary outputs."""

import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http.client import IncompleteRead
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit

STAGING = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("verify_release", STAGING / "deploy" / "verify_release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)

BACKEND_SHA = "a" * 40
FRONTEND_SHA = "b" * 40
OTHER_SHA = "c" * 40
BACKEND = "Study-Owner/HUMAN-MULTIAGENT-BACKEND"
FRONTEND = "Study-Owner/HUMAN-MULTIAGENT-FRONTEND"


def run(sha, number=1, **changes):
    value = {"head_sha": sha, "head_branch": "main", "event": "push",
             "run_number": number, "status": "completed", "conclusion": "success"}
    value.update(changes)
    return value


class ReleaseSelectionTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="release-test-")
        self.addCleanup(directory.cleanup)
        self.output = Path(directory.name) / "github-output"
        self.output.write_text("existing=value\n", encoding="utf-8")
        self.env = {"GITHUB_REPOSITORY": BACKEND, "GITHUB_SHA": BACKEND_SHA,
                    "GITHUB_REF": "refs/heads/main", "GITHUB_OUTPUT": str(self.output),
                    "GITHUB_TOKEN": "FAKE-TEST-TOKEN"}
        self.commit = {"sha": FRONTEND_SHA}
        self.backend = {"workflow_runs": [run(BACKEND_SHA)]}
        self.frontend = {"workflow_runs": [run(FRONTEND_SHA)]}
        self.opener = Mock(side_effect=self.respond)
        guard = patch.object(release, "urlopen", side_effect=AssertionError("Live network is forbidden"))
        guard.start()
        self.addCleanup(guard.stop)

    def respond(self, request, timeout):
        self.assertEqual(timeout, 20)
        url = urlsplit(request.full_url)
        self.assertEqual((url.scheme, url.netloc), ("https", "api.github.com"))
        paths = {f"/repos/{FRONTEND}/commits/main": self.commit,
                 f"/repos/{BACKEND}/actions/workflows/backend-ci.yml/runs": self.backend,
                 f"/repos/{FRONTEND}/actions/workflows/frontend-ci.yml/runs": self.frontend}
        self.assertIn(url.path, paths)
        return io.BytesIO(json.dumps(paths[url.path]).encode("utf-8"))

    def assert_blocked(self, message):
        with self.assertRaisesRegex(release.SelectionError, message):
            release.verify_release(self.env, self.opener)
        self.assertEqual(self.output.read_text(encoding="utf-8"), "existing=value\n")

    def test_selects_both_shas_and_appends_only_expected_outputs(self):
        values = release.verify_release(self.env, self.opener)
        self.assertEqual(values, {"backend_sha": BACKEND_SHA, "frontend_sha": FRONTEND_SHA,
                                  "frontend_repository": FRONTEND})
        self.assertEqual(self.output.read_text(encoding="utf-8"),
                         f"existing=value\nbackend_sha={BACKEND_SHA}\nfrontend_sha={FRONTEND_SHA}\n"
                         f"frontend_repository={FRONTEND}\n")

    def test_frontend_is_resolved_once_and_only_backend_gets_token(self):
        release.verify_release(self.env, self.opener)
        requests = [call.args[0] for call in self.opener.call_args_list]
        self.assertEqual(len(requests), 3)
        self.assertEqual(requests[0].full_url, f"https://api.github.com/repos/{FRONTEND}/commits/main")
        self.assertIsNone(requests[0].get_header("Authorization"))
        self.assertEqual(requests[1].get_header("Authorization"), "Bearer FAKE-TEST-TOKEN")
        self.assertIsNone(requests[2].get_header("Authorization"))
        for request, sha in zip(requests[1:], (BACKEND_SHA, FRONTEND_SHA)):
            self.assertEqual(parse_qs(urlsplit(request.full_url).query),
                             {"head_sha": [sha], "event": ["push"], "branch": ["main"], "per_page": ["100"]})

    def test_backend_token_is_optional(self):
        del self.env["GITHUB_TOKEN"]
        release.verify_release(self.env, self.opener)
        self.assertTrue(all(call.args[0].get_header("Authorization") is None
                            for call in self.opener.call_args_list))

    def test_urlopen_can_be_mocked_without_passing_an_opener(self):
        with patch.object(release, "urlopen", self.opener):
            self.assertEqual(release.main(self.env), 0)

    def test_non_main_refs_fail_before_network_or_output(self):
        for ref in (None, "", "main", "refs/heads/feature", "refs/tags/main", "refs/pull/1/merge",
                    "refs/heads/main\n"):
            with self.subTest(ref=ref):
                self.env["GITHUB_REF"] = ref
                self.assert_blocked("restricted to refs/heads/main")
        self.opener.assert_not_called()

    def test_invalid_repository_names_fail_before_network(self):
        for name in ("", "owner", "owner/repo/extra", "-owner/repo", "owner-/repo", "owner_name/repo",
                     "owner/.", "owner/..", "owner/repo?x=1", "owner/repo#x", "owner/repo\nextra=value",
                     "ow ner/repo", "owner/répo", "owner/rep%2fo", "a" * 40 + "/repo", "owner/" + "r" * 101):
            with self.subTest(repository=name):
                self.env["GITHUB_REPOSITORY"] = name
                self.assert_blocked("valid owner/repository")
        self.opener.assert_not_called()

    def test_invalid_backend_sha_fails_before_network(self):
        for sha in (None, "", "a" * 39, "a" * 41, "g" * 40, BACKEND_SHA + "\nextra=value"):
            with self.subTest(sha=sha):
                self.env["GITHUB_SHA"] = sha
                self.assert_blocked("GITHUB_SHA must be a full 40-character")
        self.opener.assert_not_called()

    def test_sha_outputs_are_canonical_lowercase(self):
        self.env["GITHUB_SHA"] = BACKEND_SHA.upper()
        self.commit["sha"] = FRONTEND_SHA.upper()
        values = release.verify_release(self.env, self.opener)
        self.assertEqual((values["backend_sha"], values["frontend_sha"]), (BACKEND_SHA, FRONTEND_SHA))

    def test_invalid_frontend_sha_never_reaches_ci_or_output(self):
        for value in (None, "", OTHER_SHA + "\nextra=value", "b" * 39, "x" * 40, {"sha": FRONTEND_SHA}):
            with self.subTest(sha=value):
                self.commit["sha"] = value
                self.opener.reset_mock()
                self.assert_blocked("Frontend main SHA must be a full 40-character")
                self.assertEqual(self.opener.call_count, 1)

    def test_invalid_output_configuration_fails_before_network(self):
        for output in (None, "", str(self.output) + "\nextra=value", "bad\rpath", "bad\0path", "bad\tpath"):
            with self.subTest(output=output):
                self.env["GITHUB_OUTPUT"] = output
                self.assert_blocked("GITHUB_OUTPUT must name an output file")
        self.opener.assert_not_called()

    def test_missing_required_environment_values_are_rejected(self):
        for key in ("GITHUB_REF", "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_OUTPUT"):
            with self.subTest(key=key):
                env = {name: value for name, value in self.env.items() if name != key}
                with self.assertRaises(release.SelectionError):
                    release.verify_release(env, self.opener)
        self.opener.assert_not_called()

    def test_output_write_error_is_clear_and_does_not_expose_path(self):
        self.env["GITHUB_OUTPUT"] = str(self.output.parent)
        self.assert_blocked("Cannot append release selections")

    def test_output_file_can_be_created(self):
        self.output.unlink()
        release.verify_release(self.env, self.opener)
        self.assertTrue(self.output.read_text(encoding="utf-8").startswith("backend_sha="))

    def test_both_workflows_reject_mismatched_sha_branch_or_event(self):
        for data, sha, workflow in ((self.backend, BACKEND_SHA, "backend"),
                                    (self.frontend, FRONTEND_SHA, "frontend")):
            for changes in ({"head_sha": OTHER_SHA}, {"head_branch": "feature"},
                            {"event": "pull_request"}, {"event": "workflow_dispatch"}, {"head_sha": None}):
                with self.subTest(workflow=workflow, changes=changes):
                    data["workflow_runs"] = [run(sha, **changes)]
                    self.assert_blocked("no push-to-main CI run matches")
            data["workflow_runs"] = [run(sha)]

    def test_unrelated_newer_runs_do_not_replace_exact_matching_run(self):
        self.backend["workflow_runs"] = [run(OTHER_SHA, 9), run(BACKEND_SHA, 8, event="pull_request"),
                                          run(BACKEND_SHA, 7, head_branch="feature"), run(BACKEND_SHA, 1)]
        self.assertEqual(release.main(self.env, self.opener), 0)

    def test_latest_run_wins_even_when_api_results_are_unsorted(self):
        self.backend["workflow_runs"] = [run(BACKEND_SHA, 2, status="queued", conclusion=None),
                                          run(BACKEND_SHA, 3), run(BACKEND_SHA, 1, conclusion="failure")]
        self.assertEqual(release.main(self.env, self.opener), 0)

    def test_newer_non_success_blocks_older_success_in_both_workflows(self):
        outcomes = [("queued", None), ("pending", None), ("in_progress", None),
                    ("in_progress", "success"), ("completed", "failure"), ("completed", "skipped"),
                    ("completed", "cancelled"), ("completed", "neutral"), ("completed", "timed_out"),
                    ("completed", None)]
        for data, sha, workflow in ((self.backend, BACKEND_SHA, "backend"),
                                    (self.frontend, FRONTEND_SHA, "frontend")):
            for status, conclusion in outcomes:
                with self.subTest(workflow=workflow, status=status, conclusion=conclusion):
                    data["workflow_runs"] = [run(sha, 1), run(sha, 2, status=status, conclusion=conclusion)]
                    self.assert_blocked(workflow + r"-ci.yml: latest matching push run")
            data["workflow_runs"] = [run(sha)]

    def test_rerunning_old_success_does_not_make_it_the_latest_run(self):
        self.backend["workflow_runs"] = [run(BACKEND_SHA, 4, run_attempt=9, updated_at="2030-01-01T00:00:00Z"),
                                          run(BACKEND_SHA, 5, status="queued", conclusion=None,
                                              updated_at="2026-11-21T00:00:00Z")]
        self.assert_blocked("latest matching push run")

    def test_missing_run_number_cannot_fall_back_to_older_success(self):
        for number in (None, "2", True, 0, -1):
            with self.subTest(number=number):
                self.backend["workflow_runs"] = [run(BACKEND_SHA, 1), run(BACKEND_SHA, number)]
                self.assert_blocked("invalid CI run number")

    def test_empty_run_list_cannot_authorize_release(self):
        for data in (self.backend, self.frontend):
            data["workflow_runs"] = []
            self.assert_blocked("no push-to-main CI run matches")
            data["workflow_runs"] = [run(BACKEND_SHA if data is self.backend else FRONTEND_SHA)]

    def test_malformed_or_oversized_run_lists_fail_closed(self):
        for runs in (None, {}, "body", [None], [run(BACKEND_SHA)] * 101):
            with self.subTest(type=type(runs).__name__):
                self.backend["workflow_runs"] = runs
                self.assert_blocked("invalid workflow-run list")

    def test_missing_workflow_run_list_is_rejected(self):
        self.backend.clear()
        self.assert_blocked("invalid workflow-run list")

    def test_cli_errors_never_print_exception_details_token_or_response_body(self):
        secret = "FAKE-TEST-TOKEN response-body-must-remain-private"
        errors = [HTTPError("https://api.github.com/", 403, secret, {}, io.BytesIO(secret.encode())),
                  URLError(secret), TimeoutError(secret), ValueError(secret), IncompleteRead(secret.encode())]
        for error in errors:
            with self.subTest(error=type(error).__name__):
                self.opener.side_effect = error
                stdout, stderr = io.StringIO(), io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    self.assertEqual(release.main(self.env, self.opener), 1)
                self.assertEqual(stdout.getvalue(), "")
                self.assertIn("GitHub API request failed", stderr.getvalue())
                self.assertNotIn("FAKE-TEST-TOKEN", stderr.getvalue())
                self.assertNotIn("response-body", stderr.getvalue())
                self.assertNotIn("Traceback", stderr.getvalue())
                self.assertEqual(self.output.read_text(encoding="utf-8"), "existing=value\n")
                if isinstance(error, HTTPError):
                    self.assertTrue(error.closed)

    def test_malformed_json_and_non_object_response_do_not_leak_body(self):
        for body in (b"FAKE-TEST-TOKEN not-json", b"\xff", b"[]", b"null"):
            with self.subTest(body=body):
                self.opener.side_effect = lambda *args, body=body, **kwargs: io.BytesIO(body)
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    self.assertEqual(release.main(self.env, self.opener), 1)
                self.assertNotIn("FAKE-TEST-TOKEN", stderr.getvalue())
                self.assertNotIn("Traceback", stderr.getvalue())
                self.assertEqual(self.output.read_text(encoding="utf-8"), "existing=value\n")


if __name__ == "__main__":
    unittest.main()
