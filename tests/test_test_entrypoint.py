"""Standalone unittest tests: no app imports, database fixtures, or Docker required."""

import base64
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from functools import partial
from pathlib import Path
from unittest.mock import patch

from deploy import test_entrypoint as entry


def payload(files=()):
    return json.dumps({"files": [{"path": path, "content": base64.b64encode(content).decode("ascii")}
                                for path, content in files]}).encode("utf-8")


class PayloadTests(unittest.TestCase):
    def test_binary_unicode_and_empty_files(self):
        files = [("app/caf\u00e9.py", b"\x00\xff"), ("tests/empty.py", b"")]
        self.assertEqual(entry.decode_files(payload(files)), files)
        self.assertEqual(entry.decode_files(payload()), [])

    def test_rejects_unsafe_and_ambiguous_paths(self):
        paths = ("", "/etc/passwd", "../secret", "a/../b", "a/./b", "a//b", "a/", "a\\b",
                 "C:/secret", "a\x00b", "a\nb", "a\x7fb", "x" * 301, "\ud800")
        for path in paths:
            with self.subTest(path=repr(path)), self.assertRaises(entry.InvalidPayload):
                entry.decode_files(payload([(path, b"")]))

    def test_rejects_duplicates_and_parent_file_conflicts_in_both_orders(self):
        for files in [[("a", b""), ("a", b"")], [("a", b""), ("a/b", b"")],
                      [("a/b/c", b""), ("a", b"")]]:
            with self.subTest(files=files), self.assertRaises(entry.InvalidPayload):
                entry.decode_files(payload(files))

    def test_rejects_links_settings_wrong_types_and_invalid_base64(self):
        documents = [None, [], {}, {"files": {}}, {"files": [], "image": "evil"},
                     {"files": ["x"]}, {"files": [{"path": "x", "content": "", "type": "symlink"}]},
                     {"files": [{"path": "x", "content": 1}]},
                     {"files": [{"path": "x", "content": "!!"}]},
                     {"files": [{"path": "x", "content": "\u00e9"}]},
                     {"files": [{"path": 12, "content": ""}]}]
        for document in documents:
            with self.subTest(document=document), self.assertRaises(entry.InvalidPayload):
                entry.decode_files(json.dumps(document).encode("utf-8"))
        for body in (b'null', b'{"files":[],"files":[]}', b'\xff', b'{"files":NaN}', b'[' * 2000):
            with self.subTest(body=body[:40]), self.assertRaises(entry.InvalidPayload):
                entry.decode_files(body)

    def test_byte_and_file_limits(self):
        self.assertEqual(len(entry.decode_files(payload([("x", b"x" * entry.MAX_DECODED)]))[0][1]),
                         entry.MAX_DECODED)
        bodies = [b" " * (entry.MAX_REQUEST + 1), payload([("x", b"x" * (entry.MAX_DECODED + 1))]),
                  payload([(str(index), b"") for index in range(entry.MAX_FILES + 1)]),
                  payload([("a", b"x" * entry.MAX_DECODED), ("b", b"x")])]
        for body in bodies:
            with self.subTest(size=len(body)), self.assertRaises(entry.InvalidPayload) as raised:
                entry.decode_files(body)
            self.assertEqual(raised.exception.status, 413)
        self.assertEqual(len(entry.decode_files(payload([(str(i), b"") for i in range(entry.MAX_FILES)]))),
                         entry.MAX_FILES)


class EntrypointTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.workspace = self.root / "workspace"
        self.report_dir = self.root / "report"
        self.temp_dir = self.root / "tmp"
        self.temp_dir.mkdir()

    def execute(self, body=None):
        return entry.execute(payload([("tests/test_ok.py", b"def test_ok(): assert True")]) if body is None else body,
                             self.workspace, self.report_dir, self.temp_dir)

    def write_report(self, code=0, body=None, output=b"ok"):
        def captured(command, **kwargs):
            xml = body or (f'<testsuites><testsuite><testcase file="{self.workspace.as_posix()}/tests/test_ok.py" '
                           'name="test_ok"/></testsuite></testsuites>')
            (self.report_dir / "results.xml").write_text(xml, encoding="utf-8")
            return entry.Captured(code, output, b"")
        return captured

    def test_success_uses_trusted_pytest_configuration_and_relative_result_paths(self):
        body = payload([("app/a.py", b"x = 1"), ("pytest.ini", b"[pytest]\naddopts = --evil")])
        with patch.object(entry, "capture", side_effect=self.write_report()) as run:
            value = self.execute(body)
        self.assertEqual(value["code"], 0)
        self.assertEqual((self.workspace / "app/a.py").read_bytes(), b"x = 1")
        self.assertEqual(ET.fromstring(value["report"]).find(".//testcase").get("file"), "tests/test_ok.py")
        command = run.call_args.args[0]
        self.assertEqual(command[:6], [sys.executable, "-I", "-B", "-m", "pytest", "-q"])
        self.assertIn(str(self.report_dir / "pytest.ini"), command)
        self.assertNotIn(str(self.workspace / "pytest.ini"), command)
        self.assertEqual(run.call_args.kwargs["timeout"], 60)
        self.assertEqual(run.call_args.kwargs["cwd"], self.workspace)
        self.assertIn("junit_family = xunit1", (self.report_dir / "pytest.ini").read_text())

    def test_allowlisted_environment_removes_all_application_credentials(self):
        with patch.dict(os.environ, {"DATABASE_URL": "secret-db", "RUNNER_TOKEN": "broker-secret",
                                    "OPENAI_API_KEY": "model-secret", "PYTEST_ADDOPTS": "--evil",
                                    "PYTHONPATH": "/evil", "UNUSUAL_CREDENTIAL": "secret"}), \
                patch.object(entry, "capture", side_effect=self.write_report()) as run:
            self.execute()
        environment = run.call_args.kwargs["env"]
        for name in ("DATABASE_URL", "RUNNER_TOKEN", "OPENAI_API_KEY", "PYTEST_ADDOPTS", "PYTHONPATH", "UNUSUAL_CREDENTIAL"):
            self.assertNotIn(name, environment)
        self.assertEqual(environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"], "1")

    def test_pytest_failure_collection_error_and_no_tests_codes_survive(self):
        for code in range(6):
            with self.subTest(code=code):
                folder = self.root / str(code)
                with patch.object(entry, "capture", side_effect=partial(self.report_result, folder, code)):
                    value = entry.execute(payload(), folder / "workspace", folder / "report", self.temp_dir)
                self.assertEqual(value["code"], code)

    def report_result(self, folder, code, *args, **kwargs):
        (folder / "report/results.xml").write_text('<testsuites><testsuite tests="0"/></testsuites>')
        return entry.Captured(code, b"", b"")

    def test_timeout_and_output_overflow_are_not_passing_results(self):
        for captured, code, message in [(entry.Captured(-9, b"partial", b"", timed_out=True), None, "deadline"),
                                        (entry.Captured(-9, b"partial", b"", overflow=True), 3, "limit"),
                                        (entry.Captured(137, b"", b""), 3, "unexpectedly")]:
            with self.subTest(code=code, message=message):
                folder = self.root / message
                with patch.object(entry, "capture", return_value=captured):
                    value = entry.execute(payload(), folder / "workspace", folder / "report", self.temp_dir)
                self.assertEqual(value["code"], code)
                self.assertEqual(value["report"], "")
                self.assertIn(message, value["output"])

    def test_missing_malformed_and_entity_reports_fail_closed(self):
        for index, report in enumerate((None, "garbage", "<wrong/>",
                                        '<!DOCTYPE x [<!ENTITY a "abc">]><testsuites>&a;</testsuites>')):
            folder = self.root / str(index)
            def captured(*args, folder=folder, report=report, **kwargs):
                if report is not None:
                    (folder / "report/results.xml").write_text(report)
                return entry.Captured(0, b"", b"")
            with self.subTest(report=report), patch.object(entry, "capture", side_effect=captured):
                value = entry.execute(payload(), folder / "workspace", folder / "report", self.temp_dir)
            self.assertEqual(value["code"], 3)
            self.assertEqual(value["report"], "")

    def test_invalid_input_and_nonempty_workspace_never_start_pytest(self):
        with patch.object(entry, "capture") as run:
            self.assertEqual(self.execute(b'{"files": [], "command": "evil"}')["code"], 3)
            self.workspace.mkdir()
            (self.workspace / "preexisting").write_text("kept")
            self.assertEqual(self.execute()["code"], 3)
        run.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "Linux filesystem checks")
    def test_symlinks_and_fifo_reports_are_rejected(self):
        secret = self.root / "secret"
        secret.write_text("private")
        linked = self.root / "linked"
        linked.symlink_to(secret)
        with self.assertRaises(ValueError):
            entry.read_report(linked)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            entry.read_report(fifo)
        workspace_link = self.root / "workspace-link"
        workspace_link.symlink_to(self.temp_dir, target_is_directory=True)
        with self.assertRaises(ValueError):
            entry.write_files([], workspace_link)

    def test_report_limits_normalization_and_output_tail(self):
        with self.assertRaises(ValueError):
            entry.normalise_report("x" * (entry.MAX_REPORT + 1))
        oversized = self.root / "large.xml"
        oversized.write_bytes(b"x" * (entry.MAX_REPORT + 1))
        with self.assertRaises(ValueError):
            entry.read_report(oversized)
        xml = '<testsuites><testcase file="/workspace/tests/a.py"><error>File "/workspace/app/a.py", line 2</error></testcase></testsuites>'
        normal = entry.normalise_report(xml)
        self.assertNotIn("/workspace/", normal)
        self.assertIn('file="tests/a.py"', normal)
        with patch.object(entry, "capture", side_effect=self.write_report(output=b"x" * 9000 + b"tail")):
            value = self.execute()
        self.assertEqual(len(value["output"]), 4000)
        self.assertTrue(value["output"].endswith("tail"))
        encoded = entry.encode_result(entry.result(0, report="\x00" * entry.MAX_REPORT))
        self.assertLessEqual(len(encoded) + 1, entry.MAX_RESPONSE)
        self.assertEqual(json.loads(encoded)["code"], 3)

    def test_main_reads_bounded_input_and_prints_only_wrapper_json(self):
        incoming, outgoing = io.BytesIO(payload()), io.BytesIO()
        with patch.object(entry.sys, "stdin", type("Input", (), {"buffer": incoming})()), \
                patch.object(entry.sys, "stdout", type("Output", (), {"buffer": outgoing})()), \
                patch.object(entry, "execute", return_value=entry.result(None, output="timeout")) as run:
            entry.main()
        run.assert_called_once_with(payload())
        self.assertEqual(json.loads(outgoing.getvalue()), entry.result(None, output="timeout"))

    @unittest.skipUnless(importlib.util.find_spec("pytest"), "pytest is not installed in this Python")
    def test_real_pytest_imports_workspace_and_ignores_participant_pytest_ini(self):
        files = [("app/example.py", b"def double(value): return value * 2\n"),
                 ("tests/test_example.py", (b"import os\nfrom app.example import double\n"
                  b"def test_ok():\n    assert double(2) == 4\n    assert 'RUNNER_TOKEN' not in os.environ\n")),
                 ("pytest.ini", b"[pytest]\naddopts = --this-option-must-not-be-used\n")]
        with patch.dict(os.environ, {"RUNNER_TOKEN": "test-secret"}):
            value = self.execute(payload(files))
        self.assertEqual(value["code"], 0, value["output"])
        cases = list(ET.fromstring(value["report"]).iter("testcase"))
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0].get("file"), "tests/test_example.py")

    @unittest.skipUnless(importlib.util.find_spec("pytest"), "pytest is not installed in this Python")
    def test_real_pytest_collection_error_preserves_error_and_relative_location(self):
        value = self.execute(payload([("tests/test_broken.py", b"def test_broken(:\n")]))
        self.assertEqual(value["code"], 2, value["output"])
        self.assertTrue(list(ET.fromstring(value["report"]).iter("error")))
        self.assertNotIn(self.workspace.as_posix() + "/", value["report"])


class CaptureTests(unittest.TestCase):
    def test_small_standard_library_child_and_stdin(self):
        done = entry.capture([sys.executable, "-I", "-B", "-c", "import sys; print(sys.stdin.read()); sys.stderr.write('err')"],
                             timeout=3, env=entry.test_environment(Path(tempfile.gettempdir())), body=b"hello")
        self.assertEqual(done.code, 0)
        self.assertEqual(done.stdout.strip(), b"hello")
        self.assertEqual(done.stderr, b"err")
        self.assertFalse(done.timed_out or done.overflow)

    def test_output_overflow_and_deadline_are_bounded(self):
        for source, expected in [("import sys; sys.stdout.write('x' * 20000)", "overflow"),
                                 ("import time; time.sleep(5)", "timed_out")]:
            with self.subTest(expected=expected):
                done = entry.capture([sys.executable, "-I", "-B", "-c", source], timeout=0.2,
                                     env=entry.test_environment(Path(tempfile.gettempdir())), limit=1000)
                self.assertTrue(getattr(done, expected))
                self.assertLessEqual(len(done.stdout), 1000)


if __name__ == "__main__":
    unittest.main()
