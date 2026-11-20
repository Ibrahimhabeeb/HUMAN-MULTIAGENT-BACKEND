"""Broker tests use fake HTTP handlers and Docker calls; no daemon or server is started."""

import base64
import io
import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from email.message import Message
from types import SimpleNamespace
from unittest.mock import Mock, patch

from deploy import runner_broker as broker
from deploy.test_entrypoint import MAX_REQUEST, MAX_RESPONSE, Captured, result

TOKEN = "unit-test-only-token"
BODY = json.dumps({"files": [{"path": "tests/test_x.py", "content": base64.b64encode(b"test").decode()}]}).encode()
XML = '<testsuites><testsuite><testcase file="/workspace/tests/test_x.py" name="test_x"/></testsuite></testsuites>'


def done(code=0, stdout=b"", **kwargs):
    return Captured(code, stdout, b"", **kwargs)


def handler(service, body=BODY, headers=None, path="/run"):
    request = object.__new__(broker.Handler)
    request.path = path
    request.server = SimpleNamespace(broker=service)
    request.connection = Mock()
    request.headers = Message()
    for key, value in (headers if headers is not None else [("Authorization", "Bearer " + TOKEN),
                                                           ("Content-Type", "application/json"),
                                                           ("Content-Length", str(len(body)))]):
        request.headers[key] = value
    request.rfile = io.BytesIO(body)
    request.wfile = io.BytesIO()
    request.send_response = Mock()
    request.send_header = Mock()
    request.end_headers = Mock()
    return request


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.service = broker.Broker(TOKEN)

    def test_auth_is_exact_and_constant_time_including_nonascii_input(self):
        for header, expected in [("Bearer " + TOKEN, True), (None, False), ("bearer " + TOKEN, False),
                                 ("Bearer wrong", False), ("Bearer \u00e9", False)]:
            with self.subTest(header=header), patch.object(broker.hmac, "compare_digest", wraps=broker.hmac.compare_digest) as compare:
                self.assertEqual(self.service.authorized(header), expected)
                compare.assert_called_once()
        for token in ("", "spaces not allowed", "x\n", "\u00e9", "x" * 1025):
            with self.subTest(token=repr(token)), self.assertRaises(ValueError):
                broker.Broker(token)

    def test_fixed_container_command_has_all_limits_and_no_host_mounts(self):
        command = broker.create_command("generated-name")
        required = [("--user", "65534:65534"), ("--network", "none"), ("--cap-drop", "ALL"),
                    ("--security-opt", "no-new-privileges=true"), ("--pids-limit", "64"),
                    ("--memory", "384m"), ("--memory-swap", "384m"), ("--cpus", "0.5"),
                    ("--log-driver", "none"), ("--label", broker.JOB_LABEL), ("--pull=never", None)]
        for flag, value in required:
            self.assertIn(flag, command)
            if value is not None:
                self.assertEqual(command[command.index(flag) + 1], value)
        for flag in ("--interactive", "--read-only"):
            self.assertIn(flag, command)
        for flag in ("--privileged", "--volume", "-v", "--mount", "--publish", "--pid=host"):
            self.assertNotIn(flag, command)
        self.assertEqual(sum(value == "--tmpfs" for value in command), 3)
        self.assertIn("fsize=16777216:16777216", command)
        self.assertIn("nofile=128:128", command)
        self.assertEqual(command[-4:], [broker.IMAGE, "-I", "-B", "/opt/runner/test_entrypoint.py"])
        self.assertNotIn(TOKEN, " ".join(command))

    def test_success_and_pytest_failure_use_stdin_and_always_remove_container(self):
        for code in (0, 1, 2, 3, 4, 5, None):
            with self.subTest(code=code):
                wrapper = json.dumps(result(code, XML if code is not None else "", "x" * 5000)).encode()
                with patch.object(broker, "docker", side_effect=[done(), done(stdout=wrapper), done()]) as docker:
                    value = self.service.run(lambda: BODY)
                self.assertEqual(value["code"], code)
                self.assertEqual(len(value["output"]), 4000)
                self.assertNotIn("/workspace/", value["report"])
                calls = docker.call_args_list
                name = calls[0].args[0][calls[0].args[0].index("--name") + 1]
                self.assertEqual(calls[1].args[0], ["start", "--attach", "--interactive", name])
                self.assertEqual(calls[1].kwargs["body"], BODY)
                self.assertLessEqual(calls[1].kwargs["timeout"], 70)
                self.assertEqual(calls[2].args[0], ["rm", "--force", name])

    def test_failed_create_failed_start_invalid_response_and_timeout_cleanup(self):
        scenarios = [[done(1), done()], [done(), done(125), done()],
                     [done(), done(stdout=b"garbage"), done()],
                     [done(), done(0, b"", overflow=True), done()],
                     [OSError("docker unavailable"), done()]]
        for steps in scenarios:
            with self.subTest(steps=steps), patch.object(broker, "docker", side_effect=steps) as docker:
                with self.assertRaises(broker.Unavailable):
                    self.service.run(lambda: BODY)
                self.assertEqual(docker.call_args.args[0][:2], ["rm", "--force"])
        with patch.object(broker, "docker", side_effect=[done(), done(-9, timed_out=True), done()]) as docker:
            value = self.service.run(lambda: BODY)
        self.assertIsNone(value["code"])
        self.assertEqual(value["report"], "")
        self.assertIn("deadline", value["output"])
        self.assertEqual(docker.call_args.args[0][:2], ["rm", "--force"])

    def test_failed_cleanup_disables_further_jobs_and_readiness(self):
        with patch.object(broker, "docker", side_effect=[done(), done(stdout=json.dumps(result(0, XML)).encode()),
                                                        done(1), done(stdout=b"123456789abc")]), \
                self.assertRaises(broker.Unavailable):
            self.service.run(lambda: BODY)
        self.assertTrue(self.service.cleanup_failed)
        self.assertFalse(self.service.ready())
        read = Mock(return_value=BODY)
        with self.assertRaises(broker.Unavailable):
            self.service.run(read)
        read.assert_not_called()

    def test_remove_of_never_created_container_verifies_absence(self):
        with patch.object(broker, "docker", side_effect=[done(125), done(1), done()]) as docker, \
                self.assertRaises(broker.Unavailable):
            self.service.run(lambda: BODY)
        self.assertFalse(self.service.cleanup_failed)
        self.assertIn("name=^/secure-coding-room-test-", " ".join(docker.call_args.args[0]))

    def test_startup_cleanup_is_label_scoped(self):
        identifiers = b"0123456789ab\nabcdef012345\n"
        with patch.object(broker, "docker", side_effect=[done(stdout=identifiers), done()]) as docker:
            self.service.cleanup_stale()
        self.assertEqual(docker.call_args_list[0].args[0],
                         ["ps", "--all", "--quiet", "--filter", "label=" + broker.JOB_LABEL])
        self.assertEqual(docker.call_args_list[1].args[0], ["rm", "--force", "0123456789ab", "abcdef012345"])
        for value in (done(1), done(stdout=b"--all")):
            with patch.object(broker, "docker", return_value=value), self.assertRaises(broker.Unavailable):
                self.service.cleanup_stale()

    def test_health_checks_socket_and_fixed_linux_image_in_one_short_call(self):
        for response, expected in [(done(stdout=b"linux\n"), True), (done(1), False),
                                   (done(stdout=b"windows"), False), (done(timed_out=True), False)]:
            with self.subTest(expected=expected), patch.object(broker, "docker", return_value=response) as docker:
                self.assertEqual(self.service.ready(), expected)
                docker.assert_called_once_with(["image", "inspect", "--format", "{{.Os}}", broker.IMAGE], timeout=2)
        self.assertEqual(broker.PORT, 9000)

    def test_queue_allows_one_running_and_four_waiting_then_503(self):
        entered = threading.Event()
        release = threading.Event()
        counts_lock = threading.Lock()
        calls = 0
        active = 0
        peak = 0

        def read():
            nonlocal calls
            with counts_lock:
                calls += 1
                if calls == 5:
                    entered.set()
            return BODY

        def execute(body):
            nonlocal active, peak
            with counts_lock:
                active += 1
                peak = max(peak, active)
            if not release.wait(3):
                raise AssertionError("Test failed to release jobs")
            with counts_lock:
                active -= 1
            return result(5)

        with patch.object(self.service, "_execute", side_effect=execute), ThreadPoolExecutor(max_workers=5) as pool:
            futures = [pool.submit(self.service.run, read) for _ in range(5)]
            try:
                self.assertTrue(entered.wait(2))
                with self.assertRaises(broker.Unavailable):
                    self.service.run(lambda: self.fail("Full queue must not read another body"))
            finally:
                release.set()
            self.assertEqual([future.result(timeout=3)["code"] for future in futures], [5] * 5)
        self.assertEqual(peak, 1)

    def test_queue_timeout_and_invalid_input_release_admission(self):
        self.service.job.acquire()
        try:
            with patch.object(broker, "QUEUE_TIMEOUT", 0.01), self.assertRaises(broker.Unavailable):
                self.service.run(lambda: BODY)
        finally:
            self.service.job.release()
        for _ in range(8):
            with self.assertRaises(broker.InvalidPayload):
                self.service.run(lambda: b"invalid")
        with patch.object(self.service, "_execute", return_value=result(5)):
            self.assertEqual(self.service.run(lambda: BODY), result(5))

    def test_untrusted_wrapper_cannot_overflow_or_inject_xml_entities(self):
        invalid = [b"x" * (MAX_RESPONSE + 1), b'{}', b'{"code":true,"report":"","output":""}',
                   json.dumps(result(0)).encode(), json.dumps(result(9)).encode(),
                   json.dumps(result(0, '<!DOCTYPE x><testsuites/>')).encode(),
                   b'{"code":3,"report":"","output":"\\ud800"}']
        for value in invalid:
            with self.subTest(prefix=value[:60]), self.assertRaises(broker.Unavailable):
                broker.parse_result(value)

    def test_docker_cli_environment_omits_shared_token_and_app_secrets(self):
        with patch.object(broker, "capture", return_value=done()) as capture:
            broker.docker(["info"])
        args = capture.call_args
        self.assertEqual(args.args[0], ["docker", "info"])
        self.assertEqual(set(args.kwargs["env"]), {"PATH", "HOME", "LANG"})


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.service = broker.Broker(TOKEN)

    def test_unauthorized_requests_never_read_or_run(self):
        for authorization in ([], [("Authorization", "wrong")],
                              [("Authorization", "Bearer " + TOKEN), ("Authorization", "Bearer " + TOKEN)]):
            request = handler(self.service, headers=authorization)
            with patch.object(self.service, "run") as run:
                request.do_POST()
            request.send_response.assert_called_once_with(401)
            self.assertEqual(request.rfile.tell(), 0)
            run.assert_not_called()

    def test_success_has_bounded_json_and_no_store_headers(self):
        request = handler(self.service)
        with patch.object(self.service, "_execute", return_value=result(5)):
            request.do_POST()
        request.send_response.assert_called_once_with(200)
        self.assertEqual(json.loads(request.wfile.getvalue()), result(5))
        request.send_header.assert_any_call("Cache-Control", "no-store")
        request.send_header.assert_any_call("Content-Length", str(len(request.wfile.getvalue())))

    def test_content_length_encoding_type_and_short_body_validation(self):
        cases = [([], 411), ([("Content-Length", "-1")], 411),
                 ([("Content-Length", "1"), ("Content-Length", "1")], 411),
                 ([("Content-Length", str(MAX_REQUEST + 1))], 413),
                 ([("Content-Length", "1"), ("Transfer-Encoding", "chunked")], 400),
                 ([("Content-Length", "1"), ("Content-Encoding", "gzip")], 400),
                 ([("Content-Length", "1"), ("Content-Type", "text/plain")], 415),
                 ([("Content-Length", "100"), ("Content-Type", "application/json")], 400)]
        for headers, status in cases:
            with self.subTest(headers=headers):
                request = handler(self.service, body=b"x", headers=[("Authorization", "Bearer " + TOKEN), *headers])
                with patch.object(broker, "docker") as docker:
                    request.do_POST()
                request.send_response.assert_called_once_with(status)
                docker.assert_not_called()

    def test_clean_503_on_full_queue_and_body_timeout(self):
        for failure, status in [(broker.Unavailable("internal detail"), 503), (TimeoutError(), 408)]:
            request = handler(self.service)
            with patch.object(self.service, "run", side_effect=failure):
                request.do_POST()
            request.send_response.assert_called_once_with(status)
            self.assertNotIn("internal detail", request.wfile.getvalue().decode())
            if status == 503:
                request.send_header.assert_any_call("Retry-After", "5")

    def test_health_status_and_unknown_paths(self):
        for ready, status in [(True, 200), (False, 503)]:
            request = handler(self.service, path="/health")
            with patch.object(self.service, "ready", return_value=ready):
                request.do_GET()
            request.send_response.assert_called_once_with(status)
        for method in ("do_GET", "do_POST"):
            request = handler(self.service, path="/unrecognized")
            getattr(request, method)()
            request.send_response.assert_called_once_with(404)

    def test_connection_limit_also_returns_clean_503_without_starting_a_thread(self):
        server = object.__new__(broker.Server)
        server.connections = threading.BoundedSemaphore(0)
        server.shutdown_request = Mock()
        connection = Mock()
        server.process_request(connection, ("unused", 0))
        self.assertTrue(connection.sendall.call_args.args[0].startswith(b"HTTP/1.0 503"))
        server.shutdown_request.assert_called_once_with(connection)


if __name__ == "__main__":
    unittest.main()
