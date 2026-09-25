"""Black-box tests: local fake Vault, POSIX sh, and real curl/jq. No credentials."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/unlocker.sh"
KEYS = [f"fixture-unseal-share-{i}-not-a-real-key" for i in range(5)]
WRONG_KEYS = [f"fixture-wrong-share-{i}-not-a-real-key" for i in range(5)]


@unittest.skipUnless(shutil.which("curl") and shutil.which("jq"), "curl and jq required")
class UnlockerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.keyfile = self.directory / "keys"
        self.keyfile.write_text("\n".join(KEYS) + "\n")
        self.status = dict(initialized=True, sealed=True, type="shamir", t=3,
                           n=5, progress=0, migration=False)
        self.accepted = set()
        self.requests = []
        self.fault = None
        self.put_fault = None
        self.write_times = []
        self.lock = threading.RLock()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                self.respond()

            def do_POST(self):
                self.respond()

            def do_PUT(self):
                self.respond()

            def respond(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                with owner.lock:
                    owner.requests.append((self.command, self.path, body))
                    if self.command != "GET":
                        owner.write_times.append(time.monotonic())
                    code, result = 200, dict(owner.status)
                    if owner.fault:
                        code, result = owner.fault
                    elif self.command == "PUT" and owner.put_fault:
                        result.update(owner.put_fault)
                    elif self.command != "GET":
                        if self.path != "/v1/sys/unseal":
                            code, result = 405, {"errors": ["unexpected write"]}
                        else:
                            try:
                                payload = json.loads(body)
                            except ValueError:
                                payload = {}
                            key = payload.get("key")
                            if key not in KEYS or set(payload) != {"key"}:
                                code, result = 400, {"errors": ["invalid key"]}
                            else:
                                owner.accepted.add(key)
                                owner.status["progress"] = len(owner.accepted)
                                if len(owner.accepted) >= owner.status["t"]:
                                    owner.status.update(sealed=False, progress=0)
                                result = dict(owner.status)
                data = result.encode() if isinstance(result, str) else json.dumps(result).encode()
                try:
                    self.send_response(code)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(self.server.server_close)
        self.thread = None
        self.process = None
        self.output = self.directory / "output"
        self.argvlog = self.directory / "argv"
        # Keep real executables; record argv to catch secret leakage into process lists.
        for command in ("curl", "jq"):
            wrapper = self.directory / command
            allowed = [f"http://127.0.0.1:{self.server.server_port}/v1/sys/{endpoint}"
                       for endpoint in ("seal-status", "unseal")]
            guard = ("urls = [a for a in sys.argv[1:] if '://' in a]\n"
                     f"if len(urls) != 1 or urls[0] not in {allowed!r}:\n"
                     "    sys.exit(93)\n") if command == "curl" else ""
            wrapper.write_text(
                f"#!{sys.executable}\nimport json, os, sys\n"
                f"with open({str(self.argvlog)!r}, 'a') as f:\n"
                "    f.write(json.dumps(sys.argv[1:]) + '\\n')\n"
                + guard +
                f"os.execv({shutil.which(command)!r}, [{command!r}] + sys.argv[1:])\n")
            wrapper.chmod(0o700)
        kubectl = self.directory / "kubectl"
        kubectl.write_text("#!/bin/sh\nexit 93\n")
        kubectl.chmod(0o700)
        self.addCleanup(self.stop)

    def serve(self):
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def start(self, serve=True):
        if serve:
            self.serve()
        env = dict(os.environ, VAULT_ADDR=f"http://127.0.0.1:{self.server.server_port}",
                   UNSEAL_KEYS_FILE=str(self.keyfile), CHECK_INTERVAL="1", HTTP_TIMEOUT="1",
                   PATH=f"{self.directory}{os.pathsep}{os.environ['PATH']}",
                   NO_PROXY="127.0.0.1", no_proxy="127.0.0.1")
        with self.output.open("w") as output:
            self.process = subprocess.Popen(["/bin/sh", str(SCRIPT)], env=env,
                                            stdout=output, stderr=output, start_new_session=True)

    def stop_process(self):
        if self.process is not None:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            self.process.wait(timeout=5)

    def stop(self):
        self.stop_process()
        if self.thread is not None:
            self.server.shutdown()
            self.thread.join(timeout=5)

    def wait_for(self, predicate, timeout=8):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.lock:
                if predicate():
                    return
            time.sleep(0.02)
        self.fail("condition not reached before timeout: " + self.output.read_text())

    def writes(self):
        return [request for request in self.requests if request[0] != "GET"]

    def assert_private(self):
        observed = self.output.read_text() + self.argvlog.read_text()
        for key in KEYS + WRONG_KEYS:
            self.assertNotIn(key, observed)

    def assert_no_success(self):
        self.assertNotRegex(self.output.read_text().lower(),
                            r"vault (?:is |successfully )?unsealed|unseal(?:ing)? succe")

    def test_uninitialized_never_initializes(self):
        self.status["initialized"] = False
        self.start()
        self.wait_for(lambda: len(self.requests) >= 2 or self.process.poll() is not None)
        self.assertTrue(self.requests)
        self.assertEqual(self.writes(), [])
        self.assert_no_success()

    def test_already_unsealed_never_posts(self):
        self.status["sealed"] = False
        self.start()
        self.wait_for(lambda: len(self.requests) >= 2)
        self.assertEqual(self.writes(), [])

    def test_migration_and_non_shamir_refused(self):
        for changed in ({"migration": True}, {"type": "yandexcloudkms"}):
            with self.subTest(changed=changed):
                self.status.update(type="shamir", migration=False)
                self.status.update(changed)
                self.requests.clear()
                self.start(serve=self.thread is None)
                self.wait_for(lambda: len(self.requests) >= 2 or self.process.poll() is not None)
                self.assertTrue(self.requests)
                self.assertEqual(self.writes(), [])
                self.assert_no_success()
                self.stop_process()

    def test_insufficient_or_duplicate_keys_never_posts(self):
        for keys in (KEYS[:2], [KEYS[0]] * 5):
            with self.subTest(unique_keys=len(set(keys))):
                self.keyfile.write_text("\n".join(keys) + "\n")
                self.requests.clear()
                self.start(serve=self.thread is None)
                self.wait_for(lambda: len(self.requests) >= 2 or self.process.poll() is not None)
                self.assertTrue(self.requests)
                self.assertEqual(self.writes(), [])
                self.assert_no_success()
                self.assert_private()
                self.stop_process()

    def test_http_failure_and_malformed_json_retry_without_writes(self):
        self.fault = (503, {"errors": ["temporarily unavailable"]})
        self.start()
        self.wait_for(lambda: len(self.requests) >= 2)
        self.assertEqual(self.writes(), [])
        self.assert_no_success()
        with self.lock:
            self.fault = (200, "not-json")
            self.requests.clear()
        self.wait_for(lambda: len(self.requests) >= 2)
        self.assertEqual(self.writes(), [])
        self.assert_no_success()
        self.fault = None
        self.wait_for(lambda: not self.status["sealed"])
        self.assert_private()

    def test_unavailable_api_recovers(self):
        self.start(serve=False)
        time.sleep(1.5)  # One real curl timeout, while the listening socket has no handler.
        self.assert_no_success()
        self.assertIsNone(self.process.poll())
        self.serve()
        self.wait_for(lambda: not self.status["sealed"])

    def test_redirect_or_multiple_json_objects_never_posts(self):
        stream = json.dumps(self.status) + "\n" + json.dumps(self.status)
        for fault in ((302, dict(self.status)), (200, stream)):
            with self.subTest(http_status=fault[0]):
                self.fault = fault
                self.requests.clear()
                self.start(serve=self.thread is None)
                self.wait_for(lambda: len(self.requests) >= 2)
                self.stop_process()
                self.assertEqual(self.writes(), [])
                self.assert_no_success()

    def test_ineligible_put_response_stops_cycle(self):
        for changed in ({"migration": True}, {"type": "yandexcloudkms"},
                        {"initialized": False}):
            with self.subTest(changed=changed):
                self.put_fault = changed
                self.requests.clear()
                self.write_times.clear()
                self.start(serve=self.thread is None)
                self.wait_for(lambda: len(self.writes()) >= 2)
                self.stop_process()
                self.assertGreaterEqual(self.write_times[1] - self.write_times[0], 1)
                self.assertEqual([method for method, _, _ in self.requests[:4]],
                                 ["GET", "PUT", "GET", "PUT"])
                self.assertTrue(self.status["sealed"])
                self.assert_no_success()
                self.assert_private()

    def test_server_threshold_partial_progress_and_restart(self):
        self.status.update(t=4, progress=1)
        self.accepted = {KEYS[0]}
        self.start()
        self.wait_for(lambda: not self.status["sealed"])
        self.assertEqual(self.accepted, set(KEYS[:4]))
        with self.lock:
            self.accepted.clear()
            self.status.update(sealed=True, progress=0, t=2)
            self.requests.clear()
        self.wait_for(lambda: not self.status["sealed"])
        self.assertEqual(self.accepted, set(KEYS[:2]))
        self.assertTrue(all(path == "/v1/sys/unseal" for _, path, _ in self.writes()))
        self.assert_private()

    def test_wrong_key_no_success_then_file_rotation_recovers(self):
        self.keyfile.write_text("\n".join(WRONG_KEYS) + "\n")
        self.start()
        self.wait_for(lambda: len(self.writes()) >= 2)
        self.assertTrue(self.status["sealed"])
        self.assert_no_success()
        replacement = self.directory / "replacement"
        replacement.write_text("\n".join(KEYS) + "\n")
        replacement.replace(self.keyfile)
        self.wait_for(lambda: not self.status["sealed"])
        self.assert_private()


if __name__ == "__main__":
    unittest.main()
