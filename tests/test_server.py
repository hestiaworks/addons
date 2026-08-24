"""Unit tests for the add-on API boundary."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import contextmanager
from http.server import ThreadingHTTPServer

PATH = Path(__file__).parents[1] / "nspanel_updater/server.py"


def load_server(data_dir: str):
    """Import server.py against a throwaway data directory."""
    os.environ["NSPANEL_UPDATER_DATA"] = data_dir
    spec = spec_from_file_location("updater_server", PATH)
    module = module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@contextmanager
def running(server_module):
    """Serve the real handler on loopback and yield its base URL."""
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server_module.Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def get(url: str) -> tuple[int, dict]:
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"{}")


def post(url: str, payload: dict) -> tuple[int, dict]:
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"{}")


class PairCodeBoundaryTest(unittest.TestCase):
    def test_pairing_code_is_offered_only_to_the_local_host(self):
        """The code authorises pairing, so the LAN must never be able to read it."""
        with tempfile.TemporaryDirectory() as data:
            server = load_server(data)
            self.assertTrue(server.is_loopback("127.0.0.1"))
            self.assertTrue(server.is_loopback("::1"))
            self.assertFalse(server.is_loopback("192.168.0.76"))
            self.assertFalse(server.is_loopback(""))

    def test_local_caller_can_read_the_pairing_code(self):
        with tempfile.TemporaryDirectory() as data:
            server = load_server(data)
            with running(server) as base:
                status, payload = get(f"{base}/api/pair-code")
            self.assertEqual(200, status)
            self.assertEqual(server.PAIR_CODE, payload["code"])
            self.assertEqual(server.STATE["id"], payload["id"])

    def test_remote_caller_is_refused_the_pairing_code(self):
        """Proves the route consults the guard rather than merely defining it."""
        with tempfile.TemporaryDirectory() as data:
            server = load_server(data)
            original = server.is_loopback
            server.is_loopback = lambda address: False
            try:
                with running(server) as base:
                    status, payload = get(f"{base}/api/pair-code")
            finally:
                server.is_loopback = original
            self.assertEqual(403, status)
            self.assertNotIn("code", payload)


class PairCodeLifetimeTest(unittest.TestCase):
    def test_pairing_code_survives_a_restart(self):
        """A restart mid-pairing would otherwise invalidate the offered code."""
        with tempfile.TemporaryDirectory() as data:
            first = load_server(data).PAIR_CODE
            second = load_server(data).PAIR_CODE
            self.assertEqual(first, second)

    def test_pairing_consumes_the_code(self):
        """A code that stays valid after use is a standing key to the updater."""
        with tempfile.TemporaryDirectory() as data:
            server = load_server(data)
            used = server.PAIR_CODE
            with running(server) as base:
                status, paired = post(f"{base}/api/pair", {"code": used})
                self.assertEqual(200, status)
                self.assertTrue(paired["token"])

                replay, _ = post(f"{base}/api/pair", {"code": used})
                self.assertEqual(403, replay)

                _, offered = get(f"{base}/api/pair-code")
                self.assertNotEqual(used, offered["code"])

    def test_pairing_code_is_six_digits(self):
        with tempfile.TemporaryDirectory() as data:
            code = load_server(data).PAIR_CODE
            self.assertRegex(code, r"^[0-9]{6}$")


if __name__ == "__main__":
    unittest.main()
