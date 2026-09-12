"""Unit tests for the add-on API boundary."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import json
import os
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
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

    def test_code_is_logged_only_while_unpaired(self):
        """Add-on logs get pasted into issue reports; a live code must not sit there."""
        with tempfile.TemporaryDirectory() as data:
            server = load_server(data)
            code = server.PAIR_CODE

            unpaired = server.startup_lines()
            self.assertTrue(any(code in line for line in unpaired))

            server.STATE["token"] = "already-paired"
            paired = server.startup_lines()
            self.assertFalse(any(code in line for line in paired))
            self.assertTrue(any("paired" in line.lower() for line in paired))

    def test_pairing_code_is_six_digits(self):
        with tempfile.TemporaryDirectory() as data:
            code = load_server(data).PAIR_CODE
            self.assertRegex(code, r"^[0-9]{6}$")


if __name__ == "__main__":
    unittest.main()


class ReportedVersionTest(unittest.TestCase):
    """The status endpoint is how anyone asks what is actually deployed.

    It reported a string typed into server.py, which drifted three releases
    behind config.yaml and made a running add-on indistinguishable from an old
    one.
    """

    def test_status_reports_the_version_the_image_was_built_from(self):
        with tempfile.TemporaryDirectory() as data:
            os.environ["NSPANEL_UPDATER_VERSION"] = "9.9.9"
            try:
                server = load_server(data)
                with running(server) as base:
                    status, payload = get(f"{base}/api/status")
            finally:
                del os.environ["NSPANEL_UPDATER_VERSION"]
            self.assertEqual(200, status)
            self.assertEqual("9.9.9", payload["version"])

    def test_an_unstamped_image_says_so_rather_than_inventing_a_number(self):
        with tempfile.TemporaryDirectory() as data:
            os.environ.pop("NSPANEL_UPDATER_VERSION", None)
            server = load_server(data)
            with running(server) as base:
                status, payload = get(f"{base}/api/status")
            self.assertEqual(200, status)
            self.assertEqual("unknown", payload["version"])


class ReleaseChannelDefaultTest(unittest.TestCase):
    def test_the_default_channel_is_stable(self):
        """It shipped as prerelease because nothing else existed.

        Every early build was a beta or a release candidate, and the picker
        skips those on the stable channel, so the stable default could only
        ever error. Stable releases exist now, and leaving it as it was would
        mean the next release candidate published for testing is offered to
        every panel in the house as though it were finished.
        """
        config = (Path(__file__).parents[1] / "nspanel_updater/config.yaml").read_text()
        default = next(
            line.split(":", 1)[1].strip().strip('"')
            for line in config.splitlines()
            if line.strip().startswith("channel:") and "list(" not in line
        )
        self.assertEqual("stable", default)


class LatestReleaseCacheTest(unittest.TestCase):
    """Answering "is there anything new" without asking GitHub every time.

    The check runs on a timer. GitHub allows sixty unauthenticated requests
    an hour from one address, and a lost connection must not become an error
    someone has to dismiss — so the last good answer is kept and served.
    """

    def server(self, data: str, channel: str = "stable"):
        (Path(data) / "options.json").write_text(json.dumps({"channel": channel}))
        module = load_server(data)
        module.STATE["token"] = "t"
        return module

    def test_a_second_look_inside_the_hour_is_free(self):
        with tempfile.TemporaryDirectory() as data:
            server = self.server(data)
            calls = []

            def tool(arguments, timeout):
                calls.append(arguments)
                return 0, json.dumps({"version": "1.2.2", "version_code": 1020299}), ""

            server.run_tool = tool
            first = server.latest_release(now=1_000.0)
            second = server.latest_release(now=1_100.0)

            self.assertEqual("1.2.2", first["latest"]["version"])
            self.assertEqual(first["latest"], second["latest"])
            self.assertEqual(1, len(calls), "the cached answer should have been used")
            self.assertIn("--channel", calls[0])
            self.assertIn("stable", calls[0])

    def test_an_hour_later_it_looks_again(self):
        with tempfile.TemporaryDirectory() as data:
            server = self.server(data)
            calls = []

            def tool(arguments, timeout):
                calls.append(arguments)
                return 0, json.dumps({"version": "1.2.2", "version_code": 1020299}), ""

            server.run_tool = tool
            server.latest_release(now=1_000.0)
            server.latest_release(now=1_000.0 + server.LATEST_TTL + 1)
            self.assertEqual(2, len(calls))

    def test_a_failed_look_keeps_the_last_answer(self):
        with tempfile.TemporaryDirectory() as data:
            server = self.server(data)
            server.run_tool = lambda arguments, timeout: (
                0, json.dumps({"version": "1.2.2", "version_code": 1020299}), "",
            )
            server.latest_release(now=1_000.0)

            server.run_tool = lambda arguments, timeout: (2, "", "Could not resolve host")
            later = server.latest_release(now=1_000.0 + server.LATEST_TTL + 1)

            self.assertEqual("1.2.2", later["latest"]["version"])
            self.assertIn("Could not resolve host", later["error"])

    def test_nothing_known_yet_and_no_internet_says_so_without_inventing(self):
        with tempfile.TemporaryDirectory() as data:
            server = self.server(data)
            server.run_tool = lambda arguments, timeout: (2, "", "Could not resolve host")
            answer = server.latest_release(now=1_000.0)
            self.assertIsNone(answer["latest"])
            self.assertIn("Could not resolve host", answer["error"])


class OptionsFreshnessTest(unittest.TestCase):
    """Changing an add-on option in the UI must take effect.

    Options were read once at import, so a channel changed in Home Assistant
    kept resolving against the value the container started with. The failure
    was silent and looked like the setting had not saved.
    """

    def test_an_option_changed_after_start_is_used(self):
        with tempfile.TemporaryDirectory() as data:
            options = Path(data) / "options.json"
            options.write_text(json.dumps({"channel": "stable"}))
            server = load_server(data)
            self.assertEqual("stable", server.options().get("channel"))

            options.write_text(json.dumps({"channel": "prerelease"}))
            self.assertEqual("prerelease", server.options().get("channel"))

    def test_a_missing_options_file_reads_as_empty(self):
        with tempfile.TemporaryDirectory() as data:
            server = load_server(data)
            self.assertEqual({}, server.options())


class ReleaseErrorMessageTest(unittest.TestCase):
    """A failure the user can act on.

    'No stable release is available' is true and useless: it does not say that
    prereleases were skipped, that there were any, or which setting to change.
    """

    def load_updater(self):
        path = Path(__file__).parents[1] / "nspanel_updater/nspanel_updater.py"
        spec = spec_from_file_location("shipped_updater", path)
        module = module_from_spec(spec)
        assert spec and spec.loader
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module

    def test_it_says_prereleases_were_skipped_and_how_to_include_them(self):
        updater = self.load_updater()
        releases = [
            {"tag_name": "v1.0.0-rc.1", "draft": False, "prerelease": True},
            {"tag_name": "v1.0.0-beta.5", "draft": False, "prerelease": True},
        ]
        with patch.object(updater, "fetch_json", return_value=releases):
            with self.assertRaises(RuntimeError) as raised:
                updater.release_apk("owner/repo", "stable")
        message = str(raised.exception)
        self.assertIn("2 prerelease(s) were skipped", message)
        self.assertIn("channel", message)

    def test_a_genuinely_empty_repository_says_only_that(self):
        updater = self.load_updater()
        with patch.object(updater, "fetch_json", return_value=[]):
            with self.assertRaises(RuntimeError) as raised:
                updater.release_apk("owner/repo", "stable")
        self.assertEqual("No stable release is available", str(raised.exception))
