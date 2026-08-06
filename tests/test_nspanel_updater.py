"""Unit tests for the standalone ADB updater safety boundary."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import hashlib
import sys
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).parents[1] / "tools/nspanel-updater.py"
SPEC = spec_from_file_location("nspanel_updater", PATH)
updater = module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = updater
SPEC.loader.exec_module(updater)


class UpdaterTest(unittest.TestCase):
    def test_accepts_small_private_network(self):
        network = updater.parse_subnet("192.168.7.0/24")
        self.assertEqual("192.168.7.0/24", str(network))

    def test_rejects_public_or_overly_broad_network(self):
        with self.assertRaises(ValueError):
            updater.parse_subnet("8.8.8.0/24")
        with self.assertRaises(ValueError):
            updater.parse_subnet("10.0.0.0/8")

    def test_panel_record_defaults_to_unknown_and_uninstalled(self):
        panel = updater.Panel("192.168.1.2:5555", "device")
        self.assertEqual("unknown-android", panel.classification)
        self.assertIsNone(panel.app_version)

    def test_extracts_default_home_component(self):
        output = "priority=0 preferredOrder=0\ndev.hacompanion.panel/.MainActivity"
        with patch.object(updater, "shell", return_value=output):
            self.assertEqual(
                "dev.hacompanion.panel/.MainActivity",
                updater.default_home("adb", "192.0.2.6:5555"),
            )

    def test_resolves_stable_and_prerelease_channels(self):
        releases = [
            {"tag_name": "v2.0.0-beta.1", "draft": False, "prerelease": True},
            {"tag_name": "v1.9.0", "draft": False, "prerelease": False},
        ]
        self.assertEqual("v1.9.0", updater.resolve_release(releases, "stable")["tag_name"])
        self.assertEqual("v2.0.0-beta.1", updater.resolve_release(releases, "prerelease")["tag_name"])

    def test_downloads_and_verifies_release(self):
        payload = b"signed apk fixture"
        digest = hashlib.sha256(payload).hexdigest()
        metadata = {
            "application_id": updater.PACKAGE,
            "abi": "arm64-v8a",
            "apk": "nspanel-companion-1.0.0-arm64.apk",
            "sha256": digest,
            "version": "1.0.0",
            "version_code": 1_000_099,
        }
        release = {"draft": False, "prerelease": False, "assets": [
            {"name": "release.json", "browser_download_url": "https://download/metadata"},
            {"name": metadata["apk"], "browser_download_url": "https://download/apk"},
        ]}
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(updater, "fetch_json", side_effect=[[release], metadata]), \
                patch.object(updater, "read_url", return_value=payload):
            apk, result = updater.download_github_release("owner/repo", "stable", Path(directory))
            self.assertEqual(payload, apk.read_bytes())
            self.assertEqual(metadata, result)

    def test_rejects_corrupt_release_download(self):
        payload = b"corrupt"
        metadata = {
            "application_id": updater.PACKAGE,
            "abi": "arm64-v8a",
            "apk": "nspanel-companion-1.0.0-arm64.apk",
            "sha256": "a" * 64,
            "version": "1.0.0",
            "version_code": 1_000_099,
        }
        release = {"draft": False, "prerelease": False, "assets": [
            {"name": "release.json", "browser_download_url": "https://download/metadata"},
            {"name": metadata["apk"], "browser_download_url": "https://download/apk"},
        ]}
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(updater, "fetch_json", side_effect=[[release], metadata]), \
                patch.object(updater, "read_url", return_value=payload):
            with self.assertRaises(RuntimeError):
                updater.download_github_release("owner/repo", "stable", Path(directory))


if __name__ == "__main__":
    unittest.main()
