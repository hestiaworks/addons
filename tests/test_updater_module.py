"""Unit tests for the add-on's ADB updater module."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

PATH = Path(__file__).parents[1] / "nspanel_updater/nspanel_updater.py"
SPEC = spec_from_file_location("nspanel_updater_module", PATH)
updater = module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = updater
SPEC.loader.exec_module(updater)


class SecureSettingsGrantTest(unittest.TestCase):
    def test_grants_secure_settings_and_reports_whether_it_took(self):
        """The grant is advisory: the panel is usable either way.

        `pm grant` is silent about a permission the installed APK does not
        declare, so the only trustworthy answer comes from reading the
        permission back out of dumpsys.
        """
        granted = """    install permissions:
      android.permission.INTERNET: granted=true
      android.permission.WRITE_SECURE_SETTINGS: granted=true"""
        with patch.object(updater, "run") as fake_run, \
                patch.object(updater, "shell", return_value=granted):
            self.assertTrue(updater.grant_secure_settings("192.0.2.7:5555"))
        self.assertIn("pm", fake_run.call_args[0][0])

    def test_reports_a_refused_grant_without_raising(self):
        refused = """    install permissions:
      android.permission.INTERNET: granted=true"""
        with patch.object(updater, "run"), \
                patch.object(updater, "shell", return_value=refused):
            self.assertFalse(updater.grant_secure_settings("192.0.2.7:5555"))

    def test_does_not_mistake_a_denied_permission_for_a_granted_one(self):
        denied = "      android.permission.WRITE_SECURE_SETTINGS: granted=false"
        with patch.object(updater, "run"), \
                patch.object(updater, "shell", return_value=denied):
            self.assertFalse(updater.grant_secure_settings("192.0.2.7:5555"))

    def test_update_reports_the_grant_and_survives_it_failing(self):
        """An update that installs the app is a success either way.

        The permission only decides whether one setting works, so a panel
        that refuses it still gets the new APK — and is told so plainly
        rather than silently keeping an inert setting.
        """
        for granted, expected in ((True, "Advanced display control enabled."),
                                  (False, "could not be granted")):
            with self.subTest(granted=granted):
                self.assertIn(expected, updater.grant_summary(granted))

    def test_restarts_the_app_and_confirms_it_came_back(self):
        """The reason this path exists is a panel that stopped answering.

        So it cannot ask the app whether it restarted — it has to look. A
        pid that is present after the relaunch is the only evidence that
        means anything here.
        """
        with patch.object(updater, "run") as fake_run, \
                patch.object(updater, "shell", side_effect=["", "4242"]):
            self.assertTrue(updater.restart_app("192.0.2.7:5555"))
        commands = " ".join(" ".join(call[0][0]) for call in fake_run.call_args_list)
        self.assertIn("force-stop", commands)
        self.assertIn("dev.hacompanion.panel/.MainActivity", commands)

    def test_reports_a_restart_that_did_not_come_back(self):
        with patch.object(updater, "run"), patch.object(updater, "shell", return_value=""):
            self.assertFalse(updater.restart_app("192.0.2.7:5555"))


    def test_reboots_the_device_rather_than_the_app(self):
        """A reboot is the device, not the process.

        adb reboot returns as soon as the command is accepted, so there is
        nothing to confirm here and nothing to wait for — the panel is on
        its way down and will not answer again for a minute.
        """
        with patch.object(updater, "run") as fake_run:
            updater.reboot_device("192.0.2.7:5555")
        commands = [" ".join(call[0][0]) for call in fake_run.call_args_list]
        self.assertTrue(any(c.endswith("reboot") for c in commands), commands)


if __name__ == "__main__":
    unittest.main()


class LatestReleaseTest(unittest.TestCase):
    """What the newest release is, without fetching the APK to find out.

    A check runs on a timer and only needs to know what is published. The
    download, its digest and the signer check belong to an install, which
    happens once and deliberately — asking GitHub for a hundred megabytes
    every few hours to answer "is there anything new" would be absurd.
    """

    RELEASES = [
        {"draft": True, "prerelease": False, "tag_name": "v9.9.9", "assets": []},
        {"draft": False, "prerelease": True, "tag_name": "v1.3.0-rc.1", "html_url": "u/rc",
         "published_at": "2026-09-10T00:00:00Z", "assets": [
             {"name": "release.json", "browser_download_url": "meta/rc"}]},
        {"draft": False, "prerelease": False, "tag_name": "v1.2.2", "html_url": "u/stable",
         "published_at": "2026-09-07T00:00:00Z", "assets": [
             {"name": "release.json", "browser_download_url": "meta/stable"}]},
    ]

    def metadata(self, version: str, code: int) -> dict:
        return {
            "application_id": "dev.hacompanion.panel", "abi": "arm64-v8a",
            "certificate_sha256": updater.PINNED_CERTIFICATE_SHA256,
            "apk": f"nspanel-companion-{version}-arm64.apk", "sha256": "a" * 64,
            "version": version, "version_code": code,
        }

    def fetch(self, url: str):
        if url.endswith("/releases"):
            return self.RELEASES
        return self.metadata("1.3.0-rc.1", 1030061) if url == "meta/rc" \
            else self.metadata("1.2.2", 1020299)

    def test_the_stable_channel_skips_a_prerelease(self):
        with patch.object(updater, "fetch_json", self.fetch):
            latest = updater.latest_release("owner/repo", "stable")
        self.assertEqual("1.2.2", latest["version"])
        self.assertEqual(1020299, latest["version_code"])
        self.assertEqual("u/stable", latest["url"])

    def test_the_prerelease_channel_takes_whatever_is_newest(self):
        with patch.object(updater, "fetch_json", self.fetch):
            latest = updater.latest_release("owner/repo", "prerelease")
        self.assertEqual("1.3.0-rc.1", latest["version"])

    def test_a_draft_is_never_offered(self):
        with patch.object(updater, "fetch_json", self.fetch):
            for channel in ("stable", "prerelease"):
                self.assertNotEqual("9.9.9", updater.latest_release("owner/repo", channel)["version"])

    def test_a_release_signed_by_someone_else_is_refused(self):
        def fetch(url: str):
            if url.endswith("/releases"):
                return self.RELEASES
            return {**self.metadata("1.2.2", 1020299), "certificate_sha256": "b" * 64}
        with patch.object(updater, "fetch_json", fetch):
            with self.assertRaises(RuntimeError):
                updater.latest_release("owner/repo", "stable")
