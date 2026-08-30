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


if __name__ == "__main__":
    unittest.main()
