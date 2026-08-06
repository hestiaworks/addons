"""Unit tests for the standalone ADB updater safety boundary."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys
import unittest

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


if __name__ == "__main__":
    unittest.main()
