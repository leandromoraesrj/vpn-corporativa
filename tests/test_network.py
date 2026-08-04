import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vpn_app import network


class ManagedVpnInterfaceTests(unittest.TestCase):
    def test_missing_or_invalid_state_is_disconnected(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "interface"
            self.assertEqual(network.vpn_interface(state), "")
            state.write_text("tun0\n")
            self.assertEqual(network.vpn_interface(state), "")

    def test_only_registered_active_ppp_is_returned(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "interface"
            state.write_text("ppp1\n")
            with mock.patch.object(network, "run_text", return_value="ppp1 UP") as run:
                self.assertEqual(network.vpn_interface(state), "ppp1")
                run.assert_called_once_with(["ip", "-br", "link", "show", "up", "dev", "ppp1"])

    def test_registered_but_inactive_ppp_is_disconnected(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "interface"
            state.write_text("ppp2\n")
            with mock.patch.object(network, "run_text", return_value=""):
                self.assertEqual(network.vpn_interface(state), "")

    def test_detection_runs_against_an_isolated_fake_ip_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "interface"
            state.write_text("ppp7\n")
            fake_ip = root / "ip"
            fake_ip.write_text("#!/bin/sh\nprintf 'ppp7 UP fake-link\\n'\n")
            fake_ip.chmod(0o755)
            environment = {"PATH": f"{root}:{os.environ['PATH']}"}
            with mock.patch.dict(os.environ, environment, clear=True):
                self.assertEqual(network.vpn_interface(state), "ppp7")


class PublicIpTests(unittest.TestCase):
    def setUp(self):
        network._PUBLIC_IP_CACHE = "-"
        network._PUBLIC_IP_CACHE_TIME = 0.0

    def test_rejects_numerically_invalid_ipv4(self):
        with mock.patch.object(network, "run_text", return_value="999.1.1.1"):
            self.assertEqual(network.public_ip(cache_seconds=0), "-")

    def test_accepts_valid_ipv4(self):
        with mock.patch.object(network, "run_text", return_value="203.0.113.10"):
            self.assertEqual(network.public_ip(cache_seconds=0), "203.0.113.10")


if __name__ == "__main__":
    unittest.main()
