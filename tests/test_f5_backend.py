from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vpn_app import f5_backend


class F5BackendTests(unittest.TestCase):
    def test_active_interface_and_valid_ipv4_are_connected(self):
        connected = f5_backend.F5Status(
            True, True, True, "NÃO CONFIGURADA", "", "192.0.2.2", "tun0"
        )
        self.assertTrue(connected.connected)
        self.assertEqual(connected.label, "CONECTADA")

    def test_missing_route_does_not_disconnect_active_interface(self):
        connected = f5_backend.F5Status(
            True, True, True, "AUSENTE", "", "192.0.2.2", "tun0"
        )
        self.assertTrue(connected.connected)
        self.assertEqual(connected.route_state, "AUSENTE")
        self.assertFalse(connected.inconsistent)

    @mock.patch("vpn_app.f5_backend.subprocess.run")
    def test_route_status_is_independent_from_connection(self, run):
        run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch.object(
            f5_backend, "configured_route", return_value="198.51.100.0/24"
        ):
            self.assertEqual(f5_backend.route_status(interface="tun0"), "AUSENTE")

    def test_route_status_reports_not_configured(self):
        with mock.patch.object(f5_backend, "configured_route", return_value=""):
            self.assertEqual(
                f5_backend.route_status(interface="tun0"),
                "NÃO CONFIGURADA",
            )

    def test_missing_interface_is_disconnected(self):
        disconnected = f5_backend.F5Status(
            False, False, False, "NÃO CONFIGURADA", "", "-", ""
        )
        self.assertFalse(disconnected.connected)
        self.assertFalse(disconnected.inconsistent)
        self.assertEqual(disconnected.label, "DESCONECTADA")

    def test_registered_tunnel_without_interface_is_inconsistent(self):
        inconsistent = f5_backend.F5Status(
            True, True, False, "INDETERMINADA", "", "-", ""
        )
        self.assertFalse(inconsistent.connected)
        self.assertTrue(inconsistent.inconsistent)
        self.assertEqual(inconsistent.label, "ESTADO INCONSISTENTE")

    def test_authentication_control_follows_connection_state(self):
        connected = f5_backend.F5Status(
            True, True, True, "AUSENTE", "", "192.0.2.2", "tun0"
        )
        disconnected = f5_backend.F5Status(
            False, False, False, "NÃO CONFIGURADA", "", "-", ""
        )
        self.assertFalse(f5_backend.authentication_enabled(connected))
        self.assertTrue(f5_backend.authentication_enabled(disconnected))

    def test_open_window_without_tunnel_is_not_connected(self):
        window_only = f5_backend.F5Status(
            True, False, False, "NÃO CONFIGURADA", "0x1", "-", ""
        )
        self.assertFalse(window_only.connected)
        self.assertFalse(window_only.inconsistent)
        self.assertTrue(f5_backend.window_controls_enabled(window_only))

    def test_window_controls_follow_window_detection_not_tunnel(self):
        tunnel_without_window = f5_backend.F5Status(
            True, True, True, "NÃO CONFIGURADA", "", "192.0.2.2", "tun0"
        )
        disconnected_without_window = f5_backend.F5Status(
            False, False, False, "NÃO CONFIGURADA", "", "-", ""
        )
        connected_with_window = f5_backend.F5Status(
            True, True, True, "NÃO CONFIGURADA", "0x1", "192.0.2.2", "tun0"
        )

        self.assertFalse(f5_backend.window_controls_enabled(tunnel_without_window))
        self.assertFalse(f5_backend.window_controls_enabled(disconnected_without_window))
        self.assertTrue(f5_backend.window_controls_enabled(connected_with_window))

    @mock.patch("vpn_app.f5_backend.window_id", return_value="")
    @mock.patch("vpn_app.f5_backend.route_status", return_value="AUSENTE")
    @mock.patch("vpn_app.f5_backend.interface_ipv4", return_value="192.0.2.2")
    @mock.patch("vpn_app.f5_backend.detected_interface", return_value="tun0")
    @mock.patch("vpn_app.f5_backend._process_running", side_effect=[True, True])
    def test_status_reports_detected_interface_and_ip(
        self, _process, _interface, _ipv4, _route, _window
    ):
        current = f5_backend.status()
        self.assertTrue(current.connected)
        self.assertEqual(current.interface, "tun0")
        self.assertEqual(current.interface_ip, "192.0.2.2")
        self.assertEqual(current.route_state, "AUSENTE")

    @mock.patch("vpn_app.f5_backend._run")
    def test_window_id_uses_exact_wm_class(self, run):
        run.return_value = (
            "0x111 0 other.App host Other\n"
            "0x03000019 0 f5vpn.F5 VPN host /Common/VPN_Secondary - F5 VPN"
        )
        self.assertEqual(f5_backend.window_id(), "0x03000019")

    @mock.patch("vpn_app.f5_backend.window_id", return_value="0x03000019")
    @mock.patch("vpn_app.f5_backend.subprocess.run")
    def test_hide_uses_working_windowminimize_command(self, run, _window):
        run.return_value = mock.Mock(returncode=0, stderr="")
        ok, _message = f5_backend.hide_window()
        self.assertTrue(ok)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(
            run.call_args_list[0].args[0],
            ["wmctrl", "-i", "-r", "0x03000019", "-b", "add,skip_taskbar"],
        )
        self.assertEqual(
            run.call_args_list[1].args[0],
            ["xdotool", "windowminimize", "0x03000019"],
        )

    @mock.patch("vpn_app.f5_backend.window_id", return_value="0x03000019")
    @mock.patch("vpn_app.f5_backend.subprocess.run")
    def test_show_restores_taskbar_and_activates_window(self, run, _window):
        run.return_value = mock.Mock(returncode=0, stderr="")
        ok, _message = f5_backend.show_window()
        self.assertTrue(ok)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(
            run.call_args_list[0].args[0],
            ["wmctrl", "-i", "-r", "0x03000019", "-b", "remove,skip_taskbar"],
        )
        self.assertEqual(
            run.call_args_list[1].args[0],
            ["wmctrl", "-i", "-a", "0x03000019"],
        )


    @mock.patch("vpn_app.f5_backend.subprocess.Popen")
    @mock.patch("vpn_app.f5_backend.shutil.which")
    def test_launch_opens_secondary_portal_in_chrome(self, which, popen):
        which.side_effect = lambda name: "/usr/bin/google-chrome" if name == "google-chrome" else None
        with mock.patch.object(
            f5_backend,
            "configured_portal_url",
            return_value="https://vpn.valid.test/login",
        ):
            ok, message = f5_backend.launch()
        self.assertTrue(ok)
        self.assertIn("Portal da VPN secundária", message)
        self.assertEqual(
            popen.call_args.args[0],
            ["google-chrome", "https://vpn.valid.test/login"],
        )

    @mock.patch("vpn_app.f5_backend.subprocess.Popen")
    def test_launch_rejects_example_url(self, popen):
        with mock.patch.object(
            f5_backend,
            "configured_portal_url",
            return_value="https://vpn.example.com/",
        ):
            ok, message = f5_backend.launch()
        self.assertFalse(ok)
        self.assertIn("Configure uma URL HTTPS", message)
        popen.assert_not_called()

    def test_process_detection_matches_exact_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            (proc / "100").mkdir()
            (proc / "100" / "cmdline").write_bytes(b"/opt/f5/vpn/svpn\0")
            with mock.patch.object(f5_backend, "Path") as path_cls:
                path_cls.return_value = proc
                self.assertTrue(f5_backend._process_running("/opt/f5/vpn/svpn"))


if __name__ == "__main__":
    unittest.main()
