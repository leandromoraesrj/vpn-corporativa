from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vpn_app import f5_backend


class F5BackendTests(unittest.TestCase):
    def setUp(self):
        f5_backend._validation_snapshot = None

    @staticmethod
    def _snapshot(process_pids=(10,), interfaces=("tun0",), ipv4=("192.0.2.2",), routes=()):
        return f5_backend.ValidationSnapshot(
            process_pids=frozenset(process_pids),
            interfaces=frozenset(interfaces),
            interface_ipv4=tuple((name, value) for name, value in zip(interfaces, ipv4)),
            routes=frozenset(routes),
            captured_at=0.0,
        )

    def test_old_process_and_interface_are_not_accepted(self):
        f5_backend._validation_snapshot = self._snapshot(
            process_pids=(10,), interfaces=("tun0",), ipv4=("192.0.2.2",)
        )
        with mock.patch.object(f5_backend, "interface_up", return_value=True):
            state = f5_backend._strong_validation(
                frozenset({10}), "tun0", "192.0.2.2", ("198.51.100.0/24",)
            )
        self.assertEqual(state, "AMBÍGUA")

    def test_new_interface_with_old_process_is_not_accepted(self):
        f5_backend._validation_snapshot = self._snapshot(
            process_pids=(11,), interfaces=("tun-old",), ipv4=("192.0.2.1",)
        )
        with mock.patch.object(f5_backend, "interface_up", return_value=True):
            state = f5_backend._strong_validation(
                frozenset({11}), "tun0", "192.0.2.2", ("198.51.100.0/24",)
            )
        self.assertEqual(state, "AMBÍGUA")

    def test_new_process_interface_and_routes_without_association_are_ambiguous(self):
        f5_backend._validation_snapshot = self._snapshot(
            process_pids=(), interfaces=(), ipv4=(), routes=()
        )
        with mock.patch.object(f5_backend, "interface_up", return_value=True), mock.patch.object(
            f5_backend, "_route_present", return_value=({"new-route"}, True)
        ):
            state = f5_backend._strong_validation(
                frozenset({11}), "tun0", "192.0.2.2", ("198.51.100.0/24",)
            )
        self.assertEqual(state, "AMBÍGUA")

    def test_technical_association_is_conservative_without_client_evidence(self):
        self.assertIsNone(f5_backend.technical_association(11, "tun0"))

    def test_configured_interface_with_ipv4_is_operationally_connected(self):
        with mock.patch.object(f5_backend, "configured_interface", return_value="vpn0"), mock.patch.object(
            f5_backend, "is_configured_tunnel_interface", return_value=True
        ), mock.patch.object(f5_backend, "interface_up", return_value=True), mock.patch.object(
            f5_backend, "interface_ipv4", return_value="192.0.2.2"
        ), mock.patch.object(f5_backend, "_process_running", return_value=False), mock.patch.object(
            f5_backend, "_technical_process_pids", return_value=frozenset()
        ), mock.patch.object(f5_backend, "window_id", return_value=""):
            current = f5_backend.status()
        self.assertTrue(current.connected)
        self.assertEqual(current.label, "CONECTADA")
        self.assertEqual(current.diagnostic_label, "AMBÍGUA")

    def test_discovery_lists_tunnel_candidates_with_system_details(self):
        details = (
            '[{"ifname":"tun0","flags":["UP"],"operstate":"UP",'
            '"linkinfo":{"info_kind":"tun"}},'
            '{"ifname":"tailscale0","flags":["UP"],"operstate":"UP",'
            '"linkinfo":{"info_kind":"tun"}},'
            '{"ifname":"docker0","flags":["UP"],"operstate":"UP",'
            '"linkinfo":{"info_kind":"bridge"}}]'
        )
        route_result = mock.Mock(
            returncode=0,
            stdout='[{"dst":"198.51.100.0/24","dev":"tun0","metric":10}]',
            stderr="",
        )

        def run(command, **_kwargs):
            if command[:4] == ["ip", "-json", "-details", "link"]:
                return mock.Mock(returncode=0, stdout=details, stderr="")
            return route_result

        with mock.patch.object(f5_backend, "_run", side_effect=lambda command: details if command[:4] == ["ip", "-json", "-details", "link"] else "tun0 UP 192.0.2.2/24"), mock.patch.object(
            f5_backend.subprocess, "run", side_effect=run
        ):
            candidates = f5_backend.discover_interface_candidates()
        self.assertEqual([candidate.name for candidate in candidates], ["tun0"])
        self.assertEqual(candidates[0].kind, "tun")
        self.assertEqual(candidates[0].ipv4, "192.0.2.2")
        self.assertEqual(candidates[0].routes, ("198.51.100.0/24",))

    def test_empty_discovery_does_not_select_an_interface(self):
        with mock.patch.object(f5_backend, "_interface_details", return_value=[]):
            self.assertEqual(f5_backend.discover_interface_candidates(), ())

    def test_discovery_reports_inactive_and_non_tunnel_interfaces_without_promoting_them(self):
        details = [
            {"ifname": "tun-a", "flags": [], "operstate": "DOWN", "linkinfo": {"info_kind": "tun"}},
            {"ifname": "eth0", "flags": ["UP"], "operstate": "UP", "linkinfo": {"info_kind": "ether"}},
        ]
        with mock.patch.object(f5_backend, "_interface_details", return_value=details), mock.patch.object(
            f5_backend, "interface_ipv4", return_value="-"
        ), mock.patch.object(f5_backend, "_related_routes", return_value=()):
            candidates = f5_backend.discover_interface_candidates()
        self.assertEqual([candidate.name for candidate in candidates], ["tun-a"])
        self.assertFalse(candidates[0].active)
        self.assertEqual(candidates[0].ipv4, "")
        self.assertIn("sem IPv4 válido", candidates[0].observation)

    def test_discovery_keeps_multiple_candidates_for_explicit_user_selection(self):
        details = [
            {"ifname": "tun-b", "flags": ["UP"], "operstate": "UP", "linkinfo": {"info_kind": "tun"}},
            {"ifname": "tun-a", "flags": ["UP"], "operstate": "UP", "linkinfo": {"info_kind": "tun"}},
        ]
        with mock.patch.object(f5_backend, "_interface_details", return_value=details), mock.patch.object(
            f5_backend, "interface_ipv4", side_effect=["192.0.2.2", "192.0.2.3"]
        ), mock.patch.object(f5_backend, "_related_routes", return_value=("198.51.100.0/24",)):
            candidates = f5_backend.discover_interface_candidates()
        self.assertEqual([candidate.name for candidate in candidates], ["tun-a", "tun-b"])

    def test_multiple_routes_require_all_routes(self):
        f5_backend._validation_snapshot = self._snapshot(
            process_pids=(), interfaces=(), ipv4=(), routes=()
        )
        with mock.patch.object(f5_backend, "interface_up", return_value=True), mock.patch.object(
            f5_backend, "_route_present", side_effect=[({"new-route"}, True), (set(), False)]
        ):
            state = f5_backend._strong_validation(
                frozenset({11}), "tun0", "192.0.2.2",
                ("198.51.100.0/24", "203.0.113.0/24"),
            )
        self.assertEqual(state, "INCONSISTENTE")

    def test_route_already_in_snapshot_is_rejected(self):
        f5_backend._validation_snapshot = self._snapshot(
            process_pids=(), interfaces=(), ipv4=(), routes=("old-route",)
        )
        with mock.patch.object(f5_backend, "interface_up", return_value=True), mock.patch.object(
            f5_backend, "_route_present", return_value=({"old-route"}, True)
        ):
            state = f5_backend._strong_validation(
                frozenset({11}), "tun0", "192.0.2.2", ("198.51.100.0/24",)
            )
        self.assertEqual(state, "INCONSISTENTE")

    def test_new_route_without_explicit_association_is_ambiguous(self):
        f5_backend._validation_snapshot = self._snapshot(
            process_pids=(), interfaces=(), ipv4=(), routes=("old-route",)
        )
        with mock.patch.object(f5_backend, "interface_up", return_value=True), mock.patch.object(
            f5_backend, "_route_present", return_value=({"new-route"}, True)
        ):
            state = f5_backend._strong_validation(
                frozenset({11}), "tun0", "192.0.2.2", ("198.51.100.0/24",)
            )
        self.assertEqual(state, "AMBÍGUA")

    def test_route_json_parser_excludes_default_and_preserves_identity(self):
        payload = '[{"dst":"default","dev":"tun0"},{"dst":"198.51.100.0/24","gateway":"192.0.2.1","dev":"tun0","metric":10}]'
        result = mock.Mock(returncode=0, stdout=payload, stderr="")
        with mock.patch.object(f5_backend.subprocess, "run", return_value=result):
            parsed = f5_backend._json_routes()
        self.assertIsNotNone(parsed)
        identities, _routes = parsed
        self.assertEqual(len(identities), 1)
        self.assertIn("192.0.2.1", next(iter(identities)))

    def test_default_route_never_validates_connection(self):
        f5_backend._validation_snapshot = self._snapshot(
            process_pids=(), interfaces=(), ipv4=(), routes=()
        )
        with mock.patch.object(f5_backend, "interface_up", return_value=True), mock.patch.object(
            f5_backend, "_route_present", return_value=({"default"}, True)
        ):
            state = f5_backend._strong_validation(
                frozenset({11}), "tun0", "192.0.2.2", ("0.0.0.0/0",)
            )
        self.assertEqual(state, "INCONSISTENTE")

    def test_unconfigured_tunnel_interfaces_are_ignored(self):
        with mock.patch.object(f5_backend, "configured_interface", return_value=""), mock.patch.object(
            f5_backend, "is_configured_tunnel_interface", return_value=False
        ):
            self.assertEqual(f5_backend.detected_interfaces(True), ())
            self.assertEqual(f5_backend.detected_interface(True), "")

    def test_configured_routes_reads_repeated_route_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "secondary.conf"
            config.write_text(
                "route = 198.51.100.0/24\n"
                "route = 203.0.113.9/24\n"
                "route = 0.0.0.0/0\n"
                "route = 192.0.2.0/24\n",
                encoding="utf-8",
            )
            with mock.patch.object(f5_backend.config_store, "SECONDARY_FILE", config):
                self.assertEqual(
                    f5_backend.configured_routes(),
                    ("198.51.100.0/24", "203.0.113.0/24"),
                )

    @mock.patch("vpn_app.f5_backend.subprocess.Popen")
    @mock.patch("vpn_app.f5_backend.begin_validation")
    def test_manual_launch_captures_snapshot_before_opening_portal(self, snapshot, popen):
        with mock.patch.object(
            f5_backend,
            "configured_portal_url",
            return_value="https://vpn.valid.test/login",
        ), mock.patch.object(f5_backend.shutil, "which", return_value=None):
            ok, _message = f5_backend.launch()
        self.assertTrue(ok)
        snapshot.assert_called_once_with()
        popen.assert_called_once()

    def test_multiple_processes_are_ambiguous(self):
        f5_backend._validation_snapshot = self._snapshot(
            process_pids=(), interfaces=(), ipv4=(), routes=()
        )
        state = f5_backend._strong_validation(
            frozenset({11, 12}), "tun0", "192.0.2.2", ("198.51.100.0/24",)
        )
        self.assertEqual(state, "AMBÍGUA")

    def test_partial_interface_and_ipv4_evidence_is_not_connected(self):
        status = f5_backend.F5Status(
            True, True, True, "PRESENTE", "", "192.0.2.2", "tun0"
        )
        self.assertFalse(status.connected)
        self.assertEqual(status.label, "DESCONECTADA")
        self.assertEqual(status.diagnostic_label, "AMBÍGUA")

    def test_missing_route_does_not_disconnect_active_interface(self):
        connected = f5_backend.F5Status(
            client_running=True,
            tunnel_running=True,
            interface_up=True,
            route_state="AUSENTE",
            window_id="",
            interface_ip="192.0.2.2",
            interface="tun0",
            validation_state="INCONSISTENTE",
            operational_state="CONECTADA",
        )
        self.assertTrue(connected.connected)
        self.assertEqual(connected.route_state, "AUSENTE")
        self.assertTrue(connected.inconsistent)

    @mock.patch("vpn_app.f5_backend.subprocess.run")
    def test_route_status_is_independent_from_connection(self, run):
        with mock.patch.object(
            f5_backend, "_route_present", return_value=(set(), False)
        ), mock.patch.object(
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
            False, False, False, "NÃO CONFIGURADA", "", "-", "", "DESCONECTADA"
        )
        self.assertFalse(disconnected.connected)
        self.assertFalse(disconnected.inconsistent)
        self.assertEqual(disconnected.label, "DESCONECTADA")

    def test_registered_tunnel_without_interface_is_inconsistent(self):
        inconsistent = f5_backend.F5Status(
            True, True, False, "INDETERMINADA", "", "-", "", "INCONSISTENTE"
        )
        self.assertFalse(inconsistent.connected)
        self.assertTrue(inconsistent.inconsistent)
        self.assertEqual(inconsistent.label, "DESCONECTADA")
        self.assertEqual(inconsistent.diagnostic_label, "INCONSISTENTE")

    def test_authentication_control_follows_connection_state(self):
        connected = f5_backend.F5Status(
            client_running=True,
            tunnel_running=True,
            interface_up=True,
            route_state="PRESENTE",
            window_id="",
            interface_ip="192.0.2.2",
            interface="tun0",
            validation_state="AMBÍGUA",
            operational_state="CONECTADA",
        )
        disconnected = f5_backend.F5Status(
            client_running=False,
            tunnel_running=False,
            interface_up=False,
            route_state="NÃO CONFIGURADA",
            window_id="",
            interface_ip="-",
            interface="",
            validation_state="DESCONECTADA",
            operational_state="DESCONECTADA",
        )
        self.assertFalse(f5_backend.authentication_enabled(connected))
        self.assertTrue(f5_backend.authentication_enabled(disconnected))

    def test_open_window_without_tunnel_is_not_connected(self):
        window_only = f5_backend.F5Status(
            True, False, False, "NÃO CONFIGURADA", "0x1", "-", "", "DESCONECTADA"
        )
        self.assertFalse(window_only.connected)
        self.assertFalse(window_only.inconsistent)
        self.assertTrue(f5_backend.window_controls_enabled(window_only))

    def test_window_controls_follow_window_detection_not_tunnel(self):
        tunnel_without_window = f5_backend.F5Status(
            True, True, True, "PRESENTE", "", "192.0.2.2", "tun0", "AMBÍGUA"
        )
        disconnected_without_window = f5_backend.F5Status(
            False, False, False, "NÃO CONFIGURADA", "", "-", "", "DESCONECTADA"
        )
        connected_with_window = f5_backend.F5Status(
            True, True, True, "PRESENTE", "0x1", "192.0.2.2", "tun0", "AMBÍGUA"
        )

        self.assertFalse(f5_backend.window_controls_enabled(tunnel_without_window))
        self.assertFalse(f5_backend.window_controls_enabled(disconnected_without_window))
        self.assertTrue(f5_backend.window_controls_enabled(connected_with_window))

    @mock.patch("vpn_app.f5_backend.window_id", return_value="")
    @mock.patch("vpn_app.f5_backend.route_status", return_value="AUSENTE")
    @mock.patch("vpn_app.f5_backend.interface_ipv4", return_value="192.0.2.2")
    @mock.patch("vpn_app.f5_backend.detected_interfaces", return_value=("tun0",))
    @mock.patch("vpn_app.f5_backend._process_running", side_effect=[True, True])
    def test_status_reports_detected_interface_and_ip(
        self, _process, _interface, _ipv4, _route, _window
    ):
        current = f5_backend.status()
        self.assertTrue(current.connected)
        self.assertEqual(current.interface, "tun0")
        self.assertEqual(current.interface_ip, "192.0.2.2")
        self.assertEqual(current.route_state, "NÃO CONFIGURADA")

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

    @mock.patch("vpn_app.f5_backend._run")
    def test_window_visible_uses_ewmh_hidden_state(self, run):
        run.side_effect = [
            "0x03000019 0 f5vpn.F5 VPN host F5 VPN",
            '_NET_WM_STATE(ATOM) = _NET_WM_STATE_SKIP_TASKBAR',
        ]
        self.assertTrue(f5_backend.window_visible())
        self.assertEqual(run.call_args_list[1].args[0], ["xprop", "-id", "0x03000019", "_NET_WM_STATE"])

        run.reset_mock()
        run.side_effect = [
            "0x03000019 0 f5vpn.F5 VPN host F5 VPN",
            '_NET_WM_STATE(ATOM) = _NET_WM_STATE_SKIP_TASKBAR, _NET_WM_STATE_HIDDEN',
        ]
        self.assertFalse(f5_backend.window_visible())

    @mock.patch("vpn_app.f5_backend.window_id", return_value="0x03000019")
    @mock.patch("vpn_app.f5_backend.subprocess.run")
    def test_show_restores_taskbar_and_activates_window(self, run, _window):
        run.return_value = mock.Mock(returncode=0, stderr="")
        ok, _message = f5_backend.show_window()
        self.assertTrue(ok)
        self.assertEqual(run.call_count, 3)
        self.assertEqual(
            run.call_args_list[0].args[0],
            ["wmctrl", "-i", "-r", "0x03000019", "-b", "remove,skip_taskbar"],
        )
        self.assertEqual(
            run.call_args_list[1].args[0],
            ["wmctrl", "-i", "-r", "0x03000019", "-b", "remove,hidden"],
        )
        self.assertEqual(
            run.call_args_list[2].args[0],
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
