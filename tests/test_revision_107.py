from __future__ import annotations

import ast
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from vpn_app import app as app_module
from vpn_app import privileged_validation


ROOT = Path(__file__).resolve().parents[1]


class SecondaryInterfaceCombo:
    def __init__(self) -> None:
        self.active = -1
        self.values = []
        self.tooltip = ""

    def get_active(self):
        return self.active

    def set_active(self, index):
        self.active = index

    def remove_all(self):
        self.active = -1
        self.values = []

    def append_text(self, value):
        self.values.append(value)

    def set_tooltip_text(self, value):
        self.tooltip = value


class ImmediateThread:
    def __init__(self, target, daemon):
        self.target = target

    def start(self):
        self.target()


class TrayRevision107Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = (ROOT / "vpn_app/app.py").read_text(encoding="utf-8")
        self.install = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.manifest = (ROOT / "RELEASE_MANIFEST.json").read_text(encoding="utf-8")

    @staticmethod
    def _secondary_application():
        application = object.__new__(app_module.VPNApplication)
        combo = SecondaryInterfaceCombo()
        application.secondary_interface_candidates = combo
        application.secondary_candidate_values = []
        application.secondary_candidate_details = []
        application.secondary_discovery_label = None
        return application, combo

    @staticmethod
    def _secondary_candidate(name):
        return SimpleNamespace(
            name=name,
            active=True,
            ipv4="192.0.2.10",
            routes=("192.0.2.0/24",),
            kind="tun",
            observation="candidata",
        )

    @staticmethod
    def _controls_application():
        application = object.__new__(app_module.VPNApplication)
        application.primary_error = False
        application.is_connecting = False
        application.reconnect_status = ""
        widgets = SimpleNamespace(
            indicator=mock.Mock(),
            secondary_status=mock.Mock(),
            secondary_action=mock.Mock(),
            authentication=mock.Mock(),
            hide=mock.Mock(),
            show=mock.Mock(),
        )
        application.indicator = widgets.indicator
        application.menu_primary_status = None
        application.menu_secondary_status = widgets.secondary_status
        application.menu_primary_action = None
        application.menu_secondary_action = widgets.secondary_action
        application.connect_button = None
        application.disconnect_button = None
        application.f5_auth_buttons = [widgets.authentication]
        application.f5_hide_button = widgets.hide
        application.f5_show_button = widgets.show
        return application, widgets

    @staticmethod
    def _reconnecting_application():
        application = object.__new__(app_module.VPNApplication)
        application.auto_reconnect_primary = True
        application.desired_connected = True
        application.manual_disconnect = False
        application.reconnect_in_progress = False
        application.reconnect_status = ""
        application.is_connecting = False
        application.primary_error = True
        application.last_connected = False
        application.connected_since = None
        application.__dict__["_refresh_controls"] = mock.Mock()
        application.__dict__["_notify"] = mock.Mock()
        return application

    @staticmethod
    def _initialized_application(preference):
        events = []

        def ensure_config_dir():
            events.append("ensure")

        def read_preference():
            events.append("read")
            if isinstance(preference, BaseException):
                raise preference
            return preference

        with mock.patch.object(
            app_module.socket,
            "socket",
        ), mock.patch.object(
            app_module.network,
            "vpn_interface",
            return_value="",
        ), mock.patch.object(
            app_module.f5_backend,
            "status",
            return_value=SimpleNamespace(connected=False),
        ), mock.patch.object(
            app_module.VPNApplication,
            "_build_indicator",
            return_value=mock.Mock(),
        ), mock.patch.object(
            app_module.config_store,
            "ensure_config_dir",
            side_effect=ensure_config_dir,
        ), mock.patch.object(
            app_module.config_store,
            "read_auto_reconnect_primary",
            side_effect=read_preference,
        ) as read_auto_reconnect, mock.patch.object(
            app_module.VPNApplication,
            "_check_integrity_markup",
            return_value="ok",
        ), mock.patch.object(
            app_module.LOGGER,
            "warning",
        ) as warning:
            application = app_module.VPNApplication()

        return application, events, read_auto_reconnect, warning

    @staticmethod
    def _f5_status(operational_state, validation_state, client_running):
        connected = operational_state == "CONECTADA"
        return app_module.f5_backend.F5Status(
            client_running=client_running,
            tunnel_running=connected,
            interface_up=connected,
            route_state="PRESENTE" if connected else "NÃO CONFIGURADA",
            window_id="",
            interface_ip="192.0.2.10" if connected else "-",
            interface="tun0" if connected else "",
            validation_state=validation_state,
            operational_state=operational_state,
        )

    def test_split_icons_cover_all_connection_combinations(self) -> None:
        self.assertIn("ICON_PRIMARY", self.app)
        self.assertIn("ICON_SECONDARY", self.app)
        self.assertIn("return ICON_ON", self.app)
        self.assertIn("return ICON_PRIMARY", self.app)
        self.assertIn("return ICON_SECONDARY", self.app)
        self.assertIn("return ICON_OFF", self.app)
        for name in ("primary", "secondary"):
            self.assertTrue((ROOT / f"vpn-corporativa-{name}.svg").exists())
            self.assertIn("for split_state in primary secondary", self.install)
            self.assertIn('"$SCRIPT_DIR/vpn-corporativa-${split_state}.svg"', self.install)
            self.assertIn(f"vpn-corporativa-{name}.svg", self.manifest)

    def test_uninstaller_removes_split_icons(self) -> None:
        uninstaller = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
        self.assertIn(
            "rm -f /usr/local/share/icons/vpn-corporativa-{primary,secondary}.svg",
            uninstaller,
        )

    def test_release_manifest_matches_tracked_files(self) -> None:
        manifest = json.loads(self.manifest)
        manifest_files = set(manifest["files"])
        tracked = set(
            subprocess.check_output(["git", "ls-files"], cwd=ROOT, text=True).splitlines()
        )
        missing = {path for path in manifest_files if not (ROOT / path).is_file()}
        self.assertEqual(missing, set(), "O manifesto contém arquivos ausentes.")
        self.assertEqual(
            manifest_files - tracked,
            set(),
            "O manifesto contém arquivos não rastreados pelo Git.",
        )
        self.assertEqual(manifest_files, tracked)

    def test_icon_mapping_returns_independent_primary_and_secondary_states(self) -> None:
        tree = ast.parse(self.app)
        application = next(
            node for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "VPNApplication"
        )
        method = next(
            node for node in application.body
            if isinstance(node, ast.FunctionDef) and node.name == "_connected_icon"
        )
        module = ast.Module(body=[method], type_ignores=[])
        ast.fix_missing_locations(module)
        namespace = {
            "ICON_OFF": "off",
            "ICON_PRIMARY": "primary",
            "ICON_SECONDARY": "secondary",
            "ICON_ON": "on",
        }
        exec(compile(module, "app.py", "exec"), namespace)
        icon = namespace["_connected_icon"]
        self.assertEqual(icon(False, False), "off")
        self.assertEqual(icon(True, False), "primary")
        self.assertEqual(icon(False, True), "secondary")
        self.assertEqual(icon(True, True), "on")
        self.assertIn("bool(network.vpn_interface())", self.app)
        self.assertIn("elif network.vpn_interface():", self.app)
        self.assertIn("elif f5.connected:", self.app)
        self.assertIn('primary = "error"', self.app)
        self.assertIn('primary = "wait"', self.app)
        self.assertIn('secondary = "error"', self.app)
        self.assertIn('secondary = "wait"', self.app)
        self.assertIn("_split_icon_path(primary, secondary)", self.app)

    def test_refresh_controls_reuses_one_secondary_status(self) -> None:
        application, _widgets = self._controls_application()
        current = self._f5_status("CONECTADA", "AMBÍGUA", True)
        with mock.patch.object(
            app_module.f5_backend,
            "status",
            return_value=current,
        ) as status, mock.patch.object(
            app_module.network,
            "vpn_interface",
            return_value="",
        ), mock.patch.object(
            app_module.f5_backend,
            "window_visible",
            return_value=False,
        ), mock.patch.object(
            app_module.f5_backend,
            "authentication_enabled",
            wraps=app_module.f5_backend.authentication_enabled,
        ) as authentication_enabled, mock.patch.object(
            app_module.f5_backend,
            "window_controls_enabled",
            wraps=app_module.f5_backend.window_controls_enabled,
        ) as window_controls_enabled, mock.patch.object(
            application,
            "_split_icon_path",
            return_value="icon",
        ), mock.patch.object(
            application,
            "_tray_states",
            wraps=application._tray_states,
        ) as tray_states, mock.patch.object(
            application,
            "_tray_icon",
            wraps=application._tray_icon,
        ) as tray_icon, mock.patch.object(
            application,
            "_tray_title",
            wraps=application._tray_title,
        ) as tray_title, mock.patch.object(
            application,
            "_secondary_status_text",
            wraps=application._secondary_status_text,
        ) as secondary_status_text:
            application._refresh_controls()

        status.assert_called_once_with()
        tray_icon.assert_called_once_with(current)
        tray_states.assert_called_once_with(current)
        tray_title.assert_called_once_with(current)
        self.assertEqual(
            secondary_status_text.call_args_list,
            [mock.call(current), mock.call(current)],
        )
        authentication_enabled.assert_called_once_with(current)
        window_controls_enabled.assert_called_once_with(current)

    def test_secondary_visible_states_remain_unchanged(self) -> None:
        cases = (
            ("CONECTADA", "AMBÍGUA", True, "on", "Exibir VPN secundária", False),
            (
                "AGUARDANDO AUTENTICAÇÃO",
                "DESCONECTADA",
                True,
                "wait",
                "Autenticar VPN secundária",
                True,
            ),
            (
                "DESCONECTADA",
                "DESCONECTADA",
                False,
                "off",
                "Autenticar VPN secundária",
                True,
            ),
            (
                "DESCONECTADA",
                "AMBÍGUA",
                False,
                "error",
                "Autenticar VPN secundária",
                True,
            ),
            (
                "DESCONECTADA",
                "INCONSISTENTE",
                False,
                "error",
                "Autenticar VPN secundária",
                True,
            ),
        )
        for operational, validation, client, tray_state, action, can_authenticate in cases:
            with self.subTest(operational=operational, validation=validation):
                application, widgets = self._controls_application()
                current = self._f5_status(operational, validation, client)
                with mock.patch.object(
                    app_module.f5_backend,
                    "status",
                    return_value=current,
                ) as status, mock.patch.object(
                    app_module.network,
                    "vpn_interface",
                    return_value="",
                ), mock.patch.object(
                    app_module.f5_backend,
                    "window_visible",
                    return_value=False,
                ), mock.patch.object(
                    application,
                    "_split_icon_path",
                    side_effect=lambda primary, secondary: f"{primary}:{secondary}",
                ):
                    application._refresh_controls()

                status.assert_called_once_with()
                widgets.indicator.set_icon_full.assert_called_once()
                icon, title = widgets.indicator.set_icon_full.call_args.args
                self.assertEqual(icon, f"off:{tray_state}")
                self.assertIn(f"Secundária: {operational.lower()}", title)
                widgets.secondary_status.set_label.assert_called_once_with(
                    f"VPN secundária: {operational}"
                )
                widgets.secondary_action.set_label.assert_called_once_with(action)
                widgets.authentication.set_sensitive.assert_called_once_with(
                    can_authenticate
                )

    def test_tray_menu_reuses_current_action_labels_and_handlers(self) -> None:
        self.assertIn('Gtk.MenuItem(label="VPN principal: verificando...")', self.app)
        self.assertIn('Gtk.MenuItem(label="VPN secundária: verificando...")', self.app)
        self.assertIn('Gtk.MenuItem(label="Conectar VPN principal")', self.app)
        self.assertIn('Gtk.MenuItem(label="Autenticar VPN secundária")', self.app)
        self.assertIn('f"VPN principal: {self._primary_status_text()}"', self.app)
        self.assertIn('f"VPN secundária: {self._secondary_status_text(f5)}"', self.app)
        self.assertIn('"Desconectar VPN principal"', self.app)
        self.assertIn('"Conectar VPN principal"', self.app)
        self.assertIn('"Ocultar VPN secundária"', self.app)
        self.assertIn("f5_backend.window_visible()", self.app)
        self.assertIn("self.connect_vpn()", self.app)
        self.assertIn("self.disconnect_vpn()", self.app)
        self.assertIn("self.open_f5()", self.app)
        self.assertIn("self.show_f5()", self.app)
        self.assertIn("self.hide_f5()", self.app)

    def test_tray_secondary_action_reuses_visible_label_for_hide_or_show(self) -> None:
        method_start = self.app.index("def _activate_secondary_menu")
        method_end = self.app.index("def _build_indicator", method_start)
        method = self.app[method_start:method_end]
        self.assertIn('action_label == "Ocultar VPN secundária"', method)
        self.assertIn("self.hide_f5()", method)
        self.assertIn("self.show_f5()", method)
        self.assertIn("self._refresh_controls()", method)

    def test_f5_window_actions_refresh_after_window_manager_settles(self) -> None:
        hide_start = self.app.index("def hide_f5")
        show_start = self.app.index("def show_f5", hide_start)
        show_end = self.app.index("def _watch_f5", show_start)
        actions = self.app[hide_start:show_end]
        self.assertIn("GLib.timeout_add(150, self._refresh_controls)", actions)

    def test_f5_hide_and_show_buttons_alternate_by_window_visibility(self) -> None:
        refresh_start = self.app.index("def _refresh_controls")
        refresh_end = self.app.index("def _safe", refresh_start)
        refresh = self.app[refresh_start:refresh_end]
        self.assertIn("window_available = f5_backend.window_controls_enabled(f5)", refresh)
        self.assertIn("window_visible = f5_backend.window_visible() if window_available else False", refresh)
        self.assertIn("window_available and window_visible", refresh)
        self.assertIn("window_available and not window_visible", refresh)
        self.assertIn("self.f5_hide_button = hide_f5", self.app)
        self.assertIn("self.f5_show_button = show_f5", self.app)

    def test_panel_item_precedes_status_items_in_tray_menu(self) -> None:
        self.assertLess(
            self.app.index('Gtk.MenuItem(label="Abrir Centro de Controle")'),
            self.app.index('Gtk.MenuItem(label="VPN principal: verificando...")'),
        )

    def test_panel_item_runs_integrity_before_presenting_window(self) -> None:
        self.assertIn('Gtk.MenuItem(label="Abrir Centro de Controle")', self.app)
        method_start = self.app.index("def _open_panel_from_tray")
        self.assertLess(
            self.app.index("self._refresh_integrity_status()", method_start),
            self.app.index("self.show_window()", method_start),
        )
        self.assertIn("self.status_integrity_label.set_markup", self.app)
        self.assertIn("self._notify(\"Falha no teste de integridade.", self.app)

    def test_window_is_presented_and_focused_without_keep_above(self) -> None:
        self.assertIn("self.window.set_keep_above(False)", self.app)
        self.assertIn("timestamp = Gtk.get_current_event_time()", self.app)
        self.assertIn("self.window.present_with_time(timestamp)", self.app)
        self.assertIn("self.window.grab_focus()", self.app)
        self.assertIn("native_window.focus(timestamp)", self.app)

    def test_requested_window_title_and_primary_tab_label(self) -> None:
        self.assertIn(
            'Gtk.Window(title="Centro de Controle da Rede e VPN")',
            self.app,
        )
        self.assertIn('Gtk.Label(label="Principal")', self.app)
        self.assertNotIn('Gtk.Label(label="Painel Principal")', self.app)

    def test_requested_visible_name_and_primary_reconnect_preference(self) -> None:
        self.assertIn('APP_NAME = "Centro de Controle da Rede e VPN"', self.app)
        self.assertIn('Gtk.MenuItem(label="Abrir Centro de Controle")', self.app)
        self.assertIn('label="Reconexão automática da VPN principal"', self.app)
        self.assertIn("read_auto_reconnect_primary", self.app)
        self.assertIn("save_auto_reconnect_primary", self.app)
        self.assertIn('self.auto_reconnect_primary = True', self.app)
        self.assertIn('"RECONEXÃO AUTOMÁTICA DESATIVADA"', self.app)
        self.assertNotIn('"Ocultar F5"', self.app)
        self.assertNotIn('"Exibir F5"', self.app)
        self.assertNotIn('"Janela F5"', self.app)

    def test_init_loads_disabled_reconnect_without_opening_window(self) -> None:
        application, events, read_preference, warning = self._initialized_application(False)

        self.assertEqual(events, ["ensure", "read"])
        read_preference.assert_called_once_with()
        warning.assert_not_called()
        self.assertFalse(application.auto_reconnect_primary)
        self.assertIsNone(application.window)

    def test_init_keeps_enabled_default_when_preference_is_absent(self) -> None:
        application, events, read_preference, warning = self._initialized_application(True)

        self.assertEqual(events, ["ensure", "read"])
        read_preference.assert_called_once_with()
        warning.assert_not_called()
        self.assertTrue(application.auto_reconnect_primary)

    def test_tray_only_reconnect_respects_disabled_preference(self) -> None:
        application, _events, _read_preference, _warning = self._initialized_application(False)
        application.desired_connected = True
        refresh_controls = mock.Mock()
        application.__dict__["_refresh_controls"] = refresh_controls

        with mock.patch.object(app_module.threading, "Thread") as thread:
            application._start_reconnect("conexão perdida")

        thread.assert_not_called()
        self.assertFalse(application.reconnect_in_progress)
        self.assertEqual(
            application.reconnect_status,
            "RECONEXÃO AUTOMÁTICA DESATIVADA",
        )
        refresh_controls.assert_called_once_with()

    def test_disabling_reconnect_stops_active_helper_before_accepting_interface(self) -> None:
        application = self._reconnecting_application()
        notify = application.__dict__["_notify"]
        process = mock.Mock()
        log_path = mock.Mock()
        log_path.open = mock.mock_open()

        def interface_appears_as_preference_is_disabled():
            application.auto_reconnect_primary = False
            return "ppp0"

        success = mock.Mock()
        application.__dict__["_finish_reconnect_success"] = success
        with mock.patch.object(
            app_module,
            "LOG_PATH",
            log_path,
        ), mock.patch.object(
            app_module.os,
            "fsync",
        ), mock.patch.object(
            app_module.time,
            "sleep",
        ), mock.patch.object(
            app_module.threading,
            "Thread",
            ImmediateThread,
        ), mock.patch.object(
            app_module.GLib,
            "idle_add",
            side_effect=lambda callback, *args: callback(*args),
        ), mock.patch.object(
            app_module.network,
            "internet_available",
            return_value=True,
        ) as internet_available, mock.patch.object(
            app_module.network,
            "vpn_interface",
            side_effect=interface_appears_as_preference_is_disabled,
        ), mock.patch.object(
            app_module.VPNApplication,
            "_start_connect_helper",
            return_value=process,
        ) as start_helper, mock.patch.object(
            app_module.VPNApplication,
            "_stop_connect_process",
        ) as stop_helper:
            application._start_reconnect("conexão perdida")

        start_helper.assert_called_once()
        stop_helper.assert_called_once_with(process)
        internet_available.assert_called_once_with()
        success.assert_not_called()
        process.poll.assert_not_called()
        notify.assert_not_called()
        self.assertEqual(
            application.reconnect_status,
            "RECONEXÃO AUTOMÁTICA DESATIVADA",
        )
        self.assertFalse(application.reconnect_in_progress)
        self.assertFalse(application.is_connecting)
        self.assertFalse(application.primary_error)
        self.assertTrue(application.desired_connected)
        self.assertFalse(application.manual_disconnect)

    def test_enabled_reconnect_still_accepts_successful_interface(self) -> None:
        application = self._reconnecting_application()
        notify = application.__dict__["_notify"]
        process = mock.Mock()
        log_path = mock.Mock()
        log_path.open = mock.mock_open()

        with mock.patch.object(
            app_module,
            "LOG_PATH",
            log_path,
        ), mock.patch.object(
            app_module.os,
            "fsync",
        ), mock.patch.object(
            app_module.time,
            "sleep",
        ), mock.patch.object(
            app_module.threading,
            "Thread",
            ImmediateThread,
        ), mock.patch.object(
            app_module.GLib,
            "idle_add",
            side_effect=lambda callback, *args: callback(*args),
        ), mock.patch.object(
            app_module.network,
            "internet_available",
            return_value=True,
        ), mock.patch.object(
            app_module.network,
            "vpn_interface",
            return_value="ppp0",
        ), mock.patch.object(
            app_module.VPNApplication,
            "_start_connect_helper",
            return_value=process,
        ) as start_helper, mock.patch.object(
            app_module.VPNApplication,
            "_stop_connect_process",
        ) as stop_helper:
            application._start_reconnect("conexão perdida")

        start_helper.assert_called_once()
        stop_helper.assert_not_called()
        notify.assert_not_called()
        self.assertTrue(application.auto_reconnect_primary)
        self.assertFalse(application.reconnect_in_progress)
        self.assertFalse(application.is_connecting)
        self.assertFalse(application.primary_error)
        self.assertTrue(application.last_connected)
        self.assertTrue(application.desired_connected)
        self.assertFalse(application.manual_disconnect)

    def test_disconnect_during_backoff_never_starts_helper(self) -> None:
        application = self._reconnecting_application()
        sleep_delays = []

        def disconnect_during_backoff(delay):
            sleep_delays.append(delay)
            application.disconnect_vpn()

        with mock.patch.object(
            app_module.time,
            "sleep",
            side_effect=disconnect_during_backoff,
        ), mock.patch.object(
            app_module.threading,
            "Thread",
            ImmediateThread,
        ), mock.patch.object(
            app_module.GLib,
            "idle_add",
            side_effect=lambda callback, *args: callback(*args),
        ), mock.patch.object(
            app_module.network,
            "vpn_interface",
            return_value="",
        ), mock.patch.object(
            app_module.network,
            "internet_available",
        ) as internet_available, mock.patch.object(
            app_module.VPNApplication,
            "_start_connect_helper",
        ) as start_helper, mock.patch.object(
            app_module.subprocess,
            "run",
        ) as run:
            application._start_reconnect("conexão perdida")

        self.assertEqual(sleep_delays, [5])
        start_helper.assert_not_called()
        internet_available.assert_not_called()
        run.assert_called_once_with(
            ["sudo", "-n", app_module.DISCONNECT_HELPER],
            check=False,
        )
        self.assertFalse(application.desired_connected)
        self.assertTrue(application.manual_disconnect)
        self.assertFalse(application.reconnect_in_progress)
        self.assertFalse(application.is_connecting)

    def test_manual_connection_ignores_automatic_reconnect_preference(self) -> None:
        application = self._reconnecting_application()
        application.auto_reconnect_primary = False
        application.desired_connected = False
        application.manual_disconnect = True
        process = mock.Mock()
        log_path = mock.Mock()
        log_path.open = mock.mock_open()

        with mock.patch.object(
            app_module,
            "LOG_PATH",
            log_path,
        ), mock.patch.object(
            app_module.threading,
            "Thread",
            ImmediateThread,
        ), mock.patch.object(
            app_module.GLib,
            "idle_add",
            side_effect=lambda callback, *args: callback(*args),
        ), mock.patch.object(
            app_module.network,
            "vpn_interface",
            side_effect=("", "ppp0"),
        ), mock.patch.object(
            app_module.VPNApplication,
            "_start_connect_helper",
            return_value=process,
        ) as start_helper, mock.patch.object(
            app_module.VPNApplication,
            "_stop_connect_process",
        ) as stop_helper:
            application.connect_vpn()

        start_helper.assert_called_once()
        stop_helper.assert_not_called()
        self.assertFalse(application.auto_reconnect_primary)
        self.assertTrue(application.desired_connected)
        self.assertFalse(application.manual_disconnect)
        self.assertTrue(application.last_connected)

    def test_explicit_disconnect_keeps_existing_state_transition(self) -> None:
        application = self._reconnecting_application()
        application.reconnect_in_progress = True
        application.is_connecting = True
        application.last_connected = True
        application.connected_since = 1.0

        with mock.patch.object(app_module.subprocess, "run") as run:
            application.disconnect_vpn()

        run.assert_called_once_with(
            ["sudo", "-n", app_module.DISCONNECT_HELPER],
            check=False,
        )
        self.assertTrue(application.manual_disconnect)
        self.assertFalse(application.desired_connected)
        self.assertFalse(application.reconnect_in_progress)
        self.assertEqual(application.reconnect_status, "")
        self.assertFalse(application.is_connecting)
        self.assertFalse(application.primary_error)
        self.assertFalse(application.last_connected)
        self.assertIsNone(application.connected_since)

    def test_init_keeps_enabled_fallback_when_preference_read_fails(self) -> None:
        for failure in (
            OSError("sensitive-os-error"),
            UnicodeError("sensitive-unicode-error"),
        ):
            with self.subTest(error=type(failure).__name__):
                application, events, read_preference, warning = (
                    self._initialized_application(failure)
                )

                self.assertEqual(events, ["ensure", "read"])
                read_preference.assert_called_once_with()
                self.assertTrue(application.auto_reconnect_primary)
                warning.assert_called_once_with(
                    "Preferência de reconexão automática indisponível; "
                    "usando o padrão ativado."
                )
                self.assertNotIn(str(failure), repr(warning.call_args))

    def test_manual_connection_success_clears_reconnect_status_before_refresh(self) -> None:
        application = object.__new__(app_module.VPNApplication)
        application.is_connecting = True
        application.primary_error = True
        application.last_connected = False
        application.reconnect_status = "RECONEXÃO AUTOMÁTICA DESATIVADA"
        statuses_at_refresh = []
        refresh_controls = mock.Mock(
            side_effect=lambda: statuses_at_refresh.append(application.reconnect_status)
        )
        application.__dict__["_refresh_controls"] = refresh_controls

        self.assertFalse(application._connection_established())

        self.assertEqual(application.reconnect_status, "")
        refresh_controls.assert_called_once_with()
        self.assertEqual(statuses_at_refresh, [""])

    def test_manual_connection_success_restores_connected_menu_and_tray_state(self) -> None:
        application = object.__new__(app_module.VPNApplication)
        application.is_connecting = True
        application.primary_error = False
        application.last_connected = False
        application.reconnect_status = "RECONEXÃO AUTOMÁTICA DESATIVADA"
        application.__dict__["_refresh_controls"] = mock.Mock()
        application._connection_established()

        indicator = mock.Mock()
        primary_status_menu = mock.Mock()
        primary_action_menu = mock.Mock()
        connect_button = mock.Mock()
        disconnect_button = mock.Mock()
        application.indicator = indicator
        application.menu_primary_status = primary_status_menu
        application.menu_secondary_status = None
        application.menu_primary_action = primary_action_menu
        application.menu_secondary_action = None
        application.connect_button = connect_button
        application.disconnect_button = disconnect_button
        application.f5_auth_buttons = []
        application.f5_hide_button = None
        application.f5_show_button = None
        secondary = SimpleNamespace(
            connected=False,
            inconsistent=False,
            client_running=False,
            label="DESCONECTADA",
        )

        with mock.patch.object(
            app_module.network,
            "vpn_interface",
            return_value="ppp0",
        ), mock.patch.object(
            app_module.f5_backend,
            "status",
            return_value=secondary,
        ), mock.patch.object(
            app_module.f5_backend,
            "window_controls_enabled",
            return_value=False,
        ):
            self.assertEqual(application._primary_status_text(), "CONECTADA")
            self.assertEqual(application._tray_states()[0], "on")
            app_module.VPNApplication._refresh_controls(application)

        primary_status_menu.set_label.assert_called_once_with(
            "VPN principal: CONECTADA"
        )
        primary_action_menu.set_label.assert_called_once_with(
            "Desconectar VPN principal"
        )
        connect_button.set_sensitive.assert_called_once_with(False)
        disconnect_button.set_sensitive.assert_called_once_with(True)
        tray_title = indicator.set_title.call_args.args[0]
        self.assertNotIn("reconexão automática desativada", tray_title)

    def test_manual_connection_success_removes_old_status_from_panel_snapshot(self) -> None:
        application = object.__new__(app_module.VPNApplication)
        application.is_connecting = True
        application.primary_error = False
        application.last_connected = False
        application.reconnect_status = "RECONEXÃO AUTOMÁTICA DESATIVADA"
        application.__dict__["_refresh_controls"] = mock.Mock()
        application._connection_established()

        window = mock.Mock()
        window.get_visible.return_value = True
        application.window = window
        application.update_in_progress = False
        application.internet_sampler = mock.Mock()
        application.internet_sampler.sample.return_value = (0, 0, 0.0, 0.0)
        application.primary_sampler = mock.Mock()
        application.primary_sampler.sample.return_value = (0, 0, 0.0, 0.0)
        application.local_started_at = None

        class ImmediateThread:
            def __init__(self, target, daemon):
                self.target = target

            def start(self):
                self.target()

        secondary = SimpleNamespace(
            label="DESCONECTADA",
            interface="",
            interface_ip="-",
            window_id=None,
        )
        idle_add = mock.Mock()
        with mock.patch.object(
            app_module.threading,
            "Thread",
            ImmediateThread,
        ), mock.patch.object(
            app_module.GLib,
            "idle_add",
            idle_add,
        ), mock.patch.object(
            app_module.network,
            "vpn_interface",
            return_value="ppp0",
        ), mock.patch.object(
            app_module.network,
            "route_interface",
            return_value="eth0",
        ), mock.patch.object(
            app_module.network,
            "interface_ipv4",
            return_value="192.0.2.10",
        ), mock.patch.object(
            app_module.network,
            "internet_available",
            return_value=True,
        ), mock.patch.object(
            app_module.network,
            "public_ip",
            return_value="198.51.100.10",
        ), mock.patch.object(
            app_module.network,
            "ping_ms",
            return_value="1 ms",
        ), mock.patch.object(
            app_module.network,
            "format_bytes",
            return_value="0 B",
        ), mock.patch.object(
            app_module.network,
            "docker_summary",
            return_value="INATIVO",
        ), mock.patch.object(
            app_module.network,
            "firewall_summary",
            return_value="OK",
        ), mock.patch.object(
            app_module.f5_backend,
            "status",
            return_value=secondary,
        ), mock.patch.object(
            app_module.config_store,
            "read_hosts",
            return_value=[],
        ):
            self.assertTrue(application._visible_update())

        snapshot = idle_add.call_args.args[1]
        self.assertEqual(snapshot["primary_status"], "CONECTADA")
        self.assertNotIn(
            "RECONEXÃO AUTOMÁTICA DESATIVADA",
            snapshot.values(),
        )

    def test_secondary_interface_configuration_and_manual_discovery_are_exposed(self) -> None:
        backend = (ROOT / "vpn_app/f5_backend.py").read_text(encoding="utf-8")
        store = (ROOT / "vpn_app/config_store.py").read_text(encoding="utf-8")
        self.assertIn('Interface da VPN secundária', self.app)
        self.assertIn('Atualizar interfaces', self.app)
        self.assertIn('Salvar configurações da VPN secundária', self.app)
        self.assertIn('def refresh_secondary_interfaces', self.app)
        self.assertIn('def _secondary_candidate_index_after_refresh', self.app)
        self.assertIn('def discover_interface_candidates', backend)
        self.assertIn('DEFAULT_SECONDARY_INTERFACE = "tun0"', store)
        self.assertIn('return DEFAULT_SECONDARY_INTERFACE', store)
        self.assertIn('self.secondary_interface_candidates.append_text(candidate.name)', self.app)
        self.assertIn('combo.set_tooltip_text(details)', self.app)

    def test_secondary_interface_refresh_selection_rules(self) -> None:
        tree = ast.parse(self.app)
        application = next(
            node for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "VPNApplication"
        )
        method = next(
            node for node in application.body
            if isinstance(node, ast.FunctionDef) and node.name == "_secondary_candidate_index_after_refresh"
        )
        method.decorator_list = []
        module = ast.Module(body=[method], type_ignores=[])
        ast.fix_missing_locations(module)
        namespace = {}
        exec(compile(module, "app.py", "exec"), namespace)
        choose = namespace["_secondary_candidate_index_after_refresh"]
        self.assertEqual(choose(["tun0", "vpn1"], ""), -1)
        self.assertEqual(choose(["tun0", "vpn1"], "vpn1"), 1)
        self.assertEqual(choose(["tun0", "vpn1"], "old0"), -1)
        self.assertEqual(choose([], "tun0"), -1)

    def test_secondary_interface_absent_uses_tun0_fallback(self) -> None:
        application, combo = self._secondary_application()
        candidates = (
            self._secondary_candidate("vpn1"),
            self._secondary_candidate("tun0"),
        )
        with mock.patch.object(
            app_module.f5_backend,
            "configured_interface",
            return_value="tun0",
        ), mock.patch.object(
            app_module.f5_backend,
            "discover_interface_candidates",
            return_value=candidates,
        ):
            application.refresh_secondary_interfaces()

        self.assertEqual(combo.active, 1)
        self.assertEqual(application._selected_secondary_interface(), "tun0")

    def test_secondary_interface_explicit_empty_remains_unselected(self) -> None:
        application, combo = self._secondary_application()
        discovery_label = mock.Mock()
        application.secondary_discovery_label = discovery_label
        url_entry = mock.Mock()
        url_entry.get_text.return_value = "https://vpn.valid.test/new"
        application.secondary_url_entry = url_entry
        application.__dict__["_show_message"] = mock.Mock()
        candidates = (self._secondary_candidate("tun0"),)
        with mock.patch.object(
            app_module.f5_backend,
            "configured_interface",
            return_value="",
        ), mock.patch.object(
            app_module.f5_backend,
            "discover_interface_candidates",
            return_value=candidates,
        ):
            application.refresh_secondary_interfaces()

        self.assertEqual(combo.active, -1)
        self.assertEqual(application._selected_secondary_interface(), "")
        manual_guidance = discovery_label.set_text.call_args.args[0]
        self.assertIn("Modo de descoberta manual ativo", manual_guidance)
        self.assertIn("não será monitorado como CONECTADA", manual_guidance)
        self.assertIn("Atualizar interfaces", manual_guidance)
        self.assertIn("selecione a interface correta", manual_guidance)
        with mock.patch.object(
            app_module.f5_backend,
            "configured_interface",
            return_value="",
        ), mock.patch.object(
            app_module.config_store,
            "save_secondary_url",
        ), mock.patch.object(
            app_module.config_store,
            "save_secondary_interface",
        ) as save_interface:
            application.save_secondary_configuration()
        save_interface.assert_called_once_with("")

    def test_manual_secondary_selection_replaces_disabled_monitoring_guidance(self) -> None:
        application, combo = self._secondary_application()
        discovery_label = mock.Mock()
        application.secondary_discovery_label = discovery_label
        candidates = (self._secondary_candidate("tun0"),)
        with mock.patch.object(
            app_module.f5_backend,
            "configured_interface",
            return_value="",
        ), mock.patch.object(
            app_module.f5_backend,
            "discover_interface_candidates",
            return_value=candidates,
        ):
            application.refresh_secondary_interfaces()

        combo.active = 0
        application._select_secondary_candidate(combo)

        selected_guidance = discovery_label.set_text.call_args.args[0]
        self.assertIn("Interface tun0 selecionada", selected_guidance)
        self.assertNotIn("não será monitorado", selected_guidance)

    def test_secondary_interface_available_is_selected_during_initial_load(self) -> None:
        application, combo = self._secondary_application()
        application.config_entries = {}
        application.auto_reconnect_check = mock.Mock()
        application.auto_reconnect_primary = False
        application.routes_view = None
        application.hosts_view = None
        application.secondary_url_entry = mock.Mock()
        candidates = (
            self._secondary_candidate("tun0"),
            self._secondary_candidate("vpn1"),
        )
        with mock.patch.object(
            app_module.config_store,
            "read_key_values",
            return_value={},
        ), mock.patch.object(
            app_module.config_store,
            "read_auto_reconnect_primary",
            side_effect=AssertionError("a preferência não deve ser relida"),
        ) as read_preference, mock.patch.object(
            app_module.config_store,
            "read_secondary_url",
            return_value="https://vpn.valid.test/",
        ), mock.patch.object(
            app_module.f5_backend,
            "configured_interface",
            return_value="vpn1",
        ), mock.patch.object(
            app_module.f5_backend,
            "discover_interface_candidates",
            return_value=candidates,
        ):
            application._load_config_into_ui()

        read_preference.assert_not_called()
        application.auto_reconnect_check.set_active.assert_called_once_with(False)
        self.assertEqual(combo.active, 1)
        self.assertEqual(application._selected_secondary_interface(), "vpn1")

    def test_secondary_interface_unavailable_remains_unselected(self) -> None:
        application, combo = self._secondary_application()
        candidates = (
            self._secondary_candidate("tun0"),
            self._secondary_candidate("vpn1"),
        )
        with mock.patch.object(
            app_module.f5_backend,
            "configured_interface",
            return_value="old0",
        ), mock.patch.object(
            app_module.f5_backend,
            "discover_interface_candidates",
            return_value=candidates,
        ):
            application.refresh_secondary_interfaces()

        self.assertEqual(combo.active, -1)
        self.assertEqual(application._selected_secondary_interface(), "")

    def test_secondary_interface_manual_selection_survives_refresh(self) -> None:
        application, combo = self._secondary_application()
        application.secondary_candidate_values = ["tun0", "vpn1"]
        combo.values = ["tun0", "vpn1"]
        combo.active = 1
        candidates = (
            self._secondary_candidate("vpn1"),
            self._secondary_candidate("tun0"),
        )
        with mock.patch.object(
            app_module.f5_backend,
            "discover_interface_candidates",
            return_value=candidates,
        ):
            application.refresh_secondary_interfaces()

        self.assertEqual(combo.active, 0)
        self.assertEqual(application._selected_secondary_interface(), "vpn1")

    def test_saving_only_url_preserves_unavailable_persisted_interface(self) -> None:
        application, combo = self._secondary_application()
        url_entry = mock.Mock()
        url_entry.get_text.return_value = "https://vpn.valid.test/new"
        application.secondary_url_entry = url_entry
        application.__dict__["_show_message"] = mock.Mock()
        combo.active = -1
        with mock.patch.object(
            app_module.f5_backend,
            "configured_interface",
            return_value="old0",
        ), mock.patch.object(
            app_module.config_store,
            "save_secondary_url",
        ) as save_url, mock.patch.object(
            app_module.config_store,
            "save_secondary_interface",
        ) as save_interface:
            application.save_secondary_configuration()

        save_url.assert_called_once_with("https://vpn.valid.test/new")
        save_interface.assert_called_once_with("old0")

    def test_explicit_manual_selection_replaces_unavailable_persisted_interface(self) -> None:
        application, combo = self._secondary_application()
        url_entry = mock.Mock()
        url_entry.get_text.return_value = "https://vpn.valid.test/new"
        application.secondary_url_entry = url_entry
        application.__dict__["_show_message"] = mock.Mock()
        application.secondary_candidate_values = ["tun0"]
        combo.values = ["tun0"]
        combo.active = 0
        with mock.patch.object(
            app_module.f5_backend,
            "configured_interface",
            return_value="old0",
        ), mock.patch.object(
            app_module.config_store,
            "save_secondary_url",
        ), mock.patch.object(
            app_module.config_store,
            "save_secondary_interface",
        ) as save_interface:
            application.save_secondary_configuration()

        save_interface.assert_called_once_with("tun0")

    def test_main_panel_explains_both_vpn_roles(self) -> None:
        self.assertIn(
            'label="Otimização e gerenciamento da conexão corporativa principal."',
            self.app,
        )
        self.assertIn(
            'label="Autenticação web manual; conexão acompanhada e monitorada pelo aplicativo."',
            self.app,
        )

    def test_certificate_policy_and_safe_diagnostic_are_exposed(self) -> None:
        self.assertNotIn('("Política de certificado", "certificate-policy"', self.app)
        self.assertNotIn('("Certificado confiável", "trusted-cert"', self.app)
        self.assertNotIn('Configurações avançadas de certificado', self.app)
        self.assertNotIn('Usar fingerprint diagnosticado', self.app)
        self.assertNotIn('"Diagnosticar certificado"', self.app)
        self.assertNotIn("self.certificate_diagnostic_view", self.app)
        self.assertNotIn("def diagnose_certificate", self.app)
        self.assertIn('view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)', self.app)
        self.assertIn('url_entry.set_hexpand(True)', self.app)
        self.assertIn('self.secondary_discovery_label.set_line_wrap(True)', self.app)
        self.assertIn('"Certificado da VPN principal\\n"', self.app)
        self.assertIn("certificate_diagnostics.diagnose", self.app)
        self.assertIn("self._certificate_diagnostic_snapshot()", self.app)
        self.assertIn("RESUMO GERAL:", self.app)
        self.assertNotIn('GLib.idle_add(self._show_message, "Diagnóstico de certificado", detail)', self.app)
        self.assertIn("Cadeia CA", (ROOT / "vpn_app/certificate_diagnostics.py").read_text(encoding="utf-8"))
        self.assertIn("Hostname/SAN", (ROOT / "vpn_app/certificate_diagnostics.py").read_text(encoding="utf-8"))
        self.assertIn("Correspondência com trusted-cert", (ROOT / "vpn_app/certificate_diagnostics.py").read_text(encoding="utf-8"))

    def test_diagnostic_uses_one_validated_saved_snapshot_not_unsaved_gtk(self) -> None:
        application = object.__new__(app_module.VPNApplication)
        application.diagnostic_running = False
        application.notebook = None
        application.diagnostic_status_label = None
        application.diagnostic_view = None
        unsaved = mock.Mock()
        unsaved.get_text.return_value = "endpoint-b.example"
        application.config_entries = {"host": unsaved}
        saved = {
            "host": "endpoint-a.example",
            "port": "443",
            "username": "user",
            "set-routes": "0",
            "set-dns": "0",
            "certificate-policy": "legacy-pinned",
            "trusted-cert": "a" * 64,
        }
        tls_result = app_module.certificate_diagnostics.configuration_failure(
            "endpoint-a.example",
            "legacy-pinned",
            "mock",
        )
        helper = SimpleNamespace(
            stdout="RESUMO: 0 falha(s), 0 aviso(s)\n",
            stderr="",
            returncode=0,
        )

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            app_module,
            "DIAG_PATH",
            Path(temporary) / "diagnostic.txt",
        ), mock.patch.object(
            app_module.privileged_validation,
            "parse_connection",
            return_value=saved,
        ) as parse_connection, mock.patch.object(
            app_module.certificate_diagnostics,
            "diagnose",
            return_value=tls_result,
        ) as diagnose, mock.patch.object(
            app_module.subprocess,
            "run",
            return_value=helper,
        ), mock.patch.object(
            app_module.threading,
            "Thread",
            ImmediateThread,
        ), mock.patch.object(
            app_module.GLib,
            "idle_add",
        ) as idle_add:
            application.run_diagnostic()
            report = app_module.DIAG_PATH.read_text(encoding="utf-8")

        parse_connection.assert_called_once_with(app_module.config_store.CONNECTION_FILE)
        diagnose.assert_called_once_with(
            "endpoint-a.example",
            443,
            "a" * 64,
            "legacy-pinned",
        )
        unsaved.get_text.assert_not_called()
        self.assertIn("RESUMO GERAL: 1 falha(s), 0 aviso(s)", report)
        idle_add.assert_called_once_with(application._finish_diagnostic, 1, 0)

    def test_certificate_snapshot_matches_privileged_parser(self) -> None:
        fingerprint = "a" * 64
        valid = (
            "host = gateway.example\n"
            "port = 443\n"
            "username = user\n"
            "set-routes = 0\n"
            "set-dns = 0\n"
            f"trusted-cert = {fingerprint}\n"
        )
        cases = (
            ("valid", valid, True),
            ("duplicate", valid + "host = duplicate.example\n", False),
            ("unknown", valid + "unknown-option = 1\n", False),
            ("set-routes", valid.replace("set-routes = 0", "set-routes = 1"), False),
            ("set-dns", valid.replace("set-dns = 0", "set-dns = 1"), False),
        )

        with tempfile.TemporaryDirectory() as temporary:
            connection = Path(temporary) / "connection.conf"
            for name, content, expected_valid in cases:
                with self.subTest(name=name):
                    connection.write_text(content, encoding="utf-8")
                    try:
                        privileged_validation.parse_connection(connection)
                    except ValueError:
                        production_valid = False
                    else:
                        production_valid = True

                    with mock.patch.object(
                        app_module.config_store,
                        "CONNECTION_FILE",
                        connection,
                    ):
                        snapshot, diagnostic_valid = (
                            app_module.VPNApplication._certificate_diagnostic_snapshot()
                        )

                    self.assertEqual(production_valid, expected_valid)
                    self.assertEqual(diagnostic_valid, production_valid)
                    if expected_valid:
                        self.assertEqual(snapshot["host"], "gateway.example")
                    else:
                        self.assertEqual(snapshot, {})

    def test_integrated_summary_adds_helper_and_tls_counts(self) -> None:
        certificate = SimpleNamespace(critical_count=1, warning_count=2)
        self.assertEqual(
            app_module.VPNApplication._integrated_diagnostic_counts(
                "texto\nRESUMO: 2 falha(s), 3 aviso(s)\n",
                0,
                certificate,
            ),
            (3, 5),
        )
        self.assertEqual(
            app_module.VPNApplication._integrated_diagnostic_counts(
                "sem resumo",
                1,
                certificate,
            ),
            (2, 2),
        )
        self.assertEqual(
            app_module.VPNApplication._integrated_diagnostic_counts(
                "RESUMO: 0 falha(s), 0 aviso(s)\n",
                1,
                certificate,
            ),
            (2, 2),
        )
        self.assertEqual(
            app_module.VPNApplication._integrated_diagnostic_counts(
                "sem resumo",
                0,
                certificate,
            ),
            (1, 3),
        )

    def test_finish_diagnostic_uses_integrated_gui_summary_status(self) -> None:
        application = object.__new__(app_module.VPNApplication)
        application.diagnostic_running = True
        application.diagnostic_view = None
        application.status_diagnostic_label = None
        application.diagnostic_status_label = mock.Mock()
        application.__dict__["_notify"] = mock.Mock()

        cases = (
            (0, 0, "#2ca02c"),
            (0, 1, "#e69f00"),
            (1, 0, "#c0392b"),
        )
        for failures, warnings, color in cases:
            with self.subTest(failures=failures, warnings=warnings):
                application.diagnostic_status_label.reset_mock()
                application._finish_diagnostic(failures, warnings)
                markup = application.diagnostic_status_label.set_markup.call_args.args[0]
                self.assertIn(color, markup)
        application.__dict__["_notify"].assert_called_once()

    def test_requested_configuration_cleanup(self) -> None:
        self.assertIn('"Salvar configuração da VPN principal"', self.app)
        self.assertNotIn('"Salvar conexão"', self.app)
        self.assertNotIn("Autenticação via navegador", self.app)
        self.assertNotIn("pelo openfortivpn", self.app)
        self.assertIn('"Autenticação web manual; conexão acompanhada e monitorada pelo aplicativo."', self.app)

    def test_ast_parses_application(self) -> None:
        ast.parse(self.app, filename=str(ROOT / "vpn_app/app.py"))


if __name__ == "__main__":
    unittest.main()
