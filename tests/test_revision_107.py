from __future__ import annotations

import ast
import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class TrayRevision107Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = (ROOT / "vpn_app/app.py").read_text(encoding="utf-8")
        self.install = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.manifest = (ROOT / "RELEASE_MANIFEST.json").read_text(encoding="utf-8")

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
        tracked = set(
            subprocess.check_output(["git", "ls-files"], cwd=ROOT, text=True).splitlines()
        )
        self.assertEqual(set(manifest["files"]), tracked)

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

    def test_tray_menu_reuses_current_action_labels_and_handlers(self) -> None:
        self.assertIn('Gtk.MenuItem(label="VPN Principal: Verificando...")', self.app)
        self.assertIn('Gtk.MenuItem(label="VPN Secundária: Verificando...")', self.app)
        self.assertIn('Gtk.MenuItem(label="Conectar VPN Principal")', self.app)
        self.assertIn('Gtk.MenuItem(label="Autenticar VPN Secundária")', self.app)
        self.assertIn('f"VPN Principal: {self._primary_status_text()}"', self.app)
        self.assertIn('f"VPN Secundária: {self._secondary_status_text()}"', self.app)
        self.assertIn('"Desconectar VPN Principal"', self.app)
        self.assertIn('"Conectar VPN Principal"', self.app)
        self.assertIn('"Ocultar F5"', self.app)
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
        self.assertIn('action_label == "Ocultar F5"', method)
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
            self.app.index('Gtk.MenuItem(label="Abrir Painel de VPN Corporativa")'),
            self.app.index('Gtk.MenuItem(label="VPN Principal: Verificando...")'),
        )

    def test_panel_item_runs_integrity_before_presenting_window(self) -> None:
        self.assertIn('Gtk.MenuItem(label="Abrir Painel de VPN Corporativa")', self.app)
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
            'Gtk.Window(title="Painel VPN Corporativa - Centro de Controle da Rede")',
            self.app,
        )
        self.assertIn('Gtk.Label(label="Principal")', self.app)
        self.assertNotIn('Gtk.Label(label="Painel Principal")', self.app)

    def test_ast_parses_application(self) -> None:
        ast.parse(self.app, filename=str(ROOT / "vpn_app/app.py"))


if __name__ == "__main__":
    unittest.main()
