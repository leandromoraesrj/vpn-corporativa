from __future__ import annotations

import ast
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
        self.assertIn('Gtk.MenuItem(label="Principal: verificando...")', self.app)
        self.assertIn('Gtk.MenuItem(label="Secundária: verificando...")', self.app)
        self.assertIn('Gtk.MenuItem(label="Conectar VPN principal")', self.app)
        self.assertIn('Gtk.MenuItem(label="Autenticar VPN secundária")', self.app)
        self.assertIn('f"Principal: {self._primary_status_text()}"', self.app)
        self.assertIn('f"Secundária: {self._secondary_status_text()}"', self.app)
        self.assertIn('"Desconectar VPN principal"', self.app)
        self.assertIn('"Conectar VPN principal"', self.app)
        self.assertIn('"Ocultar F5"', self.app)
        self.assertIn("f5_backend.window_visible()", self.app)
        self.assertIn("self.connect_vpn()", self.app)
        self.assertIn("self.disconnect_vpn()", self.app)
        self.assertIn("self.open_f5()", self.app)
        self.assertIn("self.show_f5()", self.app)
        self.assertIn("self.hide_f5()", self.app)

    def test_panel_item_precedes_status_items_in_tray_menu(self) -> None:
        self.assertLess(
            self.app.index('Gtk.MenuItem(label="Abrir painel de vpn corporativa")'),
            self.app.index('Gtk.MenuItem(label="Principal: verificando...")'),
        )

    def test_panel_item_runs_integrity_before_presenting_window(self) -> None:
        self.assertIn('Gtk.MenuItem(label="Abrir painel de vpn corporativa")', self.app)
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
