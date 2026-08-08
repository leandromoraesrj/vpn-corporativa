from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class Revision102Tests(unittest.TestCase):
    def test_python_sources_parse(self):
        for path in [ROOT / "vpn.py", *sorted((ROOT / "vpn_app").glob("*.py"))]:
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    def test_runtime_files_are_not_written_to_tmp(self):
        app = (ROOT / "vpn_app/app.py").read_text(encoding="utf-8")
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertNotIn('/tmp/vpn_', app)
        self.assertIn('"$APP_DIR/vpn.py" "$STATE_DIR/launcher.log"', installer)
        self.assertIn('.local/state/vpn', installer)

    def test_connect_timeout_stops_subprocess(self):
        app = (ROOT / "vpn_app/app.py").read_text(encoding="utf-8")
        self.assertIn('def _stop_connect_process(', app)
        self.assertIn('process.terminate()', app)
        self.assertIn('process.kill()', app)
        self.assertEqual(
            app.count('GLib.idle_add(self._finish_diagnostic, result.returncode)'),
            1,
        )

    def test_installer_uses_primary_group_and_stable_name(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn('TARGET_GROUP="$(id -gn "$TARGET_USER")"', installer)
        self.assertNotIn('-g "$TARGET_USER"', installer)
        self.assertIn('Name=VPN Corporativa', installer)
        self.assertIn('VPN CORPORATIVA 1.1.1 — PRODUÇÃO', installer)
        self.assertEqual(installer.count('Version=1.0'), 2)

    def test_application_uses_release_version(self):
        app = (ROOT / "vpn_app/app.py").read_text(encoding="utf-8")
        self.assertIn('APP_VERSION = "1.1.1"', app)
        self.assertIn('Gtk.Window(title="Painel VPN Corporativa - Centro de Controle da Rede")', app)

    def test_audit_uses_terminal_only_and_safe_user_fallback(self):
        audit = (ROOT / "auditar_vpn.sh").read_text(encoding="utf-8")
        self.assertIn('CURRENT_USER="$(id -un', audit)
        self.assertNotIn('audit-latest.txt', audit)
        self.assertNotIn('tee "$REPORT"', audit)
        self.assertNotIn('Relatório salvo em:', audit)

    def test_installer_and_uninstaller_remove_known_legacy_tmp_files(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        uninstaller = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
        for name in ("vpn_start.log", "vpn_diagnostic_", "vpn_"):
            self.assertIn(name, installer)
            self.assertIn(name, uninstaller)

    def test_initial_configuration_uses_shared_validator(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn('from vpn_app.config_store import validate_connection', installer)

    def test_installer_preserves_existing_secondary_configuration(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        for name in (
            "connection.conf",
            "routes.conf",
            "hosts.conf",
            "secondary.conf",
        ):
            self.assertIn(f'if [[ ! -f "$CONFIG_DIR/{name}" ]]; then', installer)
            self.assertNotIn(f'rm -f "$CONFIG_DIR/{name}"', installer)

    def test_configuration_tabs_keep_required_order_and_expansion(self):
        app = (ROOT / "vpn_app/app.py").read_text(encoding="utf-8")
        labels = [
            'Gtk.Label(label="VPN principal")',
            'Gtk.Label(label="VPN secundária")',
            'Gtk.Label(label="Sub-redes")',
            'Gtk.Label(label="Hosts")',
        ]
        positions = [app.index(label) for label in labels]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("entry.set_hexpand(True)", app)
        self.assertIn("url_entry.set_hexpand(True)", app)
        self.assertIn('Gtk.Button(label="Autenticar VPN secundária")', app)
        self.assertIn(
            "button.set_sensitive(f5_backend.authentication_enabled(f5))",
            app,
        )
        self.assertIn(
            "button.set_sensitive(f5_backend.window_controls_enabled(f5))",
            app,
        )

    def test_primary_panel_uses_exact_vpn_titles(self):
        app = (ROOT / "vpn_app/app.py").read_text(encoding="utf-8")
        self.assertIn('Gtk.Frame(label="VPN principal (OpenFortiVPN)")', app)
        self.assertIn('Gtk.Frame(label="VPN secundária (BIG-IP/F5)")', app)

    def test_primary_panel_uses_natural_height_and_expected_labels(self):
        app = (ROOT / "vpn_app/app.py").read_text(encoding="utf-8")
        self.assertIn('Gtk.Label(label="Principal")', app)
        self.assertNotIn('Gtk.Label(label="Resumo")', app)
        self.assertIn("window.set_default_size(820, -1)", app)
        self.assertIn("notebook.set_current_page(0)", app)
        self.assertIn("self.primary_content.get_preferred_height()", app)
        self.assertIn("self.status_bar.get_preferred_height()", app)
        self.assertIn("+ self.primary_panel.get_spacing()", app)
        self.assertIn("+ status_natural_height", app)
        self.assertIn("self.window.resize(current_width, target_height)", app)
        self.assertNotIn('("Rota corporativa", "secondary_route")', app)

    def test_window_disables_maximize_and_manual_resize(self):
        app = (ROOT / "vpn_app/app.py").read_text(encoding="utf-8")
        self.assertIn('window.connect("realize", self._disable_window_maximize)', app)
        self.assertIn(
            'window.connect("configure-event", self._lock_window_at_target_size)',
            app,
        )
        self.assertIn("window.set_resizable(False)", app)
        self.assertIn("event.height >= self.initial_target_height", app)
        self.assertIn("Gdk.WMFunction.MINIMIZE", app)
        self.assertIn("Gdk.WMFunction.CLOSE", app)
        self.assertNotIn("Gdk.WMFunction.MAXIMIZE", app)

    def test_primary_vpn_panels_and_buttons_share_bottom_alignment(self):
        app = (ROOT / "vpn_app/app.py").read_text(encoding="utf-8")
        self.assertIn("primary_spacer.set_vexpand(True)", app)
        self.assertIn("primary_box.pack_start(primary_spacer, True, True, 0)", app)
        self.assertIn("secondary_spacer.set_vexpand(True)", app)
        self.assertIn("secondary_box.pack_start(secondary_spacer, True, True, 0)", app)
        self.assertIn("Gtk.SizeGroup(Gtk.SizeGroupMode.VERTICAL)", app)
        self.assertIn("vpn_height_group.add_widget(primary_frame)", app)
        self.assertIn("vpn_height_group.add_widget(secondary_frame)", app)

    def test_status_bar_uses_primary_panel_side_margins(self):
        app = (ROOT / "vpn_app/app.py").read_text(encoding="utf-8")
        self.assertIn("panel_margin = (", app)
        self.assertIn("status_bar.set_margin_start(panel_margin)", app)
        self.assertIn("status_bar.set_margin_end(panel_margin)", app)

    def test_diagnostic_and_connection_buttons_share_width_pattern(self):
        app = (ROOT / "vpn_app/app.py").read_text(encoding="utf-8")
        self.assertIn('self._full_width_button(\n            "Executar diagnóstico"', app)
        self.assertIn('self._full_width_button(\n            "Salvar conexão"', app)
        self.assertIn("button.set_hexpand(True)", app)

    def test_secondary_diagnostic_summary_uses_ok_label(self):
        diagnostic = (ROOT / "vpn-diagnose").read_text(encoding="utf-8")
        self.assertIn('STATUS_SECONDARY="OK (tun0)"', diagnostic)
        self.assertNotIn('STATUS_SECONDARY="ATIVA (tun0)"', diagnostic)

    def test_public_sources_only_contain_approved_external_hosts(self):
        allowed_hosts = {
            "api.ipify.org",
            "www.w3.org",
            "vpn.example.com",
            "vpn.valid.test",
            "old.valid.test",
        }
        url_pattern = re.compile(r"https?://([^/\s\"'<>]+)")
        found: set[str] = set()
        for path in ROOT.rglob("*"):
            if not path.is_file() or ".git" in path.parts:
                continue
            if path.suffix not in {".py", ".md", ".sh", ".svg", ".example"} and path.name not in {
                "install.sh", "uninstall.sh", "vpn-connect", "vpn-disconnect",
                "vpn-diagnose", "vpn-process-identity", "validate_release.sh",
            }:
                continue
            text = path.read_text(encoding="utf-8")
            found.update(match.group(1).lower() for match in url_pattern.finditer(text))
        self.assertLessEqual(found, allowed_hosts)


if __name__ == "__main__":
    unittest.main()
