from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class UninstallSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.app = self.home / ".local/share/vpn"
        self.libexec = self.root / "libexec"
        self.run_dir = self.root / "run/vpn"
        self.hosts = self.root / "hosts"
        self.icons = self.root / "icons"
        self.sudoers = self.root / "sudoers-vpn"
        self.bin_dir = self.root / "bin"
        for directory in (self.app, self.libexec, self.run_dir, self.icons, self.bin_dir):
            directory.mkdir(parents=True)
        self.hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
        self.critical = {
            "connect": self.libexec / "vpn-connect",
            "disconnect": self.libexec / "vpn-disconnect",
            "diagnose": self.libexec / "vpn-diagnose",
            "state": self.run_dir / "recovery-state",
        }
        for path in self.critical.values():
            path.write_text("critical\n", encoding="utf-8")
        self.critical["disconnect"].chmod(0o755)
        self._write_commands()
        self.script = self._transform_uninstaller()
        self.environment = {**os.environ, "PATH": f"{self.bin_dir}:{os.environ['PATH']}"}

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_command(self, name: str, content: str) -> None:
        path = self.bin_dir / name
        path.write_text(f"#!/bin/bash\n{content}\n", encoding="utf-8")
        path.chmod(0o755)

    def _write_commands(self) -> None:
        self._write_command("getent", f"echo 'tester:x:1000:1000::{self.home}:/bin/bash'")
        self._write_command("sudo", "shift 2; exec \"$@\"")
        self._write_command("xdg-user-dir", f"echo '{self.home / 'Desktop'}'")
        self._write_command("pkill", "exit 0")
        self._write_command("id", "[[ $1 == -u ]] && echo 1000")
        self._write_command("ip", "exit 0")

    def _transform_uninstaller(self) -> Path:
        source = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
        replacements = {
            '[[ $EUID -eq 0 ]] || { echo "Execute: sudo ./uninstall.sh"; exit 1; }': ":",
            'readonly DISCONNECT_HELPER="/usr/local/libexec/vpn-disconnect"':
                f'readonly DISCONNECT_HELPER="{self.critical["disconnect"]}"',
            'readonly RUN_DIR="/run/vpn"': f'readonly RUN_DIR="{self.run_dir}"',
            'readonly HOSTS_FILE="/etc/hosts"': f'readonly HOSTS_FILE="{self.hosts}"',
            "/usr/local/libexec/vpn-connect": str(self.critical["connect"]),
            "/usr/local/libexec/vpn-disconnect": str(self.critical["disconnect"]),
            "/usr/local/libexec/vpn-diagnose": str(self.critical["diagnose"]),
            "/usr/local/libexec/vpn-process-identity": str(self.libexec / "vpn-process-identity"),
            "/usr/local/libexec/vpn-privileged-validation.py": str(self.libexec / "validator.py"),
            "/usr/local/libexec/vpn-openfortivpn.py": str(self.libexec / "vpn-openfortivpn.py"),
            "/usr/local/share/icons": str(self.icons),
            "/etc/sudoers.d/vpn": str(self.sudoers),
        }
        for original, replacement in replacements.items():
            source = source.replace(original, replacement)
        path = self.root / "uninstall.sh"
        path.write_text(source, encoding="utf-8")
        return path

    def _set_disconnect(self, body: str) -> None:
        self.critical["disconnect"].write_text(f"#!/bin/bash\n{body}\n", encoding="utf-8")
        self.critical["disconnect"].chmod(0o755)

    def _run(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(self.script)], input="S\nN\n", text=True,
            capture_output=True, env={**self.environment, "SUDO_USER": "tester"},
            timeout=5, check=False,
        )

    def _assert_critical_preserved(self, helper_expected: bool = True) -> None:
        for name, path in self.critical.items():
            if name == "disconnect" and not helper_expected:
                continue
            self.assertTrue(path.exists(), f"{name} deveria ser preservado")

    def _remove_helper(self) -> None:
        self.critical["disconnect"].unlink()

    def test_success_disconnects_then_uninstalls(self) -> None:
        marker = self.root / "disconnected"
        self._set_disconnect(f"touch '{marker}'; rm -f '{self.critical['state']}'")
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(marker.exists())
        self.assertFalse(self.app.exists())
        self.assertFalse(self.run_dir.exists())
        self.assertFalse(self.critical["connect"].exists())

    def test_disconnect_failure_aborts_and_preserves_critical_files(self) -> None:
        self._set_disconnect("exit 7")
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Falha ao desconectar", result.stderr)
        self._assert_critical_preserved()
        self.assertTrue(self.app.exists())

    def test_missing_helper_continues_only_when_system_is_proven_clean(self) -> None:
        self._remove_helper()
        self.critical["state"].unlink()
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.app.exists())

    def test_missing_helper_with_managed_process_aborts(self) -> None:
        self._remove_helper()
        (self.run_dir / "openfortivpn.process").write_text(
            f"pid={os.getpid()}\n", encoding="utf-8"
        )
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("processo openfortivpn gerenciado ativo", result.stderr)
        self._assert_critical_preserved(helper_expected=False)

    def test_missing_helper_with_active_interface_aborts(self) -> None:
        self._remove_helper()
        (self.run_dir / "interface").write_text("ppp7\n", encoding="utf-8")
        self._write_command("ip", "[[ $1 == link ]] && exit 0; exit 1")
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("interface PPP gerenciada ativa", result.stderr)
        self._assert_critical_preserved(helper_expected=False)

    def test_missing_helper_with_managed_routes_aborts(self) -> None:
        self._remove_helper()
        (self.run_dir / "interface").write_text("ppp7\n", encoding="utf-8")
        routes = self.run_dir / "config/routes.conf"
        routes.parent.mkdir()
        routes.write_text("192.0.2.0/24\n", encoding="utf-8")
        self._write_command(
            "ip", "[[ $1 == link ]] && exit 1; [[ $1 == route ]] && echo '192.0.2.0/24 dev ppp7'",
        )
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rotas gerenciadas presentes", result.stderr)
        self._assert_critical_preserved(helper_expected=False)

    def test_missing_helper_with_managed_hosts_aborts(self) -> None:
        self._remove_helper()
        self.critical["state"].unlink()
        self.hosts.write_text(
            "127.0.0.1 localhost\n# INICIO MAPA VPN\n192.0.2.1 internal\n# FIM MAPA VPN\n",
            encoding="utf-8",
        )
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("alterações gerenciadas em /etc/hosts", result.stderr)
        self.assertIn("# INICIO MAPA VPN", self.hosts.read_text(encoding="utf-8"))
        self.assertTrue(self.app.exists())

    def test_missing_helper_with_run_state_aborts_and_preserves_it(self) -> None:
        self._remove_helper()
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("estado presente em /run/vpn", result.stderr)
        self._assert_critical_preserved(helper_expected=False)

    def test_unmanaged_active_ppp_does_not_block_clean_uninstall(self) -> None:
        self._remove_helper()
        self.critical["state"].unlink()
        self._write_command(
            "ip",
            "[[ $1 == link && $5 == ppp99 ]] && exit 0; "
            "[[ $1 == -br ]] && echo 'ppp99 UP'; exit 0",
        )
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unmanaged_openfortivpn_process_does_not_block_or_get_stopped(self) -> None:
        self._remove_helper()
        self.critical["state"].unlink()
        executable = self.root / "openfortivpn"
        executable.write_text(
            "#!/bin/bash\ntrap 'exit 0' TERM\nwhile :; do sleep 0.1; done\n",
            encoding="utf-8",
        )
        executable.chmod(0o755)
        process = subprocess.Popen([str(executable)])
        try:
            result = self._run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIsNone(process.poll())
        finally:
            process.terminate()
            process.wait(timeout=3)

    def test_empty_or_invalid_state_files_abort_without_shell_errors(self) -> None:
        for name, content in (
            ("openfortivpn.process", ""),
            ("openfortivpn.process", "pid=invalid\n"),
            ("interface", ""),
            ("interface", "eth0\n"),
        ):
            with self.subTest(name=name, content=content):
                self._remove_helper()
                self.critical["state"].unlink()
                state = self.run_dir / name
                state.write_text(content, encoding="utf-8")
                result = self._run()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("estado presente em /run/vpn", result.stderr)
                self.assertNotIn("unbound variable", result.stderr)
                self.assertTrue(state.exists())
                state.unlink()
                self.critical["state"].write_text("critical\n", encoding="utf-8")
                self.critical["disconnect"].write_text("critical\n", encoding="utf-8")
                self.critical["disconnect"].chmod(0o755)

    def test_partially_removed_clean_installation_uninstalls_successfully(self) -> None:
        self._remove_helper()
        self.critical["state"].unlink()
        self.app.rmdir()
        self.critical["connect"].unlink()
        self.critical["diagnose"].unlink()
        self.run_dir.rmdir()
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("VPN removida.", result.stdout)

    def test_repeated_uninstall_is_idempotent(self) -> None:
        self._set_disconnect(f"rm -f '{self.critical['state']}'")
        first = self._run()
        second = self._run()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)

    def test_similar_hosts_comments_are_not_treated_as_managed_block(self) -> None:
        self._remove_helper()
        self.critical["state"].unlink()
        self.hosts.write_text(
            "127.0.0.1 localhost\n# backup de # INICIO MAPA VPN antigo\n",
            encoding="utf-8",
        )
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
