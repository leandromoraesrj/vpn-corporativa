from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
import importlib.util
from unittest import mock
from pathlib import Path

from vpn_app import app, config_store, network
from vpn_app.privileged_validation import (
    create_snapshots,
    parse_connection,
    validate_all,
    validate_hosts,
    validate_routes,
)


ROOT = Path(__file__).resolve().parents[1]


class Revision103Tests(unittest.TestCase):
    @staticmethod
    def _application_for_connection_save(password: str):
        application = object.__new__(app.VPNApplication)
        application.config_entries = {}
        for key, value in {
            "host": "gateway.example",
            "port": "443",
            "username": "user",
            "password": password,
        }.items():
            entry = mock.Mock()
            entry.get_text.return_value = value
            application.config_entries[key] = entry
        application.auto_reconnect_check = mock.Mock()
        application.auto_reconnect_check.get_active.return_value = True
        application.auto_reconnect_primary = True
        application.reconnect_status = ""
        show_message = mock.Mock()
        application.__dict__["_show_message"] = show_message
        return application, show_message

    @staticmethod
    def _stored_connection_values():
        return {
            "host": "old-gateway.example",
            "port": "443",
            "username": "user",
            "certificate-policy": "system-ca-with-pinned-fallback",
            "trusted-cert": "a" * 64,
        }

    def test_credential_diagnostic_distinguishes_absent_and_unavailable(self):
        with mock.patch.object(app.secret_store, "lookup_diagnostic", return_value=(None, "ausente", {"attributes": "service=vpn-corporativa, username=user"})):
            self.assertEqual(app.secret_store.lookup_diagnostic("user")[1], "ausente")
        with mock.patch.object(app.secret_store, "lookup_diagnostic", return_value=(None, "indisponivel", {"attributes": "service=vpn-corporativa, username=user"})):
            self.assertEqual(app.secret_store.lookup_diagnostic("user")[1], "indisponivel")

    def test_connection_save_stores_new_password_and_replaces_existing_credential(self):
        application, _show_message = self._application_for_connection_save("new-secret")
        credentials = {"user": "old-secret"}

        def replace_credential(username, password):
            credentials[username] = password

        with mock.patch.object(
            config_store,
            "read_key_values",
            return_value=self._stored_connection_values(),
        ), mock.patch.object(
            app.secret_store,
            "store",
            side_effect=replace_credential,
        ) as store, mock.patch.object(
            app.secret_store,
            "lookup",
        ) as lookup, mock.patch.object(
            config_store,
            "save_connection",
        ) as save_connection, mock.patch.object(
            config_store,
            "save_auto_reconnect_primary",
        ):
            application.save_connection()

        store.assert_called_once_with("user", "new-secret")
        lookup.assert_not_called()
        self.assertEqual(credentials["user"], "new-secret")
        saved_values = save_connection.call_args.args[0]
        self.assertNotIn("password", saved_values)
        self.assertEqual(
            saved_values["certificate-policy"],
            "system-ca-with-pinned-fallback",
        )
        self.assertEqual(saved_values["trusted-cert"], "a" * 64)

    def test_connection_save_empty_password_preserves_existing_credential(self):
        application, _show_message = self._application_for_connection_save("")
        with mock.patch.object(
            config_store,
            "read_key_values",
            return_value=self._stored_connection_values(),
        ), mock.patch.object(
            app.secret_store,
            "store",
        ) as store, mock.patch.object(
            app.secret_store,
            "lookup",
            return_value="existing-secret",
        ) as lookup, mock.patch.object(
            config_store,
            "save_connection",
        ) as save_connection, mock.patch.object(
            config_store,
            "save_auto_reconnect_primary",
        ):
            application.save_connection()

        lookup.assert_called_once_with("user")
        store.assert_not_called()
        save_connection.assert_called_once()

    def test_connection_save_updates_reconnect_preference_in_memory_and_file(self):
        application, _show_message = self._application_for_connection_save("")
        application.auto_reconnect_check.get_active.return_value = False

        with tempfile.TemporaryDirectory() as temporary:
            config_dir = Path(temporary)
            with mock.patch.object(
                config_store,
                "CONFIG_DIR",
                config_dir,
            ), mock.patch.object(
                config_store,
                "PREFERENCES_FILE",
                config_dir / "preferences.conf",
            ), mock.patch.object(
                config_store,
                "read_key_values",
                return_value=self._stored_connection_values(),
            ), mock.patch.object(
                app.secret_store,
                "lookup",
                return_value="existing-secret",
            ), mock.patch.object(
                config_store,
                "save_connection",
            ):
                application.save_connection()

                self.assertFalse(application.auto_reconnect_primary)
                self.assertFalse(config_store.read_auto_reconnect_primary())
                self.assertEqual(
                    config_store.PREFERENCES_FILE.stat().st_mode & 0o777,
                    0o600,
                )

    def test_connection_save_empty_password_without_credential_is_blocked(self):
        application, show_message = self._application_for_connection_save("")
        with mock.patch.object(
            config_store,
            "read_key_values",
            return_value=self._stored_connection_values(),
        ), mock.patch.object(
            app.secret_store,
            "lookup",
            return_value=None,
        ), mock.patch.object(
            config_store,
            "save_connection",
        ) as save_connection, mock.patch.object(
            config_store,
            "save_auto_reconnect_primary",
        ) as save_preference:
            application.save_connection()

        save_connection.assert_not_called()
        save_preference.assert_not_called()
        show_message.assert_called_once_with(
            "Não foi possível salvar a conexão",
            "Informe a senha da VPN para armazená-la no GNOME Keyring.",
            error=True,
        )

    def test_connection_save_keyring_failure_does_not_save_or_expose_password(self):
        password = "secret-that-must-not-leak"
        application, show_message = self._application_for_connection_save(password)
        with mock.patch.object(
            config_store,
            "read_key_values",
            return_value=self._stored_connection_values(),
        ), mock.patch.object(
            app.secret_store,
            "store",
            side_effect=RuntimeError(password),
        ), mock.patch.object(
            config_store,
            "save_connection",
        ) as save_connection, mock.patch.object(
            config_store,
            "save_auto_reconnect_primary",
        ) as save_preference:
            application.save_connection()

        save_connection.assert_not_called()
        save_preference.assert_not_called()
        rendered_message = repr(show_message.call_args)
        self.assertNotIn(password, rendered_message)
        self.assertIn("GNOME Keyring", rendered_message)

    def test_connection_save_keyring_lookup_failure_does_not_update_configuration(self):
        sensitive_detail = "keyring-sensitive-detail"
        application, show_message = self._application_for_connection_save("")
        with mock.patch.object(
            config_store,
            "read_key_values",
            return_value=self._stored_connection_values(),
        ), mock.patch.object(
            app.secret_store,
            "lookup",
            side_effect=RuntimeError(sensitive_detail),
        ), mock.patch.object(
            config_store,
            "save_connection",
        ) as save_connection, mock.patch.object(
            config_store,
            "save_auto_reconnect_primary",
        ) as save_preference:
            application.save_connection()

        save_connection.assert_not_called()
        save_preference.assert_not_called()
        rendered_message = repr(show_message.call_args)
        self.assertNotIn(sensitive_detail, rendered_message)
        self.assertIn("GNOME Keyring", rendered_message)

    def test_missing_connection_configuration_has_clear_message(self):
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "connection.conf"
            with mock.patch.object(config_store, "CONNECTION_FILE", missing):
                with self.assertRaises(RuntimeError) as raised:
                    app.VPNApplication._credential_frame()
            self.assertIn(
                "Restaure uma configuração autorizada ou reexecute o instalador "
                "para reprovisionar a VPN principal.",
                str(raised.exception),
            )
            self.assertNotIn("Salve a conexão na aba Configuração", str(raised.exception))

    def test_configured_username_looks_up_keyring_without_password_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            connection = Path(temporary) / "connection.conf"
            connection.write_text(
                "host = gateway.example\nport = 443\nusername = user\n"
                "set-routes = 0\nset-dns = 0\ntrusted-cert = " + "a" * 64 + "\n",
                encoding="utf-8",
            )
            with mock.patch.object(config_store, "CONNECTION_FILE", connection), mock.patch.object(
                app.secret_store,
                "lookup_diagnostic",
                return_value=("secret", "encontrada", {"attributes": "service=vpn-corporativa, username=user"}),
            ) as lookup:
                frame = app.VPNApplication._credential_frame()
            lookup.assert_called_once_with("user")
            self.assertNotIn(b"secret", connection.read_bytes())
            self.assertEqual(frame[0:4], (6).to_bytes(4, "big"))
    def test_launcher_translates_certificate_policies_without_leaking_internal_directive(self):
        spec = importlib.util.spec_from_file_location(
            "vpn_openfortivpn", ROOT / "vpn-openfortivpn.py"
        )
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "connection.conf"
            fingerprint = "a" * 64
            path.write_text(
                "host = vpn.example\nport = 443\nusername = user\n"
                "set-routes = 0\nset-dns = 0\n"
                f"certificate-policy = system-ca\n",
                encoding="utf-8",
            )
            system_ca = module.config_with_password(path, "secret")
            self.assertNotIn(b"certificate-policy", system_ca)
            self.assertNotIn(b"trusted-cert", system_ca)

            path.write_text(
                "host = vpn.example\nport = 443\nusername = user\n"
                "set-routes = 0\nset-dns = 0\n"
                f"trusted-cert = {fingerprint}\n",
                encoding="utf-8",
            )
            legacy = module.config_with_password(path, "secret")
            self.assertIn(f"trusted-cert = {fingerprint}".encode(), legacy)
            self.assertNotIn(b"certificate-policy", legacy)

            path.write_text(
                "host = vpn.example\nport = 443\nusername = user\n"
                "set-routes = 0\nset-dns = 0\n"
                "certificate-policy = system-ca-with-pinned-fallback\n"
                f"trusted-cert = {fingerprint}\n",
                encoding="utf-8",
            )
            fallback = module.config_with_password(path, "secret")
            self.assertIn(f"trusted-cert = {fingerprint}".encode(), fallback)
            self.assertNotIn(b"certificate-policy", fallback)

    def test_installer_does_not_pass_password_in_python_arguments(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertNotIn(
            'python3 - "$HOST" "$PORT" "$VPN_USER" "$VPN_PASSWORD"',
            installer,
        )
        self.assertIn("sys.stdin.buffer.read()", installer)

    def test_credential_flow_security_contract(self):
        app = (ROOT / "vpn_app/app.py").read_text(encoding="utf-8")
        launcher = (ROOT / "vpn-openfortivpn.py").read_text(encoding="utf-8")
        connect = (ROOT / "vpn-connect").read_text(encoding="utf-8")
        uninstall = (ROOT / "uninstall.sh").read_text(encoding="utf-8")

        self.assertLess(
            app.index("secret_store.store(username, legacy_password)"),
            app.index("config_store.save_connection(values)", app.index("legacy_password")),
        )
        self.assertIn("finally:", app[app.index("def _start_connect_helper"):])
        self.assertIn("process.stdin.close()", app)
        self.assertIn("MFD_ALLOW_SEALING", launcher)
        self.assertIn("F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL", launcher)
        self.assertNotIn("except OSError:\n                pass", launcher)
        self.assertIn("/usr/bin/python3 -I -E", connect)
        self.assertIn('"$ROOT_CONF" <&0 &', connect)
        self.assertIn("clear_keyring_credential", uninstall)
        self.assertIn("Remover a credencial do GNOME Keyring?", uninstall)
        identity = (ROOT / "vpn-process-identity").read_text(encoding="utf-8")
        self.assertIn('/proc/$pid/fd/${arguments[2]##*/}', identity)
        self.assertIn("/memfd:vpn-openfortivpn-config*", identity)

    def _write_valid_configuration(self, root: Path) -> tuple[Path, Path, Path]:
        connection = root / "connection.conf"
        routes = root / "routes.conf"
        hosts = root / "hosts.conf"
        connection.write_text(
            "host = vpn.example\nport = 0443\nusername = user\n"
            "password = secret\nset-routes = 0\nset-dns = 0\n"
            "trusted-cert = " + "a" * 64 + "\n",
            encoding="utf-8",
        )
        routes.write_text("198.51.100.8/24\n198.51.100.0/24\n", encoding="utf-8")
        hosts.write_text("192.0.2.1 internal_alias.example\n", encoding="utf-8")
        return connection, routes, hosts

    def test_privileged_validator_ignores_malicious_pythonpath(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            connection, routes, hosts = self._write_valid_configuration(root)
            output = root / "snapshots"
            malicious = root / "malicious" / "vpn_app"
            malicious.mkdir(parents=True)
            marker = root / "imported"
            (malicious / "__init__.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).touch()\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(root / "malicious")
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-E",
                    str(ROOT / "vpn_app/privileged_validation.py"),
                    "--connection", str(connection),
                    "--routes", str(routes),
                    "--hosts", str(hosts),
                    "--output", str(output),
                ],
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(marker.exists())
            self.assertEqual(
                (output / "routes.conf").read_text(encoding="utf-8"),
                "198.51.100.0/24\n",
            )

    def test_repeated_connect_preserves_all_managed_runtime_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "run" / "vpn"
            snapshots = run_dir / "config"
            snapshots.mkdir(parents=True)
            interface = run_dir / "interface"
            identity = run_dir / "openfortivpn.process"
            route_state = run_dir / "route_state.txt"
            interface.write_text("ppp7\n", encoding="utf-8")
            identity.write_text("4242\n", encoding="utf-8")
            route_state.write_text("default via 192.0.2.1\n", encoding="utf-8")
            (snapshots / "connection.conf").write_text(
                "snapshot preservado\n", encoding="utf-8"
            )
            hosts = root / "hosts"
            hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
            (root / "control.lock").touch()

            identity_library = root / "vpn-process-identity"
            identity_library.write_text(
                "verify_process_identity() {\n"
                "    [[ -f \"$1\" ]] || return 1\n"
                "    cat \"$1\"\n"
                "}\n",
                encoding="utf-8",
            )
            helper_source = (ROOT / "vpn-connect").read_text(encoding="utf-8")
            helper_source = helper_source.replace(
                'readonly RUN_DIR="/run/vpn"',
                f'readonly RUN_DIR="{run_dir}"',
            ).replace(
                'readonly CONTROL_LOCK="/run/lock/vpn-corporativa.lock"',
                f'readonly CONTROL_LOCK="{root / "control.lock"}"',
            ).replace(
                'readonly HOSTS_FILE="/etc/hosts"',
                f'readonly HOSTS_FILE="{hosts}"',
            ).replace(
                'readonly PROCESS_IDENTITY="/usr/local/libexec/vpn-process-identity"',
                f'readonly PROCESS_IDENTITY="{identity_library}"',
            )
            helper = root / "vpn-connect"
            helper.write_text(helper_source, encoding="utf-8")

            before = {
                path.relative_to(root): path.read_bytes()
                for path in root.rglob("*") if path.is_file()
            }
            result = subprocess.run(
                ["bash", str(helper)],
                env={**os.environ, "SUDO_USER": os.environ.get("USER", "nobody")},
                text=True,
                capture_output=True,
                check=False,
            )
            after = {
                path.relative_to(root): path.read_bytes()
                for path in root.rglob("*") if path.is_file()
            }

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("VPN já em execução com PID 4242", result.stdout)
            self.assertEqual(after, before)
            with mock.patch.object(network, "run_text", return_value="ppp7 UP"):
                self.assertEqual(network.vpn_interface(interface), "ppp7")

    def test_snapshots_are_private_normalized_and_immutable_from_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            connection, routes, hosts = self._write_valid_configuration(root)
            output = root / "snapshots"
            create_snapshots(connection, routes, hosts, output)
            routes.write_text("0.0.0.0/0\n", encoding="utf-8")
            hosts.write_text("203.0.113.4 changed.example\n", encoding="utf-8")

            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            for snapshot in output.iterdir():
                self.assertEqual(snapshot.stat().st_mode & 0o777, 0o600)
                self.assertNotIn("password", snapshot.read_text(encoding="utf-8"))
            self.assertEqual(
                validate_routes(output / "routes.conf"),
                ["198.51.100.0/24"],
            )
            self.assertEqual(
                validate_hosts(output / "hosts.conf"),
                ["192.0.2.1 internal_alias.example"],
            )

    def test_process_identity_rejects_changed_starttime_and_arguments(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "process.state"
            code = "import time; time.sleep(30)"
            process = subprocess.Popen([sys.executable, "-c", code])
            executable = str(Path(f"/proc/{process.pid}/exe").resolve())
            library = ROOT / "vpn-process-identity"
            try:
                command = (
                    f'source "$1"; '
                    f'write_process_identity "$2" "$3" "$4" "$5"; '
                    f'verify_process_identity "$5"'
                )
                valid = subprocess.run(
                    ["bash", "-c", command, "bash", str(library),
                     str(process.pid), executable, code, str(state)],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(valid.returncode, 0, valid.stderr)
                self.assertEqual(valid.stdout.strip(), str(process.pid))

                content = state.read_text(encoding="utf-8")
                state.write_text(
                    content.replace(f"config={code}", "config=wrong"),
                    encoding="utf-8",
                )
                wrong_arguments = subprocess.run(
                    ["bash", "-c", 'source "$1"; verify_process_identity "$2"',
                     "bash", str(library), str(state)],
                    check=False,
                )
                self.assertNotEqual(wrong_arguments.returncode, 0)

                state.write_text(
                    content.replace(f"executable={executable}", "executable=/bin/false"),
                    encoding="utf-8",
                )
                wrong_executable = subprocess.run(
                    ["bash", "-c", 'source "$1"; verify_process_identity "$2"',
                     "bash", str(library), str(state)],
                    check=False,
                )
                self.assertNotEqual(wrong_executable.returncode, 0)

                state.write_text(
                    content.replace("starttime=", "starttime=9"),
                    encoding="utf-8",
                )
                invalid = subprocess.run(
                    ["bash", "-c", 'source "$1"; verify_process_identity "$2"',
                     "bash", str(library), str(state)],
                    check=False,
                )
                self.assertNotEqual(invalid.returncode, 0)
            finally:
                process.terminate()
                process.wait(timeout=5)

    def test_process_identity_publish_is_atomic_for_concurrent_readers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "process.state"
            code = "import time; time.sleep(30)"
            process = subprocess.Popen([sys.executable, "-c", code])
            executable = str(Path(f"/proc/{process.pid}/exe").resolve())
            library = ROOT / "vpn-process-identity"
            command = r'''
source "$1"
write_process_identity "$2" "$3" "$4" "$5" || exit 1
printf() {
    builtin printf "$@"
    case "$1" in
        pid=*|starttime=*|executable=*|config=*) sleep 0.03 ;;
    esac
}
write_process_identity "$2" "$3" "$4" "$5" &
writer=$!
reads=0
invalid=0
while kill -0 "$writer" 2>/dev/null; do
    if verify_process_identity "$5" >/dev/null 2>&1; then
        reads=$((reads + 1))
    else
        invalid=$((invalid + 1))
    fi
done
wait "$writer" || exit 1
verify_process_identity "$5" >/dev/null || exit 1
compgen -G "${5}.tmp.*" >/dev/null && exit 1
((reads > 0 && invalid == 0))
'''
            try:
                result = subprocess.run(
                    ["bash", "-c", command, "bash", str(library),
                     str(process.pid), executable, code, str(state)],
                    text=True,
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
            finally:
                process.terminate()
                process.wait(timeout=5)

    def test_audit_reports_missing_and_incorrect_privileged_helpers(self):
        audit = (ROOT / "auditar_vpn.sh").read_text(encoding="utf-8")
        start = audit.index("audit_root_helper() {")
        end = audit.index("\n}\n", start) + 3
        function_source = audit[start:end]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            function_file = root / "audit-function.sh"
            function_file.write_text(function_source, encoding="utf-8")
            command = (
                'source "$1"; '
                'audit_root_helper "$2" || true; '
                'audit_root_helper "$3" || true'
            )
            helpers = [
                root / "vpn-process-identity",
                root / "vpn-privileged-validation.py",
            ]
            for incorrect, missing in (helpers, reversed(helpers)):
                for helper in helpers:
                    helper.unlink(missing_ok=True)
                incorrect.write_text("#!/bin/bash\n", encoding="utf-8")
                incorrect.chmod(0o644)
                result = subprocess.run(
                    ["bash", "-c", command, "bash", str(function_file),
                     str(incorrect), str(missing)],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"INCORRETO: {incorrect}", result.stdout)
                self.assertIn(f"AUSENTE: {missing}", result.stdout)

    def test_audit_does_not_require_passwordless_visudo(self):
        audit = (ROOT / "auditar_vpn.sh").read_text(encoding="utf-8")
        self.assertIn("if [[ $EUID -eq 0 ]]", audit)
        self.assertIn("modo e proprietário foram verificados", audit)

    def test_runtime_validation_rejects_unknown_directive(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "connection.conf"
            path.write_text(
                "host = vpn.example\n"
                "port = 443\n"
                "username = user\n"
                "password = secret\n"
                "set-routes = 0\n"
                "set-dns = 0\n"
                "trusted-cert = " + "a" * 64 + "\n"
                "pppd-use-peerdns = 1\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "não permitidas"):
                parse_connection(path)

    def test_runtime_validation_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            connection = root / "connection.conf"
            routes = root / "routes.conf"
            hosts = root / "hosts.conf"
            connection.write_text(
                "host = vpn.example\n"
                "port = 443\n"
                "username = user\n"
                "password = secret\n"
                "set-routes = 0\n"
                "set-dns = 0\n"
                "trusted-cert = " + "a" * 64 + "\n",
                encoding="utf-8",
            )
            routes.write_text("192.0.2.0/24\n", encoding="utf-8")
            real_hosts = root / "hosts-real.conf"
            real_hosts.write_text(
                "192.0.2.1 host.example\n",
                encoding="utf-8",
            )
            hosts.symlink_to(real_hosts)
            with self.assertRaisesRegex(ValueError, "Link simbólico"):
                validate_all(connection, routes, hosts)

    def test_routes_and_hosts_are_validated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            routes = root / "routes.conf"
            hosts = root / "hosts.conf"
            routes.write_text(
                "198.51.100.8/24\n198.51.100.0/24\n",
                encoding="utf-8",
            )
            hosts.write_text(
                "192.0.2.1 host.example\n",
                encoding="utf-8",
            )
            self.assertEqual(validate_routes(routes), ["198.51.100.0/24"])
            self.assertEqual(
                validate_hosts(hosts),
                ["192.0.2.1 host.example"],
            )


if __name__ == "__main__":
    unittest.main()
