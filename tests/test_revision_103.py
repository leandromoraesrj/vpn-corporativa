from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from vpn_app import network
from vpn_app.privileged_validation import (
    create_snapshots,
    parse_connection,
    validate_all,
    validate_hosts,
    validate_routes,
)


ROOT = Path(__file__).resolve().parents[1]


class Revision103Tests(unittest.TestCase):
    def test_installer_does_not_pass_password_in_python_arguments(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertNotIn(
            'python3 - "$HOST" "$PORT" "$VPN_USER" "$VPN_PASSWORD"',
            installer,
        )
        self.assertIn("sys.stdin.buffer.read()", installer)

    def _write_valid_configuration(self, root: Path) -> tuple[Path, Path, Path]:
        connection = root / "connection.conf"
        routes = root / "routes.conf"
        hosts = root / "hosts.conf"
        connection.write_text(
            "host = vpn.example\nport = 0443\nusername = user\n"
            "password = secret\nset-routes = 0\nset-dns = 0\n"
            "trusted-cert = abc\n",
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
                "trusted-cert = abc\n"
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
                "trusted-cert = abc\n",
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
