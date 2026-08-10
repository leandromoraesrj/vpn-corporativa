from __future__ import annotations

import os
import secrets
import struct
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ConnectionTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.run_dir = self.root / "run" / "vpn"
        self.config_dir = self.root / "config"
        self.bin_dir = self.root / "bin"
        self.run_dir.mkdir(parents=True)
        self.config_dir.mkdir()
        self.bin_dir.mkdir()
        self.hosts = self.root / "hosts"
        self.hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
        self.mode = self.root / "mode"
        self.mode.write_text("normal\n", encoding="utf-8")
        self.processes = self.root / "processes"
        self.ready = self.root / "ready"
        self.consumed = self.root / "consumed"
        self.lock = self.root / "control.lock"
        self.identity_library = self.root / "vpn-process-identity"
        self.validator = self.root / "validator.py"
        self.launcher = self.root / "launcher"
        self.canary = secrets.token_hex(24).encode("ascii")
        self.valid_frame = struct.pack("!I", len(self.canary)) + self.canary

        (self.config_dir / "connection.conf").write_text(
            "host = vpn.example\nport = 443\nusername = user\n"
            "set-routes = 0\nset-dns = 0\n"
            "trusted-cert = " + "a" * 64 + "\n",
            encoding="utf-8",
        )
        (self.config_dir / "routes.conf").write_text(
            "192.0.2.0/24\n", encoding="utf-8"
        )
        (self.config_dir / "hosts.conf").write_text(
            "192.0.2.1 internal.example\n", encoding="utf-8"
        )
        self._write_support_files()
        self.connect = self._transform_helper("vpn-connect")
        self.disconnect = self._transform_helper("vpn-disconnect")
        self.environment = {
            **os.environ,
            "PATH": f"{self.bin_dir}:{os.environ['PATH']}",
            "SUDO_USER": os.environ.get("USER", "nobody"),
        }

    def tearDown(self) -> None:
        if self.processes.exists():
            for raw in self.processes.read_text(encoding="utf-8").splitlines():
                try:
                    os.kill(int(raw), 15)
                except (ProcessLookupError, ValueError):
                    pass
        self.temporary.cleanup()

    def _write_support_files(self) -> None:
        self.identity_library.write_text(
            r'''process_starttime() {
    local line rest
    IFS= read -r line < "/proc/$1/stat" || return 1
    rest="${line##*) }"
    read -r -a fields <<< "$rest"
    printf '%s\n' "${fields[19]}"
}
write_process_identity() {
    local pid="$1" exe="$2" conf="$3" file="$4" start temp
    start="$(process_starttime "$pid")" || return 1
    temp="$(mktemp "${file}.tmp.XXXXXX")" || return 1
    printf 'pid=%s\nstarttime=%s\nexecutable=%s\nconfig=%s\n' \
        "$pid" "$start" "$exe" "$conf" > "$temp"
    chmod 600 "$temp"
    mv -f "$temp" "$file"
}
verify_process_identity() {
    local pid="" starttime="" key value
    [[ -f "$1" ]] || return 1
    while IFS='=' read -r key value; do
        case "$key" in pid) pid="$value" ;; starttime) starttime="$value" ;; esac
    done < "$1"
    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    kill -0 "$pid" 2>/dev/null || return 1
    [[ "$(process_starttime "$pid")" == "$starttime" ]] || return 1
    printf '%s\n' "$pid"
}
''',
            encoding="utf-8",
        )
        self.validator.write_text(
            "import pathlib, shutil, sys\n"
            f"mode = pathlib.Path({str(self.mode)!r}).read_text().strip()\n"
            "if mode == 'fail_before': raise SystemExit(1)\n"
            "args = sys.argv\n"
            "out = pathlib.Path(args[args.index('--output') + 1])\n"
            "out.mkdir(parents=True, exist_ok=True)\n"
            "for option, name in [('--connection', 'connection.conf'), "
            "('--routes', 'routes.conf'), ('--hosts', 'hosts.conf')]:\n"
            "    shutil.copyfile(args[args.index(option) + 1], out / name)\n",
            encoding="utf-8",
        )
        openfortivpn = self.bin_dir / "openfortivpn"
        openfortivpn.write_text(
            "#!/bin/bash\n"
            "set -euo pipefail\n"
            "exec 1>/dev/null 2>/dev/null\n"
            "[[ $# -eq 2 && $1 == -c && $2 == /proc/self/fd/[0-9]* ]] || exit 64\n"
            "[[ $(readlink \"$2\") == /memfd:vpn-openfortivpn-config* ]] || exit 65\n"
            "IFS= read -r expected <&\"$EXPECTED_CANARY_FD\"\n"
            "config=\"$(<\"$2\")\"\n"
            "password=\"${config##*$'\\npassword = '}\"\n"
            "[[ $password == \"$expected\" ]] || exit 66\n"
            "[[ \"$config\" == *$'\\npassword = '\"$password\" ]] || exit 67\n"
            "unset expected password config\n"
            f"printf '%s\\n' \"$$\" >> \"{self.processes!s}\"\n"
            f"printf '%s\\n' memfd-validado > \"{self.consumed!s}\"\n"
            f"mode=$(< {self.mode!s})\n"
            "if [[ $mode == fail_after ]]; then sleep 0.1; exit 1; fi\n"
            "if [[ $mode == delayed ]]; then sleep 0.3; fi\n"
            f"touch {self.ready!s}\n"
            f"trap 'rm -f {self.ready!s}; exit 0' TERM INT EXIT\n"
            "while :; do sleep 0.1; done\n",
            encoding="utf-8",
        )
        openfortivpn.chmod(0o755)
        launcher_source = (ROOT / "vpn-openfortivpn.py").read_text(encoding="utf-8")
        executable_discovery = (
            '            executable = shutil.which("openfortivpn", '
            'path="/usr/sbin:/usr/bin:/sbin:/bin")'
        )
        self.assertEqual(launcher_source.count(executable_discovery), 1)
        launcher_source = launcher_source.replace(
            executable_discovery,
            f"            executable = {str(openfortivpn)!r}",
        )
        self.launcher.write_text(launcher_source, encoding="utf-8")
        self.launcher.chmod(0o755)
        ip = self.bin_dir / "ip"
        ip.write_text(
            "#!/bin/bash\n"
            f"ready={self.ready!s}\n"
            "if [[ $1 == route && $2 == show && $3 == default && $# == 3 ]]; then\n"
            "  echo 'default via 192.0.2.1 dev eth0'; exit 0\n"
            "fi\n"
            "if [[ $1 == route && $2 == get ]]; then echo \"$3 dev eth0\"; exit 0; fi\n"
            "if [[ $1 == route ]]; then exit 0; fi\n"
            "if [[ $1 == -br && $2 == link ]]; then\n"
            "  [[ -e $ready ]] && echo 'ppp7 UP'; exit 0\n"
            "fi\n"
            "if [[ $1 == link && $2 == show && $3 == up && $4 == dev ]]; then\n"
            "  [[ -e $ready && $5 == ppp7 ]]; exit\n"
            "fi\n"
            "exit 0\n",
            encoding="utf-8",
        )
        ip.chmod(0o755)

    def _transform_helper(self, name: str) -> Path:
        source = (ROOT / name).read_text(encoding="utf-8")
        replacements = {
            'readonly RUN_DIR="/run/vpn"': f'readonly RUN_DIR="{self.run_dir}"',
            'readonly CONTROL_LOCK="/run/lock/vpn-corporativa.lock"':
                f'readonly CONTROL_LOCK="{self.lock}"',
            'readonly CONFIG_DIR="$TARGET_HOME/.config/vpn"':
                f'readonly CONFIG_DIR="{self.config_dir}"',
            'readonly HOSTS_FILE="/etc/hosts"': f'readonly HOSTS_FILE="{self.hosts}"',
            'readonly VALIDATOR="/usr/local/libexec/vpn-privileged-validation.py"':
                f'readonly VALIDATOR="{self.validator}"',
            'readonly PROCESS_IDENTITY="/usr/local/libexec/vpn-process-identity"':
                f'readonly PROCESS_IDENTITY="{self.identity_library}"',
            'readonly OPENFORTIVPN_LAUNCHER="/usr/local/libexec/vpn-openfortivpn.py"':
                f'readonly OPENFORTIVPN_LAUNCHER="{self.launcher}"',
            'readonly OPENFORTIVPN_EXE="$(readlink -f "$(command -v openfortivpn)")"':
                'readonly OPENFORTIVPN_EXE="/usr/bin/bash"',
        }
        for original, replacement in replacements.items():
            source = source.replace(original, replacement)
        path = self.root / name
        path.write_text(source, encoding="utf-8")
        return path

    def _start_connect(self, frame: bytes | None = None) -> subprocess.Popen:
        expected_read, expected_write = os.pipe()
        os.write(expected_write, self.canary + b"\n")
        os.close(expected_write)
        try:
            process = subprocess.Popen(
                ["bash", str(self.connect)],
                env={**self.environment, "EXPECTED_CANARY_FD": str(expected_read)},
                pass_fds=(expected_read,),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        finally:
            os.close(expected_read)
        assert process.stdin is not None
        process.stdin.write(self.valid_frame if frame is None else frame)
        process.stdin.close()
        process.stdin = None
        return process

    def _assert_configs_have_no_password(self) -> None:
        paths = [self.config_dir / "connection.conf", self.run_dir / "config" / "connection.conf"]
        for path in paths:
            if path.exists():
                self.assertNotIn(b"password", path.read_bytes(), str(path))

    def _assert_canary_not_persisted(self, *outputs: bytes) -> None:
        for output in outputs:
            self.assertNotIn(self.canary, output)
        for path in self.root.rglob("*"):
            if not path.is_file():
                continue
            try:
                content = path.read_bytes()
            except OSError:
                continue
            self.assertNotIn(self.canary, content, str(path))

    def _wait_for(self, path: Path, timeout: float = 3) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists():
                return
            time.sleep(0.01)
        self.fail(f"Timeout aguardando {path}")

    def _managed_pids(self) -> list[int]:
        if not self.processes.exists():
            return []
        return [
            int(value)
            for value in self.processes.read_text(encoding="utf-8").splitlines()
            if value
        ]

    def test_valid_frame_reaches_memfd_consumer_without_persisting_secret(self) -> None:
        connection = self._start_connect()
        self._wait_for(self.run_dir / "interface")
        self._wait_for(self.consumed)
        self.assertEqual(self.consumed.read_text(encoding="utf-8"), "memfd-validado\n")
        self._assert_configs_have_no_password()
        self._assert_canary_not_persisted()

        disconnected = subprocess.run(
            ["bash", str(self.disconnect)], env=self.environment,
            capture_output=True, timeout=5, check=False,
        )
        stdout, stderr = connection.communicate(timeout=5)
        self.assertEqual(disconnected.returncode, 0, disconnected.stderr)
        self.assertEqual(connection.returncode, 0, stderr)
        for pid in self._managed_pids():
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
        self.assertFalse((self.run_dir / "config").exists())
        self._assert_configs_have_no_password()
        self._assert_canary_not_persisted(
            stdout, stderr, disconnected.stdout, disconnected.stderr,
        )

    def test_invalid_credential_frames_roll_back_without_starting_consumer(self) -> None:
        cases = {
            "stdin vazio": b"",
            "header truncado": b"\0\0\0",
            "payload truncado": struct.pack("!I", 4) + b"abc",
            "tamanho zero": struct.pack("!I", 0),
            "tamanho acima do limite": struct.pack("!I", 4097),
            "bytes excedentes": self.valid_frame + b"x",
            "utf-8 inválido": struct.pack("!I", 1) + b"\xff",
            "newline": struct.pack("!I", 3) + b"a\nb",
            "NUL": struct.pack("!I", 3) + b"a\0b",
        }
        for name, frame in cases.items():
            with self.subTest(name=name):
                connection = self._start_connect(frame)
                stdout, stderr = connection.communicate(timeout=5)
                self.assertNotEqual(connection.returncode, 0)
                self.assertFalse(self.consumed.exists())
                self.assertEqual(self._managed_pids(), [])
                self.assertFalse((self.run_dir / "openfortivpn.process").exists())
                self.assertFalse((self.run_dir / "interface").exists())
                self.assertFalse((self.run_dir / "route_state.txt").exists())
                self.assertFalse((self.run_dir / "config").exists())
                self._assert_configs_have_no_password()
                self._assert_canary_not_persisted(stdout, stderr)

    def test_two_simultaneous_connections_start_only_one_process(self) -> None:
        first = self._start_connect()
        second = self._start_connect()
        self._wait_for(self.run_dir / "interface")
        deadline = time.monotonic() + 3
        while first.poll() is None and second.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        exited, owner = (
            (first, second) if first.poll() is not None else (second, first)
        )
        exited_result = exited.communicate(timeout=3)
        self.assertEqual(exited.returncode, 0, exited_result[1])
        self.assertIn("já em execução".encode(), exited_result[0])
        self.assertEqual(len(self._managed_pids()), 1)
        self.assertIsNone(owner.poll())

        disconnected = subprocess.run(
            ["bash", str(self.disconnect)], env=self.environment,
            capture_output=True, check=True, timeout=5,
        )
        owner_result = owner.communicate(timeout=5)
        self.assertFalse((self.run_dir / "interface").exists())
        self.assertFalse((self.run_dir / "openfortivpn.process").exists())
        self._assert_configs_have_no_password()
        self._assert_canary_not_persisted(
            *exited_result, *owner_result, disconnected.stdout, disconnected.stderr,
        )

    def test_disconnect_during_initialization_waits_then_rolls_back(self) -> None:
        self.mode.write_text("delayed\n", encoding="utf-8")
        connection = self._start_connect()
        self._wait_for(self.processes)
        disconnected = subprocess.run(
            ["bash", str(self.disconnect)], env=self.environment,
            capture_output=True, timeout=5, check=False,
        )
        self.assertEqual(disconnected.returncode, 0, disconnected.stderr)
        connection_result = connection.communicate(timeout=5)
        self.assertFalse((self.run_dir / "interface").exists())
        self.assertFalse((self.run_dir / "openfortivpn.process").exists())
        self._assert_configs_have_no_password()
        self._assert_canary_not_persisted(
            *connection_result, disconnected.stdout, disconnected.stderr,
        )

    def test_failure_before_identity_starts_no_process(self) -> None:
        self.mode.write_text("fail_before\n", encoding="utf-8")
        connection = self._start_connect()
        stdout, stderr = connection.communicate(timeout=5)
        self.assertNotEqual(connection.returncode, 0)
        self.assertNotIn(b"unbound variable", stderr)
        self.assertEqual(self._managed_pids(), [])
        self.assertFalse((self.run_dir / "openfortivpn.process").exists())
        self.assertFalse((self.run_dir / "interface").exists())
        self.assertFalse((self.run_dir / "route_state.txt").exists())
        self.assertFalse((self.run_dir / "config").exists())
        self._assert_configs_have_no_password()
        self._assert_canary_not_persisted(stdout, stderr)

    def test_failure_after_process_start_terminates_and_removes_attempt(self) -> None:
        self.mode.write_text("fail_after\n", encoding="utf-8")
        connection = self._start_connect()
        stdout, stderr = connection.communicate(timeout=5)
        self.assertNotEqual(connection.returncode, 0)
        pids = self._managed_pids()
        self.assertEqual(len(pids), 1)
        with self.assertRaises(ProcessLookupError):
            os.kill(pids[0], 0)
        self.assertFalse((self.run_dir / "interface").exists())
        self.assertFalse((self.run_dir / "openfortivpn.process").exists())
        self.assertEqual(self.hosts.read_text(encoding="utf-8"), "127.0.0.1 localhost\n")
        self._assert_configs_have_no_password()
        self._assert_canary_not_persisted(stdout, stderr)


if __name__ == "__main__":
    unittest.main()
