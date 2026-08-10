from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class VpnDiagnoseSecondaryInterfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.config = self.home / ".config" / "vpn"
        self.config.mkdir(parents=True)
        (self.config / "routes.conf").write_text("", encoding="utf-8")
        (self.config / "hosts.conf").write_text("", encoding="utf-8")
        self.secondary = self.config / "secondary.conf"
        self.primary_state = self.root / "primary-interface"
        self.bin = self.root / "bin"
        self.bin.mkdir()

        source = (ROOT / "vpn-diagnose").read_text(encoding="utf-8")
        source = source.replace("/run/vpn/interface", str(self.primary_state))
        self.script = self.root / "vpn-diagnose"
        self.script.write_text(source, encoding="utf-8")
        self.script.chmod(0o755)

        self._write_command(
            "getent",
            """#!/bin/bash
if [[ "$1" == "passwd" ]]; then
    printf 'diagnostic:x:1000:1000::%s:/bin/bash\n' "$TEST_HOME"
elif [[ "$1" == "ahostsv4" ]]; then
    printf '203.0.113.10 STREAM %s\n' "$2"
else
    exit 1
fi
""",
        )
        self._write_command(
            "ip",
            """#!/bin/bash
link_state() {
    local requested="$1" name state kind address
    while IFS=: read -r name state kind address; do
        [[ "$name" == "$requested" ]] && { printf '%s' "$state"; return; }
    done <<< "$TEST_LINKS"
}

link_kind() {
    local requested="$1" name state kind address
    while IFS=: read -r name state kind address; do
        [[ "$name" == "$requested" ]] && { printf '%s' "$kind"; return; }
    done <<< "$TEST_LINKS"
}

link_address() {
    local requested="$1" name state kind address
    while IFS=: read -r name state kind address; do
        [[ "$name" == "$requested" ]] && { printf '%s' "$address"; return; }
    done <<< "$TEST_LINKS"
}

print_links() {
    local name state kind address
    while IFS=: read -r name state kind address; do
        [[ -n "$name" ]] || continue
        printf '%s %s %s\n' "$name" "$state" "${address:+$address/24}"
    done <<< "$TEST_LINKS"
}

if [[ "$1 $2 $3" == "-br address show" || "$1 $2 $3" == "-br link show" ]]; then
    print_links
elif [[ "$1 $2 $3 $4 $5" == "-4 -br addr show dev" ]]; then
    state="$(link_state "$6")"
    [[ "$state" == "UP" ]] || exit 1
    address="$(link_address "$6")"
    printf '%s UP %s\n' "$6" "${address:+$address/24}"
elif [[ "$1 $2 $3 $4 $5" == "-json -details link show dev" ]]; then
    state="$(link_state "$6")"
    kind="$(link_kind "$6")"
    [[ -n "$state" ]] || exit 1
    printf '[{"ifname":"%s","flags":["%s"],"linkinfo":{"info_kind":"%s"}}]\n' \
        "$6" "$state" "$kind"
elif [[ "$1 $2 $3 $4 $5" == "link show up dev"* ]]; then
    [[ "$(link_state "$5")" == "UP" ]]
elif [[ "$1 $2 $3" == "link show tailscale0" ]]; then
    exit 1
elif [[ "$1 $2 $3" == "route show default" ]]; then
    printf 'default via 192.0.2.1 dev eth0\n'
elif [[ "$1 $2 $3 $4" == "route show scope link" ]]; then
    printf '192.0.2.0/24 dev eth0 scope link\n'
elif [[ "$1 $2" == "route get" ]]; then
    printf '%s via 192.0.2.1 dev eth0\n' "$3"
elif [[ "$1 $2" == "route show" ]]; then
    :
else
    exit 1
fi
""",
        )
        self._write_command("timeout", "#!/bin/bash\nexit 0\n")
        self._write_command("ping", "#!/bin/bash\nexit 0\n")

        self.environment = os.environ.copy()
        self.environment.update(
            {
                "PATH": f"{self.bin}:/usr/bin:/bin",
                "SUDO_USER": "diagnostic",
                "TEST_HOME": str(self.home),
                "TEST_LINKS": "",
            }
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_command(self, name: str, content: str) -> None:
        path = self.bin / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)

    def _run(
        self,
        content: str | bytes | None,
        links: dict[str, str],
        primary: str = "",
        details: dict[str, tuple[str, str]] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if self.secondary.exists() or self.secondary.is_symlink():
            self.secondary.unlink()
        if isinstance(content, bytes):
            self.secondary.write_bytes(content)
        elif content is not None:
            self.secondary.write_text(content, encoding="utf-8")

        return self._run_existing_secondary(links, primary, details)

    def _run_existing_secondary(
        self,
        links: dict[str, str],
        primary: str = "",
        details: dict[str, tuple[str, str]] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if primary:
            self.primary_state.write_text(primary + "\n", encoding="utf-8")
        elif self.primary_state.exists():
            self.primary_state.unlink()

        environment = dict(self.environment)
        details = details or {}
        environment["TEST_LINKS"] = "\n".join(
            f"{name}:{state}:{details.get(name, ('tun', '192.0.2.10'))[0]}:"
            f"{details.get(name, ('tun', '192.0.2.10'))[1]}"
            for name, state in links.items()
        )
        return subprocess.run(
            ["bash", str(self.script)],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )

    def assert_secondary_status(self, result: subprocess.CompletedProcess[str], status: str) -> None:
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"Secundária:  {status}", result.stdout)

    def test_missing_interface_directive_defaults_to_tun0(self) -> None:
        for content in (None, "portal-url = https://vpn.valid.test/\n"):
            with self.subTest(content=content):
                result = self._run(content, {"tun0": "UP"})
                self.assert_secondary_status(result, "OK (tun0)")

    def test_explicit_empty_interface_enables_manual_mode(self) -> None:
        result = self._run("interface =\n", {"tun0": "UP"})

        self.assert_secondary_status(result, "MODO MANUAL")
        self.assertIn("nenhuma interface secundária foi assumida", result.stdout)
        self.assertNotIn("Secundária:  OK (tun0)", result.stdout)

    def test_configured_vpn_and_ppp_names_are_used_exactly(self) -> None:
        for interface in ("vpn1", "ppp0"):
            with self.subTest(interface=interface):
                result = self._run(
                    f"interface = {interface}\n",
                    {"tun0": "UP", interface: "UP"},
                )
                self.assert_secondary_status(result, f"OK ({interface})")

    def test_only_tunnel_types_with_valid_ipv4_are_ok(self) -> None:
        for interface, kind in (("tun1", "tun"), ("tap1", "tap"), ("ppp1", "ppp")):
            with self.subTest(kind=kind):
                result = self._run(
                    f"interface = {interface}\n",
                    {interface: "UP"},
                    details={interface: (kind, "192.0.2.10")},
                )
                self.assert_secondary_status(result, f"OK ({interface})")

    def test_active_non_tunnel_interface_is_inconsistent(self) -> None:
        result = self._run(
            "interface = eth0\n",
            {"eth0": "UP"},
            details={"eth0": ("ether", "192.0.2.10")},
        )

        self.assert_secondary_status(result, "INCONSISTENTE (eth0)")
        self.assertNotIn("Secundária:  OK (eth0)", result.stdout)

    def test_tunnel_without_ipv4_is_inconsistent(self) -> None:
        result = self._run(
            "interface = tun0\n",
            {"tun0": "UP"},
            details={"tun0": ("tun", "")},
        )

        self.assert_secondary_status(result, "INCONSISTENTE (tun0)")
        self.assertNotIn("Secundária:  OK (tun0)", result.stdout)

    def test_unrelated_tun0_does_not_validate_configured_interface(self) -> None:
        result = self._run(
            "interface = vpn1\n",
            {"tun0": "UP", "vpn1": "DOWN"},
        )

        self.assert_secondary_status(result, "NÃO DETECTADA (vpn1)")
        self.assertIn("Outros túneis VPN detectados: tun0", result.stdout)
        self.assertNotIn("Secundária:  OK (tun0)", result.stdout)

    def test_tun01_does_not_match_default_tun0(self) -> None:
        result = self._run(None, {"tun01": "UP"})

        self.assert_secondary_status(result, "NÃO DETECTADA (tun0)")
        self.assertNotIn("Secundária:  OK (tun0)", result.stdout)

    def test_configured_inactive_interface_is_not_connected(self) -> None:
        result = self._run("interface = tap1\n", {"tap1": "DOWN"})

        self.assert_secondary_status(result, "NÃO DETECTADA (tap1)")

    def test_primary_interface_cannot_also_be_secondary(self) -> None:
        result = self._run(
            "interface = ppp0\n",
            {"ppp0": "UP"},
            primary="ppp0",
        )

        self.assert_secondary_status(result, "CONFLITO (ppp0)")
        self.assertIn("coincide com a VPN principal", result.stdout)
        self.assertNotIn("Secundária:  OK (ppp0)", result.stdout)

    def test_invalid_interfaces_never_fall_back_to_tun0(self) -> None:
        invalid_values: tuple[str | bytes, ...] = (
            "/dev/tun0",
            "tun 0",
            "tun0;id",
            "x" * 16,
            "tun0\tbad",
            "tun0\rbad",
            "vpné",
            b"tun0\0evil",
        )
        for value in invalid_values:
            with self.subTest(value=repr(value)):
                if isinstance(value, bytes):
                    content: str | bytes = b"interface = " + value + b"\n"
                else:
                    content = f"interface = {value}\n"
                result = self._run(content, {"tun0": "UP"})
                self.assert_secondary_status(result, "CONFIGURAÇÃO INVÁLIDA")
                self.assertNotIn("Secundária:  OK (tun0)", result.stdout)

    def test_configuration_content_is_never_executed(self) -> None:
        marker = self.root / "executed"
        result = self._run(
            f"interface = $(touch {marker})\n",
            {"tun0": "UP"},
        )

        self.assert_secondary_status(result, "CONFIGURAÇÃO INVÁLIDA")
        self.assertFalse(marker.exists())

    def test_existing_symlink_is_invalid_instead_of_using_fallback(self) -> None:
        target = self.root / "secondary-target.conf"
        target.write_text("interface = tun0\n", encoding="utf-8")
        self.secondary.symlink_to(target)
        result = self._run_existing_secondary({"tun0": "UP"})

        self.assert_secondary_status(result, "CONFIGURAÇÃO INVÁLIDA")
        self.assertNotIn("Secundária:  OK (tun0)", result.stdout)

    def test_comments_external_spaces_and_first_active_directive_are_preserved(self) -> None:
        result = self._run(
            "  # interface = tun0\n"
            "portal-url = https://vpn.valid.test/\n"
            "  interface   =   vpn1   \n"
            "interface = ppp0\n",
            {"tun0": "UP", "vpn1": "UP", "ppp0": "UP"},
        )

        self.assert_secondary_status(result, "OK (vpn1)")
        self.assertNotIn("Secundária:  OK (ppp0)", result.stdout)

    def test_other_tunnels_remain_informational_only(self) -> None:
        result = self._run(
            "interface = vpn1\n",
            {"vpn1": "DOWN", "tap9": "UP", "wg2": "UP"},
        )

        self.assert_secondary_status(result, "NÃO DETECTADA (vpn1)")
        self.assertIn("Outros túneis VPN detectados: tap9 wg2", result.stdout)
        self.assertNotIn("Secundária:  ATIVA", result.stdout)


if __name__ == "__main__":
    unittest.main()
