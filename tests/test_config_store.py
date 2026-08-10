import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vpn_app import config_store


class ConfigStoreTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.config_dir = Path(self.tempdir.name)
        self.patches = [
            mock.patch.object(config_store, "CONFIG_DIR", self.config_dir),
            mock.patch.object(config_store, "CONNECTION_FILE", self.config_dir / "connection.conf"),
            mock.patch.object(config_store, "ROUTES_FILE", self.config_dir / "routes.conf"),
            mock.patch.object(config_store, "HOSTS_FILE", self.config_dir / "hosts.conf"),
            mock.patch.object(config_store, "SECONDARY_FILE", self.config_dir / "secondary.conf"),
            mock.patch.object(config_store, "PREFERENCES_FILE", self.config_dir / "preferences.conf"),
        ]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.tempdir.cleanup()

    def test_connection_is_written_with_private_permissions(self):
        config_store.save_connection({
            "host": "vpn.example.test",
            "port": "443",
            "username": "usuario",
            "password": "segredo",
            "trusted-cert": "a" * 64,
        })
        self.assertEqual(config_store.CONNECTION_FILE.stat().st_mode & 0o777, 0o600)
        self.assertIn("set-routes = 0", config_store.CONNECTION_FILE.read_text())
        self.assertNotIn("password", config_store.CONNECTION_FILE.read_text())

    def test_connection_rejects_invalid_port_and_line_injection(self):
        base = {
            "host": "vpn.example.test",
            "port": "invalid",
            "username": "usuario",
            "password": "segredo",
            "trusted-cert": "a" * 64,
        }
        with self.assertRaisesRegex(ValueError, "porta deve ser"):
            config_store.save_connection(base)
        base["port"] = "443"
        base["username"] = "usuario\nset-dns = 1"
        with self.assertRaisesRegex(ValueError, "quebra de linha"):
            config_store.save_connection(base)

    def test_connection_rejects_nul_and_out_of_range_port(self):
        values = {
            "host": "vpn.example.test",
            "port": "70000",
            "username": "usuario",
            "password": "segredo",
            "trusted-cert": "a" * 64,
        }
        with self.assertRaisesRegex(ValueError, "porta deve ser"):
            config_store.validate_connection(values)
        values["port"] = "443"
        values["host"] = "vpn.example.test\0set-dns"
        with self.assertRaisesRegex(ValueError, "controle"):
            config_store.validate_connection(values)

    def test_routes_are_normalized_and_deduplicated(self):
        config_store.save_routes("192.0.2.8/24\n192.0.2.0/24\n")
        self.assertEqual(config_store.read_routes(), ["192.0.2.0/24"])

    def test_invalid_host_mapping_is_rejected(self):
        with self.assertRaises(ValueError):
            config_store.save_hosts("192.0.2.1 nome_inválido")

    def test_internal_host_alias_uses_shared_validation(self):
        config_store.save_hosts("192.0.2.1 internal_alias.example")
        self.assertEqual(
            config_store.read_hosts(),
            ["192.0.2.1 internal_alias.example"],
        )

    def test_secondary_url_is_loaded_from_existing_file(self):
        config_store.SECONDARY_FILE.write_text(
            "route = 192.0.2.0/24\nportal-url = https://vpn.valid.test/login\n",
            encoding="utf-8",
        )
        self.assertEqual(
            config_store.read_secondary_url(),
            "https://vpn.valid.test/login",
        )

    def test_secondary_url_is_saved_privately_and_preserves_other_values(self):
        config_store.SECONDARY_FILE.write_text(
            "# configuração local\nroute = 192.0.2.0/24\nportal-url = https://old.valid.test/\n",
            encoding="utf-8",
        )
        config_store.save_secondary_url("https://vpn.valid.test/login")
        content = config_store.SECONDARY_FILE.read_text(encoding="utf-8")
        self.assertIn("route = 192.0.2.0/24", content)
        self.assertIn("portal-url = https://vpn.valid.test/login", content)
        self.assertNotIn("old.valid.test", content)
        self.assertEqual(config_store.SECONDARY_FILE.stat().st_mode & 0o777, 0o600)

    def test_secondary_url_rejects_http(self):
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            config_store.save_secondary_url("http://vpn.valid.test/login")

    def test_secondary_url_rejects_empty_value(self):
        with self.assertRaisesRegex(ValueError, "Informe"):
            config_store.save_secondary_url("   ")

    def test_secondary_url_rejects_control_characters(self):
        with self.assertRaisesRegex(ValueError, "controle"):
            config_store.save_secondary_url(
                "https://vpn.valid.test/login\nportal-url = https://vpn.valid.test/other"
            )

    def test_secondary_interface_defaults_to_tun0_when_absent(self):
        self.assertEqual(config_store.read_secondary_interface(), "tun0")

    def test_secondary_interface_preserves_explicit_empty_value(self):
        config_store.SECONDARY_FILE.write_text("interface =\n", encoding="utf-8")
        self.assertEqual(config_store.read_secondary_interface(), "")

    def test_secondary_interface_is_saved_and_preserves_other_values(self):
        config_store.SECONDARY_FILE.write_text(
            "portal-url = https://vpn.valid.test/login\nroute = 198.51.100.0/24\n",
            encoding="utf-8",
        )
        config_store.save_secondary_interface("vpn0")
        content = config_store.SECONDARY_FILE.read_text(encoding="utf-8")
        self.assertIn("interface = vpn0", content)
        self.assertIn("portal-url = https://vpn.valid.test/login", content)
        self.assertEqual(config_store.SECONDARY_FILE.stat().st_mode & 0o777, 0o600)

    def test_secondary_interface_rejects_invalid_values(self):
        for value in ("/dev/tun0", "tun 0", "tun0\nroute=x", "x" * 16):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    config_store.save_secondary_interface(value)

    def test_auto_reconnect_defaults_to_enabled(self):
        self.assertTrue(config_store.read_auto_reconnect_primary())

    def test_auto_reconnect_invalid_value_defaults_to_enabled(self):
        config_store.PREFERENCES_FILE.write_text(
            "auto-reconnect-primary = invalid\n",
            encoding="utf-8",
        )
        self.assertTrue(config_store.read_auto_reconnect_primary())

    def test_auto_reconnect_preference_is_private_and_persistent(self):
        config_store.save_auto_reconnect_primary(False)
        self.assertFalse(config_store.read_auto_reconnect_primary())
        self.assertEqual(
            config_store.PREFERENCES_FILE.stat().st_mode & 0o777,
            0o600,
        )
        self.assertNotIn("password", config_store.PREFERENCES_FILE.read_text())

    def test_trusted_cert_requires_exact_sha256_hex(self):
        base = {
            "host": "vpn.example.test",
            "port": "443",
            "username": "usuario",
            "trusted-cert": "a" * 64,
        }
        self.assertEqual(config_store.validate_connection(base)["trusted-cert"], "a" * 64)
        for value in ("a" * 63, "a" * 65, "a" * 63 + ":", "sha256:" + "a" * 64, "a" * 32 + " "):
            invalid = dict(base, **{"trusted-cert": value})
            with self.assertRaisesRegex(ValueError, "64 caracteres"):
                config_store.validate_connection(invalid)

    def test_certificate_policies_are_explicit_and_legacy_is_default(self):
        base = {
            "host": "vpn.example.test",
            "port": "443",
            "username": "usuario",
            "trusted-cert": "a" * 64,
        }
        self.assertEqual(
            config_store.validate_connection(base)["certificate-policy"],
            "legacy-pinned",
        )
        self.assertEqual(
            config_store.validate_connection(
                dict(base, **{"certificate-policy": "system-ca", "trusted-cert": ""})
            )["certificate-policy"],
            "system-ca",
        )
        with self.assertRaisesRegex(ValueError, "não pode ser usado"):
            config_store.validate_connection(
                dict(base, **{"certificate-policy": "system-ca"})
            )
        with self.assertRaisesRegex(ValueError, "trusted-cert"):
            config_store.validate_connection(
                dict(base, **{"certificate-policy": "system-ca-with-pinned-fallback", "trusted-cert": ""})
            )
        with self.assertRaisesRegex(ValueError, "Política"):
            config_store.validate_connection(dict(base, **{"certificate-policy": "unknown"}))

    def test_system_ca_file_can_omit_trusted_cert_only_explicitly(self):
        config_store.CONNECTION_FILE.write_text(
            "host = vpn.example.test\nport = 443\nusername = usuario\n"
            "set-routes = 0\nset-dns = 0\ncertificate-policy = system-ca\n",
            encoding="utf-8",
        )
        values = config_store.read_key_values()
        self.assertEqual(config_store.validate_connection(values)["certificate-policy"], "system-ca")
        self.assertEqual(values.get("trusted-cert", ""), "")


if __name__ == "__main__":
    unittest.main()
