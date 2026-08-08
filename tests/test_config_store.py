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
            "trusted-cert": "abc123",
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
            "trusted-cert": "abc123",
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
            "trusted-cert": "abc123",
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


if __name__ == "__main__":
    unittest.main()
