from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_app import config_store
from vpn_app.privileged_validation import parse_connection_text


class Revision106Tests(unittest.TestCase):
    def test_privileged_parser_preserves_password_surrounding_spaces(self):
        values = parse_connection_text(
            "host = vpn.example\n"
            "port = 443\n"
            "username = leandro\n"
            "password =   segredo  \n"
            "set-routes = 0\n"
            "set-dns = 0\n"
            "trusted-cert = abc123\n"
        )
        self.assertEqual(values["password"], "  segredo  ")

    def test_config_reader_preserves_password_surrounding_spaces(self):
        with tempfile.TemporaryDirectory() as directory:
            connection = Path(directory) / "connection.conf"
            connection.write_text(
                "host = vpn.example\n"
                "port = 443\n"
                "username = leandro\n"
                "password =   segredo  \n"
                "set-routes = 0\n"
                "set-dns = 0\n"
                "trusted-cert = abc123\n",
                encoding="utf-8",
            )
            with patch.object(config_store, "CONNECTION_FILE", connection):
                values = config_store.read_key_values()
            self.assertEqual(values["password"], "  segredo  ")

    def test_password_only_spaces_remains_invalid(self):
        with self.assertRaisesRegex(ValueError, "Campo obrigatório vazio: password"):
            parse_connection_text(
                "host = vpn.example\n"
                "port = 443\n"
                "username = leandro\n"
                "password =    \n"
                "set-routes = 0\n"
                "set-dns = 0\n"
                "trusted-cert = abc123\n"
            )


if __name__ == "__main__":
    unittest.main()
