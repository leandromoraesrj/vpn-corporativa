from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from vpn_app.runtime_validation import (
    valid_hosts_alias,
    validate_hosts,
)


class Revision104Tests(unittest.TestCase):
    def test_internal_alias_with_underscore_is_accepted(self):
        alias = "internal_service_132.example.com"
        self.assertTrue(valid_hosts_alias(alias))

    def test_hosts_file_with_internal_alias_is_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "hosts.conf"
            path.write_text(
                "192.0.2.10 "
                "internal_service_132.example.com\n",
                encoding="utf-8",
            )
            self.assertEqual(
                validate_hosts(path),
                [
                    "192.0.2.10 "
                    "internal_service_132.example.com"
                ],
            )

    def test_unsafe_aliases_remain_rejected(self):
        for alias in (
            "host name.example",
            "/etc/passwd",
            "host\\name",
            "-host.example",
            "host-.example",
            "host:80",
            "host\nname",
        ):
            with self.subTest(alias=alias):
                self.assertFalse(valid_hosts_alias(alias))


if __name__ == "__main__":
    unittest.main()
