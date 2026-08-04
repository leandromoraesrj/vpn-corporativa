from __future__ import annotations

import ast
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


class Revision105Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = (
            ROOT / "vpn_app/app.py"
        ).read_text(encoding="utf-8")

    def _method(self, name):
        tree = ast.parse(self.app)
        application = next(
            node for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "VPNApplication"
        )
        method = next(
            node for node in application.body
            if isinstance(node, ast.FunctionDef) and node.name == name
        )
        module = ast.Module(body=[method], type_ignores=[])
        ast.fix_missing_locations(module)
        namespace = {
            "subprocess": SimpleNamespace(
                run=mock.Mock(),
                TimeoutExpired=subprocess.TimeoutExpired,
            ),
            "DISCONNECT_HELPER": "/helper",
            "LOGGER": mock.Mock(),
            "AyatanaAppIndicator3": SimpleNamespace(
                IndicatorStatus=SimpleNamespace(PASSIVE="passive")
            ),
            "Gtk": mock.Mock(),
        }
        exec(compile(module, "app.py", "exec"), namespace)
        return namespace[name], namespace

    def test_quit_preserves_vpn_and_exits_interface(self) -> None:
        quit_method, namespace = self._method("quit")
        instance = SimpleNamespace(
            reconnect_in_progress=True,
            reconnect_status="x",
            is_connecting=True,
        )
        namespace["subprocess"].run = mock.Mock()
        quit_method(instance)
        namespace["subprocess"].run.assert_not_called()
        namespace["Gtk"].main_quit.assert_called_once_with()
        self.assertFalse(instance.reconnect_in_progress)
        self.assertEqual(instance.reconnect_status, "")
        self.assertFalse(instance.is_connecting)

    def test_closing_window_still_only_hides_application(self) -> None:
        hide_method, namespace = self._method("_hide_window")
        window = mock.Mock()
        instance = SimpleNamespace(window=window, visible_timer=42)
        namespace["GLib"] = mock.Mock()
        self.assertTrue(hide_method(instance))
        window.hide.assert_called_once_with()
        namespace["GLib"].source_remove.assert_called_once_with(42)
        self.assertIsNone(instance.visible_timer)
        namespace["subprocess"].run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
