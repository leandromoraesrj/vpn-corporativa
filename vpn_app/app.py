#!/usr/bin/env python3
from __future__ import annotations

import logging
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

import gi
gi.require_version("Gtk", "3.0")
gi.require_version("AyatanaAppIndicator3", "0.1")
from gi.repository import AyatanaAppIndicator3, Gdk, GLib, Gtk

from . import (
    certificate_diagnostics,
    config_store,
    f5_backend,
    network,
    privileged_validation,
    secret_store,
)

LOGGER = logging.getLogger(__name__)

APP_VERSION = "1.1.3"
APP_NAME = "Centro de Controle da Rede e VPN"
APP_ID = "br.local.vpncorporativa"
CONNECT_HELPER = "/usr/local/libexec/vpn-connect"
DISCONNECT_HELPER = "/usr/local/libexec/vpn-disconnect"
DIAGNOSE_HELPER = "/usr/local/libexec/vpn-diagnose"
LOCK_NAME = "\0vpn_corporativa_1_1_lock"
STATE_DIR = Path.home() / ".local" / "state" / "vpn"
STATE_DIR.mkdir(parents=True, exist_ok=True)
LOG_PATH = STATE_DIR / "connection.log"
DIAG_PATH = STATE_DIR / "diagnostic-latest.txt"

ICON_OFF = "/usr/local/share/icons/vpn-corporativa-gray.svg"
ICON_ON = "/usr/local/share/icons/vpn-corporativa-green.svg"
ICON_PRIMARY = "/usr/local/share/icons/vpn-corporativa-primary.svg"
ICON_SECONDARY = "/usr/local/share/icons/vpn-corporativa-secondary.svg"
ICON_COLORS = {
    "off": "#7a7a7a",
    "wait": "#e69f00",
    "on": "#2ca02c",
    "error": "#c0392b",
}


class VPNApplication:
    def __init__(self) -> None:
        self.lock_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.lock_socket.bind(LOCK_NAME)
        except OSError:
            raise SystemExit(0)

        self.window: Gtk.Window | None = None
        self.labels: dict[str, Gtk.Label] = {}
        self.config_entries: dict[str, Gtk.Entry] = {}
        self.secondary_url_entry: Gtk.Entry | None = None
        self.secondary_interface_candidates: Gtk.ComboBoxText | None = None
        self.secondary_candidate_values: list[str] = []
        self.secondary_candidate_details: list[str] = []
        self.secondary_discovery_label: Gtk.Label | None = None
        self.routes_view: Gtk.TextView | None = None
        self.hosts_view: Gtk.TextView | None = None
        self.diagnostic_view: Gtk.TextView | None = None
        self.last_credential_diagnostic = ""
        self.diagnostic_status_label: Gtk.Label | None = None
        self.diagnostic_running = False
        self.notebook: Gtk.Notebook | None = None
        self.log_view: Gtk.TextView | None = None
        self.primary_panel: Gtk.Box | None = None
        self.primary_scroll: Gtk.ScrolledWindow | None = None
        self.primary_content: Gtk.Box | None = None
        self.vpn_height_group: Gtk.SizeGroup | None = None
        self.initial_target_width: int | None = None
        self.initial_target_height: int | None = None

        self.is_connecting = False
        self.primary_error = False
        self.desired_connected = False
        self.reconnect_in_progress = False
        self.reconnect_status = ""
        self.auto_reconnect_primary = True
        self.manual_disconnect = False
        self.connect_button: Gtk.Button | None = None
        self.disconnect_button: Gtk.Button | None = None
        self.f5_auth_buttons: list[Gtk.Button] = []
        self.f5_window_buttons: list[Gtk.Button] = []
        self.f5_hide_button: Gtk.Button | None = None
        self.f5_show_button: Gtk.Button | None = None
        self.menu_primary_status: Gtk.MenuItem | None = None
        self.menu_secondary_status: Gtk.MenuItem | None = None
        self.menu_primary_action: Gtk.MenuItem | None = None
        self.menu_secondary_action: Gtk.MenuItem | None = None
        self.status_update_label: Gtk.Label | None = None
        self.status_diagnostic_label: Gtk.Label | None = None
        self.status_integrity_label: Gtk.Label | None = None
        self.status_bar: Gtk.Box | None = None
        self.integrity_status_markup = "<span foreground='#666666'>Integridade: verificando...</span>"
        self.last_diagnostic_at = "Nunca"

        self.visible_timer: int | None = None
        self.low_cost_timer: int | None = None
        self.connected_since: float | None = None
        self.last_connected = bool(network.vpn_interface())
        self.internet_sampler = network.MetricsSampler()
        self.primary_sampler = network.MetricsSampler()
        self.local_started_at: float | None = None
        self.update_in_progress = False
        self.f5_last_connected = f5_backend.status().connected
        self.f5_auto_hidden = self.f5_last_connected

        self.indicator = self._build_indicator()

        config_store.ensure_config_dir()
        try:
            self.auto_reconnect_primary = config_store.read_auto_reconnect_primary()
        except (OSError, UnicodeError):
            LOGGER.warning(
                "Preferência de reconexão automática indisponível; usando o padrão ativado."
            )
        self.integrity_status_markup = self._check_integrity_markup()
        if self.last_connected:
            self.connected_since = time.monotonic()


    def _primary_status_text(self) -> str:
        if self.primary_error:
            return "ERRO"
        if self.reconnect_status:
            return self.reconnect_status
        if self.is_connecting:
            return "CONECTANDO"
        return "CONECTADA" if bool(network.vpn_interface()) else "DESCONECTADA"

    @staticmethod
    def _secondary_status_text(current: f5_backend.F5Status | None = None) -> str:
        return (current or f5_backend.status()).label

    def _tray_title(self, current: f5_backend.F5Status | None = None) -> str:
        primary = self._primary_status_text().lower()
        secondary = self._secondary_status_text(current).lower()
        return f"Centro de Controle da Rede e VPN — Principal: {primary} | Secundária: {secondary}"

    @staticmethod
    def _connected_icon(primary_connected: bool, secondary_connected: bool) -> str:
        if primary_connected and secondary_connected:
            return ICON_ON
        if primary_connected:
            return ICON_PRIMARY
        if secondary_connected:
            return ICON_SECONDARY
        return ICON_OFF

    @staticmethod
    def _split_icon_svg(primary_color: str, secondary_color: str) -> str:
        return f'''<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">
  <defs>
    <clipPath id="left"><rect x="0" y="0" width="32" height="64"/></clipPath>
    <clipPath id="right"><rect x="32" y="0" width="32" height="64"/></clipPath>
  </defs>
  <path d="M32 4 54 12 51 39 42 52 32 60 22 52 13 39 10 12Z" fill="{secondary_color}" stroke="#fff" stroke-width="3" stroke-linejoin="round"/>
  <path d="M32 4 54 12 51 39 42 52 32 60 22 52 13 39 10 12Z" fill="{primary_color}" clip-path="url(#left)"/>
  <rect x="20" y="27" width="24" height="18" rx="4" fill="#fff"/>
  <path d="M24 28V23c0-6 3.5-10.5 8-10.5S40 17 40 23v5" fill="none" stroke="#fff" stroke-width="5" stroke-linecap="round"/>
</svg>
'''

    def _split_icon_path(self, primary_state: str, secondary_state: str) -> str:
        if primary_state in {"on", "off"} and secondary_state in {"on", "off"}:
            return self._connected_icon(primary_state == "on", secondary_state == "on")

        path = STATE_DIR / f"tray-icon-{primary_state}-{secondary_state}.svg"
        if not path.exists():
            path.write_text(
                self._split_icon_svg(
                    ICON_COLORS[primary_state], ICON_COLORS[secondary_state]
                ),
                encoding="utf-8",
            )
        return str(path)

    def _tray_states(
        self,
        current: f5_backend.F5Status | None = None,
    ) -> tuple[str, str]:
        f5 = current or f5_backend.status()
        if self.primary_error:
            primary = "error"
        elif self.is_connecting or self.reconnect_status:
            primary = "wait"
        elif network.vpn_interface():
            primary = "on"
        else:
            primary = "off"

        if not f5.connected and f5.inconsistent:
            secondary = "error"
        elif f5.connected:
            secondary = "on"
        elif f5.client_running:
            secondary = "wait"
        else:
            secondary = "off"
        return primary, secondary

    def _tray_icon(self, current: f5_backend.F5Status | None = None) -> str:
        primary, secondary = self._tray_states(current)
        return self._split_icon_path(primary, secondary)

    def can_connect(self, _item=None) -> bool:
        return not self.is_connecting and not bool(network.vpn_interface())

    def can_disconnect(self, _item=None) -> bool:
        return self.is_connecting or bool(network.vpn_interface())

    def _activate_primary_menu(self, _item=None) -> None:
        if self.can_disconnect():
            self.disconnect_vpn()
        else:
            self.connect_vpn()

    def _activate_secondary_menu(self, _item=None) -> None:
        current = f5_backend.status()
        if not current.connected:
            self.open_f5()
            return

        action_label = (
            self.menu_secondary_action.get_label()
            if self.menu_secondary_action is not None
            else ""
        )
        if action_label == "Ocultar VPN secundária":
            self.hide_f5()
            self._refresh_controls()
        else:
            self.show_f5()

    def _build_indicator(self):
        icon = self._tray_icon()
        indicator = AyatanaAppIndicator3.Indicator.new(
            APP_ID,
            icon,
            AyatanaAppIndicator3.IndicatorCategory.SYSTEM_SERVICES,
        )
        indicator.set_icon_full(icon, self._tray_title())
        indicator.set_status(AyatanaAppIndicator3.IndicatorStatus.ACTIVE)
        indicator.set_title(self._tray_title())

        menu = Gtk.Menu()

        open_item = Gtk.MenuItem(label="Abrir Centro de Controle")
        open_item.connect("activate", lambda *_: self._open_panel_from_tray())
        menu.append(open_item)

        menu.append(Gtk.SeparatorMenuItem())

        self.menu_primary_status = Gtk.MenuItem(label="VPN principal: verificando...")
        self.menu_primary_status.set_sensitive(False)
        menu.append(self.menu_primary_status)

        self.menu_secondary_status = Gtk.MenuItem(label="VPN secundária: verificando...")
        self.menu_secondary_status.set_sensitive(False)
        menu.append(self.menu_secondary_status)

        menu.append(Gtk.SeparatorMenuItem())

        self.menu_primary_action = Gtk.MenuItem(label="Conectar VPN principal")
        self.menu_primary_action.connect("activate", self._activate_primary_menu)
        menu.append(self.menu_primary_action)

        self.menu_secondary_action = Gtk.MenuItem(label="Autenticar VPN secundária")
        self.menu_secondary_action.connect("activate", self._activate_secondary_menu)
        menu.append(self.menu_secondary_action)

        menu.append(Gtk.SeparatorMenuItem())

        quit_item = Gtk.MenuItem(label="Sair")
        quit_item.connect("activate", lambda *_: self.quit())
        menu.append(quit_item)

        menu.show_all()
        indicator.set_menu(menu)
        return indicator

    def _refresh_controls(self) -> None:
        connected = bool(network.vpn_interface())
        f5 = f5_backend.status()

        icon = self._tray_icon(f5)

        title = self._tray_title(f5)
        self.indicator.set_icon_full(icon, title)
        self.indicator.set_title(title)
        if self.menu_primary_status is not None:
            self.menu_primary_status.set_label(f"VPN principal: {self._primary_status_text()}")
        if self.menu_secondary_status is not None:
            self.menu_secondary_status.set_label(
                f"VPN secundária: {self._secondary_status_text(f5)}"
            )
        if self.menu_primary_action is not None:
            self.menu_primary_action.set_label(
                "Desconectar VPN principal"
                if self.can_disconnect()
                else "Conectar VPN principal"
            )
        if self.menu_secondary_action is not None:
            self.menu_secondary_action.set_label(
                (
                    "Ocultar VPN secundária"
                    if f5_backend.window_visible()
                    else "Exibir VPN secundária"
                )
                if f5.connected
                else "Autenticar VPN secundária"
            )

        if self.connect_button is not None:
            self.connect_button.set_sensitive(not self.is_connecting and not connected)
        if self.disconnect_button is not None:
            self.disconnect_button.set_sensitive(self.is_connecting or connected)
        for button in self.f5_auth_buttons:
            button.set_sensitive(f5_backend.authentication_enabled(f5))
        window_available = f5_backend.window_controls_enabled(f5)
        window_visible = f5_backend.window_visible() if window_available else False
        if self.f5_hide_button is not None:
            self.f5_hide_button.set_sensitive(window_available and window_visible)
        if self.f5_show_button is not None:
            self.f5_show_button.set_sensitive(window_available and not window_visible)

    def _safe(self, callback):
        def wrapper(*_args):
            GLib.idle_add(self._invoke, callback)
        return wrapper

    def _invoke(self, callback):
        try:
            callback()
        except Exception:
            self._notify(f"Erro em {callback.__name__}. Consulte os logs.")
        return False

    @staticmethod
    def _notify(message: str) -> None:
        subprocess.run(["notify-send", APP_NAME, message], check=False)

    def _build_window(self) -> None:
        window = Gtk.Window(title="Centro de Controle da Rede e VPN")
        window.set_default_size(820, -1)
        window.set_position(Gtk.WindowPosition.CENTER)
        window.connect("realize", self._disable_window_maximize)
        window.connect("configure-event", self._lock_window_at_target_size)
        window.connect("delete-event", self._hide_window)

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        root.set_border_width(12)
        window.add(root)

        title = Gtk.Label()
        title.set_markup("<span size='x-large' weight='bold'>Centro de Controle da Rede e VPN</span>")
        title.set_xalign(0)
        root.pack_start(title, False, False, 0)

        notebook = Gtk.Notebook()
        self.notebook = notebook
        root.pack_start(notebook, True, True, 0)

        notebook.append_page(
            self._build_summary_tab(),
            Gtk.Label(label="Principal"),
        )
        notebook.append_page(self._build_diagnostic_tab(), Gtk.Label(label="Diagnóstico"))
        notebook.append_page(self._build_logs_tab(), Gtk.Label(label="Log da conexão"))
        notebook.append_page(self._build_config_tab(), Gtk.Label(label="Configuração"))
        notebook.set_current_page(0)

        status_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=18)
        status_bar.set_margin_top(4)
        panel_margin = (
            self.primary_panel.get_border_width()
            if self.primary_panel is not None
            else root.get_border_width()
        )
        status_bar.set_margin_start(panel_margin)
        status_bar.set_margin_end(panel_margin)
        self.status_bar = status_bar

        update_label = Gtk.Label(label="Última atualização: aguardando")
        update_label.set_xalign(0)
        status_bar.pack_start(update_label, True, True, 0)
        self.status_update_label = update_label

        integrity_label = Gtk.Label()
        integrity_label.set_markup(self.integrity_status_markup)
        integrity_label.set_xalign(0.5)
        integrity_label.set_selectable(True)
        status_bar.pack_start(integrity_label, True, True, 0)
        self.status_integrity_label = integrity_label

        diagnostic_label = Gtk.Label(label="Último diagnóstico: Nunca")
        diagnostic_label.set_xalign(1)
        status_bar.pack_end(diagnostic_label, True, True, 0)
        self.status_diagnostic_label = diagnostic_label

        root.pack_start(status_bar, False, False, 0)
        self.window = window

    @staticmethod
    def _disable_window_maximize(window: Gtk.Window) -> None:
        native_window = window.get_window()
        if native_window is not None:
            native_window.set_functions(
                Gdk.WMFunction.MOVE
                | Gdk.WMFunction.RESIZE
                | Gdk.WMFunction.MINIMIZE
                | Gdk.WMFunction.CLOSE
            )

    def _lock_window_at_target_size(
        self,
        window: Gtk.Window,
        event: Gdk.EventConfigure,
    ) -> bool:
        if (
            self.initial_target_width is not None
            and self.initial_target_height is not None
            and event.height >= self.initial_target_height
        ):
            geometry = Gdk.Geometry()
            geometry.min_width = self.initial_target_width
            geometry.max_width = self.initial_target_width
            geometry.min_height = self.initial_target_height
            geometry.max_height = self.initial_target_height
            window.set_geometry_hints(
                None,
                geometry,
                Gdk.WindowHints.MIN_SIZE | Gdk.WindowHints.MAX_SIZE,
            )
            window.resize(
                self.initial_target_width,
                self.initial_target_height,
            )
            window.set_resizable(False)
            native_window = window.get_window()
            if native_window is not None:
                native_window.set_functions(
                    Gdk.WMFunction.MOVE
                    | Gdk.WMFunction.MINIMIZE
                    | Gdk.WMFunction.CLOSE
                )
            self.initial_target_height = None
            self.initial_target_width = None
        return False

    def _new_grid(self) -> Gtk.Grid:
        grid = Gtk.Grid()
        grid.set_hexpand(True)
        grid.set_column_spacing(16)
        grid.set_row_spacing(8)
        grid.set_border_width(14)
        return grid

    def _add_row(self, grid: Gtk.Grid, row: int, title: str, key: str) -> None:
        left = Gtk.Label()
        left.set_markup(f"<b>{title}</b>")
        left.set_xalign(0)
        right = Gtk.Label(label="-")
        right.set_xalign(0)
        right.set_selectable(True)
        grid.attach(left, 0, row, 1, 1)
        grid.attach(right, 1, row, 1, 1)
        self.labels[key] = right

    def _summary_card(self, title: str, rows: list[tuple[str, str]]) -> Gtk.Frame:
        frame = Gtk.Frame(label=title)
        frame.set_shadow_type(Gtk.ShadowType.ETCHED_IN)

        grid = Gtk.Grid()
        grid.set_column_spacing(18)
        grid.set_row_spacing(7)
        grid.set_border_width(10)
        frame.add(grid)

        for row, (label, key) in enumerate(rows):
            self._add_row(grid, row, label, key)

        return frame

    def _build_summary_tab(self) -> Gtk.Widget:
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        outer.set_border_width(10)
        self.primary_panel = outer

        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        outer.pack_start(scroll, True, True, 0)
        self.primary_scroll = scroll

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        content.set_border_width(2)
        scroll.add_with_viewport(content)
        self.primary_content = content

        network_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        content.pack_start(network_row, False, False, 0)

        internet_card = self._summary_card(
            "Rede local e Internet",
            [
                ("Estado", "internet_status"),
                ("Interface", "internet_interface"),
                ("IP local", "internet_local_ip"),
                ("IP público", "public_ip"),
                ("Latência", "internet_latency"),
                ("Tempo ativo", "internet_uptime"),
                ("Download", "internet_download"),
                ("Upload", "internet_upload"),
            ],
        )
        summary_card_width = 378
        summary_button_width = 120

        internet_card.set_size_request(summary_card_width, -1)
        network_row.pack_start(internet_card, False, False, 0)

        other_card = self._summary_card(
            "Outros serviços de rede",
            [
                ("Tailscale", "tailscale"),
                ("Docker", "docker"),
                ("Firewall", "firewall"),
            ],
        )
        other_card.set_size_request(summary_card_width, -1)
        network_row.pack_start(other_card, False, False, 0)

        vpn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        content.pack_start(vpn_row, False, False, 0)

        primary_frame = Gtk.Frame(label="VPN principal")
        primary_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        primary_box.set_border_width(10)
        primary_frame.add(primary_box)

        primary_info = Gtk.Label(
            label="Otimização e gerenciamento da conexão corporativa principal."
        )
        primary_info.set_xalign(0)
        primary_info.set_line_wrap(True)
        primary_info.set_max_width_chars(32)
        primary_box.pack_start(primary_info, False, False, 0)

        primary_grid = Gtk.Grid()
        primary_grid.set_column_spacing(14)
        primary_grid.set_row_spacing(7)
        for row, (label, key) in enumerate([
            ("Estado", "primary_status"),
            ("Interface", "primary_interface"),
            ("IP VPN", "primary_ip"),
            ("Latência", "primary_latency"),
            ("Tempo conectado", "primary_uptime"),
            ("Download", "primary_download"),
            ("Upload", "primary_upload"),
        ]):
            self._add_row(primary_grid, row, label, key)
        primary_box.pack_start(primary_grid, False, False, 0)

        primary_spacer = Gtk.Box()
        primary_spacer.set_vexpand(True)
        primary_box.pack_start(primary_spacer, True, True, 0)

        primary_buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        primary_buttons.set_homogeneous(True)
        connect = Gtk.Button(label="Conectar")
        connect.set_size_request(summary_button_width, -1)
        connect.connect("clicked", lambda *_: self.connect_vpn())
        primary_buttons.pack_start(connect, True, True, 0)
        self.connect_button = connect

        disconnect = Gtk.Button(label="Desconectar")
        disconnect.set_size_request(summary_button_width, -1)
        disconnect.connect("clicked", lambda *_: self.disconnect_vpn())
        primary_buttons.pack_start(disconnect, True, True, 0)
        self.disconnect_button = disconnect

        primary_box.pack_start(primary_buttons, False, False, 0)
        primary_frame.set_size_request(summary_card_width, -1)
        vpn_row.pack_start(primary_frame, False, False, 0)

        secondary_frame = Gtk.Frame(label="VPN secundária")
        secondary_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        secondary_box.set_border_width(10)
        secondary_frame.add(secondary_box)

        secondary_info = Gtk.Label(
            label="Autenticação web manual; conexão acompanhada e monitorada pelo aplicativo."
        )
        secondary_info.set_xalign(0)
        secondary_info.set_line_wrap(True)
        secondary_info.set_max_width_chars(32)
        secondary_box.pack_start(secondary_info, False, False, 0)

        secondary_grid = Gtk.Grid()
        secondary_grid.set_column_spacing(14)
        secondary_grid.set_row_spacing(7)
        for row, (label, key) in enumerate([
            ("Estado", "secondary_status"),
            ("Interface", "secondary_interface"),
            ("IP VPN", "secondary_ip"),
            ("Janela da VPN secundária", "secondary_window"),
        ]):
            self._add_row(secondary_grid, row, label, key)
        secondary_box.pack_start(secondary_grid, False, True, 0)

        secondary_spacer = Gtk.Box()
        secondary_spacer.set_vexpand(True)
        secondary_box.pack_start(secondary_spacer, True, True, 0)

        open_f5 = Gtk.Button(label="Autenticar VPN secundária")
        open_f5.set_size_request(summary_button_width * 2 + 8, -1)
        open_f5.connect("clicked", lambda *_: self.open_f5())
        self.f5_auth_buttons.append(open_f5)
        secondary_box.pack_start(open_f5, False, False, 0)

        secondary_buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        secondary_buttons.set_homogeneous(True)
        hide_f5 = Gtk.Button(label="Ocultar VPN secundária")
        hide_f5.set_size_request(summary_button_width, -1)
        hide_f5.connect("clicked", lambda *_: self.hide_f5())
        secondary_buttons.pack_start(hide_f5, True, True, 0)
        self.f5_window_buttons.append(hide_f5)
        self.f5_hide_button = hide_f5

        show_f5 = Gtk.Button(label="Exibir VPN secundária")
        show_f5.set_size_request(summary_button_width, -1)
        show_f5.connect("clicked", lambda *_: self.show_f5())
        secondary_buttons.pack_start(show_f5, True, True, 0)
        self.f5_window_buttons.append(show_f5)
        self.f5_show_button = show_f5
        secondary_box.pack_start(secondary_buttons, False, False, 0)
        secondary_frame.set_size_request(summary_card_width, -1)
        vpn_row.pack_start(secondary_frame, False, False, 0)

        vpn_height_group = Gtk.SizeGroup(Gtk.SizeGroupMode.VERTICAL)
        vpn_height_group.add_widget(primary_frame)
        vpn_height_group.add_widget(secondary_frame)
        self.vpn_height_group = vpn_height_group

        return outer

    def _build_diagnostic_tab(self) -> Gtk.Widget:
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        outer.set_border_width(10)

        status = Gtk.Label(label="Nenhum diagnóstico em execução.")
        status.set_xalign(0)
        outer.pack_start(status, False, False, 0)
        self.diagnostic_status_label = status

        controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        outer.pack_start(controls, False, False, 0)

        run_button = self._full_width_button(
            "Executar diagnóstico geral",
            self.run_diagnostic,
        )
        controls.pack_start(run_button, True, True, 0)

        view = Gtk.TextView()
        view.set_editable(False)
        view.set_monospace(True)
        view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        scroll = Gtk.ScrolledWindow()
        scroll.add(view)
        outer.pack_start(scroll, True, True, 0)
        self.diagnostic_view = view
        return outer

    def _entry_row(self, grid: Gtk.Grid, row: int, title: str, key: str, secret: bool = False):
        label = Gtk.Label(label=title)
        label.set_xalign(0)
        entry = Gtk.Entry()
        entry.set_hexpand(True)
        entry.set_visibility(not secret)
        grid.attach(label, 0, row, 1, 1)
        grid.attach(entry, 1, row, 1, 1)
        self.config_entries[key] = entry

    @staticmethod
    def _full_width_button(label: str, callback) -> Gtk.Button:
        button = Gtk.Button(label=label)
        button.set_hexpand(True)
        button.connect("clicked", lambda *_: callback())
        return button

    def _build_config_tab(self) -> Gtk.Widget:
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        outer.set_border_width(10)
        notebook = Gtk.Notebook()
        outer.pack_start(notebook, True, True, 0)

        connection = self._new_grid()
        for row, args in enumerate([
            ("Host", "host", False),
            ("Porta", "port", False),
            ("Usuário", "username", False),
            ("Senha", "password", True),
        ]):
            self._entry_row(connection, row, *args)

        self.auto_reconnect_check = Gtk.CheckButton(
            label="Reconexão automática da VPN principal"
        )
        self.auto_reconnect_check.set_active(self.auto_reconnect_primary)
        connection.attach(self.auto_reconnect_check, 0, 4, 2, 1)

        save_connection = self._full_width_button(
            "Salvar configuração da VPN principal",
            self.save_connection,
        )
        connection.attach(save_connection, 0, 5, 2, 1)
        notebook.append_page(connection, Gtk.Label(label="VPN principal"))

        secondary_frame = Gtk.Frame(
            label="VPN secundária"
        )
        secondary_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=10,
        )
        secondary_box.set_border_width(14)
        secondary_frame.add(secondary_box)

        explanation = Gtk.Label(
            label=(
                "Utilize esta configuração quando a VPN secundária realizar "
                "autenticação web pelo navegador."
            )
        )
        explanation.set_xalign(0)
        explanation.set_line_wrap(True)
        secondary_box.pack_start(explanation, False, False, 0)

        secondary_grid = Gtk.Grid()
        secondary_grid.set_hexpand(True)
        secondary_grid.set_column_spacing(16)
        secondary_grid.set_row_spacing(8)
        url_label = Gtk.Label(label="URL de autenticação")
        url_label.set_xalign(0)
        url_entry = Gtk.Entry()
        url_entry.set_hexpand(True)
        url_entry.set_placeholder_text("https://vpn.example.com/")
        secondary_grid.attach(url_label, 0, 0, 1, 1)
        secondary_grid.attach(url_entry, 1, 0, 2, 1)
        self.secondary_url_entry = url_entry

        interface_label = Gtk.Label(label="Interface da VPN secundária")
        interface_label.set_xalign(0)
        secondary_grid.attach(interface_label, 0, 1, 1, 1)
        candidates = Gtk.ComboBoxText()
        candidates.set_hexpand(True)
        candidates.connect("changed", self._select_secondary_candidate)
        self.secondary_interface_candidates = candidates
        secondary_grid.attach(candidates, 1, 1, 1, 1)
        refresh_interfaces = Gtk.Button(label="Atualizar interfaces")
        refresh_interfaces.connect("clicked", lambda *_: self.refresh_secondary_interfaces())
        secondary_grid.attach(refresh_interfaces, 2, 1, 1, 1)
        self.secondary_discovery_label = Gtk.Label()
        self.secondary_discovery_label.set_xalign(0)
        self.secondary_discovery_label.set_line_wrap(True)
        self.secondary_discovery_label.set_max_width_chars(70)
        self.secondary_discovery_label.set_hexpand(True)
        secondary_grid.attach(self.secondary_discovery_label, 0, 2, 3, 1)

        save_secondary = Gtk.Button(label="Salvar configurações da VPN secundária")
        save_secondary.connect("clicked", lambda *_: self.save_secondary_configuration())
        secondary_grid.attach(save_secondary, 0, 3, 3, 1)
        secondary_box.pack_start(secondary_grid, False, True, 0)
        notebook.append_page(secondary_frame, Gtk.Label(label="VPN secundária"))

        self.routes_view = Gtk.TextView()
        self.routes_view.set_monospace(True)
        routes_box = self._editor_box(self.routes_view, "Salvar sub-redes", self.save_routes)
        notebook.append_page(routes_box, Gtk.Label(label="Sub-redes"))

        self.hosts_view = Gtk.TextView()
        self.hosts_view.set_monospace(True)
        hosts_box = self._editor_box(self.hosts_view, "Salvar mapa de hosts", self.save_hosts)
        notebook.append_page(hosts_box, Gtk.Label(label="Hosts"))

        return outer

    @staticmethod
    def _editor_box(view: Gtk.TextView, button_text: str, callback) -> Gtk.Widget:
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        outer.set_border_width(8)
        scroll = Gtk.ScrolledWindow()
        scroll.add(view)
        outer.pack_start(scroll, True, True, 0)
        button = Gtk.Button(label=button_text)
        button.connect("clicked", lambda *_: callback())
        outer.pack_start(button, False, False, 0)
        return outer


    def _build_logs_tab(self) -> Gtk.Widget:
        view = Gtk.TextView()
        view.set_editable(False)
        view.set_monospace(True)
        scroll = Gtk.ScrolledWindow()
        scroll.set_border_width(10)
        scroll.add(view)
        self.log_view = view
        return scroll

    def _load_config_into_ui(self) -> None:
        values = config_store.read_key_values()
        legacy_password = values.pop("password", None)
        if legacy_password:
            try:
                username = values.get("username", "")
                secret_store.store(username, legacy_password)
                config_store.save_connection(values)
            except (OSError, RuntimeError, ValueError):
                LOGGER.warning("Migração da credencial para o Secret Service não foi concluída.")
        for key, entry in self.config_entries.items():
            entry.set_text(values.get(key, ""))
        if hasattr(self, "auto_reconnect_check"):
            self.auto_reconnect_check.set_active(self.auto_reconnect_primary)

        if self.routes_view:
            self.routes_view.get_buffer().set_text("\n".join(config_store.read_routes()))
        if self.hosts_view:
            self.hosts_view.get_buffer().set_text("\n".join(config_store.read_hosts()))
        if self.secondary_url_entry is not None:
            self.secondary_url_entry.set_text(config_store.read_secondary_url())
        if self.secondary_interface_candidates is not None:
            self.refresh_secondary_interfaces(f5_backend.configured_interface())

    def save_connection(self) -> None:
        values = config_store.read_key_values()
        values.update({key: entry.get_text() for key, entry in self.config_entries.items()})
        try:
            password = values.pop("password", "")
            username = config_store.validate_connection(values)["username"]
            if password:
                secret_store.store(username, password)
            elif not secret_store.lookup(username):
                raise ValueError("Informe a senha da VPN para armazená-la no GNOME Keyring.")
            config_store.save_connection(values)
            self.auto_reconnect_primary = self.auto_reconnect_check.get_active()
            config_store.save_auto_reconnect_primary(self.auto_reconnect_primary)
            if self.auto_reconnect_primary and self.reconnect_status == "RECONEXÃO AUTOMÁTICA DESATIVADA":
                self.reconnect_status = ""
        except RuntimeError:
            self._show_message(
                "Não foi possível salvar a conexão",
                "Não foi possível acessar o GNOME Keyring.",
                error=True,
            )
            return
        except (KeyError, OSError, ValueError) as exc:
            self._show_message("Não foi possível salvar a conexão", str(exc), error=True)
            return
        self._show_message("Configuração salva", "Os dados da conexão foram atualizados.")

    @staticmethod
    def _certificate_diagnostic_result(
        values: dict[str, str],
        configuration_valid: bool = True,
    ) -> certificate_diagnostics.CertificateDiagnostic:
        host = values.get("host", "").strip()
        policy = values.get("certificate-policy", "legacy-pinned")
        if not configuration_valid:
            return certificate_diagnostics.configuration_failure(
                host,
                policy,
                "O snapshot salvo de connection.conf não pôde ser validado.",
            )
        try:
            port = int(values.get("port", ""))
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            return certificate_diagnostics.configuration_failure(
                host,
                policy,
                "A porta salva em connection.conf é inválida.",
            )
        if not host:
            return certificate_diagnostics.configuration_failure(
                host,
                policy,
                "O host salvo em connection.conf está ausente.",
            )
        try:
            return certificate_diagnostics.diagnose(
                host,
                port,
                values.get("trusted-cert", ""),
                policy,
            )
        except Exception:
            LOGGER.warning("Diagnóstico de certificado indisponível.")
            return certificate_diagnostics.CertificateDiagnostic(
                hostname=host,
                subject="Indisponível",
                san=(),
                issuer="Indisponível",
                not_before="Indisponível",
                not_after="Indisponível",
                fingerprint_sha256="Indisponível",
                ca_status="Indisponível",
                hostname_status="Indisponível",
                fingerprint_match="Indisponível",
                reason="Não foi possível concluir uma observação TLS correlacionada.",
                policy=policy,
                severity="WARNING",
                warning_count=1,
                indeterminate_count=1,
            )

    @staticmethod
    def _certificate_diagnostic_snapshot() -> tuple[dict[str, str], bool]:
        try:
            normalized = privileged_validation.parse_connection(
                config_store.CONNECTION_FILE
            )
        except (KeyError, OSError, UnicodeError, ValueError):
            return {}, False
        snapshot = {
            key: normalized.get(key, "")
            for key in ("host", "port", "certificate-policy", "trusted-cert")
        }
        return snapshot, True

    @staticmethod
    def _integrated_diagnostic_counts(
        helper_report: str,
        helper_return_code: int,
        certificate_result: certificate_diagnostics.CertificateDiagnostic,
    ) -> tuple[int, int]:
        summaries = re.findall(
            r"RESUMO: (\d+) falha\(s\), (\d+) aviso\(s\)",
            helper_report,
        )
        if summaries:
            helper_failures, helper_warnings = map(int, summaries[-1])
            if helper_return_code != 0:
                helper_failures = max(helper_failures, 1)
        else:
            helper_failures = int(helper_return_code != 0)
            helper_warnings = int(helper_return_code == 0)
        return (
            helper_failures + certificate_result.critical_count,
            helper_warnings + certificate_result.warning_count,
        )

    @staticmethod
    def _credential_frame() -> bytes:
        if not config_store.CONNECTION_FILE.is_file():
            raise RuntimeError(
                "A configuração da VPN principal não foi encontrada. "
                "Restaure uma configuração autorizada ou reexecute o instalador "
                "para reprovisionar a VPN principal."
            )
        values = config_store.read_key_values()
        username = values.get("username", "")
        if not username:
            raise RuntimeError(
                "O usuário da VPN principal não está configurado. "
                "Revise a aba Configuração."
            )
        password, status, details = secret_store.lookup_diagnostic(username)
        if status == "indisponivel":
            raise RuntimeError(
                "O GNOME Keyring está indisponível. Inicie o Secret Service e tente novamente."
            )
        if status == "ausente" or not password:
            raise RuntimeError(
                "Credencial não encontrada no GNOME Keyring. "
                "Cadastre a credencial usando os atributos "
                f"{details['attributes']} e tente novamente."
            )
        encoded = password.encode("utf-8")
        if len(encoded) > 4096:
            raise RuntimeError("A credencial da VPN é inválida.")
        return struct.pack("!I", len(encoded)) + encoded

    @classmethod
    def _start_connect_helper(cls, stdout=None) -> subprocess.Popen:
        process = subprocess.Popen(
            ["sudo", "-n", CONNECT_HELPER],
            stdin=subprocess.PIPE,
            stdout=stdout,
            stderr=subprocess.STDOUT,
        )
        try:
            frame = cls._credential_frame()
            assert process.stdin is not None
            process.stdin.write(frame)
        except Exception:
            process.terminate()
            raise
        finally:
            if process.stdin is not None and not process.stdin.closed:
                process.stdin.close()
        return process

    def _buffer_text(self, view: Gtk.TextView) -> str:
        buffer = view.get_buffer()
        return buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), True)

    def save_routes(self) -> None:
        assert self.routes_view is not None
        try:
            config_store.save_routes(self._buffer_text(self.routes_view))
        except (OSError, ValueError) as exc:
            self._show_message("Não foi possível salvar as sub-redes", str(exc), error=True)
            return
        self._show_message("Sub-redes salvas", "As rotas corporativas foram atualizadas.")

    def save_hosts(self) -> None:
        assert self.hosts_view is not None
        try:
            config_store.save_hosts(self._buffer_text(self.hosts_view))
        except (OSError, ValueError) as exc:
            self._show_message("Não foi possível salvar o mapa de hosts", str(exc), error=True)
            return
        self._show_message("Mapa de hosts salvo", "Os nomes corporativos foram atualizados.")

    def _selected_secondary_interface(self) -> str:
        if self.secondary_interface_candidates is None:
            return ""
        index = self.secondary_interface_candidates.get_active()
        if 0 <= index < len(self.secondary_candidate_values):
            return self.secondary_candidate_values[index]
        return ""

    def save_secondary_configuration(self) -> None:
        assert self.secondary_url_entry is not None
        try:
            config_store.save_secondary_url(self.secondary_url_entry.get_text())
            selected_interface = self._selected_secondary_interface()
            config_store.save_secondary_interface(
                selected_interface or f5_backend.configured_interface()
            )
        except (OSError, ValueError) as exc:
            self._show_message(
                "Não foi possível salvar a configuração da VPN secundária",
                str(exc),
                error=True,
            )
            return
        self._show_message(
            "Configuração da VPN secundária salva",
            "A URL e a interface selecionada foram atualizadas.",
        )

    def _select_secondary_candidate(self, combo: Gtk.ComboBoxText) -> None:
        index = combo.get_active()
        if index < 0 or index >= len(self.secondary_candidate_values):
            return
        details = self.secondary_candidate_details[index]
        combo.set_tooltip_text(details)
        if self.secondary_discovery_label is not None:
            self.secondary_discovery_label.set_text(
                f"Interface {self.secondary_candidate_values[index]} selecionada. "
                "Confirme em Salvar configurações da VPN secundária."
            )

    def refresh_secondary_interfaces(self, preferred_interface: str | None = None) -> None:
        if self.secondary_interface_candidates is None:
            return
        configured_interface = (
            f5_backend.configured_interface()
            if preferred_interface is None
            else preferred_interface
        )
        previous = self._selected_secondary_interface()
        if not previous:
            previous = configured_interface
        self.secondary_interface_candidates.remove_all()
        self.secondary_candidate_values = []
        self.secondary_candidate_details = []
        candidates = f5_backend.discover_interface_candidates()
        for candidate in candidates:
            state = "ativa" if candidate.active else "inativa"
            address = candidate.ipv4 or "sem IPv4 válido"
            routes = ", ".join(candidate.routes) if candidate.routes else "nenhuma"
            details = (
                f"Estado: {state}\nTipo: {candidate.kind}\nIPv4: {address}\n"
                f"Rotas: {routes}\nObservação: {candidate.observation}"
            )
            self.secondary_interface_candidates.append_text(candidate.name)
            self.secondary_candidate_values.append(candidate.name)
            self.secondary_candidate_details.append(details)
        active_index = self._secondary_candidate_index_after_refresh(
            self.secondary_candidate_values,
            previous,
        )
        self.secondary_interface_candidates.set_active(active_index)
        if self.secondary_discovery_label is not None:
            if active_index >= 0:
                self.secondary_discovery_label.set_text(
                    f"Interface {self.secondary_candidate_values[active_index]} selecionada. "
                    "Confirme em Salvar configurações da VPN secundária."
                )
            elif configured_interface == "":
                self.secondary_discovery_label.set_text(
                    "Modo de descoberta manual ativo. O estado operacional da VPN "
                    "secundária não será monitorado como CONECTADA até que uma interface "
                    "seja selecionada e salva. Após autenticar manualmente, clique em "
                    "Atualizar interfaces, selecione a interface correta e salve a configuração."
                )
            elif not candidates:
                self.secondary_discovery_label.set_text(
                    "Nenhuma interface candidata encontrada. Conecte manualmente a VPN secundária antes de atualizar a lista."
                )
            else:
                self.secondary_discovery_label.set_text(
                    "Selecione uma interface candidata e confirme em Salvar configurações da VPN secundária."
                )

    @staticmethod
    def _secondary_candidate_index_after_refresh(values: list[str], previous: str) -> int:
        if not values:
            return -1
        if previous in values:
            return values.index(previous)
        return -1


    def _show_message(self, title: str, detail: str, error: bool = False) -> None:
        dialog = Gtk.MessageDialog(
            transient_for=self.window,
            flags=0,
            message_type=Gtk.MessageType.ERROR if error else Gtk.MessageType.INFO,
            buttons=Gtk.ButtonsType.OK,
            text=title,
        )
        dialog.format_secondary_text(detail)
        dialog.run()
        dialog.destroy()

    def _check_integrity_markup(self) -> str:
        checks = [
            ("Aplicação", Path.home() / ".local/share/vpn/vpn.py"),
            ("Configuração", Path.home() / ".config/vpn/connection.conf"),
            ("Sub-redes", Path.home() / ".config/vpn/routes.conf"),
            ("Mapa de hosts", Path.home() / ".config/vpn/hosts.conf"),
            ("Helper de conexão", Path(CONNECT_HELPER)),
            ("Helper de desconexão", Path(DISCONNECT_HELPER)),
            ("Helper de diagnóstico", Path(DIAGNOSE_HELPER)),
            ("Regra sudoers", Path("/etc/sudoers.d/vpn")),
        ]

        failures = [name for name, path in checks if not path.exists()]

        for command in ("openfortivpn", "ip", "ping", "openssl"):
            result = subprocess.run(
                ["bash", "-lc", f"command -v {command}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if result.returncode != 0:
                failures.append(f"Comando {command}")

        sudo_test = subprocess.run(
            ["sudo", "-n", "-l", DIAGNOSE_HELPER],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if sudo_test.returncode != 0:
            failures.append("Permissão do helper de diagnóstico")

        if failures:
            details = GLib.markup_escape_text(", ".join(failures))
            return f"<span foreground='#c62828'><b>Integridade — Falha:</b> {details}</span>"
        return "<span foreground='#2e7d32'><b>Integridade: OK</b></span>"

    def _refresh_integrity_status(self) -> bool:
        self.integrity_status_markup = self._check_integrity_markup()
        if self.status_integrity_label is not None:
            self.status_integrity_label.set_markup(self.integrity_status_markup)
        if "Integridade — Falha:" in self.integrity_status_markup:
            self._notify("Falha no teste de integridade. Consulte o status do painel.")
        return "Integridade — Falha:" not in self.integrity_status_markup

    def _open_panel_from_tray(self, _item=None) -> None:
        self._refresh_integrity_status()
        self.show_window()

    @staticmethod
    def _stop_connect_process(process: subprocess.Popen) -> None:
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
        subprocess.run(
            ["sudo", "-n", DISCONNECT_HELPER],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def connect_vpn(self) -> None:
        if self.is_connecting:
            return

        if network.vpn_interface():
            self._refresh_controls()
            return

        self.desired_connected = True
        self.manual_disconnect = False
        self.is_connecting = True
        self.primary_error = False
        self._refresh_controls()

        def worker():
            with LOG_PATH.open("w", encoding="utf-8") as log:
                try:
                    process = self._start_connect_helper(log)
                except (OSError, RuntimeError, ValueError) as exc:
                    self.last_credential_diagnostic = str(exc)
                    LOGGER.warning("Não foi possível preparar a credencial: %s", self.last_credential_diagnostic)
                    GLib.idle_add(self._connection_failed, 1, self.last_credential_diagnostic)
                    return

                connected = False
                # O helper aguarda a PPP por até 60 s; damos margem para
                # inicialização e encerramento antes de declarar falha.
                for _ in range(140):
                    if network.vpn_interface():
                        connected = True
                        break
                    if process.poll() is not None:
                        break
                    time.sleep(0.5)

                if connected:
                    GLib.idle_add(self._connection_established)
                else:
                    self._stop_connect_process(process)
                    return_code = process.poll()
                    GLib.idle_add(
                        self._connection_failed,
                        return_code if return_code is not None else 1,
                    )

        threading.Thread(target=worker, daemon=True).start()

    def _connection_established(self) -> bool:
        self.is_connecting = False
        self.primary_error = False
        self.last_connected = True
        self.connected_since = time.monotonic()
        self.reconnect_status = ""
        self._refresh_controls()
        return False

    def _connection_failed(self, _return_code: int, reason: str = "") -> bool:
        self.is_connecting = False
        self.primary_error = True
        self.last_connected = False
        if not self.reconnect_in_progress:
            self.desired_connected = False
        self._refresh_controls()

        self._notify(reason or "Falha ao conectar. Consulte o Log da conexão.")
        return False

    def disconnect_vpn(self) -> None:
        if not self.is_connecting and not network.vpn_interface():
            self._refresh_controls()
            return

        self.manual_disconnect = True
        self.desired_connected = False
        self.reconnect_in_progress = False
        self.reconnect_status = ""
        self.primary_error = False
        subprocess.run(["sudo", "-n", DISCONNECT_HELPER], check=False)
        self.is_connecting = False
        self.last_connected = False
        self.connected_since = None
        self._refresh_controls()

    def _set_reconnect_status(self, status: str) -> bool:
        self.reconnect_status = status
        self._refresh_controls()
        return False

    def _start_reconnect(self, reason: str) -> None:
        if not self.auto_reconnect_primary:
            self.reconnect_status = "RECONEXÃO AUTOMÁTICA DESATIVADA"
            self._refresh_controls()
            return
        if (
            self.reconnect_in_progress
            or not self.desired_connected
            or self.manual_disconnect
        ):
            return

        self.reconnect_in_progress = True
        self.is_connecting = True
        self.primary_error = False
        self.reconnect_status = "AGUARDANDO INTERNET"
        self._refresh_controls()

        def worker():
            delays = (5, 15, 30)

            for attempt, delay in enumerate(delays, start=1):
                if not self.desired_connected or self.manual_disconnect:
                    GLib.idle_add(self._finish_reconnect_cancelled)
                    return

                GLib.idle_add(
                    self._set_reconnect_status,
                    f"AGUARDANDO INTERNET — tentativa {attempt}/{len(delays)} em {delay}s",
                )
                time.sleep(delay)

                if not self.desired_connected or self.manual_disconnect:
                    GLib.idle_add(self._finish_reconnect_cancelled)
                    return

                if not self.auto_reconnect_primary:
                    GLib.idle_add(
                        self._set_reconnect_status,
                        "RECONEXÃO AUTOMÁTICA DESATIVADA",
                    )
                    GLib.idle_add(self._finish_reconnect_cancelled, True)
                    return

                if not network.internet_available():
                    continue

                GLib.idle_add(
                    self._set_reconnect_status,
                    f"RECONECTANDO — tentativa {attempt}/{len(delays)}",
                )

                with LOG_PATH.open("a", encoding="utf-8") as log:
                    log.write(
                        f"\n--- Reconexão automática "
                        f"{attempt}/{len(delays)} ---\n"
                    )
                    log.flush()
                    os.fsync(log.fileno())
                    try:
                        process = self._start_connect_helper(log)
                    except (OSError, RuntimeError, ValueError):
                        LOGGER.warning("Não foi possível preparar a credencial.")
                        continue

                    for _ in range(140):
                        if not self.desired_connected or self.manual_disconnect:
                            subprocess.run(
                                ["sudo", "-n", DISCONNECT_HELPER],
                                check=False,
                            )
                            GLib.idle_add(self._finish_reconnect_cancelled)
                            return

                        connected_interface = network.vpn_interface()
                        if not self.auto_reconnect_primary:
                            self._stop_connect_process(process)
                            GLib.idle_add(
                                self._set_reconnect_status,
                                "RECONEXÃO AUTOMÁTICA DESATIVADA",
                            )
                            GLib.idle_add(self._finish_reconnect_cancelled, True)
                            return

                        if connected_interface:
                            GLib.idle_add(
                                self._finish_reconnect_success,
                                attempt,
                            )
                            return

                        if process.poll() is not None:
                            break

                        time.sleep(0.5)

                    if not network.vpn_interface():
                        self._stop_connect_process(process)

            GLib.idle_add(self._finish_reconnect_failed)

        threading.Thread(target=worker, daemon=True).start()

    def _finish_reconnect_success(self, attempt: int) -> bool:
        self.reconnect_in_progress = False
        self.reconnect_status = ""
        self.is_connecting = False
        self.primary_error = False
        self.last_connected = True
        self.connected_since = time.monotonic()
        self._refresh_controls()
        return False

    def _finish_reconnect_failed(self) -> bool:
        self.reconnect_in_progress = False
        self.is_connecting = False
        self.primary_error = True
        self.last_connected = False
        self.desired_connected = False
        self.reconnect_status = ""
        self._refresh_controls()

        self._notify(
            "Não foi possível restabelecer a VPN após 3 tentativas."
        )
        return False

    def _finish_reconnect_cancelled(self, keep_reason: bool = False) -> bool:
        self.reconnect_in_progress = False
        if not keep_reason:
            self.reconnect_status = ""
        self.is_connecting = False
        self.primary_error = False
        self._refresh_controls()
        return False

    def open_f5(self) -> None:
        ok, message = f5_backend.launch()
        if not ok:
            self._notify(message)
        self._refresh_controls()
        if ok and self.window is not None and self.window.get_visible():
            self._visible_update()

    def hide_f5(self, notify: bool = True) -> bool:
        ok, message = f5_backend.hide_window()
        if notify and not ok:
            self._notify(message)
        self._refresh_controls()
        if ok:
            GLib.timeout_add(150, self._refresh_controls)
        return ok

    def show_f5(self) -> None:
        ok, message = f5_backend.show_window()
        if not ok:
            self._notify(message)
        self._refresh_controls()
        if ok:
            GLib.timeout_add(150, self._refresh_controls)

    def _watch_f5(self) -> None:
        current = f5_backend.status()
        changed = False
        if current.connected and not self.f5_last_connected:
            self.f5_last_connected = True
            changed = True
            if self.hide_f5(notify=False):
                self.f5_auto_hidden = True
        elif not current.connected and self.f5_last_connected:
            self.f5_last_connected = False
            self.f5_auto_hidden = False
            changed = True
        if changed:
            self._refresh_controls()

    def run_diagnostic(self) -> None:
        if self.diagnostic_running:
            if self.notebook is not None:
                self.notebook.set_current_page(1)
            return

        self.diagnostic_running = True

        if self.notebook is not None:
            self.notebook.set_current_page(1)

        if self.diagnostic_status_label is not None:
            self.diagnostic_status_label.set_markup(
                "<b>Diagnóstico em andamento...</b>"
            )

        if self.diagnostic_view is not None:
            self.diagnostic_view.get_buffer().set_text(
                "Executando verificações de Internet, VPN, LAN, Tailscale, "
                "Docker, rotas corporativas e firewall. Aguarde..."
            )

        certificate_values, certificate_configuration_valid = (
            self._certificate_diagnostic_snapshot()
        )

        def worker():
            try:
                result = subprocess.run(
                    ["sudo", "-n", DIAGNOSE_HELPER],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                certificate_result = self._certificate_diagnostic_result(
                    certificate_values,
                    certificate_configuration_valid,
                )
                certificate_report = (
                    "Certificado da VPN principal\n"
                    + certificate_diagnostics.format_diagnostic(certificate_result)
                )
                helper_report = result.stdout + result.stderr
                failures, warnings = self._integrated_diagnostic_counts(
                    helper_report,
                    result.returncode,
                    certificate_result,
                )
                separator = "\n\n" if helper_report else ""
                DIAG_PATH.write_text(
                    helper_report
                    + separator
                    + certificate_report
                    + f"\n\nRESUMO GERAL: {failures} falha(s), {warnings} aviso(s)\n",
                    encoding="utf-8",
                )
                GLib.idle_add(self._finish_diagnostic, failures, warnings)
            except Exception:
                DIAG_PATH.write_text(
                    "Falha ao executar diagnóstico.\n\n"
                    "RESUMO GERAL: 1 falha(s), 0 aviso(s)\n",
                    encoding="utf-8",
                )
                GLib.idle_add(self._finish_diagnostic, 1, 0)

        threading.Thread(target=worker, daemon=True).start()

    def _finish_diagnostic(self, failures: int, warnings: int):
        self.diagnostic_running = False

        if self.diagnostic_view:
            report = (
                DIAG_PATH.read_text(encoding="utf-8")
                if DIAG_PATH.exists()
                else "Sem relatório."
            )
            self.diagnostic_view.get_buffer().set_text(report)

        if self.diagnostic_status_label is not None:
            if failures > 0:
                self.diagnostic_status_label.set_markup(
                    "<span foreground='#c0392b'><b>Diagnóstico concluído com falhas críticas.</b></span>"
                )
            elif warnings > 0:
                self.diagnostic_status_label.set_markup(
                    "<span foreground='#e69f00'><b>Diagnóstico concluído com avisos ou resultado indeterminado.</b></span>"
                )
            else:
                self.diagnostic_status_label.set_markup(
                    "<span foreground='#2ca02c'><b>Diagnóstico concluído sem falhas ou avisos.</b></span>"
                )

        self.last_diagnostic_at = time.strftime("%H:%M:%S")
        if self.status_diagnostic_label is not None:
            self.status_diagnostic_label.set_text(
                f"Último diagnóstico: {self.last_diagnostic_at}"
            )

        if failures > 0:
            self._notify(
                f"Diagnóstico encontrou {failures} falha(s). "
                "Consulte a aba Diagnóstico."
            )
        return False

    def open_diagnostic(self) -> None:
        if DIAG_PATH.exists():
            subprocess.Popen(["xdg-open", str(DIAG_PATH)])
        else:
            self._notify("Nenhum diagnóstico executado.")

    def _hidden_watch(self) -> bool:
        connected = bool(network.vpn_interface())
        self._watch_f5()

        if connected and not self.last_connected:
            self.last_connected = True
            self.is_connecting = False
            self.reconnect_in_progress = False
            self.manual_disconnect = False
            self.connected_since = time.monotonic()
            self._refresh_controls()

        elif not connected and self.last_connected:
            self.last_connected = False
            self.connected_since = None
            self._refresh_controls()

            if self.desired_connected and not self.manual_disconnect:
                if network.internet_available():
                    self._start_reconnect(
                        "A conexão VPN caiu inesperadamente."
                    )
                else:
                    self._start_reconnect(
                        "A Internet ficou indisponível e a VPN foi perdida."
                    )

        elif (
            self.desired_connected
            and not connected
            and not self.is_connecting
            and not self.reconnect_in_progress
            and not self.manual_disconnect
        ):
            self._start_reconnect("A VPN principal está desconectada.")

        elif not self.is_connecting:
            self._refresh_controls()

        return True

    def _visible_update(self) -> bool:
        if not self.window or not self.window.get_visible():
            self.visible_timer = None
            return False

        if self.update_in_progress:
            return True

        self.update_in_progress = True

        def worker():
            try:
                now = time.monotonic()

                ppp = network.vpn_interface()
                internet_iface = network.route_interface("8.8.8.8")
                internet_ip = network.interface_ipv4(internet_iface)
                f5 = f5_backend.status()

                tailscale_ip = (
                    network.interface_ipv4("tailscale0")
                    if Path("/sys/class/net/tailscale0").exists()
                    else "-"
                )

                # Rede local / Internet
                if internet_iface and internet_iface != "-":
                    if self.local_started_at is None:
                        self.local_started_at = now

                    (
                        local_rx,
                        local_tx,
                        local_rx_speed,
                        local_tx_speed,
                    ) = self.internet_sampler.sample(internet_iface)

                    local_elapsed = int(now - self.local_started_at)
                    local_h, local_rem = divmod(local_elapsed, 3600)
                    local_m, local_s = divmod(local_rem, 60)
                    local_uptime = f"{local_h:02d}:{local_m:02d}:{local_s:02d}"
                else:
                    local_rx = local_tx = 0
                    local_rx_speed = local_tx_speed = 0.0
                    local_uptime = "-"
                    self.local_started_at = None

                # VPN principal
                if ppp:
                    (
                        ppp_rx,
                        ppp_tx,
                        ppp_rx_speed,
                        ppp_tx_speed,
                    ) = self.primary_sampler.sample(ppp)

                    if self.connected_since is None:
                        self.connected_since = now

                    ppp_elapsed = int(now - self.connected_since)
                    ppp_h, ppp_rem = divmod(ppp_elapsed, 3600)
                    ppp_m, ppp_s = divmod(ppp_rem, 60)
                    ppp_uptime = f"{ppp_h:02d}:{ppp_m:02d}:{ppp_s:02d}"
                else:
                    ppp_rx = ppp_tx = 0
                    ppp_rx_speed = ppp_tx_speed = 0.0
                    ppp_uptime = "-"
                    self.connected_since = None

                internet_ok = bool(internet_iface and internet_iface != "-") and network.internet_available()

                if self.reconnect_status:
                    primary_state = self.reconnect_status
                elif self.is_connecting:
                    primary_state = "CONECTANDO"
                elif ppp and not internet_ok:
                    primary_state = "DEGRADADA — sem Internet"
                elif ppp:
                    primary_state = "CONECTADA"
                else:
                    primary_state = "DESCONECTADA"

                configured_hosts = config_store.read_hosts()
                latency_target = (
                    configured_hosts[0].split(maxsplit=1)[0]
                    if configured_hosts
                    else ""
                )

                snapshot = {
                    "internet_status": (
                        "OK"
                        if internet_ok and internet_iface not in {"-", ppp}
                        else "FALHA"
                    ),
                    "internet_interface": internet_iface or "-",
                    "internet_local_ip": internet_ip,
                    "public_ip": network.public_ip(),
                    "internet_latency": network.ping_ms("8.8.8.8"),
                    "internet_uptime": local_uptime,
                    "internet_download": (
                        f"{network.format_bytes(local_rx)} "
                        f"({network.format_bytes(int(local_rx_speed))}/s)"
                    ),
                    "internet_upload": (
                        f"{network.format_bytes(local_tx)} "
                        f"({network.format_bytes(int(local_tx_speed))}/s)"
                    ),

                    "primary_status": primary_state,
                    "primary_interface": ppp or "-",
                    "primary_ip": network.interface_ipv4(ppp) if ppp else "-",
                    "primary_latency": (
                        network.ping_ms(latency_target)
                        if ppp and latency_target
                        else "-"
                    ),
                    "primary_uptime": ppp_uptime,
                    "primary_download": (
                        f"{network.format_bytes(ppp_rx)} "
                        f"({network.format_bytes(int(ppp_rx_speed))}/s)"
                    ),
                    "primary_upload": (
                        f"{network.format_bytes(ppp_tx)} "
                        f"({network.format_bytes(int(ppp_tx_speed))}/s)"
                    ),

                    "secondary_status": f5.label,
                    "secondary_interface": f5.interface or "-",
                    "secondary_ip": f5.interface_ip,
                    "secondary_window": "ABERTA" if f5.window_id else "NÃO DETECTADA",
                    "tailscale": (
                        f"ATIVO / {tailscale_ip}"
                        if tailscale_ip != "-"
                        else "INATIVO"
                    ),
                    "docker": network.docker_summary(),
                    "firewall": network.firewall_summary(),
                }

                GLib.idle_add(self._apply_snapshot, snapshot)
            finally:
                self.update_in_progress = False

        threading.Thread(target=worker, daemon=True).start()
        return True

    def _apply_snapshot(self, snapshot: dict[str, str]):
        for key, value in snapshot.items():
            if key in self.labels:
                self.labels[key].set_text(value)

        if self.status_update_label is not None:
            self.status_update_label.set_text(
                f"Última atualização: {time.strftime('%H:%M:%S')}"
            )

        if self.log_view:
            log = LOG_PATH.read_text(encoding="utf-8") if LOG_PATH.exists() else "Sem log técnico."
            self.log_view.get_buffer().set_text(log)
        return False

    def show_window(self) -> None:
        first_show = self.window is None
        if self.window is None:
            self._build_window()
            self._load_config_into_ui()
        assert self.window is not None
        self.window.show_all()
        self.window.set_keep_above(False)
        timestamp = Gtk.get_current_event_time()
        self.window.present_with_time(timestamp)
        self.window.grab_focus()
        native_window = self.window.get_window()
        if native_window is not None:
            native_window.focus(timestamp)
        self._refresh_controls()
        self._visible_update()
        if first_show:
            GLib.idle_add(self._apply_initial_natural_height)
        if self.visible_timer is None:
            self.visible_timer = GLib.timeout_add_seconds(5, self._visible_update)

    def _apply_initial_natural_height(self) -> bool:
        if (
            self.window is None
            or self.primary_panel is None
            or self.primary_scroll is None
            or self.primary_content is None
            or self.status_bar is None
        ):
            return False

        _minimum, natural_content_height = (
            self.primary_content.get_preferred_height()
        )
        current_height = self.window.get_allocated_height()
        viewport_height = self.primary_scroll.get_allocated_height()
        current_width, _current_window_height = self.window.get_size()
        _status_minimum, status_natural_height = (
            self.status_bar.get_preferred_height()
        )
        lower_margin = (
            self.primary_panel.get_border_width()
            + self.primary_panel.get_spacing()
            + status_natural_height
        )

        if viewport_height > 0 and current_width > 0:
            non_content_height = current_height - viewport_height
            target_height = max(
                current_height,
                non_content_height + natural_content_height + lower_margin,
            )
            self.initial_target_width = current_width
            self.initial_target_height = target_height
            self.window.resize(current_width, target_height)
        return False

    def _hide_window(self, *_args) -> bool:
        if self.window:
            self.window.hide()
        if self.visible_timer is not None:
            GLib.source_remove(self.visible_timer)
            self.visible_timer = None
        return True

    def quit(self) -> None:
        """Close only the graphical interface and preserve active VPN tunnels."""
        self.reconnect_in_progress = False
        self.reconnect_status = ""
        self.is_connecting = False
        Gtk.main_quit()

    def run(self) -> None:
        self.low_cost_timer = GLib.timeout_add_seconds(5, self._hidden_watch)
        self._refresh_controls()
        Gtk.main()


def main() -> None:
    VPNApplication().run()


if __name__ == "__main__":
    main()
