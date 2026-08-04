#!/usr/bin/env python3
from __future__ import annotations

import logging
import os
import re
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import gi
gi.require_version("Gtk", "3.0")
gi.require_version("AyatanaAppIndicator3", "0.1")
from gi.repository import AyatanaAppIndicator3, Gdk, GLib, Gtk

from . import config_store, f5_backend, network

LOGGER = logging.getLogger(__name__)

APP_VERSION = "1.0"
APP_NAME = "VPN Corporativa"
APP_ID = "br.local.vpncorporativa"
CONNECT_HELPER = "/usr/local/libexec/vpn-connect"
DISCONNECT_HELPER = "/usr/local/libexec/vpn-disconnect"
DIAGNOSE_HELPER = "/usr/local/libexec/vpn-diagnose"
LOCK_NAME = "\0vpn_corporativa_1_0_lock"
STATE_DIR = Path.home() / ".local" / "state" / "vpn"
STATE_DIR.mkdir(parents=True, exist_ok=True)
LOG_PATH = STATE_DIR / "connection.log"
DIAG_PATH = STATE_DIR / "diagnostic-latest.txt"

ICON_OFF = "/usr/local/share/icons/vpn-corporativa-gray.svg"
ICON_WAIT = "/usr/local/share/icons/vpn-corporativa-yellow.svg"
ICON_ON = "/usr/local/share/icons/vpn-corporativa-green.svg"
ICON_ERROR = "/usr/local/share/icons/vpn-corporativa-red.svg"


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
        self.routes_view: Gtk.TextView | None = None
        self.hosts_view: Gtk.TextView | None = None
        self.diagnostic_view: Gtk.TextView | None = None
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
        self.desired_connected = False
        self.reconnect_in_progress = False
        self.reconnect_status = ""
        self.manual_disconnect = False
        self.connect_button: Gtk.Button | None = None
        self.disconnect_button: Gtk.Button | None = None
        self.f5_auth_buttons: list[Gtk.Button] = []
        self.f5_window_buttons: list[Gtk.Button] = []
        self.menu_primary_status: Gtk.MenuItem | None = None
        self.menu_secondary_status: Gtk.MenuItem | None = None
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
        self.integrity_status_markup = self._check_integrity_markup()
        if self.last_connected:
            self.connected_since = time.monotonic()


    def _primary_status_text(self) -> str:
        if self.reconnect_status:
            return self.reconnect_status
        if self.is_connecting:
            return "CONECTANDO"
        return "CONECTADA" if bool(network.vpn_interface()) else "DESCONECTADA"

    @staticmethod
    def _secondary_status_text() -> str:
        return f5_backend.status().label

    def _tray_title(self) -> str:
        primary = self._primary_status_text().lower()
        secondary = self._secondary_status_text().lower()
        return f"VPN Corporativa — Principal: {primary} | Secundária: {secondary}"

    def can_connect(self, _item=None) -> bool:
        return not self.is_connecting and not bool(network.vpn_interface())

    def can_disconnect(self, _item=None) -> bool:
        return self.is_connecting or bool(network.vpn_interface())

    def _build_indicator(self):
        f5 = f5_backend.status()
        if self.last_connected and f5.connected:
            icon = ICON_ON
        elif self.last_connected or f5.connected or (f5.client_running and not f5.inconsistent):
            icon = ICON_WAIT
        elif f5.inconsistent:
            icon = ICON_ERROR
        else:
            icon = ICON_OFF
        indicator = AyatanaAppIndicator3.Indicator.new(
            APP_ID,
            icon,
            AyatanaAppIndicator3.IndicatorCategory.SYSTEM_SERVICES,
        )
        indicator.set_icon_full(icon, self._tray_title())
        indicator.set_status(AyatanaAppIndicator3.IndicatorStatus.ACTIVE)
        indicator.set_title(self._tray_title())

        menu = Gtk.Menu()

        self.menu_primary_status = Gtk.MenuItem(label="Principal: verificando...")
        self.menu_primary_status.set_sensitive(False)
        menu.append(self.menu_primary_status)

        self.menu_secondary_status = Gtk.MenuItem(label="Secundária: verificando...")
        self.menu_secondary_status.set_sensitive(False)
        menu.append(self.menu_secondary_status)

        menu.append(Gtk.SeparatorMenuItem())

        open_item = Gtk.MenuItem(label="Abrir VPN Corporativa")
        open_item.connect("activate", lambda *_: self.show_window())
        menu.append(open_item)

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

        if f5.inconsistent or "FALHOU" in self.reconnect_status:
            icon = ICON_ERROR
        elif connected and f5.connected:
            icon = ICON_ON
        elif (
            connected
            or f5.connected
            or self.reconnect_status
            or self.is_connecting
            or (f5.client_running and not f5.connected)
        ):
            icon = ICON_WAIT
        else:
            icon = ICON_OFF

        title = self._tray_title()
        self.indicator.set_icon_full(icon, title)
        self.indicator.set_title(title)
        if self.menu_primary_status is not None:
            self.menu_primary_status.set_label(
                f"Principal: {self._primary_status_text()}"
            )
        if self.menu_secondary_status is not None:
            self.menu_secondary_status.set_label(
                f"Secundária: {self._secondary_status_text()}"
            )

        if self.connect_button is not None:
            self.connect_button.set_sensitive(not self.is_connecting and not connected)
        if self.disconnect_button is not None:
            self.disconnect_button.set_sensitive(self.is_connecting or connected)
        for button in self.f5_auth_buttons:
            button.set_sensitive(f5_backend.authentication_enabled(f5))
        for button in self.f5_window_buttons:
            button.set_sensitive(f5_backend.window_controls_enabled(f5))

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
        window = Gtk.Window(title=f"VPN Corporativa {APP_VERSION}")
        window.set_default_size(820, -1)
        window.set_position(Gtk.WindowPosition.CENTER)
        window.connect("realize", self._disable_window_maximize)
        window.connect("configure-event", self._lock_window_at_target_size)
        window.connect("delete-event", self._hide_window)

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        root.set_border_width(12)
        window.add(root)

        title = Gtk.Label()
        title.set_markup("<span size='x-large' weight='bold'>VPN Corporativa — Centro de Controle da Rede</span>")
        title.set_xalign(0)
        root.pack_start(title, False, False, 0)

        notebook = Gtk.Notebook()
        self.notebook = notebook
        root.pack_start(notebook, True, True, 0)

        notebook.append_page(
            self._build_summary_tab(),
            Gtk.Label(label="Painel Principal"),
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

        primary_frame = Gtk.Frame(label="VPN principal (OpenVPN)")
        primary_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        primary_box.set_border_width(10)
        primary_frame.add(primary_box)

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

        secondary_frame = Gtk.Frame(label="VPN secundária (BIG-IP/F5)")
        secondary_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        secondary_box.set_border_width(10)
        secondary_frame.add(secondary_box)

        secondary_grid = Gtk.Grid()
        secondary_grid.set_column_spacing(14)
        secondary_grid.set_row_spacing(7)
        for row, (label, key) in enumerate([
            ("Estado", "secondary_status"),
            ("Interface", "secondary_interface"),
            ("IP VPN", "secondary_ip"),
            ("Janela F5", "secondary_window"),
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
        hide_f5 = Gtk.Button(label="Ocultar F5")
        hide_f5.set_size_request(summary_button_width, -1)
        hide_f5.connect("clicked", lambda *_: self.hide_f5())
        secondary_buttons.pack_start(hide_f5, True, True, 0)
        self.f5_window_buttons.append(hide_f5)

        show_f5 = Gtk.Button(label="Exibir F5")
        show_f5.set_size_request(summary_button_width, -1)
        show_f5.connect("clicked", lambda *_: self.show_f5())
        secondary_buttons.pack_start(show_f5, True, True, 0)
        self.f5_window_buttons.append(show_f5)
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
            "Executar diagnóstico",
            self.run_diagnostic,
        )
        controls.pack_start(run_button, True, True, 0)

        view = Gtk.TextView()
        view.set_editable(False)
        view.set_monospace(True)
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
            ("Certificado confiável", "trusted-cert", False),
        ]):
            self._entry_row(connection, row, *args)

        save_connection = self._full_width_button(
            "Salvar conexão",
            self.save_connection,
        )
        connection.attach(save_connection, 0, 5, 2, 1)
        notebook.append_page(connection, Gtk.Label(label="VPN principal"))

        secondary_frame = Gtk.Frame(
            label="VPN secundária — autenticação via navegador"
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
                "autenticação web pelo\n"
                "navegador, como BIG-IP/F5, em vez de usuário e senha pelo "
                "openfortivpn."
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
        secondary_grid.attach(url_entry, 1, 0, 1, 1)
        self.secondary_url_entry = url_entry

        save_secondary = Gtk.Button(label="Salvar URL de autenticação")
        save_secondary.connect("clicked", lambda *_: self.save_secondary_url())
        secondary_grid.attach(save_secondary, 0, 1, 2, 1)
        authenticate_secondary = Gtk.Button(label="Autenticar VPN secundária")
        authenticate_secondary.connect("clicked", lambda *_: self.open_f5())
        secondary_grid.attach(authenticate_secondary, 0, 2, 2, 1)
        self.f5_auth_buttons.append(authenticate_secondary)
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
        for key, entry in self.config_entries.items():
            entry.set_text(values.get(key, ""))

        if self.routes_view:
            self.routes_view.get_buffer().set_text("\n".join(config_store.read_routes()))
        if self.hosts_view:
            self.hosts_view.get_buffer().set_text("\n".join(config_store.read_hosts()))
        if self.secondary_url_entry is not None:
            self.secondary_url_entry.set_text(config_store.read_secondary_url())

    def save_connection(self) -> None:
        values = {key: entry.get_text() for key, entry in self.config_entries.items()}
        try:
            config_store.save_connection(values)
        except (KeyError, OSError, ValueError) as exc:
            self._show_message("Não foi possível salvar a conexão", str(exc), error=True)
            return
        self._show_message("Configuração salva", "Os dados da conexão foram atualizados.")

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

    def save_secondary_url(self) -> None:
        assert self.secondary_url_entry is not None
        try:
            config_store.save_secondary_url(self.secondary_url_entry.get_text())
        except (OSError, ValueError) as exc:
            self._show_message(
                "Não foi possível salvar a URL de autenticação",
                str(exc),
                error=True,
            )
            return
        self._show_message(
            "URL de autenticação salva",
            "A VPN secundária usará a URL configurada localmente.",
        )

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

        for command in ("openfortivpn", "ip", "ping"):
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
        self._refresh_controls()

        def worker():
            with LOG_PATH.open("w", encoding="utf-8") as log:
                process = subprocess.Popen(
                    ["sudo", "-n", CONNECT_HELPER],
                    stdout=log,
                    stderr=subprocess.STDOUT,
                )

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
        self.last_connected = True
        self.connected_since = time.monotonic()
        self._refresh_controls()
        return False

    def _connection_failed(self, _return_code: int) -> bool:
        self.is_connecting = False
        self.last_connected = False
        if not self.reconnect_in_progress:
            self.desired_connected = False
        self.indicator.set_icon_full(ICON_ERROR, "VPN Corporativa — erro de conexão")
        self.indicator.set_title("VPN Corporativa — erro de conexão")
        if self.menu_primary_status is not None:
            self.menu_primary_status.set_label("Principal: ERRO DE CONEXÃO")

        if self.connect_button is not None:
            self.connect_button.set_sensitive(True)
        if self.disconnect_button is not None:
            self.disconnect_button.set_sensitive(False)

        self._notify("Falha ao conectar. Consulte o Log da conexão.")
        return False

    def disconnect_vpn(self) -> None:
        if not self.is_connecting and not network.vpn_interface():
            self._refresh_controls()
            return

        self.manual_disconnect = True
        self.desired_connected = False
        self.reconnect_in_progress = False
        self.reconnect_status = ""
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
        if (
            self.reconnect_in_progress
            or not self.desired_connected
            or self.manual_disconnect
        ):
            return

        self.reconnect_in_progress = True
        self.is_connecting = True
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
                    process = subprocess.Popen(
                        ["sudo", "-n", CONNECT_HELPER],
                        stdout=log,
                        stderr=subprocess.STDOUT,
                    )

                    for _ in range(140):
                        if not self.desired_connected or self.manual_disconnect:
                            subprocess.run(
                                ["sudo", "-n", DISCONNECT_HELPER],
                                check=False,
                            )
                            GLib.idle_add(self._finish_reconnect_cancelled)
                            return

                        if network.vpn_interface():
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
        self.last_connected = True
        self.connected_since = time.monotonic()
        self._refresh_controls()
        return False

    def _finish_reconnect_failed(self) -> bool:
        self.reconnect_in_progress = False
        self.is_connecting = False
        self.last_connected = False
        self.desired_connected = False
        self.reconnect_status = ""
        self.indicator.set_icon_full(ICON_ERROR, "VPN Corporativa — reconexão falhou")
        self.indicator.set_title("VPN Corporativa — reconexão falhou")
        if self.menu_primary_status is not None:
            self.menu_primary_status.set_label("Principal: RECONEXÃO FALHOU")

        if self.connect_button is not None:
            self.connect_button.set_sensitive(True)
        if self.disconnect_button is not None:
            self.disconnect_button.set_sensitive(False)

        self._notify(
            "Não foi possível restabelecer a VPN após 3 tentativas."
        )
        return False

    def _finish_reconnect_cancelled(self) -> bool:
        self.reconnect_in_progress = False
        self.reconnect_status = ""
        self.is_connecting = False
        self._refresh_controls()
        return False

    def open_f5(self) -> None:
        ok, message = f5_backend.launch()
        if not ok:
            self._notify(message)
        if ok and self.window is not None and self.window.get_visible():
            self._visible_update()

    def hide_f5(self, notify: bool = True) -> bool:
        ok, message = f5_backend.hide_window()
        if notify and not ok:
            self._notify(message)
        return ok

    def show_f5(self) -> None:
        ok, message = f5_backend.show_window()
        if not ok:
            self._notify(message)

    def _watch_f5(self) -> None:
        current = f5_backend.status()
        if current.connected and not self.f5_last_connected:
            self.f5_last_connected = True
            if self.hide_f5(notify=False):
                self.f5_auto_hidden = True
        elif not current.connected and self.f5_last_connected:
            self.f5_last_connected = False
            self.f5_auto_hidden = False

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


        def worker():
            try:
                result = subprocess.run(
                    ["sudo", "-n", DIAGNOSE_HELPER],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                DIAG_PATH.write_text(
                    result.stdout + result.stderr,
                    encoding="utf-8",
                )
                GLib.idle_add(self._finish_diagnostic, result.returncode)
            except Exception as exc:
                DIAG_PATH.write_text(
                    f"Falha ao executar diagnóstico: {exc}\n",
                    encoding="utf-8",
                )
                GLib.idle_add(self._finish_diagnostic, 1)

        threading.Thread(target=worker, daemon=True).start()

    def _finish_diagnostic(self, return_code: int):
        self.diagnostic_running = False

        if self.diagnostic_view:
            report = (
                DIAG_PATH.read_text(encoding="utf-8")
                if DIAG_PATH.exists()
                else "Sem relatório."
            )
            self.diagnostic_view.get_buffer().set_text(report)

        if self.diagnostic_status_label is not None:
            if return_code == 0:
                self.diagnostic_status_label.set_markup(
                    "<span foreground='#2ca02c'><b>Diagnóstico concluído sem falhas críticas.</b></span>"
                )
            else:
                self.diagnostic_status_label.set_markup(
                    "<span foreground='#e69f00'><b>Diagnóstico concluído com avisos ou falhas.</b></span>"
                )

        self.last_diagnostic_at = time.strftime("%H:%M:%S")
        if self.status_diagnostic_label is not None:
            self.status_diagnostic_label.set_text(
                f"Último diagnóstico: {self.last_diagnostic_at}"
            )

        report_text = (
            DIAG_PATH.read_text(encoding="utf-8")
            if DIAG_PATH.exists()
            else ""
        )
        summary_match = re.search(
            r"RESUMO: (\d+) falha\(s\), (\d+) aviso\(s\)",
            report_text,
        )
        if summary_match:
            failures, _warnings = summary_match.groups()
            if int(failures) > 0:
                self._notify(
                    f"Diagnóstico encontrou {failures} falha(s). "
                    "Consulte a aba Diagnóstico."
                )
        elif return_code != 0:
            self._notify(
                "Falha ao interpretar o resultado do diagnóstico."
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
            self._start_reconnect(
                "A VPN Corporativa está desconectada."
            )

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
        self.window.present()
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
