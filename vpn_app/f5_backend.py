from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from . import config_store

F5_EXECUTABLE = Path("/opt/f5/vpn/f5vpn")
F5_TUNNEL_EXECUTABLE = "/opt/f5/vpn/svpn"
F5_WINDOW_CLASS = "f5vpn.F5 VPN"
F5_INTERFACE = "tun0"


def _secondary_value(key_name: str) -> str:
    try:
        lines = config_store.SECONDARY_FILE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ""
    for raw in lines:
        if "=" not in raw or raw.lstrip().startswith("#"):
            continue
        key, value = raw.split("=", 1)
        if key.strip() == key_name:
            return value.strip()
    return ""


def configured_route() -> str:
    value = _secondary_value("route")
    return "" if value == "192.0.2.0/24" else value


def configured_interface() -> str:
    value = _secondary_value("interface")
    return value if value and "/" not in value and "\0" not in value else ""


def configured_portal_url() -> str:
    return config_store.read_secondary_url()


def _is_example_url(value: str) -> bool:
    try:
        hostname = urlsplit(value).hostname or ""
    except ValueError:
        return False
    return hostname == "example.com" or hostname.endswith(".example.com")


@dataclass(frozen=True)
class F5Status:
    client_running: bool
    tunnel_running: bool
    interface_up: bool
    route_state: str
    window_id: str
    interface_ip: str
    interface: str = ""

    @property
    def connected(self) -> bool:
        return self.interface_up and _valid_ipv4(self.interface_ip)

    @property
    def inconsistent(self) -> bool:
        return self.tunnel_running and not self.connected

    @property
    def label(self) -> str:
        if self.connected:
            return "CONECTADA"
        if self.inconsistent:
            return "ESTADO INCONSISTENTE"
        if self.client_running:
            return "AGUARDANDO AUTENTICAÇÃO"
        return "DESCONECTADA"


def window_controls_enabled(current: F5Status) -> bool:
    return bool(current.window_id)


def window_visible() -> bool:
    return bool(_run(["xdotool", "search", "--onlyvisible", "--class", F5_WINDOW_CLASS]))


def _run(command: list[str], timeout: float = 4.0) -> str:
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip()


def _process_running(executable: str) -> bool:
    proc = Path("/proc")
    try:
        entries = list(proc.iterdir())
    except OSError:
        return False

    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        if not cmdline or not cmdline[0]:
            continue
        try:
            command = os.fsdecode(cmdline[0])
        except UnicodeDecodeError:
            continue
        if command == executable:
            return True
    return False


def window_id() -> str:
    output = _run(["wmctrl", "-lx"])
    class_marker = f" {F5_WINDOW_CLASS.lower()} "
    for line in output.splitlines():
        normalized = f" {line.lower()} "
        if class_marker in normalized:
            fields = line.split(maxsplit=1)
            if fields:
                return fields[0]
    return ""


def interface_up(interface: str = F5_INTERFACE) -> bool:
    output = _run(["ip", "-br", "link", "show", "up", "dev", interface])
    return output.split(maxsplit=1)[:1] == [interface]


def interface_ipv4(interface: str = F5_INTERFACE) -> str:
    output = _run(["ip", "-4", "-br", "addr", "show", "dev", interface])
    parts = output.split()
    return parts[2].split("/", 1)[0] if len(parts) >= 3 else "-"


def _valid_ipv4(value: str) -> bool:
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        return False
    return not address.is_unspecified


def detected_interface(tunnel_running: bool) -> str:
    configured = configured_interface()
    candidates = [configured] if configured else []
    if F5_INTERFACE not in candidates:
        candidates.append(F5_INTERFACE)
    for candidate in candidates:
        if candidate and interface_up(candidate):
            return candidate
    if not tunnel_running:
        return ""
    output = _run(["ip", "-br", "link", "show", "up"])
    for line in output.splitlines():
        fields = line.split()
        if fields and fields[0].startswith(("tun", "tap")):
            return fields[0]
    return ""


def route_status(route: str | None = None, interface: str = F5_INTERFACE) -> str:
    route = configured_route() if route is None else route
    if not route:
        return "NÃO CONFIGURADA"
    try:
        result = subprocess.run(
            ["ip", "route", "show", route],
            text=True,
            capture_output=True,
            timeout=4,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "INDETERMINADA"
    if result.returncode != 0:
        return "INDETERMINADA"
    present = any(
        line.startswith(route) and f" dev {interface}" in f" {line} "
        for line in result.stdout.splitlines()
    )
    return "PRESENTE" if present else "AUSENTE"


def authentication_enabled(current: F5Status) -> bool:
    return not current.connected


def status() -> F5Status:
    client_running = _process_running(str(F5_EXECUTABLE))
    tunnel_running = _process_running(F5_TUNNEL_EXECUTABLE)
    interface = detected_interface(tunnel_running)
    address = interface_ipv4(interface) if interface else "-"
    return F5Status(
        client_running=client_running,
        tunnel_running=tunnel_running,
        interface_up=bool(interface),
        route_state=route_status(interface=interface) if interface else (
            "NÃO CONFIGURADA" if not configured_route() else "INDETERMINADA"
        ),
        window_id=window_id(),
        interface_ip=address,
        interface=interface,
    )


def launch() -> tuple[bool, str]:
    portal_url = configured_portal_url()
    if not portal_url or _is_example_url(portal_url):
        return False, (
            "Configure uma URL HTTPS de autenticação válida para a VPN "
            "secundária na aba Configuração."
        )
    try:
        portal_url = config_store.validate_secondary_url(portal_url)
    except ValueError:
        return False, (
            "A URL de autenticação da VPN secundária é inválida. "
            "Revise-a na aba Configuração."
        )
    browser = next(
        (
            executable
            for executable in (
                "google-chrome",
                "google-chrome-stable",
                "chromium",
                "chromium-browser",
            )
            if shutil.which(executable)
        ),
        None,
    )
    command = [browser, portal_url] if browser else ["xdg-open", portal_url]

    try:
        subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        return False, f"Falha ao abrir o portal de autenticação da VPN secundária: {exc}"

    return True, "Portal da VPN secundária aberto no navegador. Conclua a autenticação web."


def hide_window() -> tuple[bool, str]:
    wid = window_id()
    if not wid:
        return False, "Janela do F5 VPN não encontrada."
    try:
        skip_result = subprocess.run(
            ["wmctrl", "-i", "-r", wid, "-b", "add,skip_taskbar"],
            text=True,
            capture_output=True,
            timeout=4,
            check=False,
        )
        result = subprocess.run(
            ["xdotool", "windowminimize", wid],
            text=True,
            capture_output=True,
            timeout=4,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"Falha ao ocultar a janela F5: {exc}"
    if skip_result.returncode != 0:
        return False, skip_result.stderr.strip() or "Não foi possível remover o F5 da barra de tarefas."
    if result.returncode != 0:
        return False, result.stderr.strip() or "Não foi possível ocultar a janela F5."
    return True, "Janela F5 minimizada e removida da barra de tarefas."


def show_window() -> tuple[bool, str]:
    wid = window_id()
    if not wid:
        return False, "Janela do F5 VPN não encontrada."
    try:
        subprocess.run(
            ["wmctrl", "-i", "-r", wid, "-b", "remove,skip_taskbar"],
            text=True,
            capture_output=True,
            timeout=4,
            check=False,
        )
        result = subprocess.run(
            ["wmctrl", "-i", "-a", wid],
            text=True,
            capture_output=True,
            timeout=4,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"Falha ao exibir a janela F5: {exc}"
    if result.returncode != 0:
        return False, result.stderr.strip() or "Janela do F5 VPN não encontrada."
    return True, "Janela F5 exibida."
