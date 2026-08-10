from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from . import config_store

F5_EXECUTABLE = Path("/opt/f5/vpn/f5vpn")
F5_TUNNEL_EXECUTABLE = "/opt/f5/vpn/svpn"
F5_WINDOW_CLASS = "f5vpn.F5 VPN"
F5_INTERFACE = "tun0"
TUNNEL_INTERFACE_KINDS = frozenset({"tun", "tap", "ppp"})
EXCLUDED_TUNNEL_PREFIXES = ("tailscale", "docker", "br-", "veth")


@dataclass(frozen=True)
class ValidationSnapshot:
    """Estado observado antes de uma tentativa manual de autenticação."""

    process_pids: frozenset[int]
    interfaces: frozenset[str]
    interface_ipv4: tuple[tuple[str, str], ...]
    routes: frozenset[str]
    captured_at: float
    routes_valid: bool = True

    def ipv4_for(self, interface: str) -> str:
        return dict(self.interface_ipv4).get(interface, "")


_validation_snapshot: ValidationSnapshot | None = None


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


def configured_routes() -> tuple[str, ...]:
    """Retorna todas as linhas route=, preservando configurações antigas."""
    try:
        lines = config_store.SECONDARY_FILE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ()
    routes: list[str] = []
    for raw in lines:
        if "=" not in raw or raw.lstrip().startswith("#"):
            continue
        key, value = raw.split("=", 1)
        if key.strip() != "route":
            continue
        value = value.strip()
        if not value or value == "192.0.2.0/24":
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if network.prefixlen == 0:
            continue
        normalized = str(network)
        if normalized not in routes:
            routes.append(normalized)
    return tuple(routes)


def configured_route() -> str:
    routes = configured_routes()
    return routes[0] if routes else ""


def _is_default_route(route: str) -> bool:
    try:
        return ipaddress.ip_network(route, strict=False).prefixlen == 0
    except ValueError:
        return True


def configured_interface() -> str:
    try:
        return config_store.read_secondary_interface()
    except (OSError, ValueError):
        return ""


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
    validation_state: str = "AMBÍGUA"
    operational_state: str = "DESCONECTADA"

    @property
    def connected(self) -> bool:
        return self.operational_state == "CONECTADA"

    @property
    def inconsistent(self) -> bool:
        return self.validation_state in {"INCONSISTENTE", "AMBÍGUA"}

    @property
    def label(self) -> str:
        return self.operational_state

    @property
    def diagnostic_label(self) -> str:
        return self.validation_state


def window_controls_enabled(current: F5Status) -> bool:
    return bool(current.window_id)


def window_visible() -> bool:
    wid = window_id()
    if not wid:
        return False

    state = _run(["xprop", "-id", wid, "_NET_WM_STATE"])
    if state.startswith("_NET_WM_STATE"):
        return "_NET_WM_STATE_HIDDEN" not in state

    # Fallback for desktops without xprop/EWMH state reporting.
    instance = F5_WINDOW_CLASS.split(".", 1)[0]
    return bool(_run(["xdotool", "search", "--onlyvisible", "--classname", instance]))


def _run(command: list[str], timeout: float = 4.0) -> str:
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
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


def _technical_process_pids() -> frozenset[int]:
    proc = Path("/proc")
    found: set[int] = set()
    try:
        entries = list(proc.iterdir())
    except OSError:
        return frozenset()
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            command = os.fsdecode((entry / "cmdline").read_bytes().split(b"\0")[0])
        except (OSError, UnicodeDecodeError):
            continue
        if command == F5_TUNNEL_EXECUTABLE:
            found.add(int(entry.name))
    return frozenset(found)


def _interface_snapshot() -> tuple[frozenset[str], tuple[tuple[str, str], ...]]:
    links = _run(["ip", "-br", "link", "show"]).splitlines()
    interfaces = frozenset(line.split(maxsplit=1)[0] for line in links if line.split())
    ipv4: list[tuple[str, str]] = []
    for interface in interfaces:
        value = interface_ipv4(interface)
        if _valid_ipv4(value):
            ipv4.append((interface, value))
    return interfaces, tuple(sorted(ipv4))


def _route_identity(route: dict) -> str | None:
    destination = route.get("dst", "default")
    if destination in {"default", "0.0.0.0/0", "::/0"}:
        return None
    return json.dumps(route, sort_keys=True, separators=(",", ":"))


def _json_routes(argument: str | None = None) -> tuple[set[str], list[dict]] | None:
    command = ["ip", "-json", "route", "show"]
    if argument:
        command.append(argument)
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=4,
            check=False,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    try:
        payload = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, list) or not all(isinstance(item, dict) for item in payload):
        return None
    identities = {
        identity
        for item in payload
        if (identity := _route_identity(item)) is not None
    }
    return identities, payload


def _route_snapshot() -> tuple[frozenset[str], bool]:
    parsed = _json_routes()
    if parsed is None:
        return frozenset(), False
    identities, _routes = parsed
    return frozenset(identities), True


def capture_validation_snapshot() -> ValidationSnapshot:
    interfaces, ipv4 = _interface_snapshot()
    routes, routes_valid = _route_snapshot()
    snapshot = ValidationSnapshot(
        process_pids=_technical_process_pids(),
        interfaces=interfaces,
        interface_ipv4=ipv4,
        routes=routes,
        captured_at=time.monotonic(),
        routes_valid=routes_valid,
    )
    return snapshot


def begin_validation() -> ValidationSnapshot:
    global _validation_snapshot
    _validation_snapshot = capture_validation_snapshot()
    return _validation_snapshot


def _route_present(route: str, interface: str) -> tuple[set[str], bool] | None:
    parsed = _json_routes(route)
    if parsed is None:
        return None
    identities, payload = parsed
    matching = {
        _route_identity(item)
        for item in payload
        if item.get("dev") == interface and _route_identity(item) is not None
    }
    return {item for item in matching if item is not None}, bool(identities)


def technical_association(process_pid: int, interface: str) -> bool | None:
    """Returns None until the client exposes verifiable process/interface evidence."""
    del process_pid, interface
    return None


def _strong_validation(
    tunnel_pids: frozenset[int],
    interface: str,
    address: str,
    routes: tuple[str, ...],
    interface_ambiguous: bool = False,
) -> str:
    snapshot = _validation_snapshot
    if snapshot is None:
        return "AMBÍGUA" if tunnel_pids or interface else "DESCONECTADA"
    if not tunnel_pids and not interface:
        return "DESCONECTADA"
    if interface_ambiguous:
        return "AMBÍGUA"
    if len(tunnel_pids) != 1:
        return "AMBÍGUA" if tunnel_pids else "INCONSISTENTE"
    if next(iter(tunnel_pids)) in snapshot.process_pids:
        return "AMBÍGUA"
    if not interface or not interface_up(interface) or not _valid_ipv4(address):
        return "INCONSISTENTE"
    interface_new = (
        interface not in snapshot.interfaces
        or snapshot.ipv4_for(interface) != address
    )
    if not interface_new:
        return "AMBÍGUA"
    if not routes:
        return "INCONSISTENTE"
    if any(_is_default_route(route) for route in routes):
        return "INCONSISTENTE"
    if not snapshot.routes_valid:
        return "INCONSISTENTE"
    route_results = [_route_present(route, interface) for route in routes]
    if any(result is None for result in route_results):
        return "INCONSISTENTE"
    for result in route_results:
        assert result is not None
        identities, _has_routes = result
        if not identities or identities.issubset(snapshot.routes):
            return "INCONSISTENTE"
    association = technical_association(next(iter(tunnel_pids)), interface)
    if association is not True:
        return "AMBÍGUA" if association is None else "INCONSISTENTE"
    return "CONECTADA"


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


def _excluded_tunnel_name(interface: str) -> bool:
    return interface.startswith(EXCLUDED_TUNNEL_PREFIXES)


def _interface_details() -> list[dict]:
    output = _run(["ip", "-json", "-details", "link", "show"])
    try:
        payload = json.loads(output)
    except (TypeError, json.JSONDecodeError):
        return []
    return [item for item in payload if isinstance(item, dict)] if isinstance(payload, list) else []


def _tunnel_kind(item: dict) -> str:
    return str((item.get("linkinfo") or {}).get("info_kind") or "")


def _active_from_details(item: dict) -> bool:
    flags = item.get("flags") or []
    return "UP" in flags or str(item.get("operstate", "")).upper() == "UP"


def _related_routes(interface: str) -> tuple[str, ...]:
    parsed = _json_routes()
    if parsed is None:
        return ()
    _identities, payload = parsed
    values: list[str] = []
    for item in payload:
        if item.get("dev") != interface or _route_identity(item) is None:
            continue
        destination = str(item.get("dst", ""))
        if destination not in values:
            values.append(destination)
    return tuple(sorted(values))


@dataclass(frozen=True)
class InterfaceCandidate:
    name: str
    active: bool
    kind: str
    ipv4: str
    routes: tuple[str, ...]
    observation: str


def is_configured_tunnel_interface(interface: str) -> bool:
    """Validates only an explicitly configured interface as a tunnel."""
    if not interface or _excluded_tunnel_name(interface):
        return False
    item = next((item for item in _interface_details() if item.get("ifname") == interface), None)
    return item is not None and _tunnel_kind(item) in TUNNEL_INTERFACE_KINDS


def discover_interface_candidates() -> tuple[InterfaceCandidate, ...]:
    """List only deterministic tunnel candidates; never selects one implicitly."""
    candidates: list[InterfaceCandidate] = []
    for item in _interface_details():
        name = str(item.get("ifname") or "")
        kind = _tunnel_kind(item)
        if not name or kind not in TUNNEL_INTERFACE_KINDS or _excluded_tunnel_name(name):
            continue
        active = _active_from_details(item)
        address = interface_ipv4(name)
        ipv4 = address if _valid_ipv4(address) else ""
        routes = _related_routes(name)
        notes: list[str] = ["Candidata de túnel detectada"]
        if not active:
            notes.append("interface inativa")
        if not ipv4:
            notes.append("sem IPv4 válido")
        if not routes:
            notes.append("sem rota não padrão observada")
        candidates.append(InterfaceCandidate(name, active, kind, ipv4, routes, "; ".join(notes)))
    return tuple(sorted(candidates, key=lambda candidate: candidate.name))


def _valid_ipv4(value: str) -> bool:
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        return False
    return not address.is_unspecified


def detected_interfaces(tunnel_running: bool) -> tuple[str, ...]:
    del tunnel_running
    configured = configured_interface()
    if not configured or not is_configured_tunnel_interface(configured):
        return ()
    return (configured,) if interface_up(configured) else ()


def detected_interface(tunnel_running: bool) -> str:
    candidates = detected_interfaces(tunnel_running)
    return candidates[0] if len(candidates) == 1 else ""


def route_status(route: str | None = None, interface: str = F5_INTERFACE) -> str:
    route = configured_route() if route is None else route
    if not route:
        return "NÃO CONFIGURADA"
    present = _route_present(route, interface)
    if present is None:
        return "INDETERMINADA"
    identities, has_routes = present
    return "PRESENTE" if identities and has_routes else "AUSENTE"


def authentication_enabled(current: F5Status) -> bool:
    return not current.connected


def status() -> F5Status:
    client_running = _process_running(str(F5_EXECUTABLE))
    tunnel_running = _process_running(F5_TUNNEL_EXECUTABLE)
    candidates = detected_interfaces(tunnel_running)
    interface = candidates[0] if len(candidates) == 1 else ""
    address = interface_ipv4(interface) if interface else "-"
    routes = configured_routes()
    route_states = [route_status(route, interface) for route in routes] if interface else []
    route_state = (
        "NÃO CONFIGURADA"
        if not routes
        else "PRESENTE"
        if route_states and all(state == "PRESENTE" for state in route_states)
        else "AUSENTE"
        if route_states and all(state == "AUSENTE" for state in route_states)
        else "INDETERMINADA"
    )
    diagnostic_state = _strong_validation(
        _technical_process_pids(), interface, address, routes,
        interface_ambiguous=len(candidates) > 1,
    )
    operational_state = "DESCONECTADA"
    valid_candidate = any(_valid_ipv4(interface_ipv4(candidate)) for candidate in candidates)
    if valid_candidate:
        operational_state = "CONECTADA"
    elif client_running:
        operational_state = "AGUARDANDO AUTENTICAÇÃO"
    return F5Status(
        client_running=client_running,
        tunnel_running=tunnel_running,
        interface_up=bool(interface),
        route_state=route_state,
        window_id=window_id(),
        interface_ip=address,
        interface=interface,
        validation_state=diagnostic_state,
        operational_state=operational_state,
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
        # Snapshot is captured before opening the existing manual flow.
        begin_validation()
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
        return False, "Janela da VPN secundária não encontrada."
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
        return False, f"Falha ao ocultar a janela da VPN secundária: {exc}"
    if skip_result.returncode != 0:
        return False, skip_result.stderr.strip() or "Não foi possível remover a VPN secundária da barra de tarefas."
    if result.returncode != 0:
        return False, result.stderr.strip() or "Não foi possível ocultar a janela da VPN secundária."
    return True, "Janela da VPN secundária minimizada e removida da barra de tarefas."


def show_window() -> tuple[bool, str]:
    wid = window_id()
    if not wid:
        return False, "Janela da VPN secundária não encontrada."
    try:
        subprocess.run(
            ["wmctrl", "-i", "-r", wid, "-b", "remove,skip_taskbar"],
            text=True,
            capture_output=True,
            timeout=4,
            check=False,
        )
        subprocess.run(
            ["wmctrl", "-i", "-r", wid, "-b", "remove,hidden"],
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
        return False, f"Falha ao exibir a janela da VPN secundária: {exc}"
    if result.returncode != 0:
        return False, result.stderr.strip() or "Janela da VPN secundária não encontrada."
    return True, "Janela da VPN secundária exibida."
