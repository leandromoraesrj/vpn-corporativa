from __future__ import annotations

import re
import socket
import subprocess
import time
from pathlib import Path

VPN_INTERFACE_FILE = Path("/run/vpn/interface")


def run_text(command: list[str], timeout: float = 4.0) -> str:
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def vpn_interface(interface_file: Path = VPN_INTERFACE_FILE) -> str:
    """Retorna somente a interface registrada pela conexão gerenciada."""
    try:
        interface = interface_file.read_text(encoding="utf-8").strip()
    except OSError:
        return ""

    if not re.fullmatch(r"ppp[0-9]+", interface):
        return ""

    output = run_text(["ip", "-br", "link", "show", "up", "dev", interface])
    return interface if output.split(maxsplit=1)[:1] == [interface] else ""


def other_tunnel() -> str:
    return run_text([
        "bash", "-lc",
        "ip -br link show up | awk '$1 ~ /^(tun|tap|wg)/ {print $1; exit}'",
    ])


def interface_ipv4(interface: str) -> str:
    if not interface:
        return "-"
    output = run_text(["ip", "-4", "-br", "addr", "show", "dev", interface])
    parts = output.split()
    return parts[2].split("/")[0] if len(parts) >= 3 else "-"


def route_interface(target: str) -> str:
    output = run_text(["ip", "route", "get", target])
    fields = output.split()
    try:
        return fields[fields.index("dev") + 1]
    except (ValueError, IndexError):
        return "-"


def ping_ms(target: str) -> str:
    output = run_text(["ping", "-c", "1", "-W", "1", target], timeout=2.0)
    match = re.search(r"time[=<]([0-9.]+)\s*ms", output)
    return f"{float(match.group(1)):.0f} ms" if match else "-"


def interface_stats(interface: str) -> tuple[int, int]:
    if not interface:
        return 0, 0
    base = Path("/sys/class/net") / interface / "statistics"
    try:
        return (
            int((base / "rx_bytes").read_text().strip()),
            int((base / "tx_bytes").read_text().strip()),
        )
    except (OSError, ValueError):
        return 0, 0


def docker_summary() -> str:
    networks = run_text([
        "bash", "-lc",
        "ip -o link show | awk -F': ' '$2==\"docker0\" || $2 ~ /^br-/ {c++} END{print c+0}'",
    ])
    containers = run_text(["bash", "-lc", "docker ps -q 2>/dev/null | wc -l"])
    return f"{networks or '0'} redes / {containers or '0'} containers"


def firewall_summary() -> str:
    output = run_text(["sudo", "-n", "ufw", "status", "verbose"])
    if not output:
        return "Sem acesso ao UFW"
    active = bool(re.search(r"^(Status:\s*active|Estado:\s*ativo)", output, re.M | re.I))
    outgoing = bool(re.search(r"allow\s*\((outgoing|saída)\)", output, re.I))
    if active and outgoing:
        return "Ativo — saída permitida"
    if active:
        return "Ativo — revisar saída"
    return "Inativo"


def format_bytes(value: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    amount = float(max(value, 0))
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} TB"


class MetricsSampler:
    def __init__(self) -> None:
        self.last_rx = 0
        self.last_tx = 0
        self.last_time: float | None = None

    def sample(self, interface: str) -> tuple[int, int, float, float]:
        rx, tx = interface_stats(interface)
        now = time.monotonic()
        rx_speed = tx_speed = 0.0
        if self.last_time is not None and now > self.last_time:
            interval = now - self.last_time
            rx_speed = max(0, rx - self.last_rx) / interval
            tx_speed = max(0, tx - self.last_tx) / interval
        self.last_rx, self.last_tx, self.last_time = rx, tx, now
        return rx, tx, rx_speed, tx_speed


_PUBLIC_IP_CACHE = "-"
_PUBLIC_IP_CACHE_TIME = 0.0


def public_ip(cache_seconds: int = 60) -> str:
    global _PUBLIC_IP_CACHE, _PUBLIC_IP_CACHE_TIME

    now = time.monotonic()
    if (
        _PUBLIC_IP_CACHE != "-"
        and now - _PUBLIC_IP_CACHE_TIME < cache_seconds
    ):
        return _PUBLIC_IP_CACHE

    value = run_text(
        ["curl", "-4", "-fsS", "--max-time", "3", "https://api.ipify.org"],
        timeout=4.0,
    )

    try:
        socket.inet_aton(value)
    except OSError:
        pass
    else:
        if value.count(".") == 3:
            _PUBLIC_IP_CACHE = value
            _PUBLIC_IP_CACHE_TIME = now

    return _PUBLIC_IP_CACHE


def internet_available() -> bool:
    """Confirma acesso externo sem depender de DNS."""
    try:
        with socket.create_connection(("1.1.1.1", 443), timeout=3):
            return True
    except OSError:
        return False
