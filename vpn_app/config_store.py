from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from .privileged_validation import valid_hosts_alias, validate_connection

CONFIG_DIR = Path.home() / ".config" / "vpn"
CONNECTION_FILE = CONFIG_DIR / "connection.conf"
ROUTES_FILE = CONFIG_DIR / "routes.conf"
HOSTS_FILE = CONFIG_DIR / "hosts.conf"
SECONDARY_FILE = CONFIG_DIR / "secondary.conf"
PREFERENCES_FILE = CONFIG_DIR / "preferences.conf"
DEFAULT_SECONDARY_INTERFACE = "tun0"


def ensure_config_dir() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(CONFIG_DIR, 0o700)


def read_key_values() -> dict[str, str]:
    values: dict[str, str] = {}
    if not CONNECTION_FILE.exists():
        return values
    for raw in CONNECTION_FILE.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if not stripped or raw.lstrip().startswith("#") or "=" not in raw:
            continue
        key_text, value_text = raw.split("=", 1)
        key = key_text.strip()
        if key == "password":
            values[key] = value_text[1:] if value_text.startswith(" ") else value_text
        elif key in {"trusted-cert", "certificate-policy"}:
            values[key] = value_text[1:] if value_text.startswith(" ") else value_text
        else:
            values[key] = value_text.strip()
    return values


def read_auto_reconnect_primary() -> bool:
    """Return the safe, backward-compatible default when absent or invalid."""
    if not PREFERENCES_FILE.exists():
        return True
    for raw in PREFERENCES_FILE.read_text(encoding="utf-8").splitlines():
        if "=" not in raw or raw.lstrip().startswith("#"):
            continue
        key, value = raw.split("=", 1)
        if key.strip() == "auto-reconnect-primary":
            normalized = value.strip().lower()
            if normalized in {"1", "true", "yes", "on"}:
                return True
            if normalized in {"0", "false", "no", "off"}:
                return False
            return True
    return True


def save_auto_reconnect_primary(enabled: bool) -> None:
    atomic_write(
        PREFERENCES_FILE,
        f"auto-reconnect-primary = {'true' if enabled else 'false'}\n",
    )


def atomic_write(path: Path, content: str, mode: int = 0o600) -> None:
    ensure_config_dir()
    temp = path.with_suffix(path.suffix + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temp, flags, mode)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temp.replace(path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_secondary_lines() -> list[str]:
    if not SECONDARY_FILE.exists():
        return []
    return SECONDARY_FILE.read_text(encoding="utf-8").splitlines()


def read_secondary_url() -> str:
    for raw in _read_secondary_lines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() == "portal-url":
            return value.strip()
    return ""


def validate_secondary_interface(value: str) -> str:
    """Validate a Linux interface name without accepting path-like input."""
    normalized = value.strip()
    if not normalized:
        return ""
    if any(ord(char) < 32 or ord(char) == 127 for char in normalized):
        raise ValueError("O nome da interface contém um caractere inválido.")
    if len(normalized) > 15 or not re.fullmatch(r"[A-Za-z0-9_.-]+", normalized):
        raise ValueError("Informe um nome de interface Linux válido.")
    return normalized


def read_secondary_interface() -> str:
    """Return the configured interface, preserving an explicit empty value."""
    for raw in _read_secondary_lines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() == "interface":
            return validate_secondary_interface(value)
    return DEFAULT_SECONDARY_INTERFACE


def save_secondary_interface(value: str) -> None:
    normalized = validate_secondary_interface(value)
    lines = _read_secondary_lines()
    updated: list[str] = []
    replaced = False
    for raw in lines:
        if "=" in raw and not raw.lstrip().startswith("#"):
            key, _existing = raw.split("=", 1)
            if key.strip() == "interface":
                if not replaced:
                    updated.append(f"interface = {normalized}")
                    replaced = True
                continue
        updated.append(raw)
    if not replaced:
        updated.append(f"interface = {normalized}")
    atomic_write(SECONDARY_FILE, "\n".join(updated) + "\n")


def validate_secondary_url(value: str) -> str:
    if not value or not value.strip():
        raise ValueError("Informe a URL de autenticação da VPN secundária.")
    if any(char in value for char in ("\n", "\r", "\0")) or any(
        ord(char) < 32 or ord(char) == 127 for char in value
    ):
        raise ValueError("A URL contém um caractere de controle inválido.")
    normalized = value.strip()
    parsed = urlsplit(normalized)
    if parsed.scheme.lower() != "https" or not parsed.netloc:
        raise ValueError("A URL de autenticação deve ser uma URL HTTPS válida.")
    if parsed.username or parsed.password:
        raise ValueError("A URL de autenticação não deve conter credenciais.")
    return normalized


def save_secondary_url(value: str) -> None:
    normalized = validate_secondary_url(value)
    lines = _read_secondary_lines()
    updated: list[str] = []
    replaced = False
    for raw in lines:
        if "=" in raw and not raw.lstrip().startswith("#"):
            key, _existing = raw.split("=", 1)
            if key.strip() == "portal-url":
                if not replaced:
                    updated.append(f"portal-url = {normalized}")
                    replaced = True
                continue
        updated.append(raw)
    if not replaced:
        updated.append(f"portal-url = {normalized}")
    atomic_write(SECONDARY_FILE, "\n".join(updated) + "\n")



def save_connection(values: dict[str, str]) -> None:
    normalized = validate_connection(values)
    content = (
        f"host = {normalized['host']}\n"
        f"port = {normalized['port']}\n"
        f"username = {normalized['username']}\n"
        "set-routes = 0\n"
        "set-dns = 0\n"
    )
    if str(values.get("certificate-policy", "")).strip():
        content += f"certificate-policy = {normalized['certificate-policy']}\n"
    if normalized["trusted-cert"]:
        content += f"trusted-cert = {normalized['trusted-cert']}\n"
    atomic_write(CONNECTION_FILE, content)


def read_routes() -> list[str]:
    if not ROUTES_FILE.exists():
        return []
    return [
        line.strip()
        for line in ROUTES_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def save_routes(text: str) -> None:
    routes: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        network = ipaddress.ip_network(line, strict=False)
        if network.version != 4:
            raise ValueError(f"Somente IPv4 é aceito: {line}")
        normalized = str(network)
        if normalized not in routes:
            routes.append(normalized)
    if not routes:
        raise ValueError("A lista de sub-redes não pode ficar vazia.")
    atomic_write(ROUTES_FILE, "\n".join(routes) + "\n")


def read_hosts() -> list[str]:
    if not HOSTS_FILE.exists():
        return []
    return [
        line.strip()
        for line in HOSTS_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def save_hosts(text: str) -> None:
    normalized: list[str] = []
    seen: set[tuple[str, str]] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2:
            raise ValueError(f"Use o formato: IP hostname — linha: {line}")
        ip_text, hostname = parts
        ipaddress.IPv4Address(ip_text)
        if not valid_hosts_alias(hostname):
            raise ValueError(f"Hostname inválido: {hostname}")
        key = (ip_text, hostname)
        if key not in seen:
            seen.add(key)
            normalized.append(f"{ip_text} {hostname}")
    atomic_write(HOSTS_FILE, "\n".join(normalized) + "\n")
