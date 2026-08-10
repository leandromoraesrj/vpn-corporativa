"""Senha da VPN no Secret Service da sessão gráfica do usuário."""

from __future__ import annotations

import gi

gi.require_version("Secret", "1")
from gi.repository import Secret


SCHEMA = Secret.Schema.new(
    "br.local.vpncorporativa",
    Secret.SchemaFlags.NONE,
    {"service": Secret.SchemaAttributeType.STRING, "username": Secret.SchemaAttributeType.STRING},
)
SERVICE = "vpn-corporativa"


def _attributes(username: str) -> dict[str, str]:
    if not username or "\n" in username or "\0" in username:
        raise ValueError("Usuário inválido para a credencial.")
    return {"service": SERVICE, "username": username}


def lookup_diagnostic(username: str) -> tuple[str | None, str, dict[str, str]]:
    """Look up the item and return only a safe status plus non-secret attributes."""
    attributes = _attributes(username)
    try:
        value = Secret.password_lookup_sync(SCHEMA, attributes, None)
    except Exception:
        return None, "indisponivel", {"attributes": ", ".join(
            f"{key}={value}" for key, value in attributes.items()
        )}
    if value is None:
        return None, "ausente", {"attributes": ", ".join(
            f"{key}={value}" for key, value in attributes.items()
        )}
    return value, "encontrada", {"attributes": ", ".join(
        f"{key}={value}" for key, value in attributes.items()
    )}


def lookup(username: str) -> str | None:
    value, status, _details = lookup_diagnostic(username)
    if status == "indisponivel":
        raise RuntimeError("Não foi possível acessar o GNOME Keyring.")
    return value


def store(username: str, password: str) -> None:
    if not password or "\n" in password or "\r" in password or "\0" in password:
        raise ValueError("A senha da VPN é inválida.")
    try:
        ok = Secret.password_store_sync(
            SCHEMA,
            _attributes(username),
            Secret.COLLECTION_DEFAULT,
            "VPN Corporativa",
            password,
            None,
        )
    except Exception:
        raise RuntimeError("Não foi possível acessar o GNOME Keyring.") from None
    if not ok:
        raise RuntimeError("O Secret Service não aceitou a credencial.")


def clear(username: str) -> bool:
    try:
        return bool(Secret.password_clear_sync(SCHEMA, _attributes(username), None))
    except Exception:
        return False
