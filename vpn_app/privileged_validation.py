from __future__ import annotations

import argparse
import ipaddress
import os
import stat
from pathlib import Path


ALLOWED_FIXED_DIRECTIVES = {
    "set-routes": "0",
    "set-dns": "0",
}
REQUIRED_CONNECTION_KEYS = {
    "host",
    "port",
    "username",
    "password",
    "trusted-cert",
    *ALLOWED_FIXED_DIRECTIVES,
}


def validate_connection(values: dict[str, str]) -> dict[str, str]:
    try:
        port = int(values.get("port", ""))
    except ValueError as exc:
        raise ValueError("A porta deve ser um número entre 1 e 65535.") from exc
    if not 1 <= port <= 65535:
        raise ValueError("A porta deve ser um número entre 1 e 65535.")

    normalized: dict[str, str] = {"port": str(port)}
    required = ("host", "username", "password", "trusted-cert")
    for key in required:
        value = str(values.get(key, ""))
        if not value.strip():
            raise ValueError(f"Campo obrigatório vazio: {key}")
        if "\n" in value or "\r" in value:
            raise ValueError(f"O campo {key} contém uma quebra de linha inválida.")
        if "\0" in value:
            raise ValueError(f"O campo {key} contém um caractere de controle inválido.")
        normalized[key] = value if key == "password" else value.strip()
    return normalized


def valid_hosts_alias(hostname: str) -> bool:
    if not hostname or len(hostname) > 253:
        return False
    if any(char.isspace() or ord(char) < 32 for char in hostname):
        return False
    if "/" in hostname or "\\" in hostname or ":" in hostname:
        return False

    labels = hostname.rstrip(".").split(".")
    return all(
        label
        and len(label) <= 63
        and label[0].isalnum()
        and label[-1].isalnum()
        and all(
            (char.isascii() and char.isalnum()) or char in {"-", "_"}
            for char in label
        )
        for label in labels
    )


def _read_regular_file(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"Link simbólico ou arquivo inválido: {path}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"Arquivo não regular: {path}")
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = -1
            return stream.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def parse_connection_text(content: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for number, raw in enumerate(content.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or raw.lstrip().startswith("#"):
            continue
        if "=" not in raw:
            raise ValueError(f"Linha inválida em connection.conf ({number}).")
        key_text, value_text = raw.split("=", 1)
        key = key_text.strip()
        if key in values:
            raise ValueError(f"Diretiva duplicada em connection.conf: {key}")

        # O escritor usa exatamente um espaço de formatação depois de "=".
        # Remova somente esse separador para a senha, preservando quaisquer
        # espaços adicionais que façam parte da credencial.
        if key == "password":
            value = value_text[1:] if value_text.startswith(" ") else value_text
        else:
            value = value_text.strip()
        values[key] = value

    unknown = set(values) - REQUIRED_CONNECTION_KEYS
    if unknown:
        raise ValueError(
            "Diretivas não permitidas em connection.conf: "
            + ", ".join(sorted(unknown))
        )
    missing = REQUIRED_CONNECTION_KEYS - set(values)
    if missing:
        raise ValueError(
            "Diretivas ausentes em connection.conf: "
            + ", ".join(sorted(missing))
        )

    normalized = validate_connection(values)
    for key, expected in ALLOWED_FIXED_DIRECTIVES.items():
        if values.get(key) != expected:
            raise ValueError(f"A diretiva {key} deve permanecer igual a {expected}.")
    return normalized


def parse_connection(path: Path) -> dict[str, str]:
    return parse_connection_text(_read_regular_file(path))


def validate_routes_text(content: str) -> list[str]:
    routes: list[str] = []
    for number, raw in enumerate(content.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError as exc:
            raise ValueError(f"Rota inválida na linha {number}: {line}") from exc
        if network.version != 4:
            raise ValueError(f"Somente IPv4 é aceito: {line}")
        normalized = str(network)
        if normalized not in routes:
            routes.append(normalized)
    if not routes:
        raise ValueError("A lista de sub-redes não pode ficar vazia.")
    return routes


def validate_routes(path: Path) -> list[str]:
    return validate_routes_text(_read_regular_file(path))


def validate_hosts_text(content: str) -> list[str]:
    entries: list[str] = []
    seen: set[tuple[str, str]] = set()
    for number, raw in enumerate(content.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2:
            raise ValueError(f"Entrada inválida em hosts.conf na linha {number}.")
        ip_text, hostname = parts
        try:
            ipaddress.IPv4Address(ip_text)
        except ValueError as exc:
            raise ValueError(f"IPv4 inválido em hosts.conf: {ip_text}") from exc
        if not valid_hosts_alias(hostname):
            raise ValueError(f"Hostname inválido: {hostname}")
        key = (ip_text, hostname)
        if key not in seen:
            seen.add(key)
            entries.append(f"{ip_text} {hostname}")
    return entries


def validate_hosts(path: Path) -> list[str]:
    return validate_hosts_text(_read_regular_file(path))


def _connection_content(values: dict[str, str]) -> str:
    return (
        f"host = {values['host']}\n"
        f"port = {values['port']}\n"
        f"username = {values['username']}\n"
        f"password = {values['password']}\n"
        "set-routes = 0\n"
        "set-dns = 0\n"
        f"trusted-cert = {values['trusted-cert']}\n"
    )


def _private_write(path: Path, content: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def create_snapshots(connection: Path, routes: Path, hosts: Path, output: Path) -> None:
    connection_values = parse_connection(connection)
    route_values = validate_routes(routes)
    host_values = validate_hosts(hosts)

    output.mkdir(mode=0o700, parents=False, exist_ok=True)
    os.chmod(output, 0o700)
    _private_write(output / "connection.conf", _connection_content(connection_values))
    _private_write(output / "routes.conf", "\n".join(route_values) + "\n")
    _private_write(output / "hosts.conf", "\n".join(host_values) + "\n")

    # Valide novamente exatamente os snapshots que o helper consumirá.
    parse_connection(output / "connection.conf")
    validate_routes(output / "routes.conf")
    validate_hosts(output / "hosts.conf")


def validate_all(connection: Path, routes: Path, hosts: Path) -> None:
    parse_connection(connection)
    validate_routes(routes)
    validate_hosts(hosts)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--connection", type=Path, required=True)
    parser.add_argument("--routes", type=Path, required=True)
    parser.add_argument("--hosts", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if args.output is None:
            validate_all(args.connection, args.routes, args.hosts)
        else:
            create_snapshots(args.connection, args.routes, args.hosts, args.output)
    except (OSError, UnicodeError, ValueError) as exc:
        parser.exit(1, f"Configuração inválida: {exc}\n")


if __name__ == "__main__":
    main()
