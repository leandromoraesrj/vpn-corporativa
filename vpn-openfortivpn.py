#!/usr/bin/env python3
"""Monta a configuração do openfortivpn em memfd e faz exec como root."""

from __future__ import annotations

import argparse
import fcntl
import os
import shutil
import struct
import sys
import re
from pathlib import Path


MAX_PASSWORD_BYTES = 4096
F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
F_SEAL_SEAL = getattr(fcntl, "F_SEAL_SEAL", 1)
F_SEAL_SHRINK = getattr(fcntl, "F_SEAL_SHRINK", 2)
F_SEAL_GROW = getattr(fcntl, "F_SEAL_GROW", 4)
F_SEAL_WRITE = getattr(fcntl, "F_SEAL_WRITE", 8)
MFD_ALLOW_SEALING = getattr(os, "MFD_ALLOW_SEALING", 2)
# Duplicado deliberadamente: este launcher privilegiado deve permanecer autocontido.
# O teste de paridade das regras de certificado deve acompanhar qualquer alteração.
CERTIFICATE_POLICIES = {
    "legacy-pinned",
    "system-ca",
    "system-ca-with-pinned-fallback",
}
FINGERPRINT_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def read_secret() -> str:
    header = sys.stdin.buffer.read(4)
    if len(header) != 4:
        raise ValueError("credencial ausente")
    size = struct.unpack("!I", header)[0]
    if size == 0 or size > MAX_PASSWORD_BYTES:
        raise ValueError("credencial inválida")
    payload = sys.stdin.buffer.read(size)
    if len(payload) != size or sys.stdin.buffer.read(1):
        raise ValueError("canal de credencial inválido")
    try:
        password = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("credencial inválida") from exc
    if not password.strip() or any(char in password for char in ("\n", "\r", "\0")):
        raise ValueError("credencial inválida")
    return password


def config_with_password(path: Path, password: str) -> bytes:
    lines = path.read_text(encoding="utf-8").splitlines()
    if any(line.split("=", 1)[0].strip() == "password" for line in lines if "=" in line):
        raise ValueError("configuração insegura")
    values: dict[str, str] = {}
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if "=" not in line:
            raise ValueError("configuração incompleta")
        key, value = line.split("=", 1)
        key = key.strip()
        if key in values:
            raise ValueError("configuração duplicada")
        if key in {"trusted-cert", "certificate-policy"}:
            values[key] = value[1:] if value.startswith(" ") else value
        else:
            values[key] = value.strip()

    policy = values.get("certificate-policy", "legacy-pinned").lower()
    if policy not in CERTIFICATE_POLICIES:
        raise ValueError("política de certificado inválida")
    required = {"host", "port", "username", "set-routes", "set-dns"}
    if policy != "system-ca":
        required.add("trusted-cert")
    if not required.issubset(values) or set(values) - required - {"certificate-policy"}:
        raise ValueError("configuração incompleta")
    if "trusted-cert" in values and not FINGERPRINT_RE.fullmatch(values["trusted-cert"]):
        raise ValueError("trusted-cert inválido")
    output_keys = ["host", "port", "username", "set-routes", "set-dns"]
    if "trusted-cert" in values:
        output_keys.append("trusted-cert")
    output = [f"{key} = {values[key]}" for key in output_keys]
    return ("\n".join(output) + f"\npassword = {password}\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    try:
        password = read_secret()
        content = config_with_password(args.config, password)
        fd = os.memfd_create("vpn-openfortivpn-config", MFD_ALLOW_SEALING)
        try:
            view = memoryview(content)
            while view:
                view = view[os.write(fd, view):]
            os.lseek(fd, 0, os.SEEK_SET)
            fcntl.fcntl(
                fd,
                F_ADD_SEALS,
                F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL,
            )
            os.set_inheritable(fd, True)
            executable = shutil.which("openfortivpn", path="/usr/sbin:/usr/bin:/sbin:/bin")
            if not executable:
                raise FileNotFoundError("openfortivpn não encontrado")
            executable = os.path.realpath(executable)
            os.execv(executable, [executable, "-c", f"/proc/self/fd/{fd}"])
        finally:
            os.close(fd)
    except (OSError, ValueError) as exc:
        print(f"Falha ao preparar a conexão: {exc}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
