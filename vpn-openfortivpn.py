#!/usr/bin/env python3
"""Monta a configuração do openfortivpn em memfd e faz exec como root."""

from __future__ import annotations

import argparse
import fcntl
import os
import shutil
import struct
import sys
from pathlib import Path


MAX_PASSWORD_BYTES = 4096
F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
F_SEAL_SEAL = getattr(fcntl, "F_SEAL_SEAL", 1)
F_SEAL_SHRINK = getattr(fcntl, "F_SEAL_SHRINK", 2)
F_SEAL_GROW = getattr(fcntl, "F_SEAL_GROW", 4)
F_SEAL_WRITE = getattr(fcntl, "F_SEAL_WRITE", 8)
MFD_ALLOW_SEALING = getattr(os, "MFD_ALLOW_SEALING", 2)


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
    required = {"host", "port", "username", "set-routes", "set-dns", "trusted-cert"}
    present = {line.split("=", 1)[0].strip() for line in lines if "=" in line}
    if present != required:
        raise ValueError("configuração incompleta")
    return ("\n".join(lines) + f"\npassword = {password}\n").encode("utf-8")


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
