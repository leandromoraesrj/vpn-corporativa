#!/bin/bash
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Execute: sudo ./uninstall.sh"; exit 1; }

TARGET_USER="${SUDO_USER:-}"
[[ -n "$TARGET_USER" && "$TARGET_USER" != "root" ]] || { echo "Usuário inválido."; exit 1; }
TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
APP_DIR="$TARGET_HOME/.local/share/vpn"
readonly DISCONNECT_HELPER="/usr/local/libexec/vpn-disconnect"
readonly RUN_DIR="/run/vpn"
readonly PROCESS_FILE="$RUN_DIR/openfortivpn.process"
readonly IFACE_FILE="$RUN_DIR/interface"
readonly ROOT_ROUTES="$RUN_DIR/config/routes.conf"
readonly HOSTS_FILE="/etc/hosts"
DESKTOP_DIR="$(sudo -u "$TARGET_USER" xdg-user-dir DESKTOP 2>/dev/null || true)"
[[ -n "$DESKTOP_DIR" ]] || DESKTOP_DIR="$TARGET_HOME/Desktop"

managed_process_is_active() {
    local pid="" key value
    [[ -f "$PROCESS_FILE" && ! -L "$PROCESS_FILE" ]] || return 1
    while IFS='=' read -r key value; do
        [[ "$key" == "pid" ]] && pid="$value"
    done < "$PROCESS_FILE"
    [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null
}

managed_interface_is_active() {
    local interface=""
    [[ -f "$IFACE_FILE" && ! -L "$IFACE_FILE" ]] || return 1
    IFS= read -r interface < "$IFACE_FILE" || return 1
    [[ "$interface" =~ ^ppp[0-9]+$ ]] || return 1
    ip link show up dev "$interface" >/dev/null 2>&1
}

managed_routes_are_present() {
    local interface="" route=""
    [[ -f "$IFACE_FILE" && ! -L "$IFACE_FILE" ]] || return 1
    [[ -f "$ROOT_ROUTES" && ! -L "$ROOT_ROUTES" ]] || return 1
    IFS= read -r interface < "$IFACE_FILE" || return 1
    [[ "$interface" =~ ^ppp[0-9]+$ ]] || return 1
    while IFS= read -r route; do
        [[ -n "$route" ]] || continue
        ip route show "$route" dev "$interface" | grep -q . && return 0
    done < "$ROOT_ROUTES"
    return 1
}

managed_hosts_are_present() {
    grep -Fxq '# INICIO MAPA VPN' "$HOSTS_FILE" 2>/dev/null ||
        grep -Fxq '# FIM MAPA VPN' "$HOSTS_FILE" 2>/dev/null
}

run_state_is_present() {
    [[ -e "$RUN_DIR" || -L "$RUN_DIR" ]] || return 1
    [[ ! -d "$RUN_DIR" ]] && return 0
    find "$RUN_DIR" -mindepth 1 -print -quit 2>/dev/null | grep -q .
}

verify_safe_without_disconnect_helper() {
    if managed_process_is_active; then
        echo "Helper de desconexão ausente e processo openfortivpn gerenciado ativo; desinstalação abortada." >&2
        return 1
    fi
    if managed_interface_is_active; then
        echo "Helper de desconexão ausente e interface PPP gerenciada ativa; desinstalação abortada." >&2
        return 1
    fi
    if managed_routes_are_present; then
        echo "Helper de desconexão ausente e rotas gerenciadas presentes; desinstalação abortada." >&2
        return 1
    fi
    if managed_hosts_are_present; then
        echo "Helper de desconexão ausente e alterações gerenciadas em /etc/hosts; desinstalação abortada." >&2
        return 1
    fi
    if run_state_is_present; then
        echo "Helper de desconexão ausente e estado presente em /run/vpn; desinstalação abortada." >&2
        return 1
    fi
}

sudo -u "$TARGET_USER" pkill -TERM -f "$APP_DIR/vpn.py" 2>/dev/null || true
if [[ -x "$DISCONNECT_HELPER" ]]; then
    "$DISCONNECT_HELPER" || {
        echo "Falha ao desconectar a VPN; desinstalação abortada sem remover arquivos ou estado de recuperação." >&2
        exit 1
    }
else
    verify_safe_without_disconnect_helper || exit 1
fi

read -r -p "Preservar configurações? [S/n]: " KEEP

rm -rf "$APP_DIR"
rm -f /usr/local/libexec/vpn-connect
rm -f /usr/local/libexec/vpn-disconnect
rm -f /usr/local/libexec/vpn-diagnose
rm -f /usr/local/libexec/vpn-process-identity
rm -f /usr/local/libexec/vpn-privileged-validation.py
rm -f /usr/local/share/icons/vpn.svg
rm -f /usr/local/share/icons/vpn-corporativa-{gray,yellow,green,red}.svg
rm -f /etc/sudoers.d/vpn
rm -f "$TARGET_HOME/.local/share/applications/vpn.desktop"
rm -f "$TARGET_HOME/.config/autostart/vpn.desktop"
rm -f "$DESKTOP_DIR/VPN Corporativa.desktop"
TARGET_UID="$(id -u "$TARGET_USER")"
rm -f "/tmp/vpn_${TARGET_UID}.log" \
    "/tmp/vpn_diagnostic_${TARGET_UID}.txt" \
    /tmp/vpn_start.log
rm -rf "$RUN_DIR"

if [[ "$KEEP" =~ ^[Nn]$ ]]; then
    rm -rf "$TARGET_HOME/.config/vpn"
    rm -rf "$TARGET_HOME/.local/state/vpn"
fi

echo "VPN removida."
