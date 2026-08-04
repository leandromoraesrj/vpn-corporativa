#!/bin/bash
set -uo pipefail
export LC_ALL=C

CURRENT_USER="$(id -un 2>/dev/null || true)"
USER_NAME="${SUDO_USER:-${USER:-$CURRENT_USER}}"
[[ -n "$USER_NAME" ]] || { echo "Não foi possível identificar o usuário." >&2; exit 1; }
HOME_DIR="$(getent passwd "$USER_NAME" | cut -d: -f6)"
[[ -n "$HOME_DIR" ]] || { echo "Home não encontrada para $USER_NAME." >&2; exit 1; }

section() {
    printf '\n============================================================\n%s\n============================================================\n' "$1"
}

audit_root_helper() {
    local file="$1" metadata
    if [[ ! -e "$file" ]]; then
        echo "AUSENTE: $file"
        return 1
    fi
    metadata="$(stat -c '%U:%G %a' "$file" 2>/dev/null)" || {
        echo "INCORRETO: não foi possível inspecionar $file"
        return 1
    }
    if [[ "$metadata" != "root:root 755" ]]; then
        echo "INCORRETO: $file ($metadata; esperado root:root 755)"
        return 1
    fi
    stat -c '%A %U:%G %s bytes %n' "$file"
}

section "VPN — AUDITORIA DA INSTALAÇÃO"
printf 'Data: %s\nUsuário: %s\nHome: %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')" "$USER_NAME" "$HOME_DIR"

section "ARQUIVOS INSTALADOS"
for file in \
    "$HOME_DIR/.local/share/vpn/vpn.py" \
    "$HOME_DIR/.local/share/vpn/vpn_app/app.py" \
    "$HOME_DIR/.config/vpn/connection.conf" \
    "$HOME_DIR/.config/vpn/routes.conf" \
    "$HOME_DIR/.config/vpn/hosts.conf" \
    "/usr/local/libexec/vpn-connect" \
    "/usr/local/libexec/vpn-disconnect" \
    "/usr/local/libexec/vpn-diagnose" \
    "/etc/sudoers.d/vpn" \
    "$HOME_DIR/.config/autostart/vpn.desktop" \
    "$HOME_DIR/.local/share/applications/vpn.desktop"
do
    if [[ -e "$file" ]]; then
        stat -c '%A %U:%G %s bytes %n' "$file"
    else
        echo "AUSENTE: $file"
    fi
done

for file in \
    "/usr/local/libexec/vpn-process-identity" \
    "/usr/local/libexec/vpn-privileged-validation.py"
do
    audit_root_helper "$file" || true
done

section "PERMISSÕES"
stat -c '%A %U:%G %n' \
    "$HOME_DIR/.config/vpn" \
    "$HOME_DIR/.config/vpn/"*.conf 2>/dev/null || true

if [[ $EUID -eq 0 ]]; then
    visudo -cf /etc/sudoers.d/vpn 2>&1
else
    stat -c 'Sudoers: %A %U:%G %n' /etc/sudoers.d/vpn 2>/dev/null || true
    if sudo -n true >/dev/null 2>&1; then
        sudo -n visudo -cf /etc/sudoers.d/vpn 2>&1 || \
            echo "visudo não autorizado sem senha; modo e proprietário foram verificados."
    else
        echo "Auditoria comum: visudo exige privilégio; modo e proprietário foram verificados."
    fi
fi

section "PROCESSOS E INTERFACES"
pgrep -a -f "$HOME_DIR/.local/share/vpn/vpn.py" || true
ip -br address show
ip route show

section "HELPERS"
sudo -n /usr/local/libexec/vpn-diagnose >/dev/null 2>&1
printf 'Diagnóstico executável: código %s\n' "$?"

section "AUTOSTART"
cat "$HOME_DIR/.config/autostart/vpn.desktop" 2>/dev/null || echo "Autostart ausente"

section "RESÍDUOS ANTIGOS"
find "$HOME_DIR/Downloads" -maxdepth 2 \
    \( -name 'vpn-installer-v*.zip' -o -name 'vpn-installer-v*' -o -name 'vpn-corporativa-*' \) \
    -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort
find /tmp -maxdepth 1 -user "$USER_NAME" -name 'vpn_*' -ls 2>/dev/null || true
