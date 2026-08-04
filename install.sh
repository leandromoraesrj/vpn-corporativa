#!/bin/bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Execute como usuário comum: sudo ./install.sh"
    exit 1
fi

TARGET_USER="${SUDO_USER:-}"
[[ -n "$TARGET_USER" && "$TARGET_USER" != "root" ]] || {
    echo "Não foi possível identificar o usuário da sessão."
    exit 1
}

TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
[[ -n "$TARGET_HOME" && -d "$TARGET_HOME" ]] || {
    echo "Diretório pessoal inválido para $TARGET_USER."
    exit 1
}
TARGET_GROUP="$(id -gn "$TARGET_USER")"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$TARGET_HOME/.local/share/vpn"
CONFIG_DIR="$TARGET_HOME/.config/vpn"
APPLICATIONS_DIR="$TARGET_HOME/.local/share/applications"
AUTOSTART_DIR="$TARGET_HOME/.config/autostart"
STATE_DIR="$TARGET_HOME/.local/state/vpn"
DESKTOP_DIR="$(sudo -u "$TARGET_USER" xdg-user-dir DESKTOP 2>/dev/null || true)"
[[ -n "$DESKTOP_DIR" ]] || DESKTOP_DIR="$TARGET_HOME/Desktop"

clear
echo "============================================================"
echo "VPN CORPORATIVA 1.0 — PRODUÇÃO"
echo "============================================================"
echo
echo "Este instalador:"
echo "- verifica dependências;"
echo "- instala somente pacotes ausentes após confirmação;"
echo "- preserva configuração existente;"
echo "- instala a aplicação modular, helpers, sudoers e auditoria;"
echo "- inicia apenas o ícone da bandeja, sem conectar a VPN."
echo
read -r -p "Continuar? [S/n]: " ANSWER
[[ "$ANSWER" =~ ^[Nn]$ ]] && exit 0

declare -A CHECKS=(
    [openfortivpn]=openfortivpn
    [python3]=python3
    [python3-gi]=python3
    [gir1.2-gtk-3.0]=python3
    [gir1.2-ayatanaappindicator3-0.1]=python3
    [libnotify-bin]=notify-send
    [xdg-utils]=xdg-open
    [curl]=curl
    [wmctrl]=wmctrl
    [xdotool]=xdotool
)

MISSING=()
for package in "${!CHECKS[@]}"; do
    command -v "${CHECKS[$package]}" >/dev/null 2>&1 || MISSING+=("$package")
done

python3 - <<'PY' >/dev/null 2>&1 || MISSING+=("python3-gi" "gir1.2-gtk-3.0")
import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk
PY
python3 - <<'PY' >/dev/null 2>&1 || MISSING+=("gir1.2-ayatanaappindicator3-0.1")
import gi
gi.require_version("AyatanaAppIndicator3", "0.1")
from gi.repository import AyatanaAppIndicator3
PY

mapfile -t MISSING < <(printf '%s\n' "${MISSING[@]}" | awk 'NF && !seen[$0]++')

if ((${#MISSING[@]})); then
    echo
    echo "Pacotes ausentes:"
    printf '  - %s\n' "${MISSING[@]}"
    read -r -p "Instalar agora? [S/n]: " INSTALL_DEPS
    [[ "$INSTALL_DEPS" =~ ^[Nn]$ ]] && exit 1
    apt-get update
    apt-get install -y "${MISSING[@]}"
fi

echo "Encerrando versão anterior, se existir..."
sudo -u "$TARGET_USER" pkill -TERM -f "$APP_DIR/vpn.py" 2>/dev/null || true
sudo -u "$TARGET_USER" pkill -TERM -f "$APP_DIR/vpn_indicator.py" 2>/dev/null || true
sleep 1

# Remove apenas resíduos temporários das versões anteriores.
TARGET_UID="$(id -u "$TARGET_USER")"
rm -f "/tmp/vpn_${TARGET_UID}.log" \
    "/tmp/vpn_diagnostic_${TARGET_UID}.txt" \
    /tmp/vpn_start.log

echo "Garantindo que a VPN principal permaneça desconectada após a atualização..."
if [[ -x /usr/local/libexec/vpn-disconnect ]]; then
    /usr/local/libexec/vpn-disconnect 2>/dev/null || true
fi

install -d -m 755 /usr/local/libexec /usr/local/share/icons
install -d -o "$TARGET_USER" -g "$TARGET_GROUP" -m 755 "$APP_DIR"
install -d -o "$TARGET_USER" -g "$TARGET_GROUP" -m 700 "$CONFIG_DIR"
install -d -o "$TARGET_USER" -g "$TARGET_GROUP" -m 755 "$APPLICATIONS_DIR"
install -d -o "$TARGET_USER" -g "$TARGET_GROUP" -m 700 "$STATE_DIR"

rm -rf "$APP_DIR/vpn_app"
cp -a "$SCRIPT_DIR/vpn_app" "$APP_DIR/"
install -o "$TARGET_USER" -g "$TARGET_GROUP" -m 755 "$SCRIPT_DIR/vpn.py" "$APP_DIR/vpn.py"
install -o "$TARGET_USER" -g "$TARGET_GROUP" -m 755 "$SCRIPT_DIR/auditar_vpn.sh" "$APP_DIR/auditar_vpn.sh"
chown -R "$TARGET_USER:$TARGET_GROUP" "$APP_DIR"

install -m 755 "$SCRIPT_DIR/vpn-connect" /usr/local/libexec/vpn-connect
install -m 755 "$SCRIPT_DIR/vpn-disconnect" /usr/local/libexec/vpn-disconnect
install -m 755 "$SCRIPT_DIR/vpn-diagnose" /usr/local/libexec/vpn-diagnose
install -m 755 "$SCRIPT_DIR/vpn-process-identity" /usr/local/libexec/vpn-process-identity
install -m 755 "$SCRIPT_DIR/vpn_app/privileged_validation.py" \
    /usr/local/libexec/vpn-privileged-validation.py
install -m 644 "$SCRIPT_DIR/vpn.svg" /usr/local/share/icons/vpn.svg
for state in gray yellow green red; do
    install -m 644 \
        "$SCRIPT_DIR/vpn-corporativa-${state}.svg" \
        "/usr/local/share/icons/vpn-corporativa-${state}.svg"
done

if [[ ! -f "$CONFIG_DIR/connection.conf" ]]; then
    echo
    echo "Configuração inicial:"
    read -r -p "Host VPN: " HOST
    read -r -p "Porta [443]: " PORT
    PORT="${PORT:-443}"
    read -r -p "Usuário VPN: " VPN_USER
    read -r -s -p "Senha VPN: " VPN_PASSWORD
    echo
    read -r -p "Fingerprint confiável: " CERT

    if ! VALIDATED=$(
        printf '%s\0%s\0%s\0%s\0%s\0' \
            "$HOST" "$PORT" "$VPN_USER" "$VPN_PASSWORD" "$CERT" |
        sudo -u "$TARGET_USER" env HOME="$TARGET_HOME" \
            PYTHONPATH="$APP_DIR" python3 -c '
import sys
from vpn_app.config_store import validate_connection

fields = sys.stdin.buffer.read().split(b"\\0")
if fields and fields[-1] == b"":
    fields.pop()
if len(fields) != 5:
    raise SystemExit("Quantidade inválida de campos.")

host, port, username, password, trusted_cert = (
    field.decode("utf-8") for field in fields
)
values = validate_connection({
    "host": host,
    "port": port,
    "username": username,
    "password": password,
    "trusted-cert": trusted_cert,
})
for key in ("host", "port", "username", "password", "trusted-cert"):
    print(values[key])
'
    ); then
        echo "Configuração inicial inválida." >&2
        exit 1
    fi
    mapfile -t VALIDATED_FIELDS <<< "$VALIDATED"
    HOST="${VALIDATED_FIELDS[0]}"
    PORT="${VALIDATED_FIELDS[1]}"
    VPN_USER="${VALIDATED_FIELDS[2]}"
    VPN_PASSWORD="${VALIDATED_FIELDS[3]}"
    CERT="${VALIDATED_FIELDS[4]}"

    umask 077
    cat > "$CONFIG_DIR/connection.conf" <<EOF
host = $HOST
port = $PORT
username = $VPN_USER
password = $VPN_PASSWORD
set-routes = 0
set-dns = 0
trusted-cert = $CERT
EOF

fi

if [[ ! -f "$CONFIG_DIR/routes.conf" ]]; then
    install -o "$TARGET_USER" -g "$TARGET_GROUP" -m 600 \
        "$SCRIPT_DIR/examples/routes.conf.example" "$CONFIG_DIR/routes.conf"
fi

if [[ ! -f "$CONFIG_DIR/hosts.conf" ]]; then
    install -o "$TARGET_USER" -g "$TARGET_GROUP" -m 600 \
        "$SCRIPT_DIR/examples/hosts.conf.example" "$CONFIG_DIR/hosts.conf"
fi

if [[ ! -f "$CONFIG_DIR/secondary.conf" ]]; then
    install -o "$TARGET_USER" -g "$TARGET_GROUP" -m 600 \
        "$SCRIPT_DIR/examples/secondary.conf.example" "$CONFIG_DIR/secondary.conf"
fi

chown -R "$TARGET_USER:$TARGET_GROUP" "$CONFIG_DIR"
chmod 600 "$CONFIG_DIR"/*.conf

cat > /etc/sudoers.d/vpn <<EOF
$TARGET_USER ALL=(root) NOPASSWD: /usr/local/libexec/vpn-connect
$TARGET_USER ALL=(root) NOPASSWD: /usr/local/libexec/vpn-disconnect
$TARGET_USER ALL=(root) NOPASSWD: /usr/local/libexec/vpn-diagnose
$TARGET_USER ALL=(root) NOPASSWD: /usr/sbin/ufw status verbose
EOF
chown root:root /etc/sudoers.d/vpn
chmod 440 /etc/sudoers.d/vpn
visudo -cf /etc/sudoers.d/vpn

cat > "$APPLICATIONS_DIR/vpn.desktop" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=VPN Corporativa
Comment=Centro de controle da VPN corporativa e da rede
Exec=$APP_DIR/vpn.py
Icon=/usr/local/share/icons/vpn.svg
Terminal=false
StartupNotify=false
Categories=Network;
EOF
chmod 755 "$APPLICATIONS_DIR/vpn.desktop"
chown "$TARGET_USER:$TARGET_GROUP" "$APPLICATIONS_DIR/vpn.desktop"

install -d -o "$TARGET_USER" -g "$TARGET_GROUP" -m 755 "$AUTOSTART_DIR"
cat > "$AUTOSTART_DIR/vpn.desktop" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=VPN Corporativa
Comment=Indicador da VPN Corporativa
Exec=$APP_DIR/vpn.py
Icon=/usr/local/share/icons/vpn.svg
Terminal=false
StartupNotify=false
X-GNOME-Autostart-enabled=true
EOF
chmod 644 "$AUTOSTART_DIR/vpn.desktop"
chown "$TARGET_USER:$TARGET_GROUP" "$AUTOSTART_DIR/vpn.desktop"

read -r -p "Criar atalho na Área de Trabalho? [S/n]: " CREATE_DESKTOP
if [[ ! "$CREATE_DESKTOP" =~ ^[Nn]$ ]]; then
    install -d -o "$TARGET_USER" -g "$TARGET_GROUP" -m 755 "$DESKTOP_DIR"
    cp "$APPLICATIONS_DIR/vpn.desktop" "$DESKTOP_DIR/VPN Corporativa.desktop"
    chmod 755 "$DESKTOP_DIR/VPN Corporativa.desktop"
    chown "$TARGET_USER:$TARGET_GROUP" "$DESKTOP_DIR/VPN Corporativa.desktop"
fi

python3 -m py_compile "$APP_DIR/vpn.py" "$APP_DIR"/vpn_app/*.py

echo
echo "VPN Corporativa 1.0 instalada com sucesso."
echo "A auditoria específica está em:"
echo "  $APP_DIR/auditar_vpn.sh"
echo
read -r -p "Iniciar o ícone agora? [S/n]: " START
if [[ ! "$START" =~ ^[Nn]$ ]]; then
    sudo -u "$TARGET_USER" env HOME="$TARGET_HOME" DISPLAY="${DISPLAY:-:0}" \
        XAUTHORITY="$TARGET_HOME/.Xauthority" \
        nohup "$APP_DIR/vpn.py" >"$STATE_DIR/launcher.log" 2>&1 &
fi
