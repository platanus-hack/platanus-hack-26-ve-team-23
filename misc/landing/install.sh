#!/bin/sh
# HAWK host daemon installer.
#
#   curl -fsSL https://<landing>/install.sh | sh
#   curl -fsSL https://<landing>/install.sh | sh -s -- --core 192.168.1.20:7443
#   curl -fsSL https://<landing>/install.sh | sh -s -- --uninstall
#
# Installs the host daemon from the HAWK release on this machine, runs it as
# its own system user under systemd (the daemon must never run as the same
# user as the agents), installs the OpenCode plugin for the user who ran the
# command, and registers HAWK's hook in Claude Code and Codex when they are
# there (ADR-0034). Every download is checked against SHA256SUMS.
#
# Options (or the environment variable in brackets):
#   --core IP:PORT     skip discovery and use this Core        [HAWK_CORE]
#   --version X.Y.Z    release to install (default 0.1.7)       [HAWK_VERSION]
#   --base-url URL     where the release files are served        [HAWK_BASE_URL]
#   --no-service       install the binary only, no systemd unit  [HAWK_NO_SERVICE=1]
#   --no-plugin        do not install the OpenCode plugin        [HAWK_NO_PLUGIN=1]
#   --no-hooks         do not register the Claude Code and Codex hooks [HAWK_NO_HOOKS=1]
#   --dry-run          print what would change, change nothing   [HAWK_DRY_RUN=1]
#   --uninstall        remove the daemon, its service and the plugin

set -eu

VERSION="${HAWK_VERSION:-0.1.7}"
BASE_URL="${HAWK_BASE_URL:-}"
CORE="${HAWK_CORE:-}"
NO_SERVICE="${HAWK_NO_SERVICE:-0}"
NO_PLUGIN="${HAWK_NO_PLUGIN:-0}"
NO_HOOKS="${HAWK_NO_HOOKS:-0}"
DRY_RUN="${HAWK_DRY_RUN:-0}"
UNINSTALL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --core) CORE="${2:?falta IP:PUERTO después de --core}"; shift 2 ;;
    --version) VERSION="${2:?falta la versión}"; shift 2 ;;
    --base-url) BASE_URL="${2:?falta la URL}"; shift 2 ;;
    --no-service) NO_SERVICE=1; shift ;;
    --no-plugin) NO_PLUGIN=1; shift ;;
    --no-hooks) NO_HOOKS=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) sed -n '2,25p' "$0" 2>/dev/null || true; exit 0 ;;
    *) echo "Opción desconocida: $1" >&2; exit 2 ;;
  esac
done

[ -n "$BASE_URL" ] || BASE_URL="https://hawkeeper.xyz/downloads/v${VERSION}"

# minisign public key of the release checksums (ADR-0032). Empty until the
# team generates the key; then SHA256SUMS.minisig is verified when minisign
# is installed.
MINISIGN_PUBKEY=""

BIN_NAME="hawk-host-daemon"
SERVICE="hawk-host-daemon"
SYS_USER="hawk"
DATA_DIR="/var/lib/hawk-host-daemon"

# Output -------------------------------------------------------------------
if [ -t 1 ]; then B="$(printf '\033[1m')"; D="$(printf '\033[2m')"; R="$(printf '\033[0m')"; else B=""; D=""; R=""; fi
say()  { printf '%s\n' "$*"; }
step() { printf '%s==>%s %s\n' "$B" "$R" "$*"; }
note() { printf '    %s%s%s\n' "$D" "$*" "$R"; }
fail() { printf '%sHAWK:%s %s\n' "$B" "$R" "$*" >&2; exit 1; }
run()  { if [ "$DRY_RUN" = 1 ]; then printf '    [dry-run] %s\n' "$*"; else "$@"; fi; }

# Privileges: the script runs as the user and asks sudo only for system steps.
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi
as_root() {
  if [ "$DRY_RUN" = 1 ]; then printf '    [dry-run] %s\n' "$*"; return 0; fi
  if [ -n "$SUDO" ]; then sudo "$@"; else "$@"; fi
}
have() { command -v "$1" >/dev/null 2>&1; }

# The user who will run the agent (and gets the plugin).
AGENT_USER="${SUDO_USER:-$(id -un)}"
AGENT_HOME="$(getent passwd "$AGENT_USER" 2>/dev/null | cut -d: -f6 || true)"
[ -n "$AGENT_HOME" ] || AGENT_HOME="$HOME"
PLUGIN_DIR="$AGENT_HOME/.config/opencode/plugin"
PLUGIN_FILE="$PLUGIN_DIR/hawk.ts"

# Runs a command as the agent's user, never as root: the hooks live in that
# user's Claude Code and Codex configuration.
as_agent() {
  if [ "$DRY_RUN" = 1 ]; then printf '    [dry-run] %s\n' "$*"; return 0; fi
  if [ "$(id -u)" -eq 0 ] && [ "$AGENT_USER" != root ]; then
    sudo -u "$AGENT_USER" env HOME="$AGENT_HOME" "$@"
  else
    "$@"
  fi
}

# Uninstall ------------------------------------------------------------------
if [ "$UNINSTALL" = 1 ]; then
  step "Quitando HAWK de esta máquina"
  case "$VERSION" in 0.0.*|0.1.[0-3]) ;; *)
    for bin in "/usr/local/bin/$BIN_NAME" "$AGENT_HOME/.local/bin/$BIN_NAME"; do
      if [ -x "$bin" ]; then as_agent "$bin" hooks uninstall || true; break; fi
    done ;;
  esac
  if have systemctl && [ -f "/etc/systemd/system/$SERVICE.service" ]; then
    as_root systemctl disable --now "$SERVICE" || true
    as_root rm -f "/etc/systemd/system/$SERVICE.service"
    as_root systemctl daemon-reload
  fi
  as_root rm -f "/usr/local/bin/$BIN_NAME"
  run rm -f "$HOME/.local/bin/$BIN_NAME" "$PLUGIN_FILE"
  note "La identidad de esta máquina queda en $DATA_DIR. Bórrala a mano si quieres que HAWK la vea como una máquina nueva."
  say "Listo. El agente ya no pasa por HAWK en esta máquina."
  exit 0
fi

# Platform -------------------------------------------------------------------
OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS" in
  Linux) PLATFORM="linux" ;;
  Darwin) PLATFORM="macos" ;;
  MINGW*|MSYS*|CYGWIN*) fail "En Windows descarga hawk-$VERSION-x86_64-windows.zip de $BASE_URL/ y corre host-daemon.exe." ;;
  *) fail "Sistema no soportado: $OS." ;;
esac
case "$ARCH" in
  x86_64|amd64) TRIPLE="x86_64-$PLATFORM" ;;
  aarch64|arm64) TRIPLE="aarch64-$PLATFORM" ;;
  *) fail "Arquitectura no soportada: $ARCH. Hay builds para x86_64 y aarch64." ;;
esac

if have curl; then fetch() { curl -fsSL --retry 2 -o "$2" "$1"; }
elif have wget; then fetch() { wget -q -O "$2" "$1"; }
else fail "Necesito curl o wget."; fi
if have sha256sum; then sha() { sha256sum "$1" | cut -d' ' -f1; }
elif have shasum; then sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
else fail "Necesito sha256sum o shasum para verificar la descarga."; fi
have tar || fail "Necesito tar."

TARBALL="hawk-$VERSION-$TRIPLE.tar.gz"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

say ""
say "${B}HAWK${R}  Tu agente ejecuta. Tu HAWK revisa."
say ""

# Download and verify ---------------------------------------------------------
step "Descargando $TARBALL"
fetch "$BASE_URL/$TARBALL" "$TMP/$TARBALL" \
  || fail "No pude descargar $BASE_URL/$TARBALL. Revisa la versión (--version) o la dirección (--base-url)."
fetch "$BASE_URL/SHA256SUMS" "$TMP/SHA256SUMS" || fail "No pude descargar SHA256SUMS."

if [ -n "$MINISIGN_PUBKEY" ] && have minisign; then
  step "Verificando la firma de SHA256SUMS"
  fetch "$BASE_URL/SHA256SUMS.minisig" "$TMP/SHA256SUMS.minisig" || fail "No pude descargar SHA256SUMS.minisig."
  minisign -Vq -P "$MINISIGN_PUBKEY" -m "$TMP/SHA256SUMS" -x "$TMP/SHA256SUMS.minisig" \
    || fail "La firma de SHA256SUMS no es válida. No instalo nada."
elif [ -n "$MINISIGN_PUBKEY" ]; then
  note "minisign no está instalado: solo compruebo la suma SHA-256, no quién publicó el archivo."
fi

step "Comprobando la suma SHA-256"
EXPECTED="$(grep -E "[ *]$TARBALL\$" "$TMP/SHA256SUMS" | cut -d' ' -f1 | head -n1)"
[ -n "$EXPECTED" ] || fail "$TARBALL no aparece en SHA256SUMS."
ACTUAL="$(sha "$TMP/$TARBALL")"
[ "$EXPECTED" = "$ACTUAL" ] || fail "La descarga no coincide con SHA256SUMS. No instalo nada."
note "$ACTUAL"

tar -xzf "$TMP/$TARBALL" -C "$TMP"
SRC="$TMP/hawk-$VERSION-$TRIPLE/host-daemon"
[ -f "$SRC" ] || fail "El paquete no trae host-daemon."

# Install ---------------------------------------------------------------------
USE_SYSTEMD=0
if [ "$NO_SERVICE" != 1 ] && have systemctl && [ -d /run/systemd/system ] && { [ -z "$SUDO" ] || have sudo; }; then
  USE_SYSTEMD=1
fi

if [ "$USE_SYSTEMD" = 1 ]; then
  step "Instalando el daemon como servicio (te puede pedir tu contraseña)"
  as_root install -m 0755 "$SRC" "/usr/local/bin/$BIN_NAME"
  if ! getent passwd "$SYS_USER" >/dev/null 2>&1; then
    NOLOGIN="$(command -v nologin || echo /usr/sbin/nologin)"
    as_root useradd --system --no-create-home --home-dir "$DATA_DIR" --shell "$NOLOGIN" "$SYS_USER"
  fi
  UNIT="$TMP/$SERVICE.service"
  {
    echo "[Unit]"
    echo "Description=HAWK host daemon (relays the agent's tool calls to the HAWK Core)"
    echo "After=network-online.target"
    echo "Wants=network-online.target"
    echo ""
    echo "[Service]"
    echo "User=$SYS_USER"
    echo "StateDirectory=hawk-host-daemon"
    echo "Environment=HOST_DAEMON_DATA_DIR=$DATA_DIR"
    echo "Environment=RUST_LOG=info"
    [ -n "$CORE" ] && echo "Environment=GUARDIAN_CORE=$CORE"
    echo "ExecStart=/usr/local/bin/$BIN_NAME"
    echo "Restart=always"
    echo "RestartSec=2"
    echo "NoNewPrivileges=true"
    echo "ProtectHome=true"
    echo ""
    echo "[Install]"
    echo "WantedBy=multi-user.target"
  } > "$UNIT"
  as_root install -m 0644 "$UNIT" "/etc/systemd/system/$SERVICE.service"
  as_root systemctl daemon-reload
  as_root systemctl enable --now "$SERVICE"
  note "Servicio $SERVICE activo, como el usuario $SYS_USER."
else
  step "Instalando el daemon en ~/.local/bin"
  run mkdir -p "$HOME/.local/bin"
  run install -m 0755 "$SRC" "$HOME/.local/bin/$BIN_NAME"
  if [ "$PLATFORM" = macos ]; then note "En macOS todavía no se instala como servicio (launchd con usuario propio pendiente)."; fi
  note "Sin systemd: arráncalo tú con"
  note "  HOST_DAEMON_DATA_DIR=\$HOME/.hawk ${CORE:+GUARDIAN_CORE=$CORE }$HOME/.local/bin/$BIN_NAME"
  note "Para la demo está bien; en serio debe correr con un usuario distinto al del agente."
fi

# OpenCode plugin -------------------------------------------------------------
# Checked against SHA256SUMS like the daemon: it runs inside OpenCode.
if [ "$NO_PLUGIN" != 1 ]; then
  step "Instalando el plugin de OpenCode"
  PLUGIN_SRC=""
  # guardian.ts is the name in releases up to 0.1.1.
  for name in hawk-opencode-plugin.ts guardian.ts; do
    if fetch "$BASE_URL/$name" "$TMP/$name" 2>/dev/null; then PLUGIN_SRC="$name"; break; fi
  done
  if [ -n "$PLUGIN_SRC" ]; then
    WANT="$(grep -E "[ *]$PLUGIN_SRC\$" "$TMP/SHA256SUMS" | cut -d' ' -f1 | head -n1)"
    [ -n "$WANT" ] && [ "$WANT" = "$(sha "$TMP/$PLUGIN_SRC")" ] \
      || fail "El plugin no coincide con SHA256SUMS. No lo instalo."
    run mkdir -p "$PLUGIN_DIR"
    run cp "$TMP/$PLUGIN_SRC" "$PLUGIN_FILE"
    note "$PLUGIN_FILE"
  else
    note "No encontré el plugin en $BASE_URL. Cópialo a mano desde agent-hook/guardian.ts a $PLUGIN_DIR."
  fi
fi

# Claude Code and Codex hooks (ADR-0034) ----------------------------------------
# Releases up to 0.1.3 do not know `hooks`: they would start a second daemon.
case "$VERSION" in 0.0.*|0.1.[0-3]) NO_HOOKS=1 ;; esac
if [ "$NO_HOOKS" != 1 ]; then
  if [ "$USE_SYSTEMD" = 1 ]; then BIN="/usr/local/bin/$BIN_NAME"; else BIN="$HOME/.local/bin/$BIN_NAME"; fi
  for agent in claude codex; do
    if have "$agent" || [ -d "$AGENT_HOME/.$agent" ]; then
      step "Conectando $agent con HAWK"
      as_agent "$BIN" hooks install "$agent" \
        || note "No pude registrar el hook de $agent. Córrelo a mano: $BIN hooks install $agent"
    fi
  done
fi

# Identity --------------------------------------------------------------------
FP=""
if [ "$USE_SYSTEMD" = 1 ] && [ "$DRY_RUN" != 1 ] && have journalctl; then
  i=0
  while [ $i -lt 10 ] && [ -z "$FP" ]; do
    sleep 1
    FP="$(as_root journalctl -u "$SERVICE" -n 50 --no-pager 2>/dev/null | sed -n 's/.*host identity fingerprint=\([^ ]*\).*/\1/p' | tail -n1)"
    i=$((i + 1))
  done
fi

say ""
say "${B}Listo.${R} Ahora abre la app HAWK en tu teléfono:"
say "  1. En Equipos aparece $(hostname)${FP:+ con la huella ${B}$FP${R}}."
say "  2. Compara la huella y toca Aprobar."
say "  3. Vuelve a trabajar: cada acción del agente pasa primero por HAWK."
say ""
[ -n "$CORE" ] || note "El daemon busca tu HAWK en la red. Si no lo encuentra, vuelve a correr con --core IP:7443."
