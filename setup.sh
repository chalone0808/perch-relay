#!/usr/bin/env bash
# Perch relay server installer.
#
#   curl -fsSL <setup-url> | bash
#   curl -fsSL <setup-url> | bash -s -- --domain api.example.com --account alice
#
# This repository contains the relay server only. The laptop client is in its
# own repository. Run with no options for prompts. Nothing is installed until
# the questions are answered. Re-running is safe and keeps existing config.

set -euo pipefail

REPO_URL_DEFAULT="https://github.com/chalone0808/perch-relay.git"
REPO_URL="${PERCH_REPO_URL:-$REPO_URL_DEFAULT}"
BRANCH="${PERCH_BRANCH:-main}"
MODE=""
SOURCE=""
RELEASE="$(date +%Y%m%d%H%M%S)"
YES=0

SERVER=""
CODE=""
DOMAIN=""
ACCOUNT=""
INSTALL_MODE=""
PREFIX=""
DATA_DIR=""
CONFIG_DIR=""
PUSH_URL=""
PUSH_KEY=""

SERVICE_USER="perch-relay"
PUSH_KEY_ARG=0
SHELL_LINES=()
RC_FILE=""
SHELL_NAME=""
BUN_NEW=0
SELF_DIR=""
case "$0" in
  bash|sh|-bash|-sh|"") ;;
  *) [ -f "$0" ] && SELF_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd || true)" ;;
esac

say() { printf '\n== %s\n' "$*"; }
has_tty() { (exec 3</dev/tty) 2>/dev/null; }

COLOR=0
if [ -z "${NO_COLOR:-}" ] && [ "${TERM:-}" != dumb ]; then COLOR=1; fi
C_RESET=$'\033[0m'
C_ASK=$'\033[1;33m'
C_NOTE=$'\033[1;36m'
C_TODO=$'\033[1;32m'
C_WARN=$'\033[1;31m'

out_color() { [ "$COLOR" = 1 ] && [ -t 1 ]; }
err_color() { [ "$COLOR" = 1 ] && [ -t 2 ]; }

warn() {
  if err_color; then printf '%s!! %s%s\n' "$C_WARN" "$*" "$C_RESET" >&2
  else printf '!! %s\n' "$*" >&2; fi
}
die() {
  if err_color; then printf '%serror: %s%s\n' "$C_WARN" "$*" "$C_RESET" >&2
  else printf 'error: %s\n' "$*" >&2; fi
  exit 1
}
note() { # note FORMAT ARGS...
  local fmt=$1; shift
  if out_color; then printf '%s' "$C_NOTE"; printf "$fmt" "$@"; printf '%s\n' "$C_RESET"
  else printf "$fmt" "$@"; printf '\n'; fi
}
todo() { # todo FORMAT ARGS...
  local fmt=$1; shift
  if out_color; then printf '%s' "$C_TODO"; printf "$fmt" "$@"; printf '%s\n' "$C_RESET"
  else printf "$fmt" "$@"; printf '\n'; fi
}

if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi

as_root() {
  if [ -n "$SUDO" ]; then
    command -v sudo >/dev/null 2>&1 || die "sudo is required to install packages and the service"
    "$SUDO" -p "[sudo] Perch setup: " "$@"
  else
    "$@"
  fi
}
as_install() { if [ "$INSTALL_MODE" = user ]; then "$@"; else as_root "$@"; fi; }
as_service() {
  if [ "$INSTALL_MODE" = user ]; then "$@"
  else as_root runuser -u "$SERVICE_USER" -- "$@"; fi
}
apt_get() { as_root env DEBIAN_FRONTEND=noninteractive apt-get "$@"; }

ask() { # ask VAR "question" [default]
  local __var=$1 __q=$2 __def=${3:-} __reply=""
  if [ "$YES" = 1 ]; then printf -v "$__var" '%s' "$__def"; return; fi
  if has_tty; then
    local prompt="$__q${__def:+ [$__def]}: "
    if [ "$COLOR" = 1 ]; then printf '%s%s%s' "$C_ASK" "$prompt" "$C_RESET" > /dev/tty
    else printf '%s' "$prompt" > /dev/tty; fi
    IFS= read -r __reply < /dev/tty || true
  fi
  printf -v "$__var" '%s' "${__reply:-$__def}"
}

confirm() { # confirm "question" [Y|N]
  local __def=${2:-N} __reply=""
  [ "$YES" = 1 ] && { [ "$__def" = Y ]; return; }
  if has_tty; then
    local prompt="$1 [$([ "$__def" = Y ] && echo Y/n || echo y/N)]: "
    if [ "$COLOR" = 1 ]; then printf '%s%s%s' "$C_ASK" "$prompt" "$C_RESET" > /dev/tty
    else printf '%s' "$prompt" > /dev/tty; fi
    IFS= read -r __reply < /dev/tty || true
  fi
  __reply=${__reply:-$__def}
  [[ $__reply == [Yy]* ]]
}

choose_mode() { # sets INSTALL_MODE to system or user
  if [ -n "$INSTALL_MODE" ]; then
    case "$INSTALL_MODE" in
      system|user) ;;
      *) die "install mode must be system or user" ;;
    esac
    return
  fi
  if [ "$YES" = 1 ] || ! has_tty; then INSTALL_MODE=system; return; fi

  local sel=0 key rest hdr="" sel_color="" reset=""
  if [ "$COLOR" = 1 ]; then hdr="$C_NOTE"; sel_color="$C_ASK"; reset="$C_RESET"; fi
  local -a labels=(
    "system  /opt/perchserver, systemd service"
    "user    ~/.perchserver, systemd user service"
  )
  render() {
    local i
    printf '\033[2A' > /dev/tty 2>/dev/null || true
    for i in 0 1; do
      if [ "$i" = "$sel" ]; then
        printf '\r\033[2K%s> %d) %s%s\n' "$sel_color" "$((i + 1))" "${labels[$i]}" "$reset" > /dev/tty || true
      else
        printf '\r\033[2K  %d) %s\n' "$((i + 1))" "${labels[$i]}" > /dev/tty || true
      fi
    done
  }
  printf '%sInstall mode (up/down, Enter):%s\n' "$hdr" "$reset" > /dev/tty || true
  printf '\r\033[2K%s> 1) %s%s\n' "$sel_color" "${labels[0]}" "$reset" > /dev/tty || true
  printf '\r\033[2K  2) %s\n' "${labels[1]}" > /dev/tty || true
  while :; do
    if ! IFS= read -rsn1 key < /dev/tty; then
      INSTALL_MODE=system
      printf '\n' > /dev/tty || true
      return
    fi
    case "$key" in
      $'\x1b')
        IFS= read -rsn1 -t 1 rest < /dev/tty || rest=""
        if [ "$rest" = "[" ]; then
          IFS= read -rsn1 -t 1 rest < /dev/tty || rest=""
          case "$rest" in
            A|B) sel=$(( (sel + 1) % 2 )); render ;;
          esac
        fi
        ;;
      ""|$'\n')
        case "$sel" in 0) INSTALL_MODE=system ;; 1) INSTALL_MODE=user ;; esac
        printf '\n' > /dev/tty || true
        printf '%sUsing %s install.%s\n' "$hdr" "$INSTALL_MODE" "$reset" > /dev/tty || true
        return
        ;;
      1|k|K) sel=0; render ;;
      2|j|J) sel=1; render ;;
    esac
  done
}

usage() {
  cat <<'EOF'
usage:
  setup.sh [--layout system|user] [--domain HOST] [--account NAME]
           [--prefix DIR] [--data-dir DIR] [--config-dir DIR]
           [--source PATH] [--repo URL] [--branch BRANCH] [--version NAME]
           [--push-url URL] [--push-key KEY] [--yes]
  setup.sh --help

  Server installer; the mode is inferred from this repository.
  system: /opt/perchserver + systemd service (sudo for setup)
  user:   ~/.perchserver + systemd --user (no root for the layout)
EOF
}

MODE=""
case "${1:-}" in
  server|client) MODE="$1"; shift ;;
  -h|--help) usage; exit 0 ;;
esac

while [ $# -gt 0 ]; do
  case "$1" in
    --layout|--domain|--account|--prefix|--data-dir|--config-dir|--source|--version|--push-url|--push-key|--server|--code|--repo|--branch)
      [ $# -ge 2 ] || die "$1 needs a value" ;;
  esac
  case "$1" in
    --layout) INSTALL_MODE="${2:-}"; shift 2 ;;
    --domain) DOMAIN="${2:-}"; shift 2 ;;
    --account) ACCOUNT="${2:-}"; shift 2 ;;
    --prefix) PREFIX="${2:-}"; shift 2 ;;
    --data-dir) DATA_DIR="${2:-}"; shift 2 ;;
    --config-dir) CONFIG_DIR="${2:-}"; shift 2 ;;
    --source) SOURCE="${2:-}"; shift 2 ;;
    --version) RELEASE="${2:-}"; shift 2 ;;
    --push-url) PUSH_URL="${2:-}"; shift 2 ;;
    --push-key) PUSH_KEY="${2:-}"; PUSH_KEY_ARG=1; shift 2 ;;
    --server) SERVER="${2:-}"; shift 2 ;;
    --code) CODE="${2:-}"; shift 2 ;;
    --repo) REPO_URL="${2:-}"; shift 2 ;;
    --branch) BRANCH="${2:-}"; shift 2 ;;
    --yes|-y) YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

if [ -z "$MODE" ]; then
  case "${REPO_URL_DEFAULT:-}" in
    *perch-relay*) MODE=server ;;
    *) MODE=client ;;
  esac
fi
if [ -z "$MODE" ]; then
  if has_tty; then
    printf 'Set up [s]erver or [c]lient? ' > /dev/tty
    IFS= read -r MODE < /dev/tty || true
  fi
  case "$MODE" in s|server) MODE=server ;; c|client) MODE=client ;; *) usage; exit 1 ;; esac
fi
case "$MODE" in
  server|client) ;;
  *) die "unknown mode: $MODE" ;;
esac

fetch_code() { # fetch_code DEST
  local dest=$1
  mkdir -p "$dest"
  if [ -n "$SOURCE" ]; then
    [ -d "$SOURCE" ] || die "source not found: $SOURCE"
    (cd "$SOURCE" && tar --exclude=.git -cf - .) | (cd "$dest" && tar -xf -)
    return
  fi
  if [ -n "$SELF_DIR" ] && [ -f "$SELF_DIR/server/server.ts" ]; then
    (cd "$SELF_DIR" && tar --exclude=.git -cf - .) | (cd "$dest" && tar -xf -)
    return
  fi
  command -v git >/dev/null 2>&1 || die "git is required to fetch the code"
  git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$dest"
}

have() { command -v "$1" >/dev/null 2>&1; }
pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'; }
local_source() { [ -n "$SOURCE" ] || { [ -n "$SELF_DIR" ] && [ -f "$SELF_DIR/server/server.ts" ]; }; }

shell_rc() { # sets RC_FILE and SHELL_NAME for the invoking user
  local home="${HOME:-}" shellpath="${SHELL:-/bin/sh}" entry=""
  if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && have getent; then
    entry="$(getent passwd "$SUDO_USER" 2>/dev/null || true)"
    if [ -n "$entry" ]; then
      home="$(printf '%s' "$entry" | cut -d: -f6)"
      shellpath="$(printf '%s' "$entry" | cut -d: -f7)"
    fi
  fi
  SHELL_NAME="${shellpath##*/}"
  case "$SHELL_NAME" in
    zsh) RC_FILE="$home/.zshrc" ;;
    bash) RC_FILE="$home/.bashrc" ;;
    fish) RC_FILE="$home/.config/fish/config.fish" ;;
    *) RC_FILE="" ;;
  esac
}

path_line() { # path_line DIR
  if [ "$SHELL_NAME" = fish ]; then
    printf 'set -gx PATH "%s" $PATH' "$1"
  else
    printf 'export PATH="%s:$PATH"' "$1"
  fi
}

add_path() { # add_path DIR
  local dir=$1 line
  line="$(path_line "$dir")"
  case " ${SHELL_LINES[*]:-} " in
    *" $line "*) ;;
    *) SHELL_LINES+=("$line") ;;
  esac
  [ -n "$RC_FILE" ] || return 0
  mkdir -p "$(dirname "$RC_FILE")"
  grep -qsxF "$line" "$RC_FILE" || printf '\n# perch\n%s\n' "$line" >> "$RC_FILE"
}

install_missing() { # install_missing PKG...
  if [ $# -eq 0 ]; then return 0; fi
  have apt-get || die "missing packages: $* (this installer supports Debian and Ubuntu for now)"
  say "Packages"
  note 'sudo: install %s' "$*"
  apt_get update
  apt_get install -y "$@"
}

install_caddy() {
  if pkg_installed caddy; then return 0; fi
  local deps=()
  have gpg || deps+=(gnupg)
  pkg_installed ca-certificates || deps+=(ca-certificates)
  if [ ${#deps[@]} -gt 0 ]; then install_missing "${deps[@]}"; fi
  local keyring=/usr/share/keyrings/caddy-stable-archive-keyring.gpg
  local sources=/etc/apt/sources.list.d/caddy-stable.list
  if [ ! -s "$keyring" ] || ! as_root test -f "$sources"; then
    local tmp
    tmp="$(mktemp)"
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
      | as_root gpg --dearmor > "$tmp"
    as_root install -m 0644 "$tmp" "$keyring"
    rm -f "$tmp"
    tmp="$(mktemp)"
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > "$tmp"
    as_root install -m 0644 "$tmp" "$sources"
    rm -f "$tmp"
    apt_get update
  fi
  apt_get install -y caddy
}

setup_server() {
  [ -r /etc/os-release ] || die "server setup supports Debian and Ubuntu for now"
  . /etc/os-release
  say "Perch relay on $PRETTY_NAME"

  local cmd
  for cmd in systemctl tar realpath; do
    have "$cmd" || die "server setup needs $cmd"
  done

  shell_rc
  choose_mode

  local default_prefix
  if [ "$INSTALL_MODE" = user ]; then
    [ "$(id -u)" -ne 0 ] || die "run the user install as the user who will own it, not root"
    SERVICE_USER="$(id -un)"
    default_prefix="$HOME/.perchserver"
  else
    default_prefix="/opt/perchserver"
  fi
  if [ -z "$PREFIX" ]; then
    if [ "$YES" = 1 ] || ! has_tty; then
      PREFIX="$default_prefix"
    else
      while :; do
        ask PREFIX "Install path" "$default_prefix"
        case "$PREFIX" in
          /*) case "$PREFIX" in *[!A-Za-z0-9/._-]*) warn "use letters, digits, ., _, - and /"; continue ;; esac ;;
          *) warn "path must be absolute"; continue ;;
        esac
        break
      done
    fi
  fi
  DATA_DIR="${DATA_DIR:-$PREFIX/data}"
  CONFIG_DIR="${CONFIG_DIR:-$PREFIX}"

  case "$RELEASE" in
    ""|.|..|*/*|*[!A-Za-z0-9._-]*)
      die "invalid release name: '$RELEASE' (use letters, digits, dot, underscore, dash)" ;;
  esac
  local p
  for p in "$PREFIX" "$DATA_DIR" "$CONFIG_DIR"; do
    case "$p" in
      /*) ;;
      *) die "path must be absolute: $p" ;;
    esac
    case "$p" in
      *[!A-Za-z0-9/._-]*) die "path may only contain letters, digits, ., _, -, /: $p" ;;
    esac
  done
  if [ "$PREFIX" = / ]; then die "choose a dedicated install prefix"; fi
  PREFIX="$(realpath -m "$PREFIX")"
  DATA_DIR="$(realpath -m "$DATA_DIR")"
  CONFIG_DIR="$(realpath -m "$CONFIG_DIR")"
  if [ "$INSTALL_MODE" = system ]; then
    case "$DATA_DIR/" in
      "$PREFIX"/*) ;;
      *) die "data dir must be under $PREFIX" ;;
    esac
    case "$CONFIG_DIR" in
      "$PREFIX"|"$PREFIX"/*) ;;
      *) die "config dir must be under $PREFIX" ;;
    esac
  fi
  if [ -n "$SOURCE" ]; then
    [ -f "$SOURCE/server/server.ts" ] || die "source has no server/: $SOURCE"
  elif [ -n "$SELF_DIR" ] && [ ! -f "$SELF_DIR/server/server.ts" ]; then
    die "this checkout has no server/ (use the server repository)"
  fi

  BUN_DIR="$PREFIX/bun"
  if [ ! -x "$BUN_DIR/bin/bun" ] && [ "$INSTALL_MODE" = user ] && [ "$YES" != 1 ] && has_tty; then
    while :; do
      ask BUN_DIR "Bun install path" "$PREFIX/bun"
      case "$BUN_DIR" in
        /*) case "$BUN_DIR" in *[!A-Za-z0-9/._-]*) warn "use letters, digits, ., _, - and /"; continue ;; esac ;;
        *) warn "path must be absolute"; continue ;;
      esac
      break
    done
  fi
  BUN_DIR="$(realpath -m "$BUN_DIR")"
  BUN="$BUN_DIR/bin/bun"

  [ -z "$ACCOUNT" ] && ask ACCOUNT "Account name (empty to skip)" ""
  if [ -z "$DOMAIN" ]; then
    ask DOMAIN "Public hostname (empty for local-only)" ""
  fi
  [ -z "$PUSH_URL" ] && [ -n "${PERCH_PUSH_URL:-}" ] && PUSH_URL="$PERCH_PUSH_URL"
  [ -z "$PUSH_KEY" ] && [ -n "${PERCH_PUSH_KEY:-}" ] && PUSH_KEY="$PERCH_PUSH_KEY"
  if [ "$PUSH_KEY_ARG" = 1 ]; then
    warn "--push-key is visible in process listings; prefer PERCH_PUSH_KEY"
  fi
  case "$DOMAIN" in
    *[!A-Za-z0-9.-]*) die "invalid hostname: $DOMAIN" ;;
  esac

  local base=()
  if ! have curl; then base+=(curl); fi
  if [ ! -x "$BUN" ] || ! local_source; then
    pkg_installed ca-certificates || base+=(ca-certificates)
  fi
  if [ ! -x "$BUN" ] && ! have unzip; then base+=(unzip); fi
  if ! local_source && ! have git; then base+=(git); fi
  if [ -n "$DOMAIN" ] && ! have caddy && ! have gpg; then base+=(gnupg); fi
  say "Requirements"
  if [ -x "$BUN" ]; then
    printf 'Bun: present\n'
  else
    printf 'Bun: install under %s\n' "$BUN_DIR"
  fi
  if [ -n "$DOMAIN" ]; then
    if have caddy; then printf 'Caddy: present\n'; else printf 'Caddy: install\n'; fi
  else
    printf 'Caddy: not needed (no public hostname)\n'
  fi
  if [ ${#base[@]} -gt 0 ]; then
    printf 'Packages: %s\n' "${base[*]}"
    install_missing "${base[@]}"
  else
    printf 'Packages: none missing\n'
  fi

  say "Directories"
  if [ "$INSTALL_MODE" = user ]; then
    printf 'Install mode: user; %s\n' "$PREFIX"
    mkdir -p "$DATA_DIR" "$PREFIX/releases" "$PREFIX/bin"
    chmod 0700 "$DATA_DIR"
    chmod 0755 "$PREFIX" "$PREFIX/releases" "$PREFIX/bin"
    if [ "$CONFIG_DIR" != "$PREFIX" ]; then
      mkdir -p "$CONFIG_DIR"
      chmod 0700 "$CONFIG_DIR"
    fi
  else
    note 'Install mode: system; sudo: create the %s user and %s.' "$SERVICE_USER" "$PREFIX"
    id "$SERVICE_USER" >/dev/null 2>&1 || as_root useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
    as_root install -d -o root -g root -m 0755 "$PREFIX" "$PREFIX/releases" "$PREFIX/bin"
    as_root install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0700 "$DATA_DIR"
    if [ "$CONFIG_DIR" != "$PREFIX" ]; then
      as_root install -d -o root -g "$SERVICE_USER" -m 0750 "$CONFIG_DIR"
    fi
  fi

  say "Code"
  if [ "$INSTALL_MODE" = user ]; then
    printf 'Install release %s under %s/releases.\n' "$RELEASE" "$PREFIX"
  else
    note 'sudo: install release %s under %s/releases.' "$RELEASE" "$PREFIX"
  fi
  local release="$PREFIX/releases/$RELEASE" stage
  stage="$(mktemp -d)"
  fetch_code "$stage/src"
  [ -f "$stage/src/server/server.ts" ] || die "this checkout has no server/ (use the server repository)"
  as_install rm -rf -- "$release"
  if [ "$INSTALL_MODE" = user ]; then
    as_install install -d -m 0755 "$release"
  else
    as_root install -d -o root -g root -m 0755 "$release"
  fi
  (cd "$stage/src" && tar --exclude=.git -cf - .) | as_install tar -xf - -C "$release"
  rm -rf "$stage"
  if [ "$INSTALL_MODE" != user ]; then as_root chown -R root:root -- "$release"; fi
  as_install ln -sfn -- "$release" "$PREFIX/current"

  say "Bun"
  if [ ! -x "$BUN" ]; then
    if [ "$INSTALL_MODE" = user ]; then
      printf 'Install Bun under %s.\n' "$BUN_DIR"
      install -d -m 0755 "$BUN_DIR"
    else
      note 'sudo: install Bun under %s.' "$BUN_DIR"
      as_root install -d -o root -g root -m 0755 "$BUN_DIR"
    fi
    local bun_home
    bun_home="$(mktemp -d)"
    as_install env BUN_INSTALL="$BUN_DIR" HOME="$bun_home" bash -lc 'curl -fsSL https://bun.sh/install | bash'
    as_install rm -rf -- "$bun_home"
    as_install chmod -R a+rX -- "$BUN_DIR"
    BUN_NEW=1
  fi
  if [ "$BUN_NEW" = 1 ]; then add_path "$BUN_DIR/bin"; fi
  "$BUN" --version

  say "Configuration"
  if [ "$INSTALL_MODE" = user ]; then
    printf 'Write %s/relay.env.\n' "$CONFIG_DIR"
  else
    note 'sudo: write %s/relay.env.' "$CONFIG_DIR"
  fi
  local public_url="" env_file old_env="" old_public="" old_push_url="" old_push_key=""
  if as_install test -f "$CONFIG_DIR/relay.env"; then
    old_env="$(as_install cat "$CONFIG_DIR/relay.env" 2>/dev/null || true)"
    old_public="$(printf '%s\n' "$old_env" | sed -n 's/^PERCH_PUBLIC_URL=//p' | head -n 1)"
    old_push_url="$(printf '%s\n' "$old_env" | sed -n 's/^PUSH_GATEWAY=//p' | head -n 1)"
    old_push_key="$(printf '%s\n' "$old_env" | sed -n 's/^PUSH_GATEWAY_KEY=//p' | head -n 1)"
  fi
  if [ -z "$PUSH_URL" ]; then PUSH_URL="$old_push_url"; fi
  if [ -z "$PUSH_KEY" ]; then PUSH_KEY="$old_push_key"; fi
  if [ -n "$PUSH_URL" ] && [ -z "$PUSH_KEY" ]; then die "push-url needs push-key"; fi
  if [ -z "$PUSH_URL" ] && [ -n "$PUSH_KEY" ]; then die "push-key needs push-url"; fi
  case "$PUSH_URL" in
    ""|https://*|http://127.0.0.1:*|http://localhost:*) ;;
    *) die "push-url must be https:// or loopback http://" ;;
  esac
  case "$PUSH_URL$PUSH_KEY" in
    *[[:cntrl:]]*) die "push settings must not contain control characters" ;;
  esac
  if [ -n "$DOMAIN" ]; then public_url="https://$DOMAIN"; fi
  if [ -z "$public_url" ]; then public_url="$old_public"; fi
  env_file="$(mktemp)"
  (
    umask 077
    {
      printf 'PORT=8787\nHOST=127.0.0.1\nPERCH_DB=%s/perch.db\n' "$DATA_DIR"
      if [ -n "$public_url" ]; then printf 'PERCH_PUBLIC_URL=%s\n' "$public_url"; fi
      if [ -n "$PUSH_URL" ]; then
        printf 'PUSH_GATEWAY=%s\nPUSH_GATEWAY_KEY=%s\n' "$PUSH_URL" "$PUSH_KEY"
      fi
      printf '%s\n' "$old_env" | while IFS= read -r line; do
        case "$line" in
          ""|PORT=*|HOST=*|PERCH_DB=*|PERCH_PUBLIC_URL=*|PUSH_GATEWAY=*|PUSH_GATEWAY_KEY=*) ;;
          *) printf '%s\n' "$line" ;;
        esac
      done
    } > "$env_file"
  )
  if [ "$INSTALL_MODE" = user ]; then
    as_install install -m 0600 "$env_file" "$CONFIG_DIR/relay.env"
  else
    as_root install -o root -g "$SERVICE_USER" -m 0640 "$env_file" "$CONFIG_DIR/relay.env"
  fi
  rm -f "$env_file"

  say "Service"
  local unit unit_dir="" unit_file=""
  unit="$(mktemp)"
  if [ "$INSTALL_MODE" = user ]; then
    printf 'Install the user systemd unit and start perch-relay.\n'
    unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
    unit_file="$unit_dir/perch-relay.service"
    install -d -m 0755 "$unit_dir"
    cat > "$unit" <<EOF
[Unit]
Description=Perch relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$PREFIX/current/server
EnvironmentFile=$CONFIG_DIR/relay.env
ExecStart=$BUN server.ts
Restart=always
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=$DATA_DIR

[Install]
WantedBy=default.target
EOF
  else
    note 'sudo: install the systemd unit and start perch-relay.'
    unit_file=/etc/systemd/system/perch-relay.service
    cat > "$unit" <<EOF
[Unit]
Description=Perch relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$PREFIX/current/server
EnvironmentFile=$CONFIG_DIR/relay.env
ExecStart=$BUN server.ts
Restart=always
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=$DATA_DIR

[Install]
WantedBy=multi-user.target
EOF
  fi
  as_install install -m 0644 "$unit" "$unit_file"
  rm -f "$unit"
  if [ "$INSTALL_MODE" = user ]; then
    systemctl --user daemon-reload
    systemctl --user enable --now perch-relay
    systemctl --user restart perch-relay
    if have loginctl; then
      if ! loginctl show-user "$SERVICE_USER" -p Linger 2>/dev/null | grep -q 'Linger=yes'; then
        note 'sudo: enable linger so the relay starts at boot without a login.'
        as_root loginctl enable-linger "$SERVICE_USER" \
          || warn "could not enable linger; the relay starts on your next login"
      fi
    fi
  else
    as_root systemctl daemon-reload
    as_root systemctl enable --now perch-relay
    as_root systemctl restart perch-relay
  fi

  local wrapper relay_cmd="$PREFIX/bin/perch-relay"
  wrapper="$(mktemp)"
  if [ "$INSTALL_MODE" = user ]; then
    cat > "$wrapper" <<EOF
#!/bin/sh
set -e
db=\$(sed -n 's/^PERCH_DB=//p' "$CONFIG_DIR/relay.env" | head -n 1)
[ -n "\$db" ] || { echo "no PERCH_DB in $CONFIG_DIR/relay.env" >&2; exit 1; }
cd "$PREFIX/current/server"
exec env PERCH_DB="\$db" "$BUN" server.ts "\$@"
EOF
    install -m 0755 "$wrapper" "$relay_cmd"
  else
    cat > "$wrapper" <<EOF
#!/bin/sh
set -e
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
[ "\$(id -u)" -eq 0 ] || exec sudo "\$0" "\$@"
db=\$(sed -n 's/^PERCH_DB=//p' "$CONFIG_DIR/relay.env" | head -n 1)
[ -n "\$db" ] || { echo "no PERCH_DB in $CONFIG_DIR/relay.env" >&2; exit 1; }
cd "$PREFIX/current/server"
exec runuser -u $SERVICE_USER -- env PERCH_DB="\$db" "$BUN" server.ts "\$@"
EOF
    as_root install -m 0755 "$wrapper" "$relay_cmd"
  fi
  rm -f "$wrapper"
  add_path "$PREFIX/bin"

  if [ -n "$DOMAIN" ]; then
    say "Caddy"
    note 'sudo: configure Caddy for %s.' "$DOMAIN"
    install_caddy
    local cf=/etc/caddy/Caddyfile
    if as_root grep -qF -- "$DOMAIN {" "$cf" 2>/dev/null; then
      printf '%s already exists in %s\n' "$DOMAIN" "$cf"
      if ! as_root grep -qF -- 'header_up X-Real-IP {remote_host}' "$cf"; then
        warn "existing $DOMAIN block has no X-Real-IP; sign-in rate limits will see 127.0.0.1"
      fi
    else
      local bak="" site existed=0
      if as_root test -f "$cf"; then
        existed=1
        bak="$cf.bak-perch-$(date +%s)"
        as_root cp -- "$cf" "$bak"
      fi
      site="$(mktemp)"
      cat > "$site" <<EOF

$DOMAIN {
	header Strict-Transport-Security "max-age=31536000"
	reverse_proxy 127.0.0.1:8787 {
		header_up X-Real-IP {remote_host}
	}
}
EOF
      as_root tee -a -- "$cf" < "$site" >/dev/null
      rm -f "$site"
      if as_root caddy validate --config "$cf" >/dev/null 2>&1; then
        as_root systemctl enable --now caddy
        as_root systemctl restart caddy
      else
        if [ "$existed" = 1 ] && [ -n "$bak" ]; then
          as_root cp -- "$bak" "$cf"
        else
          as_root rm -f -- "$cf"
        fi
        warn "Caddy rejected the new site; fix $cf yourself"
      fi
    fi
  fi

  relay_cli() { # relay_cli ARGS...
    as_service sh -c 'cd "$1" || exit 1; shift; exec "$@"' sh \
      "$PREFIX/current/server" env PERCH_DB="$DATA_DIR/perch.db" "$BUN" server.ts "$@"
  }

  say "Account"
  if [ -n "$ACCOUNT" ]; then
    if [ "$INSTALL_MODE" != user ]; then
      note 'sudo: run the account command as %s.' "$SERVICE_USER"
    fi
    local accounts=""
    accounts="$(relay_cli account list 2>/dev/null || true)"
    if printf '%s' "$accounts" | grep -Fqi "\"name\": \"$ACCOUNT\""; then
      printf 'Account %s already exists; leaving it.\n' "$ACCOUNT"
    elif printf '%s' "$accounts" | grep -Fq '"name"'; then
      relay_cli account add "$ACCOUNT" --password
    else
      relay_cli account add "$ACCOUNT" --adopt --password
    fi
  else
    todo 'No account created. Later:'
    todo '  %s account add <name> --adopt --password' "$relay_cmd"
  fi

  say "Health"
  local methods="" i
  for i in $(seq 1 20); do
    if methods="$(curl -fsS --max-time 2 http://127.0.0.1:8787/v1/auth/methods 2>/dev/null)"; then break; fi
    sleep 0.5
  done
  if [ -n "$methods" ]; then
    printf '%s\n' "$methods"
  else
    warn "relay did not answer on 127.0.0.1:8787"
  fi
  printf 'perch-relay: '
  if [ "$INSTALL_MODE" = user ]; then
    systemctl --user is-active perch-relay || true
  else
    systemctl is-active perch-relay || true
  fi
  if [ -n "$DOMAIN" ]; then
    printf 'caddy: '
    systemctl is-active caddy || true
  fi
  printf '\n'
  if [ -n "$DOMAIN" ]; then
    printf 'Relay: https://%s\n' "$DOMAIN"
    curl -sS --max-time 10 "https://$DOMAIN/v1/auth/methods" \
      || warn "public TLS not ready; check DNS and ports 80/443"
  else
    printf 'Relay: http://127.0.0.1:8787 (local only)\n'
  fi
  printf 'Data:  %s\n' "$DATA_DIR"
  printf 'Config: %s\n' "$CONFIG_DIR/relay.env"
  todo 'Laptop code (single use, 10 minutes):'
  todo '  %s pair machine' "$relay_cmd"

  say "Shell"
  if [ -n "$RC_FILE" ]; then
    note 'Shell profile %s (open a new shell or source it):' "$RC_FILE"
  else
    note 'Add these lines to your shell profile:'
  fi
  local line
  for line in "${SHELL_LINES[@]}"; do todo '  %s' "$line"; done
}

setup_client() {
  [ "$(id -u)" -ne 0 ] || die "run client setup as your user, not root"
  [ -z "$PREFIX" ] && PREFIX="$HOME/.perch/app"
  case "$PREFIX" in
    /*) ;;
    *) die "prefix must be absolute: $PREFIX" ;;
  esac

  if [ -n "$SOURCE" ]; then
    [ -f "$SOURCE/client/perch.ts" ] || die "source has no client/: $SOURCE"
  elif [ -n "$SELF_DIR" ] && [ ! -f "$SELF_DIR/client/perch.ts" ]; then
    die "this checkout has no client/ (use the client repository)"
  fi

  say "Requirements"
  if [ -x "$HOME/.bun/bin/bun" ]; then
    printf 'Bun: present\n'
  else
    printf 'Bun: install under %s\n' "$HOME/.bun"
  fi
  if have curl; then printf 'curl: present\n'; else printf 'curl: install\n'; fi
  if have git; then printf 'Git: present\n'; else printf 'Git: install\n'; fi
  if have claude; then
    printf 'Claude Code: present\n'
  else
    printf 'Claude Code: not on PATH\n'
    warn "install Claude Code before running perch"
  fi

  if ! command -v curl >/dev/null 2>&1; then
    command -v apt-get >/dev/null 2>&1 || die "curl is required"
    sudo apt-get update && sudo apt-get install -y curl
  fi
  if [ ! -x "$HOME/.bun/bin/bun" ] && ! have unzip; then
    have apt-get || die "unzip is required to install Bun"
    sudo apt-get update && sudo apt-get install -y unzip
  fi
  if have apt-get && ! pkg_installed ca-certificates; then
    sudo apt-get update && sudo apt-get install -y ca-certificates
  fi

  say "Bun"
  BUN="$HOME/.bun/bin/bun"
  if [ ! -x "$BUN" ]; then
    curl -fsSL https://bun.sh/install | bash
  fi
  "$BUN" --version

  say "Code"
  if [ -n "$SOURCE" ]; then
    fetch_code "$PREFIX"
  else
    if ! command -v git >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
      sudo apt-get update && sudo apt-get install -y git
    fi
    mkdir -p "$(dirname "$PREFIX")"
    if command -v git >/dev/null 2>&1; then
      if [ -d "$PREFIX/.git" ]; then
        local cur
        cur="$(git -C "$PREFIX" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
        if [ "$cur" != "$BRANCH" ]; then
          git -C "$PREFIX" fetch --depth 1 origin "$BRANCH" \
            && git -C "$PREFIX" checkout -q -B "$BRANCH" FETCH_HEAD \
            || die "could not switch $PREFIX to branch $BRANCH"
        else
          git -C "$PREFIX" pull --ff-only
        fi
      elif [ -f "$PREFIX/client/perch.ts" ] && [ "$(cd "$PREFIX" && pwd)" = "$SELF_DIR" ]; then
        printf 'using this checkout\n'
      elif [ -e "$PREFIX" ] && [ -n "$(ls -A "$PREFIX" 2>/dev/null)" ]; then
        die "$PREFIX exists and is not a git checkout"
      else
        git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$PREFIX"
      fi
    elif [ -n "$SELF_DIR" ] && [ -f "$SELF_DIR/client/perch.ts" ]; then
      mkdir -p "$PREFIX"
      (cd "$SELF_DIR" && tar --exclude=.git -cf - .) | (cd "$PREFIX" && tar -xf -)
    else
      die "git is required, or pass --source with a checkout"
    fi
  fi

  [ -f "$PREFIX/client/perch.ts" ] || die "this checkout has no client/ (use the client repository)"

  say "Command"
  local rc="" shname="${SHELL##*/}" line
  case "$shname" in
    zsh) rc="$HOME/.zshrc" ;;
    bash) rc="$HOME/.bashrc" ;;
    fish) rc="$HOME/.config/fish/config.fish" ;;
    *) rc="" ;;
  esac
  if [ "$shname" = fish ]; then
    line="alias perch '$BUN $PREFIX/client/perch.ts'"
  else
    line="alias perch='$BUN $PREFIX/client/perch.ts'"
  fi
  if [ -n "$rc" ]; then
    mkdir -p "$(dirname "$rc")"
    if ! grep -qsxF "$line" "$rc"; then
      printf '\n# perch\n%s\n' "$line" >> "$rc"
      printf 'added to %s; open a new shell or: source %s\n' "$rc" "$rc"
    fi
  else
    printf 'Add this line to your shell config:\n  %s\n' "$line"
  fi

  if [ -n "$SERVER" ] && [ -n "$CODE" ]; then
    "$BUN" "$PREFIX/client/perch.ts" pair "$SERVER" "$CODE"
  else
    printf '\nPair this computer with a code from the phone (Settings -> Add a Laptop):\n'
    printf '  "%s" "%s" pair <server> <code>\n' "$BUN" "$PREFIX/client/perch.ts"
  fi
  printf '\nStart Claude Code with:\n  perch claude\n'
}

case "$MODE" in
  server) setup_server ;;
  client) setup_client ;;
esac
