#!/usr/bin/env bash
# Perch relay server installer (user-only).
#
#   curl -fsSL <setup-url> | bash
#   curl -fsSL <setup-url> | bash -s -- --domain api.example.com --account alice
#   curl -fsSL <setup-url> | bash -s -- --push --apns-key-file ~/AuthKey.p8 \
#     --apns-key-id ABC123DEFG --apns-team-id TEAM123456 --apns-topic com.example.app
#
# Everything Perch-owned is installed as your user under PREFIX (default
# ~/.perchserver). Sudo is used only for missing system packages, optional
# Caddy/TLS setup, and a last-resort linger enable. There is no system install.
set -euo pipefail

REPO_URL_DEFAULT="https://github.com/chalone0808/perch-relay.git"
REPO_URL="${PERCH_REPO_URL:-$REPO_URL_DEFAULT}"
BRANCH="${PERCH_BRANCH:-main}"

YES=0
SOURCE=""
PREFIX=""
DATA_DIR=""
CONFIG_DIR=""
DB_PATH=""
PORT=""
PORT_SET=0
ACCOUNT=""
ACCOUNT_SET=0
NO_ACCOUNT=0
DOMAIN=""
PUBLIC_URL=""
PUBLIC_URL_SET=0
NO_CADDY=0
BUN_ARG=""
BUN=""
BUN_DIR=""
BUN_NEW=0
UNIT="perch-relay"
PUSH=0
PUSH_OPTS=0
PUSH_PREFIX=""
PUSH_PORT=""
PUSH_PORT_SET=0
PUSH_UNIT="perch-gateway"
APNS_KEY_FILE=""
APNS_KEY_FILE_SET=0
APNS_KEY_ID=""
APNS_KEY_ID_SET=0
APNS_TEAM_ID=""
APNS_TEAM_ID_SET=0
APNS_TOPIC=""
APNS_TOPIC_SET=0
APNS_ENV=""
APNS_ENV_SET=0
RELEASE=""
FAILED=0

SHELL_LINES=()
RC_FILE=""
SHELL_NAME=""
SELF_DIR=""
STAGING=""
RUN_DIR=""
OLD_ENV=""
OLD_PORT=""
OLD_DB=""
OLD_PUBLIC=""
OLD_PUSH_URL=""
OLD_PUSH_KEY=""
OLD_PUSH_ENV=""
PUSH_KEYS_SPEC=""
PUSH_SECRET=""
ACCOUNT_CREATED=0
PASSWORD_FILE=""
CADDY_ACTION=""

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
note() {
  local fmt=$1; shift
  if out_color; then printf '%s' "$C_NOTE"; printf "$fmt" "$@"; printf '%s\n' "$C_RESET"
  else printf "$fmt" "$@"; printf '\n'; fi
}
todo() {
  local fmt=$1; shift
  if out_color; then printf '%s' "$C_TODO"; printf "$fmt" "$@"; printf '%s\n' "$C_RESET"
  else printf "$fmt" "$@"; printf '\n'; fi
}

have() { command -v "$1" >/dev/null 2>&1; }
pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'; }

as_root() {
  have sudo || { warn "sudo is not available"; return 1; }
  sudo -p "[sudo] Perch setup: " "$@"
}
apt_get() { as_root env DEBIAN_FRONTEND=noninteractive apt-get "$@"; }

ask() {
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

confirm() {
  local __def=${2:-N} __reply=""
  if [ "$YES" = 1 ]; then [ "$__def" = Y ]; return; fi
  if ! has_tty; then [ "$__def" = Y ]; return; fi
  local prompt="$1 [$([ "$__def" = Y ] && echo Y/n || echo y/N)]: "
  if [ "$COLOR" = 1 ]; then printf '%s%s%s' "$C_ASK" "$prompt" "$C_RESET" > /dev/tty
  else printf '%s' "$prompt" > /dev/tty; fi
  IFS= read -r __reply < /dev/tty || true
  __reply=${__reply:-$__def}
  [[ $__reply == [Yy]* ]]
}

shell_rc() {
  local home="${HOME:-}" shellpath="${SHELL:-/bin/sh}"
  [ -n "$home" ] || die "HOME is not set"
  SHELL_NAME="${shellpath##*/}"
  case "$SHELL_NAME" in
    zsh) RC_FILE="$home/.zshrc" ;;
    bash) RC_FILE="$home/.bashrc" ;;
    fish) RC_FILE="$home/.config/fish/config.fish" ;;
    *) RC_FILE="" ;;
  esac
}

path_line() {
  if [ "$SHELL_NAME" = fish ]; then printf 'set -gx PATH "%s" $PATH' "$1"
  else printf 'export PATH="%s:$PATH"' "$1"; fi
}

add_path() {
  local dir=$1 line
  line="$(path_line "$dir")"
  case " ${SHELL_LINES[*]:-} " in
    *" $line "*) ;;
    *) SHELL_LINES+=("$line") ;;
  esac
  [ -n "$RC_FILE" ] || return 0
  mkdir -p "$(dirname "$RC_FILE")" 2>/dev/null || { warn "could not create $(dirname "$RC_FILE")"; return 0; }
  if ! grep -qsxF "$line" "$RC_FILE" 2>/dev/null; then
    printf '\n# perch\n%s\n' "$line" >> "$RC_FILE" || warn "could not update $RC_FILE"
  fi
}

fetch_code() {
  local dest=$1
  mkdir -p "$dest"
  if [ -n "$SOURCE" ]; then
    [ -d "$SOURCE" ] || die "source not found: $SOURCE"
    (cd "$SOURCE" && tar --exclude=.git -cf - .) | (cd "$dest" && tar -xf -)
    return
  fi
  if [ -n "$SELF_DIR" ] && [ -f "$SELF_DIR/server.ts" ]; then
    (cd "$SELF_DIR" && tar --exclude=.git -cf - .) | (cd "$dest" && tar -xf -)
    return
  fi
  have git || die "git is required to fetch the code"
  git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$dest"
}

env_get() { # env_get TEXT KEY
  printf '%s\n' "$1" | sed -n "s/^$2=//p" | head -n 1
}

norm_path() { # absolute, safe, no . or .. components
  local p=$1
  case "$p" in
    /*) ;;
    *) die "path must be absolute: $p" ;;
  esac
  case "$p" in
    *[!A-Za-z0-9/._-]*) die "path may only contain letters, digits, ., _, -, /: $p" ;;
  esac
  [ "$p" = / ] && die "choose a dedicated path, not /"
  case "/$p/" in
    *'/../'*|*'/./'*) die "path must not contain . or ..: $p" ;;
  esac
  if have realpath; then realpath -m "$p"; else printf '%s' "$p"; fi
}

validate_port() {
  case "$1" in
    ''|*[!0-9]*) die "$2 must be a number" ;;
  esac
  [ "$1" -ge 1 ] && [ "$1" -le 65535 ] || die "$2 must be 1-65535"
}

normalize_unit() {
  local n=$1
  case "$n" in *.service) ;; *) n="$n.service" ;; esac
  case "${n%.service}" in
    ''|*[!A-Za-z0-9_.@-]*) die "invalid unit name: $1" ;;
  esac
  printf '%s' "$n"
}

check_no_system_unit() {
  local u=$1
  if systemctl is-active --quiet "$u" 2>/dev/null || systemctl is-enabled --quiet "$u" 2>/dev/null; then
    die "a system unit named $u exists; disable it first: sudo systemctl disable --now $u && sudo rm -f /etc/systemd/system/$u && sudo systemctl daemon-reload"
  fi
}

die_if_root() {
  [ "$(id -u)" -ne 0 ] || die "run this installer as the user who will own the install, not root"
}

preflight_user_systemd() {
  have systemctl || die "systemd is required (systemctl not found)"
  if ! systemctl --user show-environment >/dev/null 2>&1; then
    die "cannot reach the systemd user manager for $(id -un). Log in as this user (ssh) and retry; if needed set XDG_RUNTIME_DIR=/run/user/$(id -u) and run: loginctl enable-linger $(id -un)"
  fi
}

check_user_owned() {
  local p=$1 f
  if [ ! -e "$p" ]; then return 0; fi
  have find || return 0
  f="$(find "$p" -xdev -user 0 -print -quit 2>/dev/null || true)"
  [ -z "$f" ] || die "$p contains root-owned files (e.g. $f). Fix ownership first: sudo chown -R $(id -u):$(id -g) $p"
}

listener_pid() {
  local port=$1
  if have ss; then
    ss -ltnp 2>/dev/null | grep -F ":$port " | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | head -n 1
  elif have lsof; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null | head -n 1
  fi
}

port_in_use() {
  local port=$1
  if have ss; then
    ss -ltn 2>/dev/null | grep -qF ":$port "
    return
  fi
  if have lsof; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
    return
  fi
  (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null
}

check_port() { # check_port PORT UNIT LABEL
  local port=$1 unit=$2 label=$3 pid mainpid
  validate_port "$port" "$label"
  if ! port_in_use "$port"; then return 0; fi
  if systemctl --user is-active --quiet "$unit" 2>/dev/null; then
    mainpid="$(systemctl --user show -p MainPID --value "$unit" 2>/dev/null || true)"
    pid="$(listener_pid "$port")"
    if [ -n "$pid" ] && [ -n "$mainpid" ] && [ "$pid" = "$mainpid" ]; then return 0; fi
    if [ -z "$pid" ]; then
      warn "port $port is in use; assuming active unit $unit owns it"
      return 0
    fi
  fi
  die "port $port is in use${pid:+ by PID $pid}; choose another port with --port/--push-port"
}

absolute_bun() {
  case "$BUN" in
    /*) ;;
    *) BUN="$(cd "$(dirname "$BUN")" 2>/dev/null && pwd)/$(basename "$BUN")" ;;
  esac
}

find_bun() {
  local candidate
  if [ -n "$BUN_ARG" ]; then
    candidate="$BUN_ARG"
    if [ -d "$candidate" ]; then candidate="$candidate/bin/bun"; fi
    [ -x "$candidate" ] || die "Bun not executable: $candidate"
    BUN="$candidate"
    absolute_bun
    return 0
  fi
  if have bun; then BUN="$(command -v bun)"; absolute_bun; return 0; fi
  for candidate in "$HOME/.bun/bin/bun" "$PREFIX/bun/bin/bun" "${BUN_INSTALL:-}/bin/bun"; do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
      BUN="$candidate"
      absolute_bun
      return 0
    fi
  done
  return 1
}

install_bun() {
  local default_dir="$HOME/.bun" bun_home
  [ "$YES" = 1 ] || has_tty || die "Bun not found; install Bun or pass --bun PATH"
  ask BUN_DIR "Bun install path" "$default_dir"
  [ -n "$BUN_DIR" ] || BUN_DIR="$default_dir"
  BUN_DIR="$(norm_path "$BUN_DIR")"
  printf 'Install Bun under %s.\n' "$BUN_DIR"
  mkdir -p "$BUN_DIR" || die "could not create $BUN_DIR"
  bun_home="$(mktemp -d)"
  BUN_INSTALL="$BUN_DIR" HOME="$bun_home" bash -c 'curl -fsSL https://bun.sh/install | bash' \
    || { rm -rf "$bun_home"; die "Bun install failed"; }
  rm -rf "$bun_home"
  BUN="$BUN_DIR/bin/bun"
  [ -x "$BUN" ] || die "Bun was not installed at $BUN"
  BUN_NEW=1
  add_path "$BUN_DIR/bin"
}

ensure_packages() {
  local cmd pkg missing=() pkgs=() seen=" " p
  for cmd in curl git tar realpath install mktemp sed grep head tail sort ls find readlink chmod mv cp ln rm mkdir env systemctl; do
    have "$cmd" || missing+=("$cmd")
  done
  if [ "$PUSH" = 1 ]; then have openssl || missing+=(openssl); fi
  if [ -z "$BUN" ]; then have unzip || missing+=(unzip); fi
  if [ -f /etc/ssl/certs/ca-certificates.crt ] || pkg_installed ca-certificates; then :; else pkgs+=(ca-certificates); fi
  for cmd in "${missing[@]}"; do
    if [ "$cmd" = systemctl ]; then die "systemd is required (systemctl not found)"; fi
    case "$cmd" in
      curl) pkg=curl ;;
      git) pkg=git ;;
      tar) pkg=tar ;;
      realpath|install|mktemp|head|tail|sort|ls|readlink|chmod|mv|cp|ln|rm|mkdir|env) pkg=coreutils ;;
      sed) pkg=sed ;;
      grep) pkg=grep ;;
      find) pkg=findutils ;;
      openssl) pkg=openssl ;;
      unzip) pkg=unzip ;;
      *) pkg=$cmd ;;
    esac
    case "$seen" in *" $pkg "*) ;; *) seen="$seen$pkg "; pkgs+=("$pkg") ;; esac
  done
  if [ ${#pkgs[@]} -eq 0 ]; then
    note 'Requirements: all present'
    return 0
  fi
  note 'Missing packages: %s' "${pkgs[*]}"
  have apt-get || die "missing packages: ${pkgs[*]} (this installer supports Debian and Ubuntu for now)"
  local install_cmd="sudo apt-get install -y ${pkgs[*]}"
  have sudo || die "missing packages: ${pkgs[*]}. Install them as root: $install_cmd"
  if ! has_tty && ! sudo -n true 2>/dev/null; then
    die "missing packages: ${pkgs[*]}. Install them first: $install_cmd"
  fi
  if [ "$YES" != 1 ] && ! has_tty; then
    die "missing packages: ${pkgs[*]}. Install them first: $install_cmd (or rerun with --yes)"
  fi
  if [ "$YES" != 1 ] && ! confirm "Install missing packages with sudo?" Y; then
    die "missing packages: ${pkgs[*]}. Run: $install_cmd"
  fi
  apt_get update
  apt_get install -y "${pkgs[@]}"
}

write_unit() { # write_unit FILE CONTENT
  local file=$1 content=$2 tmp
  if [ -e "$file" ] && [ ! -O "$file" ]; then
    die "$file is not owned by $(id -un); fix it first: sudo chown $(id -u):$(id -g) $file"
  fi
  tmp="$(mktemp)"
  printf '%s\n' "$content" > "$tmp"
  install -m 0644 "$tmp" "$file"
  rm -f "$tmp"
}

relay_unit_content() {
  cat <<EOF
[Unit]
Description=Perch relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$PREFIX/current
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
}

push_unit_content() {
  cat <<EOF
[Unit]
Description=Perch push gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$PUSH_PREFIX
EnvironmentFile=$PUSH_PREFIX/push.env
ExecStart=$BUN gateway.ts
Restart=always
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full

[Install]
WantedBy=default.target
EOF
}

run_relay_cli() {
  ( cd "$RUN_DIR" && exec env -i PATH="$PATH" HOME="${HOME:-}" "$BUN" --env-file="$CONFIG_DIR/relay.env" server.ts "$@" )
}

install_wrapper() {
  local wrapper
  mkdir -p "$PREFIX/bin"
  wrapper="$(mktemp)"
  cat > "$wrapper" <<EOF
#!/bin/sh
set -e
cd "$PREFIX/current"
exec env -i PATH="\$PATH" HOME="\${HOME:-}" "$BUN" --env-file="$CONFIG_DIR/relay.env" server.ts "\$@"
EOF
  install -m 0755 "$wrapper" "$PREFIX/bin/perch-relay"
  rm -f "$wrapper"
  add_path "$PREFIX/bin"
}

write_relay_env() {
  local tmp
  case "$OLD_PUSH_URL$OLD_PUSH_KEY$PUBLIC_URL$PUSH_SECRET" in
    *[[:cntrl:]]*) die "relay settings must not contain control characters" ;;
  esac
  tmp="$(mktemp)"
  (
    umask 077
    {
      printf 'PORT=%s\nHOST=127.0.0.1\nPERCH_DB=%s\n' "$PORT" "$DB_PATH"
      [ -z "$PUBLIC_URL" ] || printf 'PERCH_PUBLIC_URL=%s\n' "$PUBLIC_URL"
      if [ "$PUSH" = 1 ]; then
        printf 'PUSH_GATEWAY=http://127.0.0.1:%s\nPUSH_GATEWAY_KEY=%s\n' "$PUSH_PORT" "$PUSH_SECRET"
      elif [ -n "$OLD_PUSH_URL" ] && [ -n "$OLD_PUSH_KEY" ]; then
        printf 'PUSH_GATEWAY=%s\nPUSH_GATEWAY_KEY=%s\n' "$OLD_PUSH_URL" "$OLD_PUSH_KEY"
      fi
      printf '%s\n' "$OLD_ENV" | while IFS= read -r line; do
        case "$line" in
          ""|PORT=*|HOST=*|PERCH_DB=*|PERCH_PUBLIC_URL=*|PUSH_GATEWAY=*|PUSH_GATEWAY_KEY=*) ;;
          *) printf '%s\n' "$line" ;;
        esac
      done
    } > "$tmp"
  )
  install -m 0600 "$tmp" "$CONFIG_DIR/relay.env"
  rm -f "$tmp"
}

write_push_env() {
  local tmp
  tmp="$(mktemp)"
  (
    umask 077
    {
      printf 'PORT=%s\nHOST=127.0.0.1\n' "$PUSH_PORT"
      printf 'APNS_KEY_FILE=%s\nAPNS_KEY_ID=%s\nAPNS_TEAM_ID=%s\nAPNS_TOPIC=%s\nAPNS_ENV=%s\n' \
        "$APNS_KEY_FILE" "$APNS_KEY_ID" "$APNS_TEAM_ID" "$APNS_TOPIC" "$APNS_ENV"
      printf 'PUSH_KEYS=%s\n' "$PUSH_KEYS_SPEC"
      printf '%s\n' "$OLD_PUSH_ENV" | while IFS= read -r line; do
        case "$line" in
          ""|PORT=*|HOST=*|APNS_KEY_FILE=*|APNS_KEY_ID=*|APNS_TEAM_ID=*|APNS_TOPIC=*|APNS_ENV=*|PUSH_KEYS=*) ;;
          *) printf '%s\n' "$line" ;;
        esac
      done
    } > "$tmp"
  )
  install -m 0600 "$tmp" "$PUSH_PREFIX/push.env"
  rm -f "$tmp"
}

choose_push_secret() {
  local spec=$1 relay_key=$2 entry secret name count=0 first="" chosen=""
  local IFS=','
  for entry in $spec; do
    name="${entry%%=*}"
    secret="${entry#*=}"
    [ "$name" != "$entry" ] || continue
    [ ${#secret} -ge 16 ] || continue
    count=$((count + 1))
    [ -n "$first" ] || first="$secret"
    if [ -n "$relay_key" ] && [ "$secret" = "$relay_key" ]; then chosen="$secret"; fi
  done
  if [ -n "$chosen" ]; then
    PUSH_KEYS_SPEC="$spec"
    PUSH_SECRET="$chosen"
    return
  fi
  if [ "$count" -eq 1 ]; then
    PUSH_KEYS_SPEC="$spec"
    PUSH_SECRET="$first"
    return
  fi
  local new
  new="$(openssl rand -hex 32)"
  if [ -n "$spec" ]; then PUSH_KEYS_SPEC="$spec,perch-relay=$new"; else PUSH_KEYS_SPEC="perch-relay=$new"; fi
  PUSH_SECRET="$new"
}

ensure_apns_key() {
  local src=$1 dest
  [ -f "$src" ] || die "APNs key not found: $src"
  [ -r "$src" ] || die "APNs key is not readable: $src"
  [ -O "$src" ] || die "APNs key is not owned by $(id -un): $src"
  openssl pkey -in "$src" -noout >/dev/null 2>&1 || die "APNs key is not a readable PEM private key: $src"
  case "$src" in
    "$PUSH_PREFIX"/*) dest="$src" ;;
    *)
      dest="$PUSH_PREFIX/AuthKey.p8"
      if [ "$src" != "$dest" ]; then
        if [ -f "$dest" ]; then cp -p "$dest" "$dest.bak-$(date +%s)"; fi
        install -m 0600 "$src" "$dest"
      fi
      ;;
  esac
  chmod 0600 "$dest" 2>/dev/null || true
  APNS_KEY_FILE="$dest"
}

resolve_push() {
  local base
  if [ -z "$PUSH_PREFIX" ]; then
    base="$(basename "$PREFIX")"
    case "$base" in
      *-server) PUSH_PREFIX="$(dirname "$PREFIX")/${base%-server}-push" ;;
      *) PUSH_PREFIX="${PREFIX}-push" ;;
    esac
  fi
  PUSH_PREFIX="$(norm_path "$PUSH_PREFIX")"
  mkdir -p "$PUSH_PREFIX"
  chmod 0755 "$PUSH_PREFIX" 2>/dev/null || true
  check_user_owned "$PUSH_PREFIX"
  OLD_PUSH_ENV="$(cat "$PUSH_PREFIX/push.env" 2>/dev/null || true)"
  if [ "$PUSH_PORT_SET" = 0 ]; then
    if [ -n "$(env_get "$OLD_PUSH_ENV" PORT)" ]; then PUSH_PORT="$(env_get "$OLD_PUSH_ENV" PORT)"; else PUSH_PORT=8788; fi
  fi
  validate_port "$PUSH_PORT" "--push-port"
  if [ "$PUSH_PORT" = "$PORT" ]; then die "--push-port must differ from --port"; fi

  if [ "$APNS_KEY_FILE_SET" = 0 ]; then APNS_KEY_FILE="$(env_get "$OLD_PUSH_ENV" APNS_KEY_FILE)"; fi
  if [ "$APNS_KEY_ID_SET" = 0 ]; then APNS_KEY_ID="$(env_get "$OLD_PUSH_ENV" APNS_KEY_ID)"; fi
  if [ "$APNS_TEAM_ID_SET" = 0 ]; then APNS_TEAM_ID="$(env_get "$OLD_PUSH_ENV" APNS_TEAM_ID)"; fi
  if [ "$APNS_TOPIC_SET" = 0 ]; then APNS_TOPIC="$(env_get "$OLD_PUSH_ENV" APNS_TOPIC)"; fi
  if [ "$APNS_ENV_SET" = 0 ]; then APNS_ENV="$(env_get "$OLD_PUSH_ENV" APNS_ENV)"; fi
  if [ -z "$APNS_ENV" ]; then APNS_ENV=production; fi
  case "$APNS_ENV" in production|development) ;; sandbox) APNS_ENV=development ;; *) die "APNS_ENV must be production or development" ;; esac

  local missing=""
  [ -n "$APNS_KEY_FILE" ] || missing="$missing --apns-key-file"
  [ -n "$APNS_KEY_ID" ] || missing="$missing --apns-key-id"
  [ -n "$APNS_TEAM_ID" ] || missing="$missing --apns-team-id"
  [ -n "$APNS_TOPIC" ] || missing="$missing --apns-topic"
  if [ -n "$missing" ]; then
    if [ "$YES" != 1 ] && has_tty; then
      [ -n "$APNS_KEY_FILE" ] || ask APNS_KEY_FILE "APNs key file (.p8)" ""
      [ -n "$APNS_KEY_ID" ] || ask APNS_KEY_ID "APNs key ID" ""
      [ -n "$APNS_TEAM_ID" ] || ask APNS_TEAM_ID "Apple team ID" ""
      [ -n "$APNS_TOPIC" ] || ask APNS_TOPIC "APNs topic (bundle ID)" ""
    fi
    missing=""
    [ -n "$APNS_KEY_FILE" ] || missing="$missing --apns-key-file"
    [ -n "$APNS_KEY_ID" ] || missing="$missing --apns-key-id"
    [ -n "$APNS_TEAM_ID" ] || missing="$missing --apns-team-id"
    [ -n "$APNS_TOPIC" ] || missing="$missing --apns-topic"
    [ -z "$missing" ] || die "--push needs:$missing (or an existing push.env)"
  fi
  case "$APNS_KEY_FILE$APNS_KEY_ID$APNS_TEAM_ID$APNS_TOPIC" in
    *[[:cntrl:]]*) die "APNs settings must not contain control characters" ;;
  esac
  APNS_KEY_FILE="$(norm_path "$APNS_KEY_FILE")"
  ensure_apns_key "$APNS_KEY_FILE"
  local relay_key
  relay_key="$(env_get "$OLD_ENV" PUSH_GATEWAY_KEY)"
  choose_push_secret "$(env_get "$OLD_PUSH_ENV" PUSH_KEYS)" "$relay_key"
  case "$PUSH_KEYS_SPEC$PUSH_SECRET" in
    *[[:cntrl:]]*) die "push keys must not contain control characters" ;;
  esac
}

prune_releases() {
  local current d n=0
  current="$(readlink -f "$PREFIX/current" 2>/dev/null || true)"
  have find || return 0
  while IFS= read -r d; do
    [ -n "$d" ] || continue
    n=$((n + 1))
    if [ "$n" -le 5 ]; then continue; fi
    if [ "$(readlink -f "$d")" = "$current" ]; then continue; fi
    rm -rf -- "$d"
  done < <(find "$PREFIX/releases" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' 2>/dev/null | sort -rn | sed 's/^[^ ]* //')
}

ensure_linger() {
  local user linger
  user="$(id -un)"
  have loginctl || { warn "loginctl not found; the service starts on your next login"; return 0; }
  linger="$(loginctl show-user "$user" -p Linger 2>/dev/null | sed -n 's/^Linger=//p')"
  if [ "$linger" = yes ]; then return 0; fi
  if loginctl enable-linger "$user" >/dev/null 2>&1; then
    printf 'Linger enabled for %s.\n' "$user"
    return 0
  fi
  if [ "$YES" != 1 ] && ! has_tty; then
    warn "linger is not enabled; run: sudo loginctl enable-linger $user"
    return 0
  fi
  if confirm "Enable linger for $user with sudo (start at boot without login)?" Y; then
    if have sudo; then
      as_root loginctl enable-linger "$user" || warn "could not enable linger"
    else
      warn "run: sudo loginctl enable-linger $user"
    fi
  else
    warn "run: sudo loginctl enable-linger $user"
  fi
}

start_unit() { # start_unit UNIT LABEL
  local u=$1 label=$2
  if ! systemctl --user enable "$u" >/dev/null 2>&1; then
    warn "could not enable $u"
    FAILED=1
  fi
  if ! systemctl --user restart "$u" >/dev/null 2>&1; then
    warn "$label did not start"
    systemctl --user status "$u" --no-pager 2>&1 | sed -n '1,12p' || true
    if have journalctl; then journalctl --user -u "$u" -n 20 --no-pager 2>&1 | tail -20 || true; fi
    FAILED=1
  fi
}

caddy_site_block() {
  cat <<EOF

$DOMAIN {
	header Strict-Transport-Security "max-age=31536000"
	reverse_proxy 127.0.0.1:$PORT {
		header_up X-Real-IP {remote_host}
	}
}
EOF
}

install_caddy() {
  if pkg_installed caddy; then return 0; fi
  local deps=() tmp
  if ! have gpg; then deps+=(gnupg); fi
  if ! pkg_installed ca-certificates; then deps+=(ca-certificates); fi
  if [ ${#deps[@]} -gt 0 ]; then
    apt_get update || return 1
    apt_get install -y "${deps[@]}" || return 1
  fi
  local keyring=/usr/share/keyrings/caddy-stable-archive-keyring.gpg
  local sources=/etc/apt/sources.list.d/caddy-stable.list
  if [ ! -s "$keyring" ] || ! as_root test -f "$sources"; then
    tmp="$(mktemp)"
    if ! curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | as_root gpg --dearmor > "$tmp"; then
      rm -f "$tmp"; return 1
    fi
    if ! as_root install -m 0644 "$tmp" "$keyring"; then rm -f "$tmp"; return 1; fi
    rm -f "$tmp"
    tmp="$(mktemp)"
    if ! curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > "$tmp"; then
      rm -f "$tmp"; return 1
    fi
    if ! as_root install -m 0644 "$tmp" "$sources"; then rm -f "$tmp"; return 1; fi
    rm -f "$tmp"
    apt_get update || return 1
  fi
  apt_get install -y caddy || return 1
}

add_caddy_site() {
  local cf=/etc/caddy/Caddyfile site bak=""
  if [ -f "$cf" ]; then
    bak="$cf.bak-perch-$(date +%s)"
    as_root cp -- "$cf" "$bak" || return 1
  fi
  site="$(mktemp)"
  caddy_site_block > "$site"
  if ! as_root tee -a -- "$cf" < "$site" >/dev/null; then rm -f "$site"; return 1; fi
  rm -f "$site"
  if as_root caddy validate --config "$cf" >/dev/null 2>&1; then
    if ! as_root systemctl enable --now caddy; then
      warn "Caddy enabled but could not start"
      CADDY_ACTION="failed to start Caddy"
      return 1
    fi
    as_root systemctl reload caddy 2>/dev/null || as_root systemctl restart caddy 2>/dev/null || warn "could not reload Caddy"
    CADDY_ACTION="added $DOMAIN to $cf"
  else
    if [ -n "$bak" ]; then as_root cp -- "$bak" "$cf" || warn "could not restore $bak"; else as_root rm -f -- "$cf" || true; fi
    warn "Caddy rejected the new site; fix $cf yourself"
    CADDY_ACTION="failed; fix $cf"
  fi
  return 0
}

manage_caddy() {
  if [ "$NO_CADDY" = 1 ]; then CADDY_ACTION="skipped (--no-caddy)"; return 0; fi
  if [ -z "$DOMAIN" ]; then CADDY_ACTION="not requested"; return 0; fi
  local cf=/etc/caddy/Caddyfile
  if [ -r "$cf" ]; then
    if grep -qF -- "$DOMAIN {" "$cf"; then
      CADDY_ACTION="existing site in $cf"
      grep -qF -- 'header_up X-Real-IP {remote_host}' "$cf" || warn "existing $DOMAIN block has no X-Real-IP; sign-in rate limits will see 127.0.0.1"
      return 0
    fi
    if ! have caddy; then
      if [ "$YES" = 1 ] || { has_tty && confirm "Caddy is not installed. Install it with sudo?" Y; }; then
        install_caddy || { warn "could not install Caddy; skipping"; CADDY_ACTION="skipped; Caddy missing"; return 0; }
      else
        warn "Caddy is not installed; skipping public TLS"
        CADDY_ACTION="skipped; Caddy missing"
        return 0
      fi
    fi
    if [ "$YES" = 1 ] || { has_tty && confirm "Add $DOMAIN to $cf with sudo?" Y; }; then
      if ! add_caddy_site; then
        warn "could not add the Caddy site"
        CADDY_ACTION="skipped; Caddy update failed"
      fi
    else
      warn "skipping Caddy; add the block manually"
      CADDY_ACTION="skipped by user"
    fi
    return 0
  fi
  # Unreadable or absent Caddyfile: use sudo only with confirmation.
  if [ "$YES" != 1 ] && ! has_tty; then
    warn "cannot read $cf without sudo; skipping Caddy"
    CADDY_ACTION="skipped; $cf unreadable"
    return 0
  fi
  if ! confirm "Use sudo to inspect and configure Caddy for $DOMAIN?" Y; then
    warn "skipping Caddy; add the block manually"
    CADDY_ACTION="skipped by user"
    return 0
  fi
  if ! have caddy; then install_caddy || { warn "could not install Caddy"; CADDY_ACTION="skipped; Caddy missing"; return 0; }; fi
  if as_root grep -qF -- "$DOMAIN {" "$cf" 2>/dev/null; then
    CADDY_ACTION="existing site in $cf"
    return 0
  fi
  if ! add_caddy_site; then
    warn "could not add the Caddy site"
    CADDY_ACTION="skipped; Caddy update failed"
  fi
}

account_setup() {
  local accounts out args safe_out pw
  if [ "$NO_ACCOUNT" = 1 ]; then return 0; fi
  ACCOUNT="${ACCOUNT,,}"
  case "$ACCOUNT" in
    [a-z0-9]*) ;;
    *) die "account name must start with a lowercase letter or digit" ;;
  esac
  case "$ACCOUNT" in
    *[!a-z0-9._-]*) die "account name may only contain lowercase letters, digits, ., _, -" ;;
  esac
  [ ${#ACCOUNT} -le 64 ] || die "account name is too long"
  if ! accounts="$(run_relay_cli account list 2>&1)"; then
    die "account list failed: $accounts"
  fi
  if printf '%s' "$accounts" | grep -Fq "\"name\": \"$ACCOUNT\""; then
    printf 'Account %s already exists; password unchanged.\n' "$ACCOUNT"
    if [ -f "$PASSWORD_FILE" ]; then printf 'Password file left at %s.\n' "$PASSWORD_FILE"; fi
    return 0
  fi
  args=(account add "$ACCOUNT" --password)
  printf '%s' "$accounts" | grep -Fq '"name"' || args=(account add "$ACCOUNT" --adopt --password)
  if ! out="$(run_relay_cli "${args[@]}" 2>&1)"; then
    if ! accounts="$(run_relay_cli account list 2>&1 || true)" || ! printf '%s' "$accounts" | grep -Fq "\"name\": \"$ACCOUNT\""; then
      die "account add failed: $(printf '%s\n' "$out" | grep -v '^one-time password: ' || true)"
    fi
  fi
  safe_out="$(printf '%s\n' "$out" | grep -v '^one-time password: ' || true)"
  [ -z "$safe_out" ] || printf '%s\n' "$safe_out"
  pw="$(printf '%s\n' "$out" | sed -n 's/^one-time password: //p' | head -n 1)"
  ACCOUNT_CREATED=1
  if [ -n "$pw" ]; then
    ( umask 077; { printf 'account: %s\n' "$ACCOUNT"; printf 'one-time password: %s\n' "$pw"; } > "$PASSWORD_FILE" )
    chmod 0600 "$PASSWORD_FILE"
    printf 'One-time password written to %s (0600).\n' "$PASSWORD_FILE"
  else
    warn "no one-time password in the account output; use $PREFIX/bin/perch-relay account passwd $ACCOUNT"
  fi
}

usage() {
  cat <<'EOF'
usage:
  setup.sh [--prefix DIR] [--account NAME|--no-account] [--port PORT]
           [--domain HOST] [--public-url URL] [--no-caddy]
           [--data-dir DIR] [--config-dir DIR] [--bun PATH]
           [--source PATH] [--repo URL] [--branch BRANCH] [--version NAME]
           [--unit NAME] [--yes]
  setup.sh --push [--push-prefix DIR] [--push-port PORT]
           [--apns-key-file PATH] [--apns-key-id ID] [--apns-team-id ID]
           [--apns-topic TOPIC] [--apns-env production|development]
           [--push-unit NAME]
  setup.sh --help

  Installs the relay as your user under PREFIX (default ~/.perchserver).
  Sudo is used only for missing system packages, optional Caddy/TLS setup,
  and a last-resort linger enable. Everything Perch-owned lives under
  PREFIX and belongs to you.
  --push also installs a loopback push gateway for your own APNs key (advanced).
EOF
}

parse_args() {
  case "${1:-}" in
    -h|--help) usage; exit 0 ;;
  esac
  while [ $# -gt 0 ]; do
    case "$1" in
      --prefix|--data-dir|--config-dir|--source|--repo|--branch|--version|--domain|--account|--port|--bun|--public-url|--unit|--push-prefix|--push-port|--push-unit|--apns-key-file|--apns-key-id|--apns-team-id|--apns-topic|--apns-env)
        [ $# -ge 2 ] || die "$1 needs a value" ;;
    esac
    case "$1" in
      --prefix) PREFIX="${2:-}"; shift 2 ;;
      --data-dir) DATA_DIR="${2:-}"; shift 2 ;;
      --config-dir) CONFIG_DIR="${2:-}"; shift 2 ;;
      --source) SOURCE="${2:-}"; shift 2 ;;
      --repo) REPO_URL="${2:-}"; shift 2 ;;
      --branch) BRANCH="${2:-}"; shift 2 ;;
      --version) RELEASE="${2:-}"; shift 2 ;;
      --domain) DOMAIN="${2:-}"; shift 2 ;;
      --account) ACCOUNT="${2:-}"; ACCOUNT_SET=1; shift 2 ;;
      --no-account) NO_ACCOUNT=1; shift ;;
      --port) PORT="${2:-}"; PORT_SET=1; shift 2 ;;
      --bun) BUN_ARG="${2:-}"; shift 2 ;;
      --public-url) PUBLIC_URL="${2:-}"; PUBLIC_URL_SET=1; shift 2 ;;
      --no-caddy) NO_CADDY=1; shift ;;
      --unit) UNIT="${2:-}"; shift 2 ;;
      --push) PUSH=1; shift ;;
      --push-prefix) PUSH_PREFIX="${2:-}"; PUSH_OPTS=1; shift 2 ;;
      --push-port) PUSH_PORT="${2:-}"; PUSH_PORT_SET=1; PUSH_OPTS=1; shift 2 ;;
      --push-unit) PUSH_UNIT="${2:-}"; PUSH_OPTS=1; shift 2 ;;
      --apns-key-file) APNS_KEY_FILE="${2:-}"; APNS_KEY_FILE_SET=1; PUSH_OPTS=1; shift 2 ;;
      --apns-key-id) APNS_KEY_ID="${2:-}"; APNS_KEY_ID_SET=1; PUSH_OPTS=1; shift 2 ;;
      --apns-team-id) APNS_TEAM_ID="${2:-}"; APNS_TEAM_ID_SET=1; PUSH_OPTS=1; shift 2 ;;
      --apns-topic) APNS_TOPIC="${2:-}"; APNS_TOPIC_SET=1; PUSH_OPTS=1; shift 2 ;;
      --apns-env) APNS_ENV="${2:-}"; APNS_ENV_SET=1; PUSH_OPTS=1; shift 2 ;;
      --yes|-y) YES=1; shift ;;
      -h|--help) usage; exit 0 ;;
      --layout|--server|--code|--push-url|--push-key)
        die "$1 is no longer supported; the relay installs as your user. See --help" ;;
      *) die "unknown option: $1" ;;
    esac
  done
  if [ "$NO_ACCOUNT" = 1 ] && [ "$ACCOUNT_SET" = 1 ]; then
    die "--account and --no-account are mutually exclusive"
  fi
  if [ "$PUSH" = 0 ] && [ "$PUSH_OPTS" = 1 ]; then
    die "push options require --push"
  fi
}

resolve_relay_paths() {
  PREFIX="${PREFIX:-$HOME/.perchserver}"
  PREFIX="$(norm_path "$PREFIX")"
  CONFIG_DIR="${CONFIG_DIR:-$PREFIX}"
  CONFIG_DIR="$(norm_path "$CONFIG_DIR")"
  OLD_ENV="$(cat "$CONFIG_DIR/relay.env" 2>/dev/null || true)"
  OLD_PORT="$(env_get "$OLD_ENV" PORT)"
  OLD_DB="$(env_get "$OLD_ENV" PERCH_DB)"
  OLD_PUBLIC="$(env_get "$OLD_ENV" PERCH_PUBLIC_URL)"
  OLD_PUSH_URL="$(env_get "$OLD_ENV" PUSH_GATEWAY)"
  OLD_PUSH_KEY="$(env_get "$OLD_ENV" PUSH_GATEWAY_KEY)"

  if [ "$PORT_SET" = 0 ]; then
    if [ -n "$OLD_PORT" ]; then PORT="$OLD_PORT"; else PORT=8787; fi
  fi
  validate_port "$PORT" "--port"

  if [ -n "$DATA_DIR" ]; then
    DATA_DIR="$(norm_path "$DATA_DIR")"
    DB_PATH="$DATA_DIR/perch.db"
  elif [ -n "$OLD_DB" ]; then
    DB_PATH="$OLD_DB"
    DATA_DIR="$(dirname "$DB_PATH")"
  else
    DATA_DIR="$PREFIX/data"
    DB_PATH="$DATA_DIR/perch.db"
  fi
  DATA_DIR="$(norm_path "$DATA_DIR")"
  DB_PATH="$(norm_path "$DB_PATH")"

  if [ "$PUBLIC_URL_SET" = 0 ]; then
    if [ -n "$DOMAIN" ]; then PUBLIC_URL="https://$DOMAIN"; elif [ -n "$OLD_PUBLIC" ]; then PUBLIC_URL="$OLD_PUBLIC"; fi
  fi
  if [ -n "$PUBLIC_URL" ]; then
    case "$PUBLIC_URL" in http://*|https://*) ;; *) die "--public-url must start with http:// or https://" ;; esac
    PUBLIC_URL="${PUBLIC_URL%/}"
  fi
  if [ "$PUBLIC_URL_SET" = 1 ]; then NO_CADDY=1; fi
  if [ -n "$DOMAIN" ]; then
    case "$DOMAIN" in *[!A-Za-z0-9.-]*|.*|*.) die "invalid hostname: $DOMAIN" ;; esac
  fi
  case "$PUBLIC_URL$DOMAIN" in
    *[[:cntrl:]]*) die "public URL/hostname must not contain control characters" ;;
  esac

  UNIT="$(normalize_unit "$UNIT")"
  PUSH_UNIT="$(normalize_unit "$PUSH_UNIT")"
  if [ -n "$RELEASE" ]; then
    case "$RELEASE" in ""|.|..|*/*|*[!A-Za-z0-9._-]*) die "invalid release name: '$RELEASE'" ;; esac
  else
    RELEASE="$(date +%Y%m%d%H%M%S)"
  fi

  if [ "$NO_ACCOUNT" = 0 ] && [ -z "$ACCOUNT" ]; then
    if [ "$YES" = 1 ] || ! has_tty; then
      die "--account NAME is required (or pass --no-account)"
    fi
    ask ACCOUNT "Account name (empty to skip)" ""
    [ -n "$ACCOUNT" ] || NO_ACCOUNT=1
  fi
  if [ "$NO_ACCOUNT" = 0 ]; then
    ACCOUNT="${ACCOUNT,,}"
    case "$ACCOUNT" in
      [a-z0-9]*) ;;
      *) die "account name must start with a lowercase letter or digit" ;;
    esac
    case "$ACCOUNT" in
      *[!a-z0-9._-]*) die "account name may only contain lowercase letters, digits, ., _, -" ;;
    esac
    [ ${#ACCOUNT} -le 64 ] || die "account name is too long"
  fi
}

main() {
  parse_args "$@"
  die_if_root
  preflight_user_systemd
  shell_rc
  resolve_relay_paths
  check_no_system_unit "$UNIT"
  if [ "$PUSH" = 1 ]; then check_no_system_unit "$PUSH_UNIT"; fi
  check_user_owned "$PREFIX"
  check_user_owned "$CONFIG_DIR"
  if [ -e "$DATA_DIR" ]; then check_user_owned "$DATA_DIR"; fi

  local bun_found=0
  if find_bun; then bun_found=1; fi
  ensure_packages
  if [ "$bun_found" = 0 ]; then install_bun; fi
  printf 'Bun: %s (%s)\n' "$BUN" "$("$BUN" --version)"

  if [ "$PUSH" = 1 ]; then resolve_push; fi
  check_port "$PORT" "$UNIT" "--port"
  if [ "$PUSH" = 1 ]; then check_port "$PUSH_PORT" "$PUSH_UNIT" "--push-port"; fi

  say "Install"
  mkdir -p "$PREFIX/releases" "$PREFIX/bin"
  chmod 0755 "$PREFIX" "$PREFIX/releases" "$PREFIX/bin" 2>/dev/null || true
  mkdir -p "$DATA_DIR"
  chmod 0700 "$DATA_DIR" 2>/dev/null || true
  mkdir -p "$CONFIG_DIR"
  [ "$CONFIG_DIR" = "$PREFIX" ] || chmod 0700 "$CONFIG_DIR" 2>/dev/null || true
  PASSWORD_FILE="$CONFIG_DIR/account-password.txt"

  STAGING="$(mktemp -d "$PREFIX/releases/.staging-$RELEASE-XXXXXX")"
  trap 'if [ -n "${STAGING:-}" ] && [ -d "$STAGING" ]; then rm -rf -- "$STAGING"; fi' EXIT
  fetch_code "$STAGING"
  [ -f "$STAGING/server.ts" ] || die "this checkout has no server.ts (use the server repository)"
  if [ "$PUSH" = 1 ]; then
    [ -f "$STAGING/gateway.ts" ] && [ -f "$STAGING/apns.ts" ] || die "this checkout has no gateway.ts/apns.ts"
  fi
  local release="$PREFIX/releases/$RELEASE" n=2
  while [ -e "$release" ]; do release="$PREFIX/releases/$RELEASE.$n"; n=$((n + 1)); done
  mv "$STAGING" "$release"
  STAGING=""
  RUN_DIR="$release"
  say "Configuration"
  write_relay_env
  if [ "$PUSH" = 1 ]; then write_push_env; fi

  say "Account"
  account_setup

  install_wrapper
  ln -sfn -- "$release" "$PREFIX/current"

  say "Service"
  local unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
  install -d -m 0755 "$unit_dir"
  write_unit "$unit_dir/$UNIT" "$(relay_unit_content)"
  if [ "$PUSH" = 1 ]; then write_unit "$unit_dir/$PUSH_UNIT" "$(push_unit_content)"; fi
  systemctl --user daemon-reload

  if [ "$PUSH" = 1 ]; then
    mkdir -p "$PUSH_PREFIX"
    chmod 0755 "$PUSH_PREFIX" 2>/dev/null || true
    install -m 0644 "$release/gateway.ts" "$PUSH_PREFIX/.gateway.ts.$$"
    install -m 0644 "$release/apns.ts" "$PUSH_PREFIX/.apns.ts.$$"
    mv -f "$PUSH_PREFIX/.gateway.ts.$$" "$PUSH_PREFIX/gateway.ts"
    mv -f "$PUSH_PREFIX/.apns.ts.$$" "$PUSH_PREFIX/apns.ts"
  fi

  ensure_linger
  start_unit "$UNIT" "perch-relay"
  if [ "$PUSH" = 1 ]; then start_unit "$PUSH_UNIT" "perch-gateway"; fi

  say "Caddy"
  manage_caddy

  say "Health"
  local methods="" code i
  for ((i = 0; i < 30; i++)); do
    if methods="$(curl -fsS --max-time 2 "http://127.0.0.1:$PORT/v1/auth/methods" 2>/dev/null)"; then break; fi
    sleep 0.5
  done
  if [ -n "$methods" ]; then
    printf '%s\n' "$methods"
  else
    warn "relay did not answer on 127.0.0.1:$PORT"
    FAILED=1
  fi
  printf 'perch-relay: '; systemctl --user is-active "$UNIT" || true
  if [ "$PUSH" = 1 ]; then
    printf 'perch-gateway: '; systemctl --user is-active "$PUSH_UNIT" || true
    code=""
    for ((i = 0; i < 20; i++)); do
      code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 -X POST "http://127.0.0.1:$PUSH_PORT/v1/push" 2>/dev/null || true)"
      if [ "$code" = 401 ]; then break; fi
      sleep 0.5
    done
    if [ "$code" != 401 ]; then
      warn "gateway probe returned ${code:-none} (expected 401)"
      FAILED=1
      if have journalctl; then journalctl --user -u "$PUSH_UNIT" -n 20 --no-pager 2>&1 | tail -20 || true; fi
    fi
  fi

  if [ -n "$PUBLIC_URL" ]; then
    local body=""
    for ((i = 0; i < 20; i++)); do
      if body="$(curl -fsS --max-time 2 "$PUBLIC_URL/v1/auth/methods" 2>/dev/null)"; then break; fi
      sleep 1.5
    done
    if [ -z "$body" ]; then
      warn "public URL $PUBLIC_URL is not answering; check DNS, ports 80/443, and the TLS proxy"
    fi
  fi

  if [ "$FAILED" = 0 ]; then prune_releases || true; fi

  say "Done"
  printf 'Relay:  http://127.0.0.1:%s\n' "$PORT"
  if [ -n "$PUBLIC_URL" ]; then printf 'Public: %s\n' "$PUBLIC_URL"; fi
  printf 'Data:   %s\n' "$DATA_DIR"
  printf 'Config: %s\n' "$CONFIG_DIR/relay.env"
  if [ "$PUSH" = 1 ]; then
    printf 'Push:   http://127.0.0.1:%s (gateway %s)\n' "$PUSH_PORT" "$PUSH_UNIT"
    printf 'Push config: %s\n' "$PUSH_PREFIX/push.env"
  fi
  if [ -n "$CADDY_ACTION" ]; then printf 'Caddy:  %s\n' "$CADDY_ACTION"; fi
  if [ "$ACCOUNT_CREATED" = 1 ]; then
    printf 'Account: %s (password file %s)\n' "$ACCOUNT" "$PASSWORD_FILE"
  elif [ "$NO_ACCOUNT" = 1 ]; then
    local accounts_hint="" adopt_flag="--adopt"
    if accounts_hint="$("$PREFIX/bin/perch-relay" account list 2>/dev/null)"; then
      if printf '%s' "$accounts_hint" | grep -Fq '"name"'; then adopt_flag=""; fi
    fi
    todo 'No account created. Create one with:'
    todo '  %s account add <name> %s--password' "$PREFIX/bin/perch-relay" "${adopt_flag:+$adopt_flag }"
  elif [ -n "$ACCOUNT" ]; then
    printf 'Account: %s\n' "$ACCOUNT"
  fi
  todo 'Laptop code (single use, 10 minutes):'
  todo '  %s pair machine' "$PREFIX/bin/perch-relay"
  note 'Update: rerun this installer with the same options; it preserves the account, relay.env, and push secrets.'
  say "Shell"
  if [ -n "$RC_FILE" ]; then note 'Shell profile %s (open a new shell or source it):' "$RC_FILE"
  else note 'Add these lines to your shell profile:'; fi
  local line
  for line in "${SHELL_LINES[@]}"; do todo '  %s' "$line"; done
  exit "$FAILED"
}

main "$@"
