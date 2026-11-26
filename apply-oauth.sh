#!/usr/bin/env bash
# Apply GitHub/Google OAuth clients already stored on this host, and update the relay's current
# release from GitHub. Client values are read and written only on this host: they are never
# printed, copied off the host, or embedded in this script.
#
#   bash apply-oauth.sh [--prefix DIR] [--oauth-dir DIR] [--ref REF] [--skip-code|--skip-oauth]
#                       [--service UNIT] [--providers LIST] [--public-url URL]
#                       [--no-restart] [--dry-run]
#
# Defaults match a user-mode install at ~/services/perch/perch-server. Run as the relay's user.
set -euo pipefail

PREFIX="${PERCH_PREFIX:-$HOME/services/perch/perch-server}"
OAUTH_DIR=""
REPO="chalone0808/perch-relay"
REF="e8599f4"
SERVICE="perch-relay"
PROVIDERS="github,google"
PUBLIC_URL=""
DO_CODE=1
DO_OAUTH=1
DO_RESTART=1
DRY_RUN=0

usage() {
  sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '%s\n' "$*"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="${2:-}"; shift 2 ;;
    --oauth-dir) OAUTH_DIR="${2:-}"; shift 2 ;;
    --ref) REF="${2:-}"; shift 2 ;;
    --repo) REPO="${2:-}"; shift 2 ;;
    --service) SERVICE="${2:-}"; shift 2 ;;
    --providers) PROVIDERS="${2:-}"; shift 2 ;;
    --public-url) PUBLIC_URL="${2:-}"; shift 2 ;;
    --skip-code) DO_CODE=0; shift ;;
    --skip-oauth) DO_OAUTH=0; shift ;;
    --no-restart) DO_RESTART=0; shift ;;
    --dry-run) DRY_RUN=1; DO_RESTART=0; shift ;;
    -h | --help) usage; exit 0 ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
done

[ "$(id -u)" -ne 0 ] || die "run as the user who owns the relay, not root"
[ -n "$PREFIX" ] || die "--prefix is empty"
PREFIX="${PREFIX%/}"
[ -d "$PREFIX" ] || die "no such prefix: $PREFIX"
[ -f "$PREFIX/relay.env" ] || die "missing $PREFIX/relay.env"
[ -d "$PREFIX/current" ] || die "missing $PREFIX/current"
OAUTH_DIR="${OAUTH_DIR:-$PREFIX/oauth}"
ENV_FILE="$PREFIX/oauth.env"
SERVICE_NAME="${SERVICE%.service}.service"
SYSTEMD_USER_DIR="${SYSTEMD_USER_DIR:-$HOME/.config/systemd/user}"
DROPIN_DIR="$SYSTEMD_USER_DIR/$SERVICE_NAME.d"
DROPIN="$DROPIN_DIR/oauth.conf"
[[ "$SERVICE_NAME" =~ ^[A-Za-z0-9_.@-]+$ ]] || die "invalid service name: $SERVICE_NAME"
[[ "$PROVIDERS" =~ ^(github|google|apple)(,(github|google|apple))*$ ]] || die "invalid --providers: $PROVIDERS"

command -v curl >/dev/null || die "curl is required"
command -v python3 >/dev/null || die "python3 is required"
if [ "$DO_RESTART" -eq 1 ]; then
  command -v systemctl >/dev/null || die "systemctl is required"
fi

if [ "$DO_CODE" -eq 1 ]; then
  for f in auth.ts accounts.ts server.ts; do
    [ -f "$PREFIX/current/$f" ] || die "missing $PREFIX/current/$f"
  done
fi
if [ "$DO_OAUTH" -eq 1 ]; then
  [ -d "$OAUTH_DIR" ] || die "missing $OAUTH_DIR"
fi

if [ -z "$PUBLIC_URL" ]; then
  PUBLIC_URL="$(sed -n 's/^PERCH_PUBLIC_URL=//p' "$PREFIX/relay.env" | tail -n 1 | tr -d '\r' | sed -e 's/"//g' -e "s/'//g")"
fi
PUBLIC_URL="${PUBLIC_URL%/}"

export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ] && [ -S "$XDG_RUNTIME_DIR/bus" ]; then
  export DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"
fi

timestamp="$(date +%Y%m%d%H%M%S)-$$"
stage_dir=""
staged_env=""
env_tmp=""
code_backup=""
env_backup=""
oauth_backup=""
dropin_backup=""
changed=0

cleanup_stage() {
  if [ -n "$stage_dir" ] && [ -d "$stage_dir" ]; then rm -rf "$stage_dir"; fi
  if [ -n "$staged_env" ] && [ -f "$staged_env" ]; then rm -f "$staged_env"; fi
  if [ -n "$env_tmp" ] && [ -f "$env_tmp" ]; then rm -f "$env_tmp"; fi
}
trap cleanup_stage EXIT

drop_rollback() {
  if [ -n "$oauth_backup" ]; then rm -f "$oauth_backup"; fi
  if [ -n "$dropin_backup" ]; then rm -f "$dropin_backup"; fi
  oauth_backup=""
  dropin_backup=""
}

rollback() {
  log "restoring the previous code and configuration"
  if [ -n "$code_backup" ] && [ -d "$code_backup" ]; then
    cp -p "$code_backup"/*.ts "$PREFIX/current/" 2>/dev/null || true
  fi
  if [ -n "$env_backup" ] && [ -f "$env_backup" ]; then
    cp -p "$env_backup" "$PREFIX/relay.env" && chmod 600 "$PREFIX/relay.env"
  fi
  if [ -n "$oauth_backup" ] && [ -f "$oauth_backup" ]; then
    cp -p "$oauth_backup" "$ENV_FILE" && chmod 600 "$ENV_FILE"
  else
    rm -f "$ENV_FILE"
  fi
  if [ -n "$dropin_backup" ] && [ -f "$dropin_backup" ]; then
    cp -p "$dropin_backup" "$DROPIN" && chmod 600 "$DROPIN"
  else
    rm -f "$DROPIN"
  fi
  systemctl --user daemon-reload >/dev/null 2>&1 || true
  systemctl --user restart "$SERVICE_NAME" >/dev/null 2>&1 || true
  drop_rollback
}

# Read the client files before changing anything, so a missing or ambiguous value stops the
# script while the running relay is untouched.
if [ "$DO_OAUTH" -eq 1 ]; then
  umask 077
  staged_env="$(mktemp "$PREFIX/.oauth.env.XXXXXX")"
  chmod 600 "$staged_env"
  log "reading OAuth clients from $OAUTH_DIR (values are not printed)"
  python3 - "$OAUTH_DIR" "$staged_env" <<'PY'
import json
import pathlib
import re
import sys
from collections import defaultdict

root, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
wanted = ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET"]
candidates = defaultdict(set)
value_ok = re.compile(r"[A-Za-z0-9._~:/+-]+")

def take(key, value):
    value = value.strip().strip("'\"")
    if value and value_ok.fullmatch(value):
        candidates[key].add(value)

for path in sorted(root.rglob("*")):
    if not path.is_file() or path.stat().st_size > 64_000:
        continue
    try:
        text = path.read_text()
    except (UnicodeDecodeError, OSError):
        continue
    name = path.name.lower()

    if name.endswith(".json") or text.lstrip().startswith("{"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict):
            section = data
            for key in ("web", "installed"):
                if isinstance(data.get(key), dict):
                    section = data[key]
                    break
            cid, secret = section.get("client_id"), section.get("client_secret")
            if isinstance(cid, str) and isinstance(secret, str):
                if "google" in name or "google" in text.lower():
                    take("GOOGLE_CLIENT_ID", cid)
                    take("GOOGLE_CLIENT_SECRET", secret)
                elif "github" in name or "github" in text.lower():
                    take("GITHUB_CLIENT_ID", cid)
                    take("GITHUB_CLIENT_SECRET", secret)

    for line in text.splitlines():
        match = re.match(
            r"\s*(GOOGLE_CLIENT_ID|GOOGLE_CLIENT_SECRET|GITHUB_CLIENT_ID|GITHUB_CLIENT_SECRET)\s*=\s*(.+?)\s*$",
            line,
        )
        if match:
            take(match.group(1), match.group(2))

    stem = name.split(".")[0]
    if stem in ("google_client_id", "google_client_secret", "github_client_id", "github_client_secret"):
        take(stem.upper(), text)

found = {}
for key in wanted:
    values = candidates[key]
    if len(values) > 1:
        sys.exit(f"multiple different values found for {key}; keep one client file or remove the extras")
    if not values:
        sys.exit(f"missing on the server: {key} (no values printed)")
    found[key] = next(iter(values))

out.write_text("".join(f'{key}="{found[key]}"\n' for key in wanted))
out.chmod(0o600)
print("found:", ", ".join(wanted))
PY
fi

if [ "$DRY_RUN" -eq 1 ]; then
  log "dry run: credentials parsed; would back up and update $PREFIX and restart $SERVICE_NAME"
  exit 0
fi

# Stage the new server files before replacing any, so a failed download changes nothing.
if [ "$DO_CODE" -eq 1 ]; then
  stage_dir="$(mktemp -d "$PREFIX/.oauth-update.XXXXXX")"
  for f in auth.ts accounts.ts server.ts; do
    url="https://raw.githubusercontent.com/$REPO/$REF/$f"
    log "fetching $f @ $REF"
    curl -fsSL "$url" -o "$stage_dir/$f" || die "download failed: $url"
    [ -s "$stage_dir/$f" ] || die "empty download: $url"
    chmod 0644 "$stage_dir/$f"
  done

  code_backup="$PREFIX/backup-oauth-$timestamp"
  mkdir -p "$code_backup"
  for f in auth.ts accounts.ts server.ts; do
    cp -p "$PREFIX/current/$f" "$code_backup/$f"
  done
  for f in auth.ts accounts.ts server.ts; do
    mv "$stage_dir/$f" "$PREFIX/current/$f"
  done
  changed=1
  log "updated relay code; backup: $code_backup"
fi

if [ "$DO_OAUTH" -eq 1 ]; then
  env_backup="$PREFIX/relay.env.bak.$timestamp"
  cp -p "$PREFIX/relay.env" "$env_backup"
  chmod 600 "$env_backup"

  if [ -f "$ENV_FILE" ]; then
    oauth_backup="$PREFIX/.oauth.env.rollback.$timestamp"
    cp -p "$ENV_FILE" "$oauth_backup"
    chmod 600 "$oauth_backup"
  fi
  if [ -f "$DROPIN" ]; then
    dropin_backup="$PREFIX/.oauth-dropin.rollback.$timestamp"
    cp -p "$DROPIN" "$dropin_backup"
    chmod 600 "$dropin_backup"
  fi

  mv "$staged_env" "$ENV_FILE"
  staged_env=""
  chmod 600 "$ENV_FILE"

  mkdir -p "$DROPIN_DIR"
  printf '[Service]\nEnvironmentFile=%s\n' "$ENV_FILE" > "$DROPIN"
  chmod 600 "$DROPIN"

  env_tmp="$(mktemp "$PREFIX/.relay.env.XXXXXX")"
  chmod 600 "$env_tmp"
  if grep -q '^AUTH_OAUTH=' "$PREFIX/relay.env"; then
    sed "s/^AUTH_OAUTH=.*/AUTH_OAUTH=$PROVIDERS/" "$PREFIX/relay.env" > "$env_tmp"
  else
    cat "$PREFIX/relay.env" > "$env_tmp"
    printf '\nAUTH_OAUTH=%s\n' "$PROVIDERS" >> "$env_tmp"
  fi
  grep -qx "AUTH_OAUTH=$PROVIDERS" "$env_tmp" || die "could not update AUTH_OAUTH in relay.env"
  cat "$env_tmp" > "$PREFIX/relay.env"
  rm -f "$env_tmp"
  env_tmp=""
  chmod 600 "$PREFIX/relay.env"
  changed=1
  log "wrote $ENV_FILE (0600) and enabled: $PROVIDERS"
fi

if [ "$changed" -eq 0 ]; then
  log "nothing to do"
  exit 0
fi

if [ "$DO_RESTART" -eq 0 ]; then
  drop_rollback
  log "files updated; restart skipped. Run: systemctl --user restart $SERVICE_NAME"
  exit 0
fi

if ! systemctl --user daemon-reload; then
  rollback
  die "systemctl daemon-reload failed"
fi
if ! systemctl --user restart "$SERVICE_NAME"; then
  rollback
  die "$SERVICE_NAME did not restart; previous files restored"
fi
for _ in 1 2 3 4 5; do
  systemctl --user is-active --quiet "$SERVICE_NAME" && break
  sleep 1
done
if ! systemctl --user is-active --quiet "$SERVICE_NAME"; then
  rollback
  die "$SERVICE_NAME is not active; previous files restored"
fi

drop_rollback
log "$SERVICE_NAME is active"

if [ -n "$PUBLIC_URL" ]; then
  log "sign-in methods at $PUBLIC_URL:"
  curl -fsS "$PUBLIC_URL/v1/auth/methods" || log "could not reach $PUBLIC_URL/v1/auth/methods"
  printf '\n'
else
  log "PERCH_PUBLIC_URL is not set; check /v1/auth/methods through your proxy"
fi
log "done. code backup: ${code_backup:-none}; env backup: ${env_backup:-none}"
