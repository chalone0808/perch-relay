# Perch relay

Perch gives the Perch iOS app a mailbox to coding agents on your computers. It
is agent-agnostic: the relay only stores and forwards messages, and the client
supplies an adapter for the agent. Claude Code is the adapter included today;
other agents can be added without changing the relay.

The phone and each computer exchange messages through a small relay; message
bodies are end-to-end encrypted, so the relay stores and forwards sealed
envelopes it cannot read.

This repository contains the relay server. The laptop client is in the
`chalone0808/perch` repository. The iOS app is not in this repository.

The relay code is at the repository root; its tests are in `test/`.

The relay needs [Bun](https://bun.sh) and a Linux host with systemd user
services.

## Server

The relay installs **only as your user**. Everything Perch-owned lives under a
prefix you own (default `~/.perchserver`), runs from a systemd user unit, and
never requires root. Sudo is used only for missing system packages, optional
Caddy/TLS setup, and a last-resort linger enable.

### One-command setup

```sh
curl -fsSL https://raw.githubusercontent.com/chalone0808/perch-relay/main/setup.sh \
  | bash -s -- --domain api.example.com --account alice
```

It reuses an existing Bun from `PATH`, `~/.bun/bin/bun`, or the prefix; if Bun
is missing it installs it under `~/.bun`. It writes `relay.env`, a
`perch-relay` wrapper, and `~/.config/systemd/user/perch-relay.service`, then
starts the user service. It creates the account and writes the one-time
password to `<prefix>/account-password.txt` (0600), printing only the path.

When `--domain` is given, the installer reads `/etc/caddy/Caddyfile`. If the
domain is already configured there, it does nothing and does not restart
Caddy. Otherwise it offers to add the site with sudo, or you can skip Caddy and
use your own TLS proxy (see below). Packages are installed with apt only when
missing, with a prompt.

Prefer to read the script first:

```sh
curl -fsSL https://raw.githubusercontent.com/chalone0808/perch-relay/main/setup.sh -o setup.sh
less setup.sh
bash setup.sh --domain api.example.com --account alice
```

Options:

```
--prefix DIR        install root (default ~/.perchserver)
--account NAME      account to create; required with --yes/no TTY
--no-account        skip account creation
--port PORT         relay port (default 8787)
--domain HOST       public hostname; also manages Caddy when possible
--public-url URL    set PERCH_PUBLIC_URL without touching Caddy
--no-caddy          never read or edit Caddy
--data-dir DIR      database directory (default <prefix>/data)
--config-dir DIR    config directory (default <prefix>)
--bun PATH          reuse a specific Bun binary/directory
--source PATH       install from a local checkout
--repo URL          clone from a different repository
--branch BRANCH     branch to clone (default main)
--version NAME      release name under <prefix>/releases
--unit NAME         relay user unit (default perch-relay)
--yes               non-interactive; requires --account or --no-account
--help
```

Advanced push options are separate:

```
--push
--push-prefix DIR   default: sibling perch-push when the prefix ends in -server,
                    otherwise <prefix>-push
--push-port PORT    default 8788
--push-unit NAME    default perch-gateway
--apns-key-file PATH
--apns-key-id ID
--apns-team-id ID
--apns-topic TOPIC
--apns-env production|development
```

If you already have a TLS proxy, skip Caddy entirely:

```sh
curl -fsSL https://raw.githubusercontent.com/chalone0808/perch-relay/main/setup.sh \
  | bash -s -- --public-url https://api.example.com --account alice
```

### Manual setup

```sh
git clone <repository-url> ~/perch
cd ~/perch
mkdir -p ~/perch-data

cat > relay.env <<EOF
PORT=8787
HOST=127.0.0.1
PERCH_DB=$HOME/perch-data/perch.db
PERCH_PUBLIC_URL=https://api.example.com
EOF

bun --env-file=relay.env server.ts
```

The relay binds loopback by default. Put a TLS proxy in front; a Caddy site is:

```caddy
api.example.com {
	header Strict-Transport-Security "max-age=31536000"
	reverse_proxy 127.0.0.1:8787 {
		header_up X-Real-IP {remote_host}
	}
}
```

`X-Real-IP` is required: sign-in rate limits are per client address, and the
relay trusts that header only from a loopback peer.

### Invite new accounts

New users sign in with GitHub, Google or Apple and then redeem a one-time invite
key. The key creates the account and becomes its initial username; the app
offers a skippable rename right after. Keys look like `pinv_…` and are shown
once:

```sh
perch-relay invite create --count 3 --ttl-hours 168
```

`--count` is 1–100 and `--ttl-hours` 1–720 (seven days by default). Only a
SHA-256 hash is stored, and each key works once. `perch-relay invite list` shows
expiry, whether a key was used, and which account claimed it, never the key.
There is no account or username to choose before the user claims a key.

An account can also be created and bound by the operator, without an invite:

### Create an account

Phones sign in; they do not use pairing codes. With an installer deployment:

```sh
~/.perchserver/bin/perch-relay account add alice --adopt --password
```

The installer redacts the one-time password and writes it to
`<prefix>/account-password.txt`; the manual command prints it once. Use
`--adopt` for the first account so it adopts the relay's existing tenant.
Additional accounts use a new tenant:

```sh
~/.perchserver/bin/perch-relay account add bob --password
```

Each command generates a 16-character one-time password. The app asks the user
to choose their own password at first sign-in. If the password is lost:

```sh
~/.perchserver/bin/perch-relay account passwd alice
```

Other account commands:

```sh
perch-relay account list
perch-relay account bind <name> [--email <addr>] [--github <login>] [--google <email>] [--apple <subject>]
perch-relay account disable <name> [--keep-devices]
```

Limits are 10 phones and 20 laptops per account.

### How accounts and sign-in fit together

An account's identity is its `accounts.id`, its unique `tenant_id`, and each
bound provider identity (`provider` plus the provider's immutable external id:
GitHub's numeric id, Google's `sub`, Apple's `sub`). The username is a mutable
unique handle: changing it keeps the account, tenant, devices, history and
linked providers. An invite key is a one-time claim credential, never a
permanent identifier or password.

- The first sign-in with an unknown provider identity returns a 10-minute
  pending identity instead of an account. The app asks for an invite key and
  `POST /v1/auth/claim` creates the account, tenant, bound identity and session
  atomically. A bad or already-used key consumes nothing, so the user can retry.
- Operator pre-bound identities still sign in directly. Existing password
  accounts are untouched.
- Settings → Sign-In Methods can link or unlink GitHub, Google, Apple, and
  unlink a linked email. The last remaining method cannot be removed. Native
  Apple needs no web redirect.
- Settings → Change Username renames the account; password sign-in uses the
  new name immediately.

### Pair a laptop

A laptop pairs with a single-use code, valid for 10 minutes:

- On a signed-in phone: **Settings → Add a Laptop**, then run the command it
  shows on the laptop.
- Or on the relay: `perch-relay pair machine` for the relay's own tenant, or
  `perch-relay pair machine <account>` for another account.

Codes are tenant-scoped. `perch-relay devices` lists everything paired;
`perch-relay revoke <id>` revokes one device.

### Run as a service

The installer writes this user unit to
`~/.config/systemd/user/perch-relay.service` and enables it:

```ini
[Unit]
Description=Perch relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=%h/.perchserver/current
EnvironmentFile=%h/.perchserver/relay.env
ExecStart=%h/.bun/bin/bun server.ts
Restart=always
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=%h/.perchserver/data

[Install]
WantedBy=default.target
```

Adjust the paths if you used a custom prefix, then:

```sh
systemctl --user daemon-reload
systemctl --user enable --now perch-relay
journalctl --user -u perch-relay -f
```

To start at boot without logging in, enable linger (the installer tries this
without sudo first):

```sh
loginctl enable-linger "$USER"        # may work as your user
sudo loginctl enable-linger "$USER"   # if your system requires it
```

### Configuration

`relay.env` lives under the prefix and is mode 0600. The installer manages
`PORT`, `HOST`, `PERCH_DB`, `PERCH_PUBLIC_URL`, and (with push)
`PUSH_GATEWAY`/`PUSH_GATEWAY_KEY`; other lines are preserved.

| Variable | Meaning |
| --- | --- |
| `PERCH_DB` | SQLite database path. Default `perch-server.db` in the working directory. |
| `PORT`, `HOST` | Listen address. Default `8787` on `127.0.0.1`. |
| `PERCH_PUBLIC_URL` | Public `https://` URL; required for email and OAuth links. |
| `PERCH_OWNER` | Optional identity used to derive the relay's own tenant on first start. |
| `AUTH_PASSWORD` | Password sign-in, on by default. `0` turns it off. |
| `AUTH_EMAIL` | `1` enables email magic links. Needs `SMTP_URL` and `AUTH_EMAIL_FROM`. |
| `SMTP_URL` | `smtps://user:pass@host:465`, or `smtp://…:587` with STARTTLS. |
| `AUTH_EMAIL_FROM` | Sender, e.g. `Perch <perch@example.com>`. |
| `AUTH_OAUTH` | Comma-separated `github`, `google`, `apple`. Each also needs its credentials below and an https `PERCH_PUBLIC_URL`. |
| `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | GitHub OAuth app; callback `https://your-relay/v1/auth/oauth/github/callback`. |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | Google OAuth client; callback `https://your-relay/v1/auth/oauth/google/callback`. |
| `APPLE_CLIENT_ID` | The iOS app's bundle id (`com.chalone.perch`). Apple is verified natively from its identity token; no Services ID or client secret is used. Enable the Sign in with Apple capability on the App ID and rebuild the app. |

Google OAuth clients must be type **Web application** (not iOS), with
`${PERCH_PUBLIC_URL}/v1/auth/oauth/google/callback` as an authorized redirect URI. The relay does
the code exchange with the secret, so the ID and secret stay in `relay.env` and each relay needs
its own client.

If the client files are already on the relay host, `apply-oauth.sh` can read them without printing
their values, write a mode-0600 `oauth.env`, add it to the user unit, enable GitHub/Google, update
the code, restart, and roll back on failure:

```sh
curl -fsSL https://raw.githubusercontent.com/chalone0808/perch-relay/main/apply-oauth.sh -o apply-oauth.sh
bash apply-oauth.sh --prefix ~/services/perch/perch-server --dry-run
bash apply-oauth.sh --prefix ~/services/perch/perch-server
```

Run it as the relay's user. It expects the client files under `<prefix>/oauth`; see
`bash apply-oauth.sh --help` for the layout, alternate commits, and `--skip-code` / `--skip-oauth`.
| `PUSH_GATEWAY`, `PUSH_GATEWAY_KEY` | Send push through a gateway (below). |
| `APNS_KEY_FILE`, `APNS_KEY_ID`, `APNS_TEAM_ID`, `APNS_TOPIC`, `APNS_ENV` | Push directly to Apple when no gateway is configured. |

The relay logs which sign-in methods are enabled at startup:

```
perch relay on http://127.0.0.1:8787/, sign-in: password
```

`GET /v1/auth/methods` reports the same thing.

### Versions

`GET /v1/version` is public and needs no auth:

```json
{ "name": "perch-relay", "version": "0.2.0", "protocol": 1 }
```

`version` is the release; `protocol` is the wire contract. A phone or laptop
built for a higher protocol than the relay reports can warn that the relay needs
updating. Laptops also send their own `version` and `protocol` in `/v1/sync`;
the relay stores the last valid values and returns them with each machine in the
phone's sync response, so the app can flag a computer that needs `perch update`.
Older clients that send neither keep working and simply have no version shown.

## Push (optional, advanced)

Push is only a notification hint. Messages remain in the mailbox and sync
without it. Push is app-specific: the APNs key and topic must match the app
build. Use it only with your own Apple app/key.

The installer can set up a loopback gateway:

```sh
curl -fsSL https://raw.githubusercontent.com/chalone0808/perch-relay/main/setup.sh -o setup.sh
bash setup.sh --prefix ~/.perchserver --account alice --push \
  --push-prefix ~/services/perch/perch-push \
  --apns-key-file ~/AuthKey_XXXXXXXXXX.p8 \
  --apns-key-id XXXXXXXX \
  --apns-team-id XXXXXXXX \
  --apns-topic com.example.app
```

It copies `gateway.ts` and `apns.ts` from the relay release, writes
`<push-prefix>/push.env` (0600), installs the `perch-gateway` user unit, and
points the relay at `http://127.0.0.1:8788` with a generated key. Keep the
`.p8` at mode 0600. Re-running preserves the existing gateway secret and APNs
settings unless you pass new values.

Verify without a phone:

```sh
systemctl --user is-active perch-gateway
curl -sS -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8788/v1/push
# 401 means the gateway is up and auth is required
```

The gateway has no GET health endpoint. A real push requires a signed-in app
token.

To use an external gateway instead, edit `relay.env`:

```ini
PUSH_GATEWAY=https://push.example.com
PUSH_GATEWAY_KEY=<secret issued by the gateway operator>
```

A gateway runs `gateway.ts` and holds the APNs key:

```ini
PORT=8788
HOST=127.0.0.1
APNS_KEY_FILE=/path/to/AuthKey.p8
APNS_KEY_ID=XXXXXXXXXX
APNS_TEAM_ID=XXXXXXXXXX
APNS_TOPIC=com.example.app
APNS_ENV=development
PUSH_KEYS=relayname=<secret at least 16 characters>
```

It exposes `POST /v1/push` with `Authorization: Bearer <secret>` and
`{ token, payload }`, rate-limited per key. The APNs topic belongs to the app
build: a gateway can only push apps signed with the matching bundle ID and APNs
key. If you build your own app, run your own gateway. A relay on the same host
can use the gateway over loopback; no TLS hostname is needed.

## Updating

Re-run the installer with the same options. It stages a new release under
`<prefix>/releases`, switches `<prefix>/current`, writes the same config, and
restarts the user service. Database migrations run automatically. The installer
keeps the five most recent releases and preserves the account, `relay.env`, and
push secrets.

For a manual checkout, `git pull` and restart:

```sh
systemctl --user restart perch-relay
```

This updates the relay only. Each laptop's client is a separate install and
updates there with `perch update` (or by rerunning the client installer).

If you are migrating an old system install (`/opt/perchserver`, a system
`perch-relay.service`), stop and disable the system unit, copy the database and
`relay.env` into a user-owned prefix, fix ownership, then run this installer.
Never leave Perch files owned by root.

## Backups and security

- Back up the SQLite database, `relay.env`, `push.env`, `account-password.txt`,
  and the APNs `.p8` file. Keep the env, password, and key files at mode 0600.
- Message bodies are encrypted; the relay sees routing metadata only.
- Never expose the relay without TLS. Run it as an unprivileged user and set
  `X-Real-IP` at the proxy.
- Revoke a lost device with `perch-relay revoke <id>`. Disabling an account also
  revokes its devices unless `--keep-devices` is passed.

## Tests

```sh
bun test test/
```

## License

BSD 3-Clause. See `LICENSE`.
