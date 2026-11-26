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

The relay needs [Bun](https://bun.sh).

## Server

### One-command setup

```sh
curl -fsSL https://raw.githubusercontent.com/chalone0808/perch-relay/main/setup.sh \
  | bash -s -- --domain api.example.com --account alice
```

It checks for the tools it needs and installs only what is missing. Bun goes
under the install root (`/opt/perchserver/bun` or `~/.perchserver/bun`); in user
mode, if Bun is not already present, it asks where to install it. Caddy is
installed only when you provide a public hostname. It writes `relay.env` and the
systemd unit, starts the relay, and creates the account. It asks for sudo only in
system mode (packages, the service user, the install root, and the unit). It adds
`bin/` (and Bun's path when it installs Bun) to your shell rc and prints those
lines at the end; open a new shell or source the file.

Prefer to read the script first:

```sh
curl -fsSL https://raw.githubusercontent.com/chalone0808/perch-relay/main/setup.sh -o setup.sh
less setup.sh
bash setup.sh --domain api.example.com --account alice
```

Options: `--layout system|user` (or answer the prompt), `--prefix`,
`--data-dir`, `--config-dir`, `--source PATH` (a local checkout, useful for
testing before the repository is published), `--branch BRANCH`, `--push-url`,
`--push-key`, `--version`, `--yes`.

`system` puts everything under `/opt/perchserver` and installs a systemd
service; `--data-dir` and `--config-dir` must stay under that root. `user` puts
everything under `~/.perchserver` with a systemd user unit and needs no root for
the layout; it runs as your login account, so use it on a single-user machine.
Public TLS through Caddy still needs root.

Prefer `PERCH_PUSH_KEY` over `--push-key` so the key does not appear in process
listings. The script clones `https://github.com/chalone0808/perch-relay.git` over
HTTPS; use `--source` with a local checkout or `--repo URL` to fetch from
somewhere else.

### Manual setup

```sh
git clone <repository-url> ~/perch
cd ~/perch
mkdir -p ~/perch-data

PERCH_DB="$HOME/perch-data/perch.db" \
PERCH_PUBLIC_URL="https://api.example.com" \
PORT=8787 HOST=127.0.0.1 \
bun server.ts
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

### Create an account

Phones sign in; they do not use pairing codes.

```sh
PERCH_DB="$HOME/perch-data/perch.db" bun server.ts account add alice --adopt --password
```

`--adopt` binds the relay's existing tenant to this first account. Use it for
the owner account so CLI-issued laptop codes belong to the same tenant.
Additional accounts use a new tenant:

```sh
PERCH_DB="$HOME/perch-data/perch.db" bun server.ts account add bob --password
```

Each command prints a 16-character one-time password once. The app asks the
user to choose their own password at first sign-in.

Other account commands:

```sh
bun server.ts account list
bun server.ts account passwd <name>
bun server.ts account bind <name> [--email <addr>] [--github <login>] [--google <email>]
bun server.ts account disable <name> [--keep-devices]
```

Limits are 10 phones and 20 laptops per account.

### Pair a laptop

A laptop pairs with a single-use code, valid for 10 minutes:

- On a signed-in phone: **Settings → Add a Laptop**, then run the command it
  shows on the laptop.
- Or on the relay: `bun server.ts pair machine` for the relay's own
  tenant, or `bun server.ts pair machine <account>` for another account.

Codes are tenant-scoped. `bun server.ts devices` lists everything paired;
`bun server.ts revoke <id>` revokes one device.

### Run as a service

Adjust the user and paths. The relay does not need root.

```ini
# /etc/systemd/system/perch-relay.service
[Unit]
Description=Perch relay
After=network-online.target
Wants=network-online.target

[Service]
User=perch
WorkingDirectory=/home/perch/perch
EnvironmentFile=/home/perch/perch-data/relay.env
ExecStart=/home/perch/.bun/bin/bun server.ts
Restart=always
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```ini
# /home/perch/perch-data/relay.env
PORT=8787
HOST=127.0.0.1
PERCH_DB=/home/perch/perch-data/perch.db
PERCH_PUBLIC_URL=https://api.example.com
```

### Configuration

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
| `AUTH_OAUTH` | `github`, `google`, or both. |
| `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | GitHub OAuth app; callback `/v1/auth/oauth/github/callback`. |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | Google OAuth client; callback `/v1/auth/oauth/google/callback`. |
| `PUSH_GATEWAY`, `PUSH_GATEWAY_KEY` | Send push through a gateway (below). |
| `APNS_KEY_FILE`, `APNS_KEY_ID`, `APNS_TEAM_ID`, `APNS_TOPIC`, `APNS_ENV` | Push directly to Apple when no gateway is configured. |

The relay logs which sign-in methods are enabled at startup:

```
perch relay on http://127.0.0.1:8787/, sign-in: password
```

`GET /v1/auth/methods` reports the same thing.

## Push (optional)

Push is only a notification hint. Messages remain in the mailbox and sync
without it.

The relay can send through a push gateway so it never holds the APNs key:

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
key. If you build your own app, run your own gateway.

Run the gateway as its own service, point a TLS hostname at port 8788 with the
same `X-Real-IP` header, and keep `PUSH_KEYS` and the `.p8` file at mode 0600.

## Updating

Server: `git pull` in the checkout and restart the relay. Database migrations
run automatically.

## Backups and security

- Back up the SQLite database and the environment/secret files. Message bodies
  are encrypted; the relay sees routing metadata only.
- Never expose the relay without TLS. Keep the database and env files at mode
  0600, run as an unprivileged user, and set `X-Real-IP` at the proxy.
- Revoke a lost device with `bun server.ts revoke <id>`. Disabling an
  account also revokes its devices unless `--keep-devices` is passed.

## Tests

```sh
bun test test/
```

## License

BSD 3-Clause. See `LICENSE`.
