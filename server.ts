#!/usr/bin/env bun
// perch relay: forwards messages between laptops and phones and deletes them once delivered. It never runs agents.
// One relay is one owner's mailbox by default. Data is tenant-scoped, so running more than one
// owner on the same relay does not let their devices, messages or pushes mix.
//
//   bun server.ts                                run (PORT, PERCH_DB, PERCH_OWNER env)
//   bun server.ts pair machine [owner]           print a one-time laptop pairing code (10 min)
//   bun server.ts tenant                         print this relay's tenant id
//   bun server.ts devices                        list devices
//   bun server.ts revoke <device id>             revoke a device
//   bun server.ts account <add|list|passwd|bind|disable> ...   relay accounts (accounts.ts)
//   bun server.ts invite <create|list> ...                     invite-gated sign-up keys (accounts.ts)
//
// API (all JSON):
//   GET  /v1/version                       → { name, version, protocol, id }   public; no auth
//   POST /v1/pair  { code, name, pubkey }  → { token, kind }   laptops only; phones sign in (auth.ts)
//   POST /v1/sync  Authorization: Bearer <token>
//     body { after, outbox: Msg[], wait, pubkey }  → { acked, inbox: Msg[], cursor, machines? | phones? }
//     bodies are end-to-end encrypted (client/e2e.ts); machines/phones carry the peers' public keys
//     machines push up-messages and receive down-messages addressed to them;
//     phones push down-messages (each with `machine`) and receive every up-message.
//   Sign-in, self-registration and phone-issued laptop codes: see auth.ts.
//
// ponytail: plain HTTP. Put it behind Tailscale or a TLS proxy (Caddy); never expose it bare.
// APNs notifications carry message metadata only; the relay never sees the encrypted body.
// Pushes go to Apple directly (APNS_* env) or through a push gateway (PUSH_GATEWAY, gateway.ts).
import { Database } from 'bun:sqlite'
import { createHash, createHmac, randomBytes } from 'node:crypto'
import { isIPv4 } from 'node:net'
import { makePushSender, type PushSender } from './apns'
import { accountCli, authSchema, HEAD, inviteCli, sha, sweep } from './accounts'
import { authConfig, authRoutes, clientIp, type AuthConfig, type AuthDeps } from './auth'

// The relay's release version and wire protocol. Bump VERSION for every release; bump PROTOCOL
// only when a phone or laptop built for the previous protocol can no longer talk to this relay.
export const VERSION = '0.2.0'
export const PROTOCOL = 1

type Msg = {
  id: string; type: string; session_id?: string | null; machine?: string; body?: unknown; ts?: string
  notify?: boolean; snapshot?: boolean; to?: string[]
}

// What each side may send. Anything else is rejected: a phone can't forge agent replies, a laptop can't send prompts.
const UP = new Set(['session_start', 'session_end', 'agent_reply', 'needs_attention', 'delivered', 'delivery_failed', 'interrupted', 'command_result', 'activity', 'task_note', 'commands', 'compact', 'request_expired', 'decision_result', 'presence', 'user_prompt'])
const DOWN = new Set(['prompt', 'command', 'decision', 'interrupt', 'presence'])
const MAX_WAIT = 30
// ponytail: a device offline this long loses what was waiting for it; its laptop still has the transcript.
const UNDELIVERED_TTL = 7 * 24 * 3600 * 1000
// X25519 public key, base64url. Bodies are end-to-end encrypted between devices; the relay only
// hands out these keys (so whoever runs it could swap them: compare fingerprints to be sure).
const pubkey = (k: unknown) => (typeof k === 'string' && /^[A-Za-z0-9_-]{43}$/.test(k) ? k : null)

/// A machine's direct endpoint: private IPv4 addresses only, at most eight.
export type DirectAddr = { host: string; network: 'lan' | 'tailscale' }
export function directHint(v: unknown): { port: number; addrs: DirectAddr[] } | null {
  if (!v || typeof v !== 'object') return null
  const port = Number((v as any).port)
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null
  const addrs: DirectAddr[] = []
  const seen = new Set<string>()
  for (const a of Array.isArray((v as any).addrs) ? (v as any).addrs : []) {
    const host = a?.host
    if (typeof host !== 'string' || !isIPv4(host)) continue
    const network: 'lan' | 'tailscale' | null =
      host.startsWith('10.') || host.startsWith('192.168.') ||
      /^172\.(1[6-9]|2\d|3[01])\./.test(host) ? 'lan'
      : /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(host) ? 'tailscale'
      : null
    if (!network || a.network !== network || seen.has(host)) continue
    seen.add(host)
    addrs.push({ host, network })
    if (addrs.length === 8) break
  }
  return addrs.length ? { port, addrs } : null
}

/// The pre-salt derivation, kept only to migrate relays created before the per-relay salt.
export function legacyTenantFor(owner: string) {
  return createHash('sha256').update(`perch-tenant:${owner.trim().toLowerCase()}`).digest('hex').slice(0, 32)
}

/// A stable, non-secret namespace for one owner. Emails are normalized and keyed with this relay's
/// random salt, so the same address does not produce the same id on another relay.
export function tenantFor(owner: string, salt: string) {
  return createHmac('sha256', salt).update(`perch-tenant:${owner.trim().toLowerCase()}`).digest('hex').slice(0, 32)
}

function setting(db: Database, key: string): string | null {
  return (db.query(`select v from settings where k = ?`).get(key) as { v: string } | null)?.v ?? null
}

/// This relay's own tenant. The first `open` sets it from PERCH_OWNER, or generates a random one
/// when no owner is configured.
export function relayTenant(db: Database): string {
  const tenant = setting(db, 'owner_tenant')
  if (!tenant) throw new Error('relay tenant is not initialized')
  return tenant
}

export function relaySalt(db: Database): string {
  const salt = setting(db, 'tenant_salt')
  if (!salt) throw new Error('relay salt is not initialized')
  return salt
}

/// A stable public identity for this relay. It survives restarts and database copies, and changes
/// when the relay's tenant salt changes.
export function relayId(db: Database): string {
  return createHash('sha256').update(`perch-relay-id:${relaySalt(db)}`).digest('hex').slice(0, 32)
}

export function open(path: string, opts: { owner?: string; salt?: string } = {}) {
  const db = new Database(path)
  db.exec(`
    pragma journal_mode = wal;
    pragma secure_delete = on;
    create table if not exists devices (id integer primary key, kind text, name text, token_hash text unique, last_seen text, revoked integer default 0, tenant_id text not null);
    create table if not exists codes (code_hash text primary key, kind text, expires integer, tenant_id text not null);
    create table if not exists messages (seq integer primary key autoincrement, id text, machine text, dir text, json text, tenant_id text not null, created integer, unique(tenant_id, id));
    create table if not exists settings (k text primary key, v text);`)
  authSchema(db)
  if (!db.query(`select 1 from pragma_table_info('devices') where name = 'pubkey'`).get()) db.exec('alter table devices add column pubkey text')
  if (!db.query(`select 1 from pragma_table_info('devices') where name = 'push_token'`).get()) db.exec('alter table devices add column push_token text')
  // JSON list of message types the phone switched off in its notification settings.
  if (!db.query(`select 1 from pragma_table_info('devices') where name = 'push_off'`).get()) db.exec(`alter table devices add column push_off text not null default '[]'`)
  // A machine's advertised direct endpoint, as JSON { port, addrs }.
  if (!db.query(`select 1 from pragma_table_info('devices') where name = 'direct'`).get()) db.exec('alter table devices add column direct text')
  // Pre-tenant relays get an empty column first; the migration below fills it with the owner tenant.
  if (!db.query(`select 1 from pragma_table_info('devices') where name = 'tenant_id'`).get()) db.exec("alter table devices add column tenant_id text not null default ''")
  if (!db.query(`select 1 from pragma_table_info('codes') where name = 'tenant_id'`).get()) db.exec("alter table codes add column tenant_id text not null default ''")
  if (!db.query(`select 1 from pragma_table_info('messages') where name = 'tenant_id'`).get()) db.exec("alter table messages add column tenant_id text not null default ''")
  // The relay only forwards: a message is deleted once delivered. `acked` is the highest seq the
  // device has confirmed (the `after` it sends); `created` lets undeliverable messages expire.
  if (!db.query(`select 1 from pragma_table_info('devices') where name = 'acked'`).get()) db.exec('alter table devices add column acked integer not null default 0')
  // The highest seq the relay has handed this device. An `after` beyond it acks nothing: a device
  // can only confirm what it was actually sent (notification buttons send a huge `after`).
  if (!db.query(`select 1 from pragma_table_info('devices') where name = 'served'`).get()) {
    db.exec('alter table devices add column served integer not null default 0')
    db.exec('update devices set served = acked')
  }
  // The newest end-to-end format the device reads (client/e2e.ts); senders pick per recipient.
  if (!db.query(`select 1 from pragma_table_info('devices') where name = 'e2e'`).get()) db.exec('alter table devices add column e2e integer not null default 1')
  // A laptop's reported client version and wire protocol, so phones can show it and flag old ones.
  if (!db.query(`select 1 from pragma_table_info('devices') where name = 'version'`).get()) db.exec('alter table devices add column version text')
  if (!db.query(`select 1 from pragma_table_info('devices') where name = 'protocol'`).get()) db.exec('alter table devices add column protocol integer')
  if (!db.query(`select 1 from pragma_table_info('messages') where name = 'created'`).get()) {
    db.exec('alter table messages add column created integer')
    db.run('update messages set created = ?', [Date.now()])
  }

  const owner = (opts.owner ?? process.env.PERCH_OWNER ?? '').trim()
  const providedSalt = (opts.salt ?? process.env.PERCH_TENANT_SALT ?? '').trim()
  let salt = setting(db, 'tenant_salt')
  if (!salt) {
    salt = providedSalt || randomBytes(32).toString('hex')
    db.run(`insert or ignore into settings (k, v) values ('tenant_salt', ?)`, [salt])
    salt = relaySalt(db) // another process may have won the insert
  } else if (providedSalt && providedSalt !== salt) {
    console.warn('perch: keeping the stored tenant salt; PERCH_TENANT_SALT differs')
  }

  const derived = owner ? tenantFor(owner, salt) : undefined
  let tenant = setting(db, 'owner_tenant')
  if (!tenant) {
    tenant = derived ?? randomBytes(16).toString('hex')
    db.run(`insert or ignore into settings (k, v) values ('owner_tenant', ?)`, [tenant])
    tenant = relayTenant(db)
  } else if (derived && derived !== tenant) {
    const legacy = legacyTenantFor(owner)
    if (tenant === legacy) {
      // Relays created before the salt: keep their data, move it to the salted id.
      for (const table of ['devices', 'codes', 'messages']) {
        db.run(`update ${table} set tenant_id = ? where tenant_id = ?`, [derived, legacy])
      }
      db.run(`update settings set v = ? where k = 'owner_tenant'`, [derived])
      tenant = derived
    } else {
      console.warn(`perch: keeping existing tenant ${tenant}; PERCH_OWNER would derive ${derived}`)
    }
  }
  // One-time migration from the pre-tenant relay.
  for (const table of ['devices', 'codes', 'messages']) {
    db.run(`update ${table} set tenant_id = ? where tenant_id = ''`, [tenant])
  }
  // Message ids are unique per tenant, not relay-wide: another tenant's id can never shadow yours.
  const schema = (db.query(`select sql from sqlite_master where name = 'messages'`).get() as any).sql as string
  if (!schema.includes('unique(tenant_id, id)')) {
    db.transaction(() => {
      const next = (db.query(`select seq from sqlite_sequence where name = 'messages'`).get() as any)?.seq ?? 0
      db.exec(`
        create table messages_v2 (seq integer primary key autoincrement, id text, machine text, dir text, json text, tenant_id text not null, created integer, unique(tenant_id, id));
        insert into messages_v2 (seq, id, machine, dir, json, tenant_id, created) select seq, id, machine, dir, json, tenant_id, created from messages;
        drop table messages;
        alter table messages_v2 rename to messages;`)
      // Keep counting from where the old table was: devices hold cursors into it.
      db.run(`delete from sqlite_sequence where name = 'messages'`)
      db.run(`insert into sqlite_sequence (name, seq) values ('messages', ?)`, [next])
    })()
  }
  db.exec(`
    create index if not exists messages_tenant_seq on messages (tenant_id, dir, seq);
    create index if not exists messages_tenant_machine_seq on messages (tenant_id, dir, machine, seq);`)
  return db
}

export function pairCode(db: Database, owner?: string) {
  const code = randomBytes(16).toString('base64url')
  // An explicit owner creates a code for that tenant; otherwise use the relay's own tenant.
  const tenant = owner?.trim() ? tenantFor(owner, relaySalt(db)) : relayTenant(db)
  db.run('insert into codes (code_hash, kind, expires, tenant_id) values (?, ?, ?, ?)',
    [sha(code), 'machine', Date.now() + 10 * 60_000, tenant])
  return code
}

/// The notification is metadata-only: bodies are end-to-end encrypted, so the relay can say what
/// kind of event happened and which session, but never what it says.
const PUSH_TYPES = new Set(['needs_attention', 'agent_reply', 'task_note', 'compact', 'delivery_failed'])

export function pushPayload(m: Msg) {
  if (m.snapshot) return null // replayed state for a new phone, not a new event
  const alert = pushAlert(m)
  if (!alert) return null
  // Each push is its own notification; thread-id stacks a session's notifications together
  // instead of a collapse id replacing the previous one.
  const thread = `${m.machine ?? ''}:${m.session_id ?? ''}`
  return {
    aps: { alert, sound: 'default', 'thread-id': thread },
    type: m.type, session_id: m.session_id ?? null, machine: m.machine ?? null,
  }
}

/// Adds the preview the machine sealed for this phone, if any. The relay can't read it; the phone's
/// notification extension opens it (mutable-content) and shows as much as the user chose.
function withPreview(payload: ReturnType<typeof pushPayload> & {}, m: Msg, phone: string | null) {
  const p = (m as any).preview
  const sealed = phone && (p?.e2e === 1 || p?.e2e === 2) && typeof p.from === 'string' ? p.to?.[phone] : undefined
  if (typeof sealed !== 'string' || sealed.length > 2000) return payload // APNs payloads stop at 4 KB
  // e2e 2 previews also carry the session id, which the extension uses for grouping and tapping.
  return { ...payload, aps: { ...payload.aps, 'mutable-content': 1 }, id: m.id, from: p.from, preview: sealed, ...(p.e2e === 2 ? { e2e: 2 } : {}) }
}

function pushAlert(m: Msg): { title: string; body: string } | null {
  const machine = m.machine ?? 'your laptop'
  if (m.type === 'needs_attention') return { title: 'Approval needed', body: `A session on ${machine} needs your answer.` }
  if (!m.notify) return null
  switch (m.type) {
    case 'agent_reply': return { title: 'New reply', body: `The agent replied on ${machine}.` }
    case 'task_note': return { title: 'Background task finished', body: `A background task finished on ${machine}.` }
    case 'compact': return { title: 'Context compacted', body: `This session was compacted on ${machine}.` }
    case 'delivery_failed': return { title: 'Message not delivered', body: 'Open Perch to see what happened.' }
    default: return null
  }
}

export function app(db: Database, push?: PushSender, auth: AuthConfig = authConfig({}), authDeps: AuthDeps = {}) {
  type Waiter = { tenant: string; kind: string; name: string; done: () => void }
  const waiting = new Set<Waiter>()
  // Wake only the devices whose next sync can see the change: phones for a message from a laptop,
  // the addressed laptop for a message from a phone, and a whole tenant when its device list
  // changed (a newly paired phone needs the laptop's live snapshot right away).
  const wake = (tenant: string, dir?: 'up' | 'down', machine?: string) => {
    for (const w of [...waiting]) {
      if (w.tenant !== tenant) continue
      if (dir === 'up' && w.kind !== 'phone') continue
      if (dir === 'down' && (w.kind !== 'machine' || (machine != null && w.name !== machine))) continue
      w.done()
    }
  }
  const bad = (status: number, error: string) => Response.json({ error }, { status })
  const authHandler = authRoutes(db, auth, { wake, ...authDeps })

  const notifyPhones = (m: Msg, tenant: string) => {
    if (!push) return
    const payload = pushPayload(m)
    if (!payload) return
    const tokens = db.query(
      `select id, push_token, push_off, pubkey from devices where kind = 'phone' and not revoked and tenant_id = ? and push_token is not null`,
    ).all(tenant) as { id: number; push_token: string; push_off: string; pubkey: string | null }[]
    for (const t of tokens) {
      if ((JSON.parse(t.push_off || '[]') as string[]).includes(m.type)) continue // switched off on that phone
      void push(t.push_token, withPreview(payload, m, t.pubkey)).then((r) => {
        if (r.status !== 200) console.error(`apns ${m.type} -> phone ${t.id}: ${r.status} ${r.reason ?? ''}`)
        // The phone reinstalled or revoked push access: stop trying this token.
        if (r.status === 410 || (r.status === 400 && r.reason === 'BadDeviceToken')) {
          db.run('update devices set push_token = null where id = ?', [t.id])
        }
      }).catch(() => {})
    }
  }

  const valid = (m: any, allowed: Set<string>) =>
    m && typeof m.id === 'string' && m.id.length <= 64 && allowed.has(m.type) &&
    (m.session_id == null || typeof m.session_id === 'string')

  // A device starts at its own acknowledged position. A freshly registered phone has acked=HEAD
  // but no local cursor yet, so it asks with after=0; without the floor the relay would send the
  // whole retained backlog, almost all of it sealed for phones that no longer exist.
  const inboxFor = (dev: any, after: number, tenant: string): Msg[] =>
    (dev.kind === 'machine'
      ? db.query(`select seq, json from messages where tenant_id = ? and dir = 'down' and machine = ? and seq > ? order by seq limit 500`).all(tenant, dev.name, after)
      : db.query(`select seq, json from messages where tenant_id = ? and dir = 'up' and seq > ? order by seq limit 500`).all(tenant, Math.max(after, Number(dev.acked) || 0))
    ).map((r: any) => ({ ...JSON.parse(r.json), seq: r.seq }))

  return {
    maxRequestBodySize: 5 * 1024 * 1024,
    idleTimeout: MAX_WAIT + 10,
    async fetch(req: Request, server?: { requestIP(req: Request): { address: string } | null }) {
      const path = new URL(req.url).pathname
      if (path.startsWith('/v1/auth/') || path === '/v1/devices' || path === '/v1/devices/link' || path === '/v1/devices/revoke' || path === '/v1/pair/machine' || path === '/v1/unpair')
        return authHandler(req, clientIp(server?.requestIP(req)?.address, req.headers.get('x-real-ip')))
      if (path === '/v1/version') {
        if (req.method !== 'GET') return bad(405, 'GET only')
        return Response.json({ name: 'perch-relay', version: VERSION, protocol: PROTOCOL, id: relayId(db) })
      }
      if (req.method !== 'POST') return bad(405, 'POST only')
      let body: any
      try { body = await req.json() } catch { return bad(400, 'bad json') }

      if (path === '/v1/pair') {
        const row = db.query('select kind, expires, tenant_id from codes where code_hash = ?').get(sha(String(body.code))) as any
        db.run('delete from codes where code_hash = ? or expires < ?', [sha(String(body.code)), Date.now()]) // single use
        sweep(db)
        // Codes minted for phones before sign-in existed are refused: phones sign in now.
        if (!row || row.expires < Date.now() || row.kind !== 'machine') return bad(403, 'invalid or expired code')
        const name = String(body.name ?? '').slice(0, 64)
        if (!name) return bad(400, 'name required')
        if (!pubkey(body.pubkey)) return bad(400, 'pubkey required')
        const tenant = row.tenant_id || relayTenant(db)
        if (db.query(`select 1 from devices where kind = 'machine' and name = ? and tenant_id = ? and not revoked`).get(name, tenant))
          return bad(409, 'machine name taken')
        if ((db.query(`select count(*) as n from devices where kind = 'machine' and tenant_id = ? and not revoked`).get(tenant) as any).n >= 20)
          return bad(409, 'too many machines; revoke one with `perch revoke`')
        const token = randomBytes(32).toString('base64url')
        db.run(`insert into devices (kind, name, token_hash, pubkey, tenant_id, acked, served) values ('machine', ?, ?, ?, ?, (${HEAD}), (${HEAD}))`, [name, sha(token), pubkey(body.pubkey), tenant])
        wake(tenant) // e.g. a laptop learns about a new phone now, not on its next 25s poll
        return Response.json({ token, kind: 'machine' })
      }

      if (path === '/v1/sync') {
        const token = req.headers.get('authorization')?.replace(/^Bearer /, '') ?? ''
        // Session and handoff credentials are never device tokens; legacy unprefixed tokens are.
        const dev = /^p(ses|auth)_/.test(token) ? null : db.query('select * from devices where token_hash = ? and not revoked').get(sha(token)) as any
        if (!dev) return bad(401, 'unauthorized')
        db.run('update devices set last_seen = ? where id = ?', [new Date().toISOString(), dev.id])
        // The phone's APNs token changes on reinstall; the latest one wins.
        if (dev.kind === 'phone' && typeof body.push_token === 'string' &&
            /^[A-Fa-f0-9]{32,256}$/.test(body.push_token) && body.push_token !== dev.push_token) {
          db.run('update devices set push_token = ? where id = ?', [body.push_token, dev.id])
        }
        if (dev.kind === 'phone' && Array.isArray(body.push_off)) {
          const off = JSON.stringify([...new Set(body.push_off.filter((t: unknown) => typeof t === 'string' && PUSH_TYPES.has(t)))].sort())
          if (off !== dev.push_off) db.run('update devices set push_off = ? where id = ?', [off, dev.id])
        }
        if ((body.e2e === 1 || body.e2e === 2) && body.e2e !== dev.e2e) db.run('update devices set e2e = ? where id = ?', [body.e2e, dev.id])
        // A laptop's version is informational; its protocol is what the app compares. Keep the last
        // valid values when an older client omits them or sends something malformed.
        if (dev.kind === 'machine') {
          const version = typeof body.version === 'string' && /^[0-9A-Za-z._+-]{1,32}$/.test(body.version) ? body.version : null
          if (version !== null && version !== dev.version) db.run('update devices set version = ? where id = ?', [version, dev.id])
          const protocol = Number.isInteger(body.protocol) && body.protocol >= 0 && body.protocol <= 1_000_000 ? body.protocol : null
          if (protocol !== null && protocol !== dev.protocol) db.run('update devices set protocol = ? where id = ?', [protocol, dev.id])
        }
        if (dev.kind === 'machine' && body.direct !== undefined) {
          const hint = body.direct === null ? null : directHint(body.direct)
          const json = hint ? JSON.stringify(hint) : null
          if (json !== dev.direct) db.run('update devices set direct = ? where id = ?', [json, dev.id])
        }

        const tenant = dev.tenant_id || relayTenant(db)
        const outbox: any[] = Array.isArray(body.outbox) ? body.outbox.slice(0, 500) : []
        const acked: string[] = []
        for (const m of outbox) {
          if (dev.kind === 'machine') {
            if (!valid(m, UP)) continue
            const stored = { ...m, machine: dev.name }
            const fresh = db.run(`insert or ignore into messages (id, machine, dir, json, tenant_id, created) values (?, ?, 'up', ?, ?, ?)`, [m.id, dev.name, JSON.stringify(stored), tenant, Date.now()]).changes
            if (fresh) {
              notifyPhones(stored, tenant)
              wake(tenant, 'up')
            }
          } else {
            if (!valid(m, DOWN) || typeof m.machine !== 'string') continue
            // A phone may only address a machine that belongs to its own tenant.
            if (!db.query(`select 1 from devices where kind = 'machine' and name = ? and tenant_id = ? and not revoked`).get(m.machine, tenant)) continue
            const fresh = db.run(`insert or ignore into messages (id, machine, dir, json, tenant_id, created) values (?, ?, 'down', ?, ?, ?)`, [m.id, m.machine, JSON.stringify(m), tenant, Date.now()]).changes
            if (fresh) wake(tenant, 'down', m.machine)
          }
          acked.push(m.id) // duplicates are acked too: the sender can forget them
        }

        const after = Number(body.after) || 0
        if (after > dev.acked && after <= dev.served) {
          db.run('update devices set acked = ? where id = ?', [after, dev.id])
          if (dev.kind === 'machine') db.run(`delete from messages where tenant_id = ? and dir = 'down' and machine = ? and seq <= ?`, [tenant, dev.name, after])
          else db.run(`delete from messages where tenant_id = ? and dir = 'up' and seq <= (select min(acked) from devices where tenant_id = ? and kind = 'phone' and not revoked)`, [tenant, tenant])
          db.run('delete from messages where created < ?', [Date.now() - UNDELIVERED_TTL])
        }
        let inbox = inboxFor(dev, after, tenant)
        const wait = Math.min(Number(body.wait) || 0, MAX_WAIT)
        if (!inbox.length && wait > 0) {
          await new Promise<void>((resolve) => {
            const waiter: Waiter = { tenant, kind: dev.kind, name: dev.name, done: () => {} }
            const done = () => { clearTimeout(timer); waiting.delete(waiter); resolve() }
            const timer = setTimeout(done, wait * 1000)
            waiter.done = done
            waiting.add(waiter)
            req.signal.addEventListener('abort', done)
          })
          inbox = inboxFor(dev, after, tenant)
        }
        const cursor = inbox.length ? inbox[inbox.length - 1].seq! : after
        if (inbox.length && cursor > dev.served) db.run('update devices set served = ? where id = ?', [cursor, dev.id])
        const res: any = { acked, inbox, cursor }
        // `e2e` appears only for devices that read the newer format, so older peers see no change.
        const format = ({ e2e, ...d }: any) => (e2e >= 2 ? { ...d, e2e } : d)
        if (dev.kind === 'phone') {
          res.machines = (db.query(`select name, last_seen, pubkey, direct, e2e, version, protocol from devices where kind = 'machine' and not revoked and tenant_id = ?`).all(tenant) as any[])
            .map((m) => {
              // A corrupt stored hint must not break every phone sync; show it as none.
              let direct = null
              try { direct = m.direct ? JSON.parse(m.direct) : null } catch {}
              // Version fields appear only once the laptop reported them, so older peers and
              // frozen compatibility fixtures see the same payload as before.
              const out: any = format({ ...m, direct })
              if (m.version == null) delete out.version
              if (m.protocol == null) delete out.protocol
              return out
            })
        }
        else res.phones = (db.query(`select name, pubkey, e2e from devices where kind = 'phone' and not revoked and tenant_id = ?`).all(tenant) as any[]).map(format)
        return Response.json(res)
      }
      return bad(404, 'not found')
    },
  }
}

if (import.meta.main) {
  const db = open(process.env.PERCH_DB ?? 'perch-server.db')
  const [cmd, arg, owner] = process.argv.slice(2)
  if (cmd === 'pair') {
    if (arg === 'phone') { console.error('phones sign in now: `bun server.ts account add <name> --password` (or `account passwd <name>`)'); process.exit(1) }
    if (arg !== 'machine') { console.error('usage: pair machine [owner]'); process.exit(1) }
    console.log(pairCode(db, owner))
  } else if (cmd === 'tenant') {
    console.log(relayTenant(db))
  } else if (cmd === 'devices') {
    console.table(db.query('select id, kind, name, tenant_id, last_seen, version, protocol, revoked, pubkey is not null as encrypted from devices').all())
  } else if (cmd === 'account') {
    try {
      console.log(await accountCli(db, process.argv.slice(3)))
    } catch (e) {
      console.error((e as Error).message)
      process.exit(1)
    }
  } else if (cmd === 'invite') {
    try {
      console.log(inviteCli(db, process.argv.slice(3)))
    } catch (e) {
      console.error((e as Error).message)
      process.exit(1)
    }
  } else if (cmd === 'revoke') {
    console.log(db.run('update devices set revoked = 1 where id = ?', [Number(arg)]).changes ? 'revoked' : 'no such device')
  } else {
    const push = makePushSender(process.env)
    const auth = authConfig(process.env)
    if ((process.env.AUTH_EMAIL === '1' || process.env.AUTH_OAUTH?.trim()) && !auth.publicUrl.startsWith('https://'))
      console.warn('perch: email and OAuth sign-in need PERCH_PUBLIC_URL=https://…; they stay off')
    const server = Bun.serve({ port: Number(process.env.PORT ?? 8787), hostname: process.env.HOST ?? '127.0.0.1', ...app(db, push, auth) })
    const methods = [auth.password && 'password', auth.email && 'email', ...auth.oauth].filter(Boolean).join(', ') || 'code pairing only'
    console.log(`perch relay on ${server.url}, sign-in: ${methods}${push ? (process.env.PUSH_GATEWAY && process.env.PUSH_GATEWAY_KEY ? `, push via ${process.env.PUSH_GATEWAY}` : ', APNs enabled') : ''}`)
  }
}
