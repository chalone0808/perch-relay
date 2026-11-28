// Relay accounts: an allowlisted login that owns one tenant. Logins never create accounts; the
// operator adds them (`bun server.ts account ...`) and binds the identities that may sign in.
// Every credential is a random bearer value stored only as a SHA-256 hash; passwords are scrypt.
import type { Database } from 'bun:sqlite'
import { createHash, randomBytes, scrypt, timingSafeEqual } from 'node:crypto'
import { relaySalt, relayTenant, tenantFor } from './server'

/// A new device can't open anything sealed before it paired, so it starts acked at the head and
/// never holds back deletion of older messages.
export const HEAD = 'select coalesce(max(seq), 0) from messages'

export const sha = (s: string) => createHash('sha256').update(s).digest('hex')
export type Rand = (n: number) => Buffer

export function authSchema(db: Database) {
  db.exec(`
    create table if not exists accounts (
      id integer primary key, name text not null unique, tenant_id text not null unique,
      disabled integer not null default 0, created text not null);
    create table if not exists identities (
      id integer primary key, account_id integer not null references accounts(id),
      provider text not null, subject text not null, external_id text, secret_hash text,
      created text not null, unique(provider, external_id));
    create unique index if not exists identities_subject_unbound
      on identities(provider, subject) where external_id is null;
    create table if not exists sessions (
      id integer primary key, token_hash text not null unique,
      account_id integer not null references accounts(id), expires integer not null,
      created text not null, last_seen text);
    create table if not exists auth_tokens (
      token_hash text primary key, purpose text not null, account_id integer, subject text,
      challenge text, expires integer not null, used integer not null default 0, created text not null);
    create table if not exists rate_limits (key_hash text primary key, count integer not null, expires integer not null);
    create table if not exists auth_failures (key_hash text primary key, fails integer not null, until integer not null, expires integer not null);
    create table if not exists oauth_states (
      state_hash text primary key, provider text not null, challenge text not null,
      expires integer not null, used integer not null default 0);
    create table if not exists invites (
      token_hash text primary key, expires integer not null, used integer not null default 0,
      created text not null, claimed_by integer references accounts(id));
    create table if not exists pending_identities (
      token_hash text primary key, provider text not null, external_id text not null, subject text not null,
      challenge text not null, expires integer not null, used integer not null default 0, created text not null);
    create table if not exists oauth_links (
      state_hash text primary key, provider text not null, account_id integer not null references accounts(id),
      expires integer not null, used integer not null default 0, created text not null);`)
  // An operator-set (one-time) password must be replaced before it can register a device; a session
  // from such a login carries the flag.
  for (const table of ['identities', 'sessions']) {
    if (!db.query(`select 1 from pragma_table_info('${table}') where name = 'must_change'`).get())
      db.exec(`alter table ${table} add column must_change integer not null default 0`)
  }
}

/// Drops expired one-time rows; runs alongside the pairing-code cleanup.
export function sweep(db: Database, now = Date.now()) {
  for (const table of ['sessions', 'auth_tokens', 'oauth_states', 'invites', 'pending_identities', 'oauth_links', 'rate_limits', 'auth_failures']) db.run(`delete from ${table} where expires < ?`, [now])
}

export const newToken = (prefix: string, rand: Rand = randomBytes) => prefix + rand(32).toString('base64url')

/// A per-pairing device identity. The device's name stays a display label; this id is what
/// routing, revoke and cursors index, so re-pairing under the same name is a different device.
export const newDeviceId = (rand: Rand = randomBytes) => 'dev_' + rand(16).toString('hex')

/// The row's stable identity, minted lazily for rows created before device ids (test fixtures,
/// legacy linked phones). New pairings and registrations set it at insert.
export function ensureDeviceId(db: Database, dev: any): string {
  if (typeof dev?.device_id === 'string' && dev.device_id) return dev.device_id
  const id = newDeviceId()
  db.run('update devices set device_id = ? where id = ?', [id, dev.id])
  dev.device_id = id
  return id
}

/// Inserts a fresh token's hash. A unique collision gets exactly one retry; a second one is an
/// operational error and is thrown, never ignored.
export function insertWithToken(prefix: string, insert: (hash: string) => void, rand: Rand = randomBytes): string {
  for (let attempt = 0; ; attempt++) {
    const token = newToken(prefix, rand)
    try {
      insert(sha(token))
      return token
    } catch (e) {
      if (attempt > 0 || !String((e as Error)?.message).includes('UNIQUE constraint failed')) throw e
    }
  }
}

const SCRYPT = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }
const derive = (password: string, salt: Buffer) =>
  new Promise<Buffer>((resolve, reject) => scrypt(password, salt, 32, SCRYPT, (e, key) => (e ? reject(e) : resolve(key))))

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(32)
  const key = await derive(password, salt)
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${key.toString('base64')}`
}

const DUMMY_SALT = randomBytes(32)

/// Constant-time check. With no stored hash (unknown or disabled account) it still runs one scrypt,
/// so the response time does not reveal whether the account exists.
export async function verifyPassword(password: string, stored: string | null): Promise<boolean> {
  const parts = stored?.split('$') ?? []
  if (parts.length !== 6 || parts[0] !== 'scrypt' || parts[1] !== String(SCRYPT.N) || parts[2] !== String(SCRYPT.r) || parts[3] !== String(SCRYPT.p)) {
    await derive(password, DUMMY_SALT)
    return false
  }
  const expected = Buffer.from(parts[5], 'base64')
  const key = await derive(password, Buffer.from(parts[4], 'base64'))
  return expected.length === key.length && timingSafeEqual(expected, key)
}

/// Login names: trimmed, lowercased, 1-64 characters, no whitespace or control characters.
export function canonicalName(raw: unknown): string | null {
  if (typeof raw !== 'string') return null
  const name = raw.trim().toLowerCase()
  return /^[^\s\p{Cc}]{1,64}$/u.test(name) ? name : null
}

const lower = (s: string) => s.trim().toLowerCase()
export type Binding = { email?: string; github?: string; google?: string; apple?: string }
const iso = () => new Date().toISOString()

export const INVITE_PREFIX = 'pinv_'

/// One-time sign-up keys. Only the SHA-256 of each key is stored; the raw key is returned once.
export function createInvites(
  db: Database,
  opts: { count?: number; ttlMs?: number; now?: number; rand?: Rand } = {},
): string[] {
  const count = opts.count ?? 1
  const ttlMs = opts.ttlMs ?? 7 * 24 * 3600_000
  const at = opts.now ?? Date.now()
  const rand = opts.rand ?? randomBytes
  if (!Number.isInteger(count) || count < 1 || count > 100) throw new Error('invite count must be 1-100')
  if (!Number.isFinite(ttlMs) || ttlMs < 60_000 || ttlMs > 30 * 24 * 3600_000) throw new Error('invite lifetime must be 1-720 hours')
  const keys: string[] = []
  for (let i = 0; i < count; i++) {
    keys.push(insertWithToken(INVITE_PREFIX, (hash) =>
      db.run('insert into invites (token_hash, expires, used, created) values (?, ?, 0, ?)', [hash, at + ttlMs, new Date(at).toISOString()]), rand))
  }
  return keys
}

/// `bun server.ts invite <create|list> ...`; raw keys are shown only by create, once.
export function inviteCli(db: Database, args: string[]): string {
  const [sub, ...rest] = args
  if (sub === 'create') {
    let count = 1
    let ttlHours = 168
    for (let i = 0; i < rest.length; i++) {
      const flag = rest[i].replace(/^--/, '')
      if (flag === 'count' || flag === 'ttl-hours') {
        if (!rest[i + 1]) throw new Error(`--${flag} needs a value`)
        const n = Number(rest[++i])
        if (!Number.isInteger(n)) throw new Error(`--${flag} must be a number`)
        if (flag === 'count') count = n
        else ttlHours = n
      } else throw new Error(`unknown option ${rest[i]}`)
    }
    return createInvites(db, { count, ttlMs: ttlHours * 3600_000 }).join('\n')
  }
  if (sub === 'list') {
    return JSON.stringify(db.query(`
      select i.expires, i.used, i.created, a.name as claimed_by
      from invites i left join accounts a on a.id = i.claimed_by
      order by i.created desc`).all(), null, 2)
  }
  throw new Error('usage: invite create [--count N] [--ttl-hours H] | invite list')
}

export class ClaimError extends Error {
  constructor(readonly status: 400 | 409, message: string) {
    super(message)
  }
}

/// Creates an account at invite claim time and binds the already-verified provider identity.
/// The caller must run this inside the same transaction that consumes the invite/pending rows.
export function insertClaimedAccount(
  db: Database,
  rawName: string,
  identity: { provider: string; subject: string; externalId: string },
): { id: number; name: string; tenant: string } {
  const name = canonicalName(rawName)
  if (!name) throw new ClaimError(400, 'that invite key cannot be an account name')
  const owner = relayTenant(db)
  const tenant = tenantFor(name, relaySalt(db))
  if (tenant === owner || db.query('select 1 from accounts where tenant_id = ?').get(tenant))
    throw new ClaimError(409, 'that invite key cannot create an account')
  if (db.query('select 1 from devices where tenant_id = ? limit 1').get(tenant))
    throw new ClaimError(409, 'that invite key cannot create an account')
  let id: number
  try {
    const result = db.run('insert into accounts (name, tenant_id, created) values (?, ?, ?)', [name, tenant, iso()])
    id = Number(result.lastInsertRowid)
  } catch (e) {
    if (String((e as Error)?.message).includes('UNIQUE constraint failed')) throw new ClaimError(409, 'that invite key cannot create an account')
    throw e
  }
  try {
    db.run('insert into identities (account_id, provider, subject, external_id, created) values (?, ?, ?, ?, ?)',
      [id, identity.provider, lower(identity.subject), identity.externalId, iso()])
  } catch (e) {
    if (String((e as Error)?.message).includes('UNIQUE constraint failed')) throw new ClaimError(409, 'that account is already linked')
    throw e
  }
  return { id, name, tenant }
}

function accountByName(db: Database, raw: string) {
  const name = canonicalName(raw)
  const row = name ? (db.query('select * from accounts where name = ?').get(name) as any) : null
  if (!row) throw new Error(`no such account: ${raw}`)
  return row as { id: number; name: string; tenant_id: string; disabled: number }
}

export function bindIdentity(db: Database, rawName: string, bind: Binding) {
  const account = accountByName(db, rawName)
  const rows: [string, string | undefined][] = [['email', bind.email], ['oauth:github', bind.github], ['oauth:google', bind.google], ['oauth:apple', bind.apple]]
  db.transaction(() => {
    for (const [provider, subject] of rows) {
      if (!subject?.trim()) continue
      db.run('insert into identities (account_id, provider, subject, created) values (?, ?, ?, ?)', [account.id, provider, lower(subject), iso()])
    }
  })()
}

/// A 16-character one-time password, shown once; only its scrypt hash is kept. The user must
/// replace it on first sign-in.
export async function setPassword(db: Database, rawName: string): Promise<string> {
  const account = accountByName(db, rawName)
  const password = randomBytes(12).toString('base64url')
  const hash = await hashPassword(password)
  db.transaction(() => {
    db.run(`delete from identities where account_id = ? and provider = 'password'`, [account.id])
    db.run(`insert into identities (account_id, provider, subject, secret_hash, must_change, created) values (?, 'password', ?, ?, 1, ?)`, [account.id, account.name, hash, iso()])
  })()
  return password
}

export async function addAccount(db: Database, rawName: string, opts: Binding & { adopt?: boolean; password?: boolean } = {}) {
  const name = canonicalName(rawName)
  if (!name) throw new Error('account names are 1-64 characters with no spaces')
  const owner = relayTenant(db)
  const tenant = opts.adopt ? owner : tenantFor(name, relaySalt(db))
  if (db.query('select 1 from accounts where tenant_id = ?').get(tenant)) throw new Error('another account already holds that tenant')
  // --adopt is the only way to take over a tenant that already has data.
  if (!opts.adopt && (tenant === owner || db.query('select 1 from devices where tenant_id = ? limit 1').get(tenant)))
    throw new Error(`a tenant for "${name}" already has devices; use --adopt for the relay's own tenant`)
  db.run('insert into accounts (name, tenant_id, created) values (?, ?, ?)', [name, tenant, iso()])
  bindIdentity(db, name, opts)
  const password = opts.password ? await setPassword(db, name) : undefined
  return { name, tenant, password }
}

/// Blocks every login, revokes sessions and pending handoffs, and by default revokes the tenant's
/// devices so offboarding cuts message access at once.
export function disableAccount(db: Database, rawName: string, opts: { keepDevices?: boolean } = {}) {
  const account = accountByName(db, rawName)
  db.transaction(() => {
    db.run('update accounts set disabled = 1 where id = ?', [account.id])
    db.run('delete from sessions where account_id = ?', [account.id])
    db.run('delete from auth_tokens where account_id = ?', [account.id])
    if (!opts.keepDevices) db.run('update devices set revoked = 1 where tenant_id = ?', [account.tenant_id])
  })()
}

export function listAccounts(db: Database) {
  return db.query(`
    select a.id, a.name, a.tenant_id, a.disabled, a.created,
      (select group_concat(provider || ':' || subject || case when external_id is null then '' else ' (bound)' end, ', ')
        from identities i where i.account_id = a.id) as identities
    from accounts a order by a.id`).all()
}

/// `bun server.ts account <add|list|passwd|bind|disable> ...`; returns what to print.
export async function accountCli(db: Database, args: string[]): Promise<string> {
  const [sub, name, ...rest] = args
  const flags: Record<string, string | true> = {}
  for (let i = 0; i < rest.length; i++) {
    const flag = rest[i].replace(/^--/, '')
    if (['email', 'github', 'google', 'apple'].includes(flag)) {
      if (!rest[i + 1]) throw new Error(`--${flag} needs a value`)
      flags[flag] = rest[++i]
    } else if (['adopt', 'password', 'keep-devices'].includes(flag)) flags[flag] = true
    else throw new Error(`unknown option ${rest[i]}`)
  }
  const bind = { email: flags.email as string, github: flags.github as string, google: flags.google as string, apple: flags.apple as string }
  switch (sub) {
    case 'add': {
      if (!name) break
      const r = await addAccount(db, name, { ...bind, adopt: !!flags.adopt, password: !!flags.password })
      return `added ${r.name} (tenant ${r.tenant})${r.password ? `\none-time password: ${r.password}` : ''}`
    }
    case 'list':
      return JSON.stringify(listAccounts(db), null, 2)
    case 'passwd':
      if (!name) break
      return `one-time password: ${await setPassword(db, name)}`
    case 'bind':
      if (!name) break
      bindIdentity(db, name, bind)
      return `bound to ${canonicalName(name)}`
    case 'disable':
      if (!name) break
      disableAccount(db, name, { keepDevices: !!flags['keep-devices'] })
      return `disabled ${canonicalName(name)}${flags['keep-devices'] ? ' (devices kept)' : ' and revoked its devices'}`
  }
  throw new Error('usage: account add <name> [--adopt] [--password] [--email a] [--github login] [--google email] [--apple subject] | list | passwd <name> | bind <name> [--email|--github|--google|--apple ...] | disable <name> [--keep-devices]')
}
