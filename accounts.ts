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
      expires integer not null, used integer not null default 0);`)
  // An operator-set (one-time) password must be replaced before it can register a device; a session
  // from such a login carries the flag.
  for (const table of ['identities', 'sessions']) {
    if (!db.query(`select 1 from pragma_table_info('${table}') where name = 'must_change'`).get())
      db.exec(`alter table ${table} add column must_change integer not null default 0`)
  }
}

/// Drops expired one-time rows; runs alongside the pairing-code cleanup.
export function sweep(db: Database, now = Date.now()) {
  for (const table of ['sessions', 'auth_tokens', 'oauth_states', 'rate_limits', 'auth_failures']) db.run(`delete from ${table} where expires < ?`, [now])
}

export const newToken = (prefix: string, rand: Rand = randomBytes) => prefix + rand(32).toString('base64url')

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
export type Binding = { email?: string; github?: string; google?: string }
const iso = () => new Date().toISOString()

function accountByName(db: Database, raw: string) {
  const name = canonicalName(raw)
  const row = name ? (db.query('select * from accounts where name = ?').get(name) as any) : null
  if (!row) throw new Error(`no such account: ${raw}`)
  return row as { id: number; name: string; tenant_id: string; disabled: number }
}

export function bindIdentity(db: Database, rawName: string, bind: Binding) {
  const account = accountByName(db, rawName)
  const rows: [string, string | undefined][] = [['email', bind.email], ['oauth:github', bind.github], ['oauth:google', bind.google]]
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
    if (['email', 'github', 'google'].includes(flag)) {
      if (!rest[i + 1]) throw new Error(`--${flag} needs a value`)
      flags[flag] = rest[++i]
    } else if (['adopt', 'password', 'keep-devices'].includes(flag)) flags[flag] = true
    else throw new Error(`unknown option ${rest[i]}`)
  }
  const bind = { email: flags.email as string, github: flags.github as string, google: flags.google as string }
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
  throw new Error('usage: account add <name> [--adopt] [--password] [--email a] [--github login] [--google email] | list | passwd <name> | bind <name> [--email|--github|--google ...] | disable <name> [--keep-devices]')
}
