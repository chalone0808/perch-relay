// Sign-in for relay accounts. Every flow ends the same way: a one-hour session token the app trades
// for an ordinary device token at POST /v1/devices, after which /v1/sync works exactly as for a
// code-paired device. Accounts only exist if the operator added them (accounts.ts).
//
//   GET  /v1/auth/methods                        → { password, email, oauth: [] }
//   POST /v1/auth/password  { username, password } → { session, must_change_password? }
//   POST /v1/auth/password/change { username, password, new_password } → { session }
//   POST /v1/auth/exchange  { code, verifier }     → { session }   (handoff from a browser flow)
//   POST /v1/auth/email/start { email, challenge } → 202 {}; GET …/email/verify; POST …/email/consume
//   GET  /v1/auth/oauth/:provider/start?challenge=…  → provider → …/callback → perch://auth/callback
//   POST /v1/devices        Bearer pses_…  { name, pubkey } → { token, kind: 'phone' }
//   POST /v1/devices/link   Bearer pses_…  { token }         → { token }   a code-paired phone becomes
//                           a signed-in one: same device row and key, new pdev_ token, old one dead
//   POST /v1/pair/machine   Bearer pdev_… (a phone)          → { code, expires }
//   POST /v1/unpair         Bearer <device token>            → {}  (the device revokes itself)
import type { Database } from 'bun:sqlite'
import { createHash, createPublicKey, randomBytes, timingSafeEqual, verify } from 'node:crypto'
import { isIP } from 'node:net'
import { canonicalName, ClaimError, HEAD, hashPassword, insertClaimedAccount, insertWithToken, sha, sweep, verifyPassword, type Rand } from './accounts'
import { smtpSender, type SendMail } from './smtp'

const SESSION_MS = 60 * 60_000
const HANDOFF_MS = 5 * 60_000
const EMAIL_MS = 15 * 60_000
const PENDING_MS = 10 * 60_000
const MINUTE = 60_000

export type AuthConfig = {
  password: boolean
  email: boolean
  oauth: ('github' | 'google' | 'apple')[]
  publicUrl: string
  smtpUrl?: string
  emailFrom?: string
  clients: Partial<Record<'github' | 'google', { id: string; secret: string }>>
  appleClientId?: string
}

/// What the deployer enabled. Email and OAuth also need an https PERCH_PUBLIC_URL (their links and
/// callbacks are built from it) plus their own credentials; anything missing is reported off.
export function authConfig(env: Record<string, string | undefined> = process.env): AuthConfig {
  const publicUrl = (env.PERCH_PUBLIC_URL ?? '').trim().replace(/\/+$/, '')
  const https = /^https:\/\/[^/\s]+/.test(publicUrl)
  const clients: AuthConfig['clients'] = {}
  for (const p of ['github', 'google'] as const) {
    const id = env[`${p.toUpperCase()}_CLIENT_ID`]?.trim()
    const secret = env[`${p.toUpperCase()}_CLIENT_SECRET`]?.trim()
    if (id && secret) clients[p] = { id, secret }
  }
  const wanted = (env.AUTH_OAUTH ?? '').split(',').map((s) => s.trim().toLowerCase())
  const appleClientId = env.APPLE_CLIENT_ID?.trim()
  const oauth: AuthConfig['oauth'] = []
  if (https) {
    for (const p of ['github', 'google'] as const) if (wanted.includes(p) && clients[p]) oauth.push(p)
    if (wanted.includes('apple') && appleClientId) oauth.push('apple')
  }
  return {
    password: env.AUTH_PASSWORD?.trim() !== '0',
    email: https && env.AUTH_EMAIL?.trim() === '1' && !!env.SMTP_URL?.trim() && !!env.AUTH_EMAIL_FROM?.trim(),
    oauth,
    publicUrl,
    smtpUrl: env.SMTP_URL?.trim(),
    emailFrom: env.AUTH_EMAIL_FROM?.trim(),
    clients,
    appleClientId: https ? appleClientId : undefined,
  }
}

const loopback = (a: string) => a === '::1' || a.startsWith('127.') || a.startsWith('::ffff:127.')

/// The client address for rate limits: the socket peer, unless the peer is loopback (Caddy on this
/// host), in which case Caddy's overwritten X-Real-IP. X-Forwarded-For is never read.
export function clientIp(peer: string | undefined, realIp: string | null): string {
  const real = realIp?.trim()
  return peer && loopback(peer) && real && isIP(real) ? real : peer ?? ''
}

/// Fixed-window counters in SQLite, so a restart doesn't hand out fresh budgets and several relay
/// processes on one database share them. Keys are hashed: no IP or address is stored.
export class Limiter {
  private hit
  constructor(db: Database, private now: () => number) {
    // One statement: start a new window if the old one ended, else count against it.
    this.hit = db.query(`insert into rate_limits (key_hash, count, expires) values (?1, 1, ?2 + ?3)
      on conflict(key_hash) do update set
        count = case when ?2 >= expires then 1 else count + 1 end,
        expires = case when ?2 >= expires then ?2 + ?3 else expires end
      returning count, expires`)
  }
  /// 0 when allowed, else seconds until the window resets.
  take(key: string, max: number, windowMs: number): number {
    const now = this.now()
    const r = this.hit.get(sha(key), now, windowMs) as { count: number; expires: number }
    return r.count > max ? Math.max(1, Math.ceil((r.expires - now) / 1000)) : 0
  }
}

export type AuthDeps = {
  now?: () => number
  rand?: Rand
  /// A device joined this tenant: wake its long-polls so peers learn the new key now.
  wake?: (tenant: string) => void
  /// Outbound mail; defaults to SMTP_URL. Never awaited in a request.
  sendMail?: SendMail
  /// Provider HTTP (token exchange, user info, Google's keys); stubbed in tests.
  fetch?: typeof fetch
}

type Who = { externalId: string; subject: string }
type Fetch = typeof fetch

async function getJson(fetchFn: Fetch, url: string, init: RequestInit = {}): Promise<any> {
  const res = await fetchFn(url, { ...init, signal: AbortSignal.timeout(10_000) })
  if (!res.ok) throw new Error(`${new URL(url).host} answered ${res.status}`)
  return res.json()
}

/// GitHub's numeric id is immutable; the login can be renamed or reclaimed by someone else.
async function githubIdentity(fetchFn: Fetch, client: { id: string; secret: string }, code: string, redirectUri: string): Promise<Who> {
  const tok = await getJson(fetchFn, 'https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { accept: 'application/json', 'content-type': 'application/json' },
    body: JSON.stringify({ client_id: client.id, client_secret: client.secret, code, redirect_uri: redirectUri }),
  })
  if (typeof tok?.access_token !== 'string') throw new Error('github gave no access token')
  const user = await getJson(fetchFn, 'https://api.github.com/user', {
    headers: { authorization: `Bearer ${tok.access_token}`, accept: 'application/vnd.github+json', 'user-agent': 'perch-relay' },
  })
  if (!Number.isSafeInteger(user?.id) || typeof user?.login !== 'string') throw new Error('github gave no user')
  return { externalId: String(user.id), subject: user.login.toLowerCase() }
}

/// Checks a Google ID token's RS256 signature against Google's keys, then issuer, audience, expiry
/// and a verified email. Returns the immutable `sub` and the lowercased email.
export function verifyGoogleIdToken(idToken: string, clientId: string, keys: JsonWebKey[], now: number): Who {
  const [h, p, sig, extra] = String(idToken).split('.')
  if (!h || !p || !sig || extra !== undefined) throw new Error('malformed id token')
  const header = JSON.parse(Buffer.from(h, 'base64url').toString())
  const jwk = keys.find((k: any) => k.kid === header.kid && k.kty === 'RSA')
  if (header.alg !== 'RS256' || !jwk) throw new Error('unknown id token key')
  if (!verify('RSA-SHA256', Buffer.from(`${h}.${p}`), createPublicKey({ key: jwk as any, format: 'jwk' }), Buffer.from(sig, 'base64url')))
    throw new Error('bad id token signature')
  const c = JSON.parse(Buffer.from(p, 'base64url').toString())
  if (c.iss !== 'https://accounts.google.com' && c.iss !== 'accounts.google.com') throw new Error('bad id token issuer')
  if (Array.isArray(c.aud) ? !c.aud.includes(clientId) : c.aud !== clientId) throw new Error('bad id token audience')
  if (!(Number(c.exp) * 1000 > now)) throw new Error('expired id token')
  if (c.email_verified !== true || typeof c.email !== 'string' || typeof c.sub !== 'string') throw new Error('no verified email')
  return { externalId: c.sub, subject: c.email.toLowerCase() }
}

/// Checks Apple's native identity token: RS256 against Apple's keys, Apple issuer, the app's
/// audience, expiry, and the SHA-256 of the raw nonce the app generated. Apple's `sub` is the
/// identity; email and name are not required and are never used as keys.
export function verifyAppleIdToken(idToken: string, clientId: string, keys: JsonWebKey[], now: number, rawNonce: string): Who {
  const [h, p, sig, extra] = String(idToken).split('.')
  if (!h || !p || !sig || extra !== undefined) throw new Error('malformed id token')
  const header = JSON.parse(Buffer.from(h, 'base64url').toString())
  const jwk = keys.find((k: any) => k.kid === header.kid && k.kty === 'RSA')
  if (header.alg !== 'RS256' || !jwk) throw new Error('unknown id token key')
  if (!verify('RSA-SHA256', Buffer.from(`${h}.${p}`), createPublicKey({ key: jwk as any, format: 'jwk' }), Buffer.from(sig, 'base64url')))
    throw new Error('bad id token signature')
  const c = JSON.parse(Buffer.from(p, 'base64url').toString())
  if (c.iss !== 'https://appleid.apple.com') throw new Error('bad id token issuer')
  if (Array.isArray(c.aud) ? !c.aud.includes(clientId) : c.aud !== clientId) throw new Error('bad id token audience')
  if (!(Number(c.exp) * 1000 > now)) throw new Error('expired id token')
  if (typeof c.sub !== 'string' || !c.sub) throw new Error('no id token subject')
  const expected = createHash('sha256').update(rawNonce).digest('hex')
  const actual = typeof c.nonce === 'string' ? c.nonce.toLowerCase() : ''
  if (actual.length !== expected.length || !timingSafeEqual(Buffer.from(actual), Buffer.from(expected)))
    throw new Error('bad id token nonce')
  return { externalId: c.sub, subject: c.sub }
}

const CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
export const escapeHtml = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`)

/// A self-contained page: no external assets, escaped by the caller, and a CSP that allows nothing else.
export function page(status: number, title: string, body: string, headers: Record<string, string> = {}) {
  const html = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title><style>body{font:17px -apple-system,system-ui,sans-serif;margin:0;display:grid;place-items:center;min-height:100vh;background:#f2f2f7;color:#1c1c1e}
main{max-width:22rem;padding:2rem;text-align:center}h1{font-size:1.4rem}button{font:inherit;font-weight:600;border:0;border-radius:12px;padding:.8rem 1.6rem;background:#007aff;color:#fff}
@media(prefers-color-scheme:dark){body{background:#000;color:#f2f2f7}}</style><main>${body}</main></html>`
  return new Response(html, {
    status,
    headers: { 'content-type': 'text/html; charset=utf-8', 'content-security-policy': CSP, 'cache-control': 'no-store', 'referrer-policy': 'no-referrer', ...headers },
  })
}
const appRedirect = (code: string) => new Response(null, { status: 302, headers: { location: `perch://auth/callback?code=${encodeURIComponent(code)}`, 'cache-control': 'no-store' } })
const appRedirectPending = (token: string) => new Response(null, { status: 302, headers: { location: `perch://auth/callback?pending=${encodeURIComponent(token)}`, 'cache-control': 'no-store' } })
const linkRedirect = (query: string) => new Response(null, { status: 302, headers: { location: `perch://auth/link?${query}`, 'cache-control': 'no-store' } })
const EMAIL = /^[^\s@<>()",;:\\]{1,64}@[^\s@<>()",;:\\]{1,190}$/

const json = (status: number, body: unknown, headers: Record<string, string> = {}) => Response.json(body, { status, headers })
const bad = (status: number, error: string) => json(status, { error })
const slow = (retry: number) => json(429, { error: 'slow down' }, { 'retry-after': String(retry) })
const bearer = (req: Request) => req.headers.get('authorization')?.replace(/^Bearer /, '') ?? ''
const pubkey = (k: unknown) => (typeof k === 'string' && /^[A-Za-z0-9_-]{43}$/.test(k) ? k : null)
export const CHALLENGE = /^[A-Za-z0-9_-]{43}$/
export const challengeOf = (verifier: string) => createHash('sha256').update(verifier).digest('base64url')
const sameString = (a: string, b: string) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b))

export function authRoutes(db: Database, cfg: AuthConfig, deps: AuthDeps = {}) {
  const now = deps.now ?? Date.now
  const rand = deps.rand ?? randomBytes
  const limits = new Limiter(db, now)
  const iso = () => new Date(now()).toISOString()
  const fetchFn = deps.fetch ?? fetch
  let googleKeys: { keys: JsonWebKey[]; at: number } | null = null
  let appleKeys: { keys: JsonWebKey[]; at: number } | null = null
  let appleKeysFetch: Promise<JsonWebKey[]> | null = null
  const send = deps.sendMail ?? (cfg.email ? smtpSender(cfg.smtpUrl!, cfg.emailFrom!) : undefined)

  function fetchAppleKeys(): Promise<JsonWebKey[]> {
    if (!appleKeysFetch) {
      appleKeysFetch = getJson(fetchFn, 'https://appleid.apple.com/auth/keys')
        .then((j) => (Array.isArray(j?.keys) ? j.keys : []))
        .finally(() => { appleKeysFetch = null })
    }
    return appleKeysFetch
  }

  async function getAppleKeys(refresh = false): Promise<JsonWebKey[]> {
    if (!refresh && appleKeys && now() - appleKeys.at < 60 * MINUTE) return appleKeys.keys
    const keys = await fetchAppleKeys()
    appleKeys = { keys, at: now() }
    return keys
  }

  async function appleWho(identityToken: string, rawNonce: string): Promise<Who> {
    const clientId = cfg.appleClientId!
    const keys = await getAppleKeys()
    try {
      return verifyAppleIdToken(identityToken, clientId, keys, now(), rawNonce)
    } catch (e) {
      // Apple rotates signing keys; an unknown kid gets one fresh JWKS fetch.
      if (!String((e as Error)?.message).includes('unknown id token key')) throw e
      return verifyAppleIdToken(identityToken, clientId, await getAppleKeys(true), now(), rawNonce)
    }
  }

  async function body(req: Request): Promise<any> {
    try { return await req.json() } catch { return null }
  }

  function createSession(accountId: number, mustChange = false) {
    return insertWithToken('pses_', (hash) =>
      db.run('insert into sessions (token_hash, account_id, expires, must_change, created) values (?, ?, ?, ?, ?)',
        [hash, accountId, now() + SESSION_MS, mustChange ? 1 : 0, iso()]), rand)
  }

  /// A handoff code for a browser flow: single use, five minutes, bound to the app's challenge.
  function createHandoff(accountId: number, challenge: string) {
    return insertWithToken('pauth_', (hash) =>
      db.run(`insert into auth_tokens (token_hash, purpose, account_id, challenge, expires, created) values (?, 'handoff', ?, ?, ?, ?)`,
        [hash, accountId, challenge, now() + HANDOFF_MS, iso()]), rand)
  }

  /// A verified provider identity waiting for an invite key; single use, ten minutes.
  function createPending(provider: string, who: Who, challenge: string) {
    return insertWithToken('ppend_', (hash) =>
      db.run(`insert into pending_identities (token_hash, provider, external_id, subject, challenge, expires, created) values (?, ?, ?, ?, ?, ?, ?)`,
        [hash, `oauth:${provider}`, who.externalId, who.subject, challenge, now() + PENDING_MS, iso()]), rand)
  }

  /// The session's account, if the session is live and the account is still enabled.
  function sessionAccount(req: Request): { id: number; tenant_id: string; must_change: number } | null {
    const token = bearer(req)
    if (!token.startsWith('pses_')) return null
    const row = db.query(`select s.id as sid, s.must_change, a.id, a.tenant_id from sessions s join accounts a on a.id = s.account_id
      where s.token_hash = ? and s.expires > ? and a.disabled = 0`).get(sha(token), now()) as any
    if (!row) return null
    db.run('update sessions set last_seen = ? where id = ?', [iso(), row.sid])
    return { id: row.id, tenant_id: row.tenant_id, must_change: row.must_change }
  }

  type AccountAuth = { id: number; name: string; tenant: string; mustChange: number }
  const accountName = (id: number) =>
    (db.query('select name from accounts where id = ? and disabled = 0').get(id) as any)?.name ?? ''
  const providersFor = (id: number) => {
    const set = new Set((db.query('select provider from identities where account_id = ?').all(id) as any[])
      .map((r) => r.provider.startsWith('oauth:') ? r.provider.slice(6) : r.provider))
    return ['password', 'email', 'github', 'google', 'apple'].filter((p) => set.has(p))
  }

  /// Settings uses the phone's pdev_ token; the post-claim rename can use the pses_ session.
  function accountFor(req: Request): AccountAuth | null {
    const token = bearer(req)
    if (token.startsWith('pses_')) {
      const session = sessionAccount(req)
      if (!session) return null
      const row = db.query('select name, tenant_id from accounts where id = ? and disabled = 0').get(session.id) as any
      return row ? { id: session.id, name: row.name, tenant: row.tenant_id, mustChange: session.must_change } : null
    }
    if (token.startsWith('pdev_')) {
      const row = db.query(`select a.id, a.name, a.tenant_id from devices d join accounts a on a.tenant_id = d.tenant_id
        where d.token_hash = ? and d.kind = 'phone' and not d.revoked and a.disabled = 0`).get(sha(token)) as any
      return row ? { id: row.id, name: row.name, tenant: row.tenant_id, mustChange: 0 } : null
    }
    return null
  }

  function accountGate(req: Request): AccountAuth | Response {
    const account = accountFor(req)
    if (!account) return bad(401, 'unauthorized')
    if (account.mustChange) return bad(403, 'change the one-time password first')
    return account
  }

  /// Checks a username and password under the sign-in rate limits and backoff. Returns the account
  /// row, or the response to send (429, or the uniform 401).
  async function checkPassword(ip: string, name: string, pw: string): Promise<{ id: number; must_change: number } | Response> {
    // Per-IP first: one noisy client must not spend the relay-wide budget everyone shares.
    const retry = limits.take(`pw-ip:${ip}`, 10, MINUTE) || limits.take(`pw-acct:${name}`, 10, MINUTE) || limits.take('pw', 100, MINUTE)
    if (retry) return slow(retry)
    const key = sha(`${ip}\n${name}`) // per IP + account, never per account alone
    const backoff = db.query('select until from auth_failures where key_hash = ?').get(key) as { until: number } | null
    if (backoff && backoff.until > now()) return slow(Math.ceil((backoff.until - now()) / 1000))
    const row = name && pw
      ? (db.query(`select a.id, a.disabled, i.secret_hash, i.must_change from identities i join accounts a on a.id = i.account_id
          where i.provider = 'password' and i.subject = ?`).get(name) as any)
      : null
    // Unknown, disabled and wrong all cost one scrypt and return the same answer.
    const ok = await verifyPassword(pw, row && !row.disabled ? row.secret_hash : null)
    if (!ok) {
      const { fails } = db.query(`insert into auth_failures (key_hash, fails, until, expires) values (?1, 1, 0, ?2)
        on conflict(key_hash) do update set fails = fails + 1, expires = ?2 returning fails`).get(key, now() + 60 * MINUTE) as { fails: number }
      // After five straight failures this IP + account pair waits 1, 2, 4 … 60 s. No global lock.
      // A quiet hour forgets the streak.
      if (fails >= 5) db.run('update auth_failures set until = ? where key_hash = ?', [now() + Math.min(60, 2 ** (fails - 5)) * 1000, key])
      return bad(401, 'invalid credentials')
    }
    db.run('delete from auth_failures where key_hash = ?', [key])
    return row
  }

  const passwordFields = (b: any) => ({
    name: canonicalName(b?.username) ?? '',
    pw: typeof b?.password === 'string' && b.password.length <= 1024 ? b.password : '',
  })

  async function password(req: Request, ip: string) {
    const { name, pw } = passwordFields(await body(req))
    const row = await checkPassword(ip, name, pw)
    if (row instanceof Response) return row
    // A one-time password signs in, but its session can't register a device until it's replaced.
    const mustChange = !!row.must_change
    return json(200, {
      session: createSession(row.id, mustChange),
      account_id: row.id,
      ...(mustChange ? { must_change_password: true } : {}),
    })
  }

  /// Replaces a password, proven by the current one; works for a first sign-in and from Settings
  /// alike. Ends the account's other sessions and returns a fresh, unrestricted one.
  async function changePassword(req: Request, ip: string) {
    const b = await body(req)
    const next = typeof b?.new_password === 'string' ? b.new_password : ''
    if (next.length < 10 || next.length > 1024) return bad(400, 'choose a password of at least 10 characters')
    const { name, pw } = passwordFields(b)
    if (next === pw) return bad(400, 'choose a password different from the current one')
    const row = await checkPassword(ip, name, pw)
    if (row instanceof Response) return row
    const hash = await hashPassword(next)
    db.transaction(() => {
      db.run(`update identities set secret_hash = ?, must_change = 0 where account_id = ? and provider = 'password'`, [hash, row.id])
      db.run('delete from sessions where account_id = ?', [row.id])
    })()
    return json(200, { session: createSession(row.id), account_id: row.id })
  }

  async function exchange(req: Request, ip: string) {
    const retry = limits.take(`exchange:${ip}`, 30, MINUTE)
    if (retry) return slow(retry)
    const b = await body(req)
    const denied = () => bad(403, 'invalid or expired code')
    const code = typeof b?.code === 'string' ? b.code : ''
    const verifier = typeof b?.verifier === 'string' && b.verifier.length >= 43 && b.verifier.length <= 128 ? b.verifier : ''
    if (!code.startsWith('pauth_') || !verifier) return denied()
    const row = db.query(`select account_id, challenge from auth_tokens where token_hash = ? and purpose = 'handoff' and used = 0 and expires > ?`)
      .get(sha(code), now()) as any
    // The verifier is checked before anything is consumed, so a wrong one burns nothing.
    if (!row || !sameString(challengeOf(verifier), row.challenge)) return denied()
    if (!db.run('update auth_tokens set used = 1 where token_hash = ? and used = 0', [sha(code)]).changes) return denied()
    if (!db.query('select 1 from accounts where id = ? and disabled = 0').get(row.account_id)) return denied()
    return json(200, { session: createSession(row.account_id), account_id: row.account_id })
  }

  /// Phones paired with a relay code before sign-in hold an unprefixed token. Signing in proves the
  /// account; the phone's current token proves the device. Both must belong to the same tenant.
  async function linkDevice(req: Request) {
    const account = sessionAccount(req)
    if (!account) return bad(401, 'unauthorized')
    if (account.must_change) return bad(403, 'change the one-time password first')
    const retry = limits.take(`devices:${account.id}`, 5, 60 * MINUTE)
    if (retry) return slow(retry)
    const b = await body(req)
    const old = typeof b?.token === 'string' ? b.token : ''
    if (/^p(dev|ses|auth)_/.test(old)) return bad(400, 'this phone is already signed in')
    const dev = old ? (db.query(`select id, kind, tenant_id from devices where token_hash = ? and not revoked`).get(sha(old)) as any) : null
    // Unknown, revoked, a laptop, or another tenant's device: one answer for all of them.
    if (!dev || dev.kind !== 'phone' || dev.tenant_id !== account.tenant_id) return bad(403, 'this phone is not in your account')
    const token = insertWithToken('pdev_', (hash) => db.run('update devices set token_hash = ? where id = ?', [hash, dev.id]), rand)
    return json(200, { token, account_id: account.id })
  }

  async function registerDevice(req: Request) {
    const account = sessionAccount(req)
    if (!account) return bad(401, 'unauthorized')
    if (account.must_change) return bad(403, 'change the one-time password first')
    const retry = limits.take(`devices:${account.id}`, 5, 60 * MINUTE)
    if (retry) return slow(retry)
    const b = await body(req)
    const name = typeof b?.name === 'string' ? b.name.trim() : ''
    if (name.length < 1 || name.length > 64) return bad(400, 'name must be 1-64 characters')
    const key = pubkey(b?.pubkey)
    if (!key) return bad(400, 'pubkey required')
    const phones = (db.query(`select count(*) as n from devices where kind = 'phone' and not revoked and tenant_id = ?`).get(account.tenant_id) as any).n
    if (phones >= 10) return bad(409, 'too many phones; revoke one with `perch revoke`')
    const token = insertWithToken('pdev_', (hash) =>
      db.run(`insert into devices (kind, name, token_hash, pubkey, tenant_id, acked, served) values ('phone', ?, ?, ?, ?, (${HEAD}), (${HEAD}))`, [name, hash, key, account.tenant_id]), rand)
    deps.wake?.(account.tenant_id)
    return json(200, { token, kind: 'phone', account_id: account.id })
  }

  /// The account an email address may sign in to: bound, and enabled.
  const emailAccount = (address: string) =>
    db.query(`select a.id from identities i join accounts a on a.id = i.account_id
      where i.provider = 'email' and i.subject = ? and a.disabled = 0`).get(address) as { id: number } | null

  /// Always 202 so the endpoint can't tell which addresses are bound; the mail is sent after the reply.
  async function emailStart(req: Request, ip: string) {
    const b = await body(req)
    const address = typeof b?.email === 'string' ? b.email.trim().toLowerCase() : ''
    const challenge = typeof b?.challenge === 'string' ? b.challenge : ''
    if (!EMAIL.test(address)) return bad(400, 'enter an email address')
    if (!CHALLENGE.test(challenge)) return bad(400, 'bad challenge')
    const retry = limits.take(`email-ip:${ip}`, 3, 10 * MINUTE) || limits.take(`email-to:${address}`, 3, 10 * MINUTE)
    if (retry) return slow(retry)
    const account = cfg.email && send ? emailAccount(address) : null
    if (account) {
      if (limits.take('email-sent', 30, MINUTE)) {
        console.error('perch: sign-in email cap reached (30/min); dropped one')
      } else {
        const token = insertWithToken('pauth_', (hash) =>
          db.run(`insert into auth_tokens (token_hash, purpose, subject, challenge, expires, created) values (?, 'email', ?, ?, ?, ?)`,
            [hash, address, challenge, now() + EMAIL_MS, iso()]), rand)
        const link = `${cfg.publicUrl}/v1/auth/email/verify?token=${encodeURIComponent(token)}`
        void send!({
          to: address,
          subject: 'Sign in to Perch',
          text: `Open this link on the iPhone where you asked to sign in:\n\n${link}\n\nIt works once and expires in 15 minutes. If you didn't ask for it, ignore this email.\n`,
        }).catch((e) => console.error(`perch: sign-in email failed: ${(e as Error).message}`))
      }
    }
    return json(202, {})
  }

  const expiredPage = () => page(400, 'Link expired', '<h1>This link is invalid or expired</h1><p>Request another from the Perch app.</p>')
  const liveEmailToken = (token: string) => token.startsWith('pauth_') &&
    !!db.query(`select 1 from auth_tokens where token_hash = ? and purpose = 'email' and used = 0 and expires > ?`).get(sha(token), now())

  /// GET only shows a button: mail scanners that prefetch the link must not burn it.
  function emailVerify(req: Request) {
    const token = new URL(req.url).searchParams.get('token') ?? ''
    if (!liveEmailToken(token)) return expiredPage()
    return page(200, 'Open Perch', `<h1>Sign in to Perch</h1><p>Continue on the iPhone where you asked for this link.</p>
<form method="post" action="/v1/auth/email/consume"><input type="hidden" name="token" value="${escapeHtml(token)}"><button type="submit">Open Perch</button></form>`)
  }

  async function emailConsume(req: Request, ip: string) {
    if (limits.take(`consume:${ip}`, 30, MINUTE)) return page(429, 'Slow down', '<h1>Too many attempts</h1><p>Wait a minute and try again.</p>')
    const text = await req.text().catch(() => '')
    const token = text.length <= 4096 ? new URLSearchParams(text).get('token') ?? '' : ''
    if (!token.startsWith('pauth_')) return expiredPage()
    const row = db.query(`select subject, challenge from auth_tokens where token_hash = ? and purpose = 'email' and used = 0 and expires > ?`)
      .get(sha(token), now()) as any
    if (!row || !db.run('update auth_tokens set used = 1 where token_hash = ? and used = 0', [sha(token)]).changes) return expiredPage()
    const account = emailAccount(row.subject) // still bound, still enabled
    if (!account) return expiredPage()
    return appRedirect(createHandoff(account.id, row.challenge))
  }

  const callbackUrl = (p: string) => `${cfg.publicUrl}/v1/auth/oauth/${p}/callback`
  const oauthPage = (status: number, title: string, text: string) => page(status, title, `<h1>${escapeHtml(title)}</h1><p>${escapeHtml(text)}</p>`)

  function providerAuthorizeUrl(provider: 'github' | 'google', state: string): string {
    const client = cfg.clients[provider]!
    const to = provider === 'github'
      ? new URL('https://github.com/login/oauth/authorize')
      : new URL('https://accounts.google.com/o/oauth2/v2/auth')
    to.search = new URLSearchParams({
      client_id: client.id, redirect_uri: callbackUrl(provider), state,
      ...(provider === 'github' ? { allow_signup: 'false' } : { response_type: 'code', scope: 'openid email', prompt: 'select_account' }),
    }).toString()
    return to.toString()
  }

  function oauthStart(req: Request, ip: string, provider: 'github' | 'google') {
    if (limits.take(`oauth-start:${ip}`, 30, MINUTE)) return oauthPage(429, 'Too many attempts', 'Wait a minute and try again.')
    const challenge = new URL(req.url).searchParams.get('challenge') ?? ''
    if (!CHALLENGE.test(challenge)) return oauthPage(400, 'Start again', 'Open sign-in from the Perch app.')
    const state = rand(32).toString('base64url')
    db.run('insert into oauth_states (state_hash, provider, challenge, expires) values (?, ?, ?, ?)', [sha(state), provider, challenge, now() + 10 * MINUTE])
    return new Response(null, { status: 302, headers: { location: providerAuthorizeUrl(provider, state), 'cache-control': 'no-store' } })
  }

  async function providerIdentity(provider: 'github' | 'google', code: string): Promise<Who> {
    const client = cfg.clients[provider]!
    if (provider === 'github') return githubIdentity(fetchFn, client, code, callbackUrl(provider))
    const tok = await getJson(fetchFn, 'https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ code, client_id: client.id, client_secret: client.secret, redirect_uri: callbackUrl(provider), grant_type: 'authorization_code' }),
    })
    if (!googleKeys || now() - googleKeys.at > 60 * MINUTE) {
      googleKeys = { keys: (await getJson(fetchFn, 'https://www.googleapis.com/oauth2/v3/certs')).keys ?? [], at: now() }
    }
    return verifyGoogleIdToken(tok?.id_token, client.id, googleKeys.keys, now())
  }

  /// Matches the provider's immutable id; failing that, an operator-bound subject that has no id
  /// yet, which this first login then binds. A subject already bound to another id never matches.
  function oauthAccount(provider: string, who: Who): number | null {
    const prov = `oauth:${provider}`
    const enabled = `join accounts a on a.id = i.account_id and a.disabled = 0`
    const bound = db.query(`select i.account_id from identities i ${enabled} where i.provider = ? and i.external_id = ?`).get(prov, who.externalId) as any
    if (bound) return bound.account_id
    if (db.query('select 1 from identities where provider = ? and external_id = ?').get(prov, who.externalId)) return null // bound to a disabled account
    const unbound = db.query(`select i.id, i.account_id from identities i ${enabled} where i.provider = ? and i.subject = ? and i.external_id is null`).get(prov, who.subject) as any
    if (!unbound) return null
    return db.run('update identities set external_id = ? where id = ? and external_id is null', [who.externalId, unbound.id]).changes ? unbound.account_id : null
  }

  function identityByExternalId(provider: string, externalId: string): { account_id: number; disabled: number } | null {
    return db.query(`select i.account_id, a.disabled from identities i join accounts a on a.id = i.account_id
      where i.provider = ? and i.external_id = ?`).get(provider, externalId) as any
  }

  /// Redeems a pending verified identity plus a one-time invite key. The account, identity,
  /// invite, pending row and session are created in one transaction; failures consume nothing.
  async function claim(req: Request, ip: string) {
    const retry = limits.take(`claim-ip:${ip}`, 10, 10 * MINUTE)
    if (retry) return slow(retry)
    const b = await body(req)
    const pending = typeof b?.pending === 'string' ? b.pending : ''
    const verifier = typeof b?.verifier === 'string' && b.verifier.length >= 43 && b.verifier.length <= 128 ? b.verifier : ''
    const invite = typeof b?.invite === 'string' ? b.invite.trim() : ''
    if (!pending.startsWith('ppend_') || !verifier || !invite) return bad(403, 'invalid or expired invite key')
    const pendingRetry = limits.take(`claim-pending:${pending}`, 5, 10 * MINUTE)
    if (pendingRetry) return slow(pendingRetry)
    const pendingRow = db.query(`select provider, external_id, subject, challenge from pending_identities
      where token_hash = ? and used = 0 and expires > ?`).get(sha(pending), now()) as any
    if (!pendingRow || !sameString(challengeOf(verifier), pendingRow.challenge)) return bad(403, 'invalid or expired invite key')
    if (!db.query('select 1 from invites where token_hash = ? and used = 0 and expires > ?').get(sha(invite), now()))
      return bad(403, 'invalid or expired invite key')
    const name = canonicalName(invite)
    if (!name) return bad(400, 'that invite key cannot be an account name')
    if (db.query('select 1 from identities where provider = ? and external_id = ?').get(pendingRow.provider, pendingRow.external_id))
      return bad(409, 'that account is already linked')
    let session = ''
    let claimedName = ''
    let claimedId = 0
    try {
      db.transaction(() => {
        if (!db.run('update invites set used = 1 where token_hash = ? and used = 0 and expires > ?', [sha(invite), now()]).changes)
          throw new Error('invite already used')
        if (!db.run('update pending_identities set used = 1 where token_hash = ? and used = 0 and expires > ?', [sha(pending), now()]).changes)
          throw new Error('pending already used')
        const account = insertClaimedAccount(db, name, {
          provider: pendingRow.provider,
          subject: pendingRow.subject,
          externalId: pendingRow.external_id,
        })
        claimedName = account.name
        claimedId = account.id
        db.run('update invites set claimed_by = ? where token_hash = ?', [account.id, sha(invite)])
        session = createSession(account.id)
      })()
    } catch (e) {
      if (e instanceof ClaimError) return bad(e.status, e.message)
      return bad(403, 'invalid or expired invite key')
    }
    return json(200, { session, name: claimedName, account_id: claimedId })
  }

  /// Native Sign in with Apple. A bound identity gets a session; an unbound one gets a pending
  /// token for the invite step. This endpoint never creates an account.
  async function appleSignIn(req: Request, ip: string) {
    if (!cfg.appleClientId || !cfg.oauth.includes('apple')) return bad(404, 'not found')
    const retry = limits.take(`apple:${ip}`, 30, MINUTE)
    if (retry) return slow(retry)
    const b = await body(req)
    const token = typeof b?.identity_token === 'string' ? b.identity_token : ''
    const nonce = typeof b?.nonce === 'string' && /^[A-Za-z0-9_-]{16,128}$/.test(b.nonce) ? b.nonce : ''
    const challenge = typeof b?.challenge === 'string' && CHALLENGE.test(b.challenge) ? b.challenge : ''
    if (!token || token.length > 8192 || !nonce || !challenge) return bad(400, 'bad request')
    let who: Who
    try {
      who = await appleWho(token, nonce)
    } catch (e) {
      console.error(`perch: apple sign-in failed: ${(e as Error).message}`)
      return bad(502, 'apple sign-in failed')
    }
    const existing = identityByExternalId('oauth:apple', who.externalId)
    if (existing) {
      if (existing.disabled) return bad(403, 'account disabled')
      return json(200, { session: createSession(existing.account_id), account_id: existing.account_id, name: accountName(existing.account_id) })
    }
    const bound = oauthAccount('apple', who)
    if (bound) return json(200, { session: createSession(bound), account_id: bound, name: accountName(bound) })
    const pending = createPending('apple', who, challenge)
    return json(200, { pending, expires: now() + PENDING_MS })
  }

  function accountInfo(req: Request) {
    const account = accountGate(req)
    if (account instanceof Response) return account
    return json(200, { id: account.id, name: account.name, providers: providersFor(account.id) })
  }

  async function linkStart(req: Request) {
    const account = accountGate(req)
    if (account instanceof Response) return account
    const retry = limits.take(`link-start:${account.id}`, 10, 10 * MINUTE)
    if (retry) return slow(retry)
    const b = await body(req)
    const provider = b?.provider
    if (provider !== 'github' && provider !== 'google') return bad(400, 'provider must be github or google')
    const p: 'github' | 'google' = provider
    if (!cfg.oauth.includes(p) || !cfg.clients[p]) return bad(404, 'not found')
    if (db.query('select 1 from identities where account_id = ? and provider = ?').get(account.id, `oauth:${p}`))
      return bad(409, 'already linked')
    const state = rand(32).toString('base64url')
    db.run('insert into oauth_links (state_hash, provider, account_id, expires, used, created) values (?, ?, ?, ?, 0, ?)',
      [sha(state), p, account.id, now() + 10 * MINUTE, iso()])
    return json(200, { url: providerAuthorizeUrl(p, state) })
  }

  async function linkApple(req: Request) {
    const account = accountGate(req)
    if (account instanceof Response) return account
    if (!cfg.appleClientId || !cfg.oauth.includes('apple')) return bad(404, 'not found')
    const retry = limits.take(`link-apple:${account.id}`, 10, 10 * MINUTE)
    if (retry) return slow(retry)
    const b = await body(req)
    const token = typeof b?.identity_token === 'string' ? b.identity_token : ''
    const nonce = typeof b?.nonce === 'string' && /^[A-Za-z0-9_-]{16,128}$/.test(b.nonce) ? b.nonce : ''
    if (!token || token.length > 8192 || !nonce) return bad(400, 'bad request')
    let who: Who
    try {
      who = await appleWho(token, nonce)
    } catch (e) {
      console.error(`perch: apple link failed: ${(e as Error).message}`)
      return bad(502, 'apple sign-in failed')
    }
    const existing = db.query('select account_id from identities where provider = ? and external_id = ?')
      .get('oauth:apple', who.externalId) as any
    if (existing) return existing.account_id === account.id ? json(200, {}) : bad(409, 'already linked to another account')
    try {
      db.run('insert into identities (account_id, provider, subject, external_id, created) values (?, ?, ?, ?, ?)',
        [account.id, 'oauth:apple', who.subject, who.externalId, iso()])
    } catch (e) {
      if (String((e as Error)?.message).includes('UNIQUE constraint failed')) return bad(409, 'already linked to another account')
      throw e
    }
    return json(200, {})
  }

  async function unlinkProvider(req: Request) {
    const account = accountGate(req)
    if (account instanceof Response) return account
    const retry = limits.take(`unlink:${account.id}`, 10, 10 * MINUTE)
    if (retry) return slow(retry)
    const b = await body(req)
    const provider = b?.provider
    if (!['password', 'email', 'github', 'google', 'apple'].includes(provider)) return bad(400, 'unknown provider')
    const internal = provider === 'password' || provider === 'email' ? provider : `oauth:${provider}`
    const count = (db.query('select count(*) as n from identities where account_id = ?').get(account.id) as any).n
    if (count <= 1) return bad(409, 'cannot remove the last sign-in method')
    if (!db.run('delete from identities where account_id = ? and provider = ?', [account.id, internal]).changes)
      return bad(404, 'not linked')
    return json(200, {})
  }

  async function renameAccount(req: Request) {
    const account = accountGate(req)
    if (account instanceof Response) return account
    const retry = limits.take(`rename:${account.id}`, 10, 10 * MINUTE)
    if (retry) return slow(retry)
    const b = await body(req)
    const name = canonicalName(b?.name)
    if (!name) return bad(400, 'usernames are 1-64 characters with no spaces')
    if (name === account.name) return json(200, { name })
    try {
      db.transaction(() => {
        db.run('update accounts set name = ? where id = ?', [name, account.id])
        db.run(`update identities set subject = ? where account_id = ? and provider = 'password'`, [name, account.id])
      })()
    } catch (e) {
      if (String((e as Error)?.message).includes('UNIQUE constraint failed')) return bad(409, 'that username is taken')
      throw e
    }
    return json(200, { name })
  }

  async function oauthCallback(req: Request, ip: string, provider: 'github' | 'google') {
    if (limits.take(`oauth-callback:${ip}`, 30, MINUTE)) return oauthPage(429, 'Too many attempts', 'Wait a minute and try again.')
    const q = new URL(req.url).searchParams
    const state = q.get('state') ?? ''
    const signIn = db.query('select challenge from oauth_states where state_hash = ? and provider = ? and used = 0 and expires > ?').get(sha(state), provider, now()) as any
    if (!signIn) {
      // A link started from Settings uses the same provider callback with its own state table.
      const link = db.query('select account_id from oauth_links where state_hash = ? and provider = ? and used = 0 and expires > ?').get(sha(state), provider, now()) as any
      if (!link) return oauthPage(400, 'Sign-in expired', 'Start again from the Perch app.')
      if (!db.run('update oauth_links set used = 1 where state_hash = ? and used = 0', [sha(state)]).changes) return linkRedirect('error=expired')
      const code = q.get('code')
      if (!code) return linkRedirect('error=cancelled')
      let who: Who
      try {
        who = await providerIdentity(provider, code)
      } catch (e) {
        console.error(`perch: ${provider} link failed: ${(e as Error).message}`)
        return linkRedirect('error=failed')
      }
      if (!db.query('select 1 from accounts where id = ? and disabled = 0').get(link.account_id)) return linkRedirect('error=failed')
      const prov = `oauth:${provider}`
      const bound = db.query('select account_id from identities where provider = ? and external_id = ?').get(prov, who.externalId) as any
      if (bound && bound.account_id !== link.account_id) return linkRedirect('error=taken')
      if (!bound) {
        try {
          db.run('insert into identities (account_id, provider, subject, external_id, created) values (?, ?, ?, ?, ?)',
            [link.account_id, prov, who.subject, who.externalId, iso()])
        } catch (e) {
          if (String((e as Error)?.message).includes('UNIQUE constraint failed')) return linkRedirect('error=taken')
          throw e
        }
      }
      return linkRedirect('done=1')
    }
    if (!db.run('update oauth_states set used = 1 where state_hash = ? and used = 0', [sha(state)]).changes)
      return oauthPage(400, 'Sign-in expired', 'Start again from the Perch app.')
    const code = q.get('code')
    if (!code) return oauthPage(400, 'Sign-in cancelled', 'Start again from the Perch app.')
    let who: Who
    try {
      who = await providerIdentity(provider, code)
    } catch (e) {
      console.error(`perch: ${provider} sign-in failed: ${(e as Error).message}`)
      return oauthPage(502, 'Sign-in failed', `Couldn't confirm your ${provider === 'github' ? 'GitHub' : 'Google'} account. Try again.`)
    }
    const existing = identityByExternalId(`oauth:${provider}`, who.externalId)
    if (existing) {
      if (existing.disabled) return oauthPage(403, 'Not on the allowlist', "This account is not on the relay's allowlist. Ask the relay's operator to add it.")
      return appRedirect(createHandoff(existing.account_id, signIn.challenge))
    }
    const account = oauthAccount(provider, who)
    if (account) return appRedirect(createHandoff(account, signIn.challenge))
    return appRedirectPending(createPending(provider, who, signIn.challenge))
  }

  /// A phone mints a single-use, ten-minute code that `perch pair` redeems at the unchanged /v1/pair.
  function pairMachine(req: Request) {
    const token = bearer(req)
    const dev = token.startsWith('pdev_')
      ? (db.query('select id, kind, tenant_id from devices where token_hash = ? and not revoked').get(sha(token)) as any)
      : null
    if (!dev) return bad(401, 'unauthorized')
    if (dev.kind !== 'phone') return bad(403, 'only phones can add laptops')
    const retry = limits.take(`pair-machine:${dev.id}`, 5, MINUTE)
    if (retry) return slow(retry)
    const code = rand(16).toString('base64url')
    const expires = now() + 10 * MINUTE
    db.run(`insert into codes (code_hash, kind, expires, tenant_id) values (?, 'machine', ?, ?)`, [sha(code), expires, dev.tenant_id])
    return json(200, { code, expires })
  }

  /// Unpairing on a device removes it from the relay too: its token stops working, it gets no more
  /// pushes, and its peers stop encrypting for it. A device can only revoke itself. Any device
  /// token works here (old code-paired ones too); session and handoff credentials never do.
  function unpair(req: Request) {
    const token = bearer(req)
    const dev = token && !/^p(ses|auth)_/.test(token)
      ? (db.query('select id, tenant_id from devices where token_hash = ? and not revoked').get(sha(token)) as any)
      : null
    if (!dev) return bad(401, 'unauthorized')
    db.run('update devices set revoked = 1, push_token = null where id = ?', [dev.id])
    deps.wake?.(dev.tenant_id)
    return json(200, {})
  }

  return async (req: Request, ip: string): Promise<Response> => {
    const path = new URL(req.url).pathname
    sweep(db, now())
    const route = `${req.method} ${path}`
    if (route === 'GET /v1/auth/methods') return json(200, { password: cfg.password, email: cfg.email, oauth: cfg.oauth })
    if (route === 'POST /v1/auth/password') return cfg.password ? password(req, ip) : bad(404, 'not found')
    if (route === 'POST /v1/auth/password/change') return cfg.password ? changePassword(req, ip) : bad(404, 'not found')
    if (route === 'POST /v1/auth/exchange') return exchange(req, ip)
    if (route === 'POST /v1/auth/email/start') return emailStart(req, ip)
    if (route === 'GET /v1/auth/email/verify') return emailVerify(req)
    if (route === 'POST /v1/auth/email/consume') return emailConsume(req, ip)
    if (route === 'POST /v1/auth/claim') return claim(req, ip)
    if (route === 'POST /v1/auth/apple') return appleSignIn(req, ip)
    if (route === 'GET /v1/auth/account') return accountInfo(req)
    if (route === 'POST /v1/auth/account/link/start') return linkStart(req)
    if (route === 'POST /v1/auth/account/link/apple') return linkApple(req)
    if (route === 'POST /v1/auth/account/unlink') return unlinkProvider(req)
    if (route === 'POST /v1/auth/account/rename') return renameAccount(req)
    if (route === 'POST /v1/devices') return registerDevice(req)
    if (route === 'POST /v1/devices/link') return linkDevice(req)
    if (route === 'POST /v1/pair/machine') return pairMachine(req)
    if (route === 'POST /v1/unpair') return unpair(req)
    const oauth = req.method === 'GET' && path.match(/^\/v1\/auth\/oauth\/(github|google)\/(start|callback)$/)
    if (oauth) {
      const provider = oauth[1] as 'github' | 'google'
      if (!cfg.oauth.includes(provider)) return bad(404, 'not found')
      return oauth[2] === 'start' ? oauthStart(req, ip, provider) : oauthCallback(req, ip, provider)
    }
    return bad(404, 'not found')
  }
}
