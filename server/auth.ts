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
import { canonicalName, HEAD, hashPassword, insertWithToken, sha, sweep, verifyPassword, type Rand } from './accounts'
import { smtpSender, type SendMail } from './smtp'

const SESSION_MS = 60 * 60_000
const HANDOFF_MS = 5 * 60_000
const EMAIL_MS = 15 * 60_000
const MINUTE = 60_000

export type AuthConfig = {
  password: boolean
  email: boolean
  oauth: ('github' | 'google')[]
  publicUrl: string
  smtpUrl?: string
  emailFrom?: string
  clients: Partial<Record<'github' | 'google', { id: string; secret: string }>>
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
  return {
    password: env.AUTH_PASSWORD?.trim() !== '0',
    email: https && env.AUTH_EMAIL?.trim() === '1' && !!env.SMTP_URL?.trim() && !!env.AUTH_EMAIL_FROM?.trim(),
    oauth: https ? (['github', 'google'] as const).filter((p) => wanted.includes(p) && clients[p]) : [],
    publicUrl,
    smtpUrl: env.SMTP_URL?.trim(),
    emailFrom: env.AUTH_EMAIL_FROM?.trim(),
    clients,
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
  const send = deps.sendMail ?? (cfg.email ? smtpSender(cfg.smtpUrl!, cfg.emailFrom!) : undefined)

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
    return json(200, { session: createSession(row.id, mustChange), ...(mustChange ? { must_change_password: true } : {}) })
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
    return json(200, { session: createSession(row.id) })
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
    return json(200, { session: createSession(row.account_id) })
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
    return json(200, { token })
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
    return json(200, { token, kind: 'phone' })
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

  function oauthStart(req: Request, ip: string, provider: 'github' | 'google') {
    if (limits.take(`oauth-start:${ip}`, 30, MINUTE)) return oauthPage(429, 'Too many attempts', 'Wait a minute and try again.')
    const challenge = new URL(req.url).searchParams.get('challenge') ?? ''
    if (!CHALLENGE.test(challenge)) return oauthPage(400, 'Start again', 'Open sign-in from the Perch app.')
    const state = rand(32).toString('base64url')
    db.run('insert into oauth_states (state_hash, provider, challenge, expires) values (?, ?, ?, ?)', [sha(state), provider, challenge, now() + 10 * MINUTE])
    const client = cfg.clients[provider]!
    const to = provider === 'github'
      ? new URL('https://github.com/login/oauth/authorize')
      : new URL('https://accounts.google.com/o/oauth2/v2/auth')
    to.search = new URLSearchParams({
      client_id: client.id, redirect_uri: callbackUrl(provider), state,
      ...(provider === 'github' ? { allow_signup: 'false' } : { response_type: 'code', scope: 'openid email', prompt: 'select_account' }),
    }).toString()
    return new Response(null, { status: 302, headers: { location: to.toString(), 'cache-control': 'no-store' } })
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

  async function oauthCallback(req: Request, ip: string, provider: 'github' | 'google') {
    if (limits.take(`oauth-callback:${ip}`, 30, MINUTE)) return oauthPage(429, 'Too many attempts', 'Wait a minute and try again.')
    const q = new URL(req.url).searchParams
    const state = q.get('state') ?? ''
    const row = db.query('select challenge from oauth_states where state_hash = ? and provider = ? and used = 0 and expires > ?').get(sha(state), provider, now()) as any
    if (!row || !db.run('update oauth_states set used = 1 where state_hash = ? and used = 0', [sha(state)]).changes)
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
    const account = oauthAccount(provider, who)
    if (!account) return oauthPage(403, 'Not on the allowlist', "This account is not on the relay's allowlist. Ask the relay's operator to add it.")
    return appRedirect(createHandoff(account, row.challenge))
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
