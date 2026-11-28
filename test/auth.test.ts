import { test, expect } from 'bun:test'
import { open, app, pairCode, relayTenant } from '../server'
import { addAccount, sha } from '../accounts'
import { authConfig, challengeOf, clientIp, type AuthConfig, type AuthDeps } from '../auth'

const KEY = 'A'.repeat(43)

export function relay(cfg: Partial<AuthConfig> = {}, deps: AuthDeps = {}) {
  let clock = Date.now()
  const db = open(':memory:', { owner: 'owner@test', salt: 'salt' })
  const server = Bun.serve({ port: 0, ...app(db, undefined, { ...authConfig({}), ...cfg }, { now: () => clock, ...deps }) })
  const url = `http://localhost:${server.port}`
  const call = (method: string, path: string, body?: unknown, token?: string, headers: Record<string, string> = {}) =>
    fetch(url + path, {
      method,
      redirect: 'manual',
      headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers },
      body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
    })
  const post = (path: string, body: unknown, token?: string, headers?: Record<string, string>) => call('POST', path, body, token, headers)
  const login = async (username: string, password: string, ip = '10.0.0.1') =>
    post('/v1/auth/password', { username, password }, undefined, { 'x-real-ip': ip })
  const session = async (username: string, password: string) => ((await (await login(username, password)).json()) as any).session as string
  const register = async (s: string, name = 'iPhone') => post('/v1/devices', { name, pubkey: KEY }, s)
  return {
    db, server, url, call, post, login, session, register,
    tick: (ms: number) => { clock += ms },
    stop: () => server.stop(true),
  }
}

/// A phone paired with a relay code before sign-in existed: an unprefixed token, still valid.
function legacyPhone(r: ReturnType<typeof relay>, name = 'old') {
  const token = 'legacy-' + name
  r.db.run(`insert into devices (kind, name, token_hash, pubkey, tenant_id) values ('phone', ?, ?, ?, ?)`, [name, sha(token), KEY, relayTenant(r.db)])
  return token
}

/// An account whose password is already the user's own (the one-time flag cleared).
async function withPassword(r: ReturnType<typeof relay>, name: string, adopt = false) {
  const pw = (await addAccount(r.db, name, { adopt, password: true })).password!
  r.db.run(`update identities set must_change = 0 where subject = ?`, [name])
  return pw
}

test('methods reflect the deployment settings', () => {
  const m = (env: Record<string, string>) => { const c = authConfig(env); return { password: c.password, email: c.email, oauth: c.oauth } }
  expect(m({})).toEqual({ password: true, email: false, oauth: [] })
  expect(m({ AUTH_PASSWORD: '0' })).toEqual({ password: false, email: false, oauth: [] })
  const full = {
    PERCH_PUBLIC_URL: 'https://relay.example', AUTH_EMAIL: '1', SMTP_URL: 'smtps://u:p@mail', AUTH_EMAIL_FROM: 'perch@example',
    AUTH_OAUTH: 'github,google', GITHUB_CLIENT_ID: 'g', GITHUB_CLIENT_SECRET: 's',
  }
  expect(m(full)).toEqual({ password: true, email: true, oauth: ['github'] }) // google has no credentials
  expect(m({ ...full, SMTP_URL: '' }).email).toBe(false)
  expect(m({ ...full, PERCH_PUBLIC_URL: 'http://relay.example' })).toEqual({ password: true, email: false, oauth: [] })
})

test('GET /v1/auth/methods is public and adds no CORS headers', async () => {
  const r = relay({ password: false, oauth: ['github'] })
  const res = await r.call('GET', '/v1/auth/methods')
  expect(await res.json()).toEqual({ password: false, email: false, oauth: ['github'] })
  expect(res.headers.get('access-control-allow-origin')).toBeNull()
  expect((await r.login('a', 'b')).status).toBe(404) // password off: the endpoint is gone
  r.stop()
})

test('password login: success, and identical failures for wrong, unknown and disabled', async () => {
  const r = relay()
  const pw = await withPassword(r, 'Alice')
  const ok = await r.login(' ALICE ', pw)
  expect(ok.status).toBe(200)
  const { session } = (await ok.json()) as any
  expect(session).toMatch(/^pses_[A-Za-z0-9_-]{43}$/)
  expect(r.db.query('select token_hash from sessions').get()).toEqual({ token_hash: sha(session) })

  await addAccount(r.db, 'off', { password: true })
  r.db.run(`update accounts set disabled = 1 where name = 'off'`)
  for (const [u, p] of [['alice', 'wrong'], ['nobody', pw], ['off', pw]]) {
    const res = await r.login(u, p, '10.0.0.9')
    expect(res.status).toBe(401)
    expect(await res.json()).toEqual({ error: 'invalid credentials' })
  }
  r.stop()
})

test('repeated failures back off one IP and account pair, never the account globally', async () => {
  const r = relay()
  const pw = await withPassword(r, 'alice')
  for (let i = 0; i < 5; i++) expect((await r.login('alice', 'nope', '10.0.0.2')).status).toBe(401)
  const held = await r.login('alice', pw, '10.0.0.2')
  expect(held.status).toBe(429)
  expect(Number(held.headers.get('retry-after'))).toBeGreaterThan(0)
  expect((await r.login('alice', pw, '10.0.0.3')).status).toBe(200) // another IP is unaffected
  r.tick(1001)
  expect((await r.login('alice', pw, '10.0.0.2')).status).toBe(200)
  r.stop()
})

test('password attempts are capped per IP per minute', async () => {
  const r = relay()
  for (let i = 0; i < 10; i++) await r.login(`user${i}`, 'x', '10.0.0.4')
  expect((await r.login('user99', 'x', '10.0.0.4')).status).toBe(429)
  r.tick(60_001)
  expect((await r.login('user99', 'x', '10.0.0.4')).status).toBe(401)
  r.stop()
})

test('sessions last an hour and stop working when the account is disabled', async () => {
  const r = relay()
  const pw = await withPassword(r, 'alice')
  const s1 = await r.session('alice', pw)
  r.tick(60 * 60_000 + 1)
  expect((await r.register(s1)).status).toBe(401)
  const s2 = await r.session('alice', pw)
  r.db.run(`update accounts set disabled = 1`)
  expect((await r.register(s2)).status).toBe(401)
  r.stop()
})

test('registration makes a pdev_ phone in the account tenant; tokens stay in their lanes', async () => {
  const r = relay()
  const pw = await withPassword(r, 'alice', true)
  const s = await r.session('alice', pw)
  expect((await r.post('/v1/sync', { after: 0 }, s)).status).toBe(401) // a session is not a device
  const res = await r.register(s)
  const { token, kind, device_id } = (await res.json()) as any
  expect(kind).toBe('phone')
  expect(token).toMatch(/^pdev_[A-Za-z0-9_-]{43}$/)
  expect(device_id).toMatch(/^dev_[0-9a-f]{32}$/)
  const dev = r.db.query('select tenant_id, pubkey, token_hash from devices where token_hash = ?').get(sha(token)) as any
  expect(dev).toEqual({ tenant_id: relayTenant(r.db), pubkey: KEY, token_hash: sha(token) })
  expect(r.db.query('select device_id from devices where token_hash = ?').get(sha(token))).toEqual({ device_id })
  // The same phone name is another device: ids come from the pairing, not the label.
  const again = (await (await r.register(s)).json()) as any
  expect(again.device_id).not.toBe(device_id)
  expect((await r.post('/v1/sync', { after: 0 }, token)).status).toBe(200)
  expect((await r.register(token)).status).toBe(401) // a device token can't register devices
  expect((await r.post('/v1/devices', { name: 'x' }, s)).status).toBe(400) // pubkey required
  expect((await r.post('/v1/devices', { name: ' ', pubkey: KEY }, s)).status).toBe(400)
  r.stop()
})

test('registration is limited to 5 an hour and 10 phones per account', async () => {
  const r = relay()
  const pw = await withPassword(r, 'alice')
  const s = await r.session('alice', pw)
  for (let i = 0; i < 5; i++) expect((await r.register(s, `p${i}`)).status).toBe(200)
  expect((await r.register(s)).status).toBe(429)
  r.tick(59 * 60_000)
  const s2 = await r.session('alice', pw)
  r.tick(60_001)
  for (let i = 5; i < 10; i++) expect((await r.register(s2, `p${i}`)).status).toBe(200)
  r.tick(60 * 60_000)
  const s3 = await r.session('alice', pw)
  expect((await r.register(s3)).status).toBe(409)
  r.stop()
})

test('exchange: one use, five minutes, and a wrong verifier burns nothing', async () => {
  const r = relay()
  await addAccount(r.db, 'alice')
  const id = (r.db.query('select id from accounts').get() as any).id
  const verifier = 'v'.repeat(43)
  const code = 'pauth_' + 'c'.repeat(43)
  r.db.run(`insert into auth_tokens (token_hash, purpose, account_id, challenge, expires, created) values (?, 'handoff', ?, ?, ?, '')`,
    [sha(code), id, challengeOf(verifier), Date.now() + 5 * 60_000])
  const wrong = await r.post('/v1/auth/exchange', { code, verifier: 'w'.repeat(43) })
  expect(wrong.status).toBe(403)
  const ok = await r.post('/v1/auth/exchange', { code, verifier })
  expect(ok.status).toBe(200)
  expect(((await ok.json()) as any).session).toMatch(/^pses_/)
  const again = await r.post('/v1/auth/exchange', { code, verifier })
  expect([again.status, await again.json()]).toEqual([403, await wrong.json()])
  r.stop()
})

test('X-Real-IP counts only from a loopback peer', () => {
  expect(clientIp('127.0.0.1', '203.0.113.7')).toBe('203.0.113.7')
  expect(clientIp('::1', '203.0.113.7')).toBe('203.0.113.7')
  expect(clientIp('::ffff:127.0.0.1', '203.0.113.7')).toBe('203.0.113.7')
  expect(clientIp('198.51.100.2', '203.0.113.7')).toBe('198.51.100.2')
  expect(clientIp('127.0.0.1', 'not an ip')).toBe('127.0.0.1')
  expect(clientIp('127.0.0.1', null)).toBe('127.0.0.1')
})

test('per-IP limits key on the resolved client address', async () => {
  const r = relay()
  for (let i = 0; i < 10; i++) await r.login('u', 'x', '10.1.1.1')
  expect((await r.login('u2', 'x', '10.1.1.1')).status).toBe(429)
  expect((await r.login('u2', 'x', '10.1.1.2')).status).toBe(401)
  r.stop()
})

test('relay CLI laptop codes still pair with accounts present', async () => {
  const r = relay()
  await addAccount(r.db, 'alice', { adopt: true, password: true })
  const res = await r.post('/v1/pair', { code: pairCode(r.db), name: 'mac', pubkey: KEY })
  expect(res.status).toBe(200)
  expect(((await res.json()) as any).token).not.toMatch(/^p(dev|ses|auth)_/)
  r.stop()
})

test('registering a phone wakes the laptop so it can snapshot the new phone at once', async () => {
  const r = relay()
  const mac = ((await (await r.post('/v1/pair', { code: pairCode(r.db), name: 'mac', pubkey: KEY })).json()) as any).token
  const pw = await withPassword(r, 'alice', true)
  const s = await r.session('alice', pw)
  const waiting = r.post('/v1/sync', { after: 0, wait: 20 }, mac).then((x) => x.json()) as Promise<any>
  await Bun.sleep(100)
  const t0 = Date.now()
  await r.register(s, 'iphone')
  expect((await waiting).phones.map((p: any) => p.name)).toContain('iphone')
  expect(Date.now() - t0).toBeLessThan(2000)
  r.stop()
})

async function phone(r: ReturnType<typeof relay>, name = 'alice', adopt = true) {
  const pw = await withPassword(r, name, adopt)
  return ((await (await r.register(await r.session(name, pw))).json()) as any).token as string
}

test('phones mint ten-minute, single-use laptop codes for their own tenant', async () => {
  const r = relay()
  const token = await phone(r, 'alice', false)
  const res = await r.post('/v1/pair/machine', {}, token)
  const { code, expires } = (await res.json()) as any
  expect(expires).toBeGreaterThan(Date.now() + 9 * 60_000)
  expect(expires).toBeLessThanOrEqual(Date.now() + 10 * 60_000 + 1000)
  const pair = await r.post('/v1/pair', { code, name: 'mac', pubkey: KEY })
  expect(((await pair.json()) as any).kind).toBe('machine')
  const tenant = (r.db.query(`select tenant_id from accounts where name = 'alice'`).get() as any).tenant_id
  expect(r.db.query(`select tenant_id from devices where name = 'mac'`).get()).toEqual({ tenant_id: tenant })
  expect(tenant).not.toBe(relayTenant(r.db))
  expect((await r.post('/v1/pair', { code, name: 'mac2', pubkey: KEY })).status).toBe(403) // single use

  const late = ((await (await r.post('/v1/pair/machine', {}, token)).json()) as any).code
  r.db.run(`update codes set expires = ?`, [Date.now() - 1]) // the relay's own clock decides at /v1/pair
  expect((await r.post('/v1/pair', { code: late, name: 'mac3', pubkey: KEY })).status).toBe(403)

  const taken = ((await (await r.post('/v1/pair/machine', {}, token)).json()) as any).code
  expect((await r.post('/v1/pair', { code: taken, name: 'mac', pubkey: KEY })).status).toBe(409) // name conflict
  r.stop()
})

test('only phone device tokens mint laptop codes', async () => {
  const r = relay()
  const token = await phone(r)
  const machine = ((await (await r.post('/v1/pair', { code: pairCode(r.db), name: 'mac', pubkey: KEY })).json()) as any).token
  expect((await r.post('/v1/pair/machine', {}, machine)).status).toBe(401) // unprefixed: /v1/sync only
  expect((await r.post('/v1/pair/machine', {}, legacyPhone(r))).status).toBe(401)
  const bobPw = (await addAccount(r.db, 'bob', { password: true })).password!
  expect((await r.post('/v1/pair/machine', {}, await r.session('bob', bobPw))).status).toBe(401) // sessions can't
  r.db.run(`update devices set kind = 'machine' where token_hash = ?`, [sha(token)])
  expect((await r.post('/v1/pair/machine', {}, token)).status).toBe(403)
  r.db.run(`update devices set kind = 'phone', revoked = 1 where token_hash = ?`, [sha(token)])
  expect((await r.post('/v1/pair/machine', {}, token)).status).toBe(401)
  r.stop()
})

test('laptop codes are limited to 5 a minute per phone, and a tenant to 20 laptops', async () => {
  const r = relay()
  const token = await phone(r)
  const codes: string[] = []
  for (let i = 0; i < 5; i++) codes.push(((await (await r.post('/v1/pair/machine', {}, token)).json()) as any).code)
  expect((await r.post('/v1/pair/machine', {}, token)).status).toBe(429)
  const tenant = relayTenant(r.db)
  for (let i = 0; i < 20; i++) r.db.run(`insert into devices (kind, name, token_hash, tenant_id) values ('machine', ?, ?, ?)`, [`m${i}`, `h${i}`, tenant])
  const res = await r.post('/v1/pair', { code: codes[0], name: 'one-too-many', pubkey: KEY })
  expect(res.status).toBe(409)
  expect(((await res.json()) as any).error).toMatch(/too many machines/)
  r.stop()
})

const EMAIL_CFG = { email: true, publicUrl: 'https://relay.example' }
const verifier = 'v'.repeat(43)
const challenge = challengeOf(verifier)

function mailbox() {
  const sent: { to: string; subject: string; text: string }[] = []
  let release!: () => void
  const gate = new Promise<void>((r) => { release = r })
  // The send never finishes until released: the endpoint must answer without waiting for it.
  const sendMail = async (m: { to: string; subject: string; text: string }) => { sent.push(m); await gate }
  const link = () => new URL(sent.at(-1)!.text.match(/https:\/\/\S+/)![0])
  return { sent, sendMail, release, link }
}

test('email start answers 202 at once for bound and unbound addresses alike', async () => {
  const mail = mailbox()
  const r = relay(EMAIL_CFG, { sendMail: mail.sendMail })
  await addAccount(r.db, 'alice', { email: 'Alice@Example.com' })
  const bound = await r.post('/v1/auth/email/start', { email: 'ALICE@example.com', challenge })
  const unbound = await r.post('/v1/auth/email/start', { email: 'eve@example.com', challenge })
  expect([bound.status, await bound.json()]).toEqual([202, {}])
  expect([unbound.status, await unbound.json()]).toEqual([202, {}])
  expect(mail.sent.map((m) => m.to)).toEqual(['alice@example.com'])
  expect(mail.link().origin + mail.link().pathname).toBe('https://relay.example/v1/auth/email/verify')
  expect(mail.link().searchParams.get('token')).toMatch(/^pauth_/)
  expect((await r.post('/v1/auth/email/start', { email: 'a@b.c', challenge: 'short' }, undefined, { 'x-real-ip': '10.9.9.9' })).status).toBe(400)
  mail.release()
  r.stop()
})

test('a disabled account, or email turned off, sends nothing', async () => {
  const mail = mailbox()
  const r = relay({ ...EMAIL_CFG, email: false }, { sendMail: mail.sendMail })
  await addAccount(r.db, 'alice', { email: 'a@example.com' })
  expect((await r.post('/v1/auth/email/start', { email: 'a@example.com', challenge })).status).toBe(202)
  const r2 = relay(EMAIL_CFG, { sendMail: mail.sendMail })
  await addAccount(r2.db, 'bob', { email: 'b@example.com' })
  r2.db.run('update accounts set disabled = 1')
  expect((await r2.post('/v1/auth/email/start', { email: 'b@example.com', challenge })).status).toBe(202)
  expect(mail.sent).toEqual([])
  r.stop(); r2.stop()
})

test('email start is limited per IP and per address', async () => {
  const r = relay(EMAIL_CFG, { sendMail: async () => {} })
  for (let i = 0; i < 3; i++) await r.post('/v1/auth/email/start', { email: `x${i}@e.com`, challenge }, undefined, { 'x-real-ip': '10.2.2.2' })
  expect((await r.post('/v1/auth/email/start', { email: 'y@e.com', challenge }, undefined, { 'x-real-ip': '10.2.2.2' })).status).toBe(429)
  for (let i = 0; i < 3; i++) await r.post('/v1/auth/email/start', { email: 'z@e.com', challenge }, undefined, { 'x-real-ip': `10.3.3.${i}` })
  expect((await r.post('/v1/auth/email/start', { email: 'z@e.com', challenge }, undefined, { 'x-real-ip': '10.3.3.9' })).status).toBe(429)
  r.stop()
})

test('verify only shows a button; consume hands off once; exchange needs the verifier', async () => {
  const mail = mailbox()
  const r = relay(EMAIL_CFG, { sendMail: mail.sendMail })
  await addAccount(r.db, 'alice', { email: 'a@example.com' })
  await r.post('/v1/auth/email/start', { email: 'a@example.com', challenge })
  const token = mail.link().searchParams.get('token')!
  const verifyPath = `/v1/auth/email/verify?token=${encodeURIComponent(token)}`

  for (let i = 0; i < 2; i++) { // a mail scanner prefetching the link leaves it usable
    const res = await r.call('GET', verifyPath)
    expect(res.status).toBe(200)
    expect(res.headers.get('content-security-policy')).toBe("default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
    const html = await res.text()
    expect(html).toContain('action="/v1/auth/email/consume"')
    expect(html).not.toMatch(/<(script|link|img)\b|src=|https?:\/\//)
  }
  const form = { 'content-type': 'application/x-www-form-urlencoded' }
  const consumed = await r.post('/v1/auth/email/consume', `token=${encodeURIComponent(token)}`, undefined, form)
  expect(consumed.status).toBe(302)
  const callback = new URL(consumed.headers.get('location')!)
  expect(callback.protocol + callback.host + callback.pathname).toBe('perch:auth/callback')
  const code = callback.searchParams.get('code')!
  expect(code).toMatch(/^pauth_/)

  const reused = await r.post('/v1/auth/email/consume', `token=${encodeURIComponent(token)}`, undefined, form)
  expect([reused.status, reused.headers.get('location')]).toEqual([400, null])
  expect((await r.call('GET', verifyPath)).status).toBe(400)

  expect((await r.post('/v1/auth/exchange', { code, verifier: 'x'.repeat(43) })).status).toBe(403)
  const ok = await r.post('/v1/auth/exchange', { code, verifier })
  const { session } = (await ok.json()) as any
  expect((await r.register(session)).status).toBe(200)
  mail.release()
  r.stop()
})

test('email tokens expire after 15 minutes, and a disabled account cannot consume one', async () => {
  const mail = mailbox()
  const r = relay(EMAIL_CFG, { sendMail: mail.sendMail })
  await addAccount(r.db, 'alice', { email: 'a@example.com' })
  const form = { 'content-type': 'application/x-www-form-urlencoded' }
  await r.post('/v1/auth/email/start', { email: 'a@example.com', challenge })
  const first = mail.link().searchParams.get('token')!
  r.tick(15 * 60_000 + 1)
  expect((await r.post('/v1/auth/email/consume', `token=${encodeURIComponent(first)}`, undefined, form)).status).toBe(400)
  await r.post('/v1/auth/email/start', { email: 'a@example.com', challenge })
  const second = mail.link().searchParams.get('token')!
  r.db.run('update accounts set disabled = 1')
  expect((await r.post('/v1/auth/email/consume', `token=${encodeURIComponent(second)}`, undefined, form)).status).toBe(400)
  mail.release()
  r.stop()
})

test('relay pages escape what they echo', async () => {
  const { escapeHtml, page } = await import('../auth')
  expect(escapeHtml(`<script>"x"&'y'</script>`)).toBe('&#60;script&#62;&#34;x&#34;&#38;&#39;y&#39;&#60;/script&#62;')
  const res = page(200, '<t>', `<p>${escapeHtml('<b>')}</p>`)
  const html = await res.text()
  expect(html).toContain('<title>&#60;t&#62;</title>')
  expect(html).toContain('&#60;b&#62;')
})

test('the SMTP sender speaks enough SMTP to a local server', async () => {
  const { smtpSender } = await import('../smtp')
  const seen: string[] = []
  const server = Bun.listen<{ data: boolean }>({
    hostname: '127.0.0.1', port: 0,
    socket: {
      open(s) { s.data = { data: false }; s.write('220 test\r\n') },
      data(s, chunk) {
        for (const line of chunk.toString().split('\r\n').filter(Boolean)) {
          seen.push(line)
          if (s.data.data) { if (line === '.') { s.data.data = false; s.write('250 queued\r\n') } continue }
          if (line.startsWith('EHLO')) s.write('250-test\r\n250 AUTH PLAIN\r\n')
          else if (line.startsWith('AUTH')) s.write('235 ok\r\n')
          else if (line === 'DATA') { s.data.data = true; s.write('354 go\r\n') }
          else if (line === 'QUIT') s.end()
          else s.write('250 ok\r\n')
        }
      },
    },
  })
  await smtpSender(`smtp://u%40x:p@127.0.0.1:${server.port}`, 'Perch <perch@relay.example>')({ to: 'a@example.com', subject: 'Hi', text: 'line\n.dot' })
  expect(seen).toContain(`AUTH PLAIN ${Buffer.from('\0u@x\0p').toString('base64')}`)
  expect(seen).toContain('MAIL FROM:<perch@relay.example>')
  expect(seen).toContain('RCPT TO:<a@example.com>')
  expect(seen).toContain('..dot') // dot-stuffed
  server.stop(true)
  await expect(smtpSender('smtp://127.0.0.1:1', 'p@x')({ to: 'a@b', subject: '', text: '' })).rejects.toThrow()
})

const OAUTH_CFG = {
  publicUrl: 'https://relay.example', oauth: ['github', 'google'] as ('github' | 'google')[],
  clients: { github: { id: 'gh-id', secret: 'gh-secret' }, google: { id: 'g-id', secret: 'g-secret' } },
}

/// A fake GitHub whose /user answer the test controls.
function fakeGithub(user: () => { id: number; login: string }) {
  const calls: string[] = []
  const fetchFn = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input)
    calls.push(url)
    if (url === 'https://github.com/login/oauth/access_token') {
      const b = JSON.parse(String(init?.body))
      expect(b).toMatchObject({ client_id: 'gh-id', client_secret: 'gh-secret', redirect_uri: 'https://relay.example/v1/auth/oauth/github/callback' })
      return Response.json(b.code === 'good' ? { access_token: 'gho_x' } : { error: 'bad_verification_code' })
    }
    if (url === 'https://api.github.com/user') return Response.json(user())
    return new Response('nope', { status: 404 })
  }) as typeof fetch
  return { fetchFn, calls }
}

async function githubLogin(r: ReturnType<typeof relay>, code = 'good', ip = '10.5.5.5') {
  const start = await r.call('GET', `/v1/auth/oauth/github/start?challenge=${challenge}`, undefined, undefined, { 'x-real-ip': ip })
  expect(start.status).toBe(302)
  const to = new URL(start.headers.get('location')!)
  expect(to.origin + to.pathname).toBe('https://github.com/login/oauth/authorize')
  expect(to.searchParams.get('redirect_uri')).toBe('https://relay.example/v1/auth/oauth/github/callback')
  const state = to.searchParams.get('state')!
  const cb = (s: string) => r.call('GET', `/v1/auth/oauth/github/callback?code=${code}&state=${encodeURIComponent(s)}`, undefined, undefined, { 'x-real-ip': ip })
  return { res: await cb(state), again: () => cb(state) }
}

const handoffCode = (res: Response) => new URL(res.headers.get('location')!).searchParams.get('code')!

test('OAuth: a bound GitHub login hands off; the state works once', async () => {
  const gh = fakeGithub(() => ({ id: 42, login: 'Octo' }))
  const r = relay(OAUTH_CFG, { fetch: gh.fetchFn })
  await addAccount(r.db, 'alice', { github: 'octo' })
  const { res, again } = await githubLogin(r)
  expect(res.status).toBe(302)
  const code = handoffCode(res)
  const ok = await r.post('/v1/auth/exchange', { code, verifier })
  expect(ok.status).toBe(200)
  expect(r.db.query(`select external_id from identities where provider = 'oauth:github'`).get()).toEqual({ external_id: '42' })
  const replay = await again()
  expect(replay.status).toBe(400)
  expect(replay.headers.get('location')).toBeNull()
  r.stop()
})

test('OAuth: unbound identities get a pending invite, never an account', async () => {
  const gh = fakeGithub(() => ({ id: 7, login: 'stranger' }))
  const r = relay(OAUTH_CFG, { fetch: gh.fetchFn })
  await addAccount(r.db, 'alice', { github: 'octo' })
  const { res } = await githubLogin(r)
  expect(res.status).toBe(302)
  const loc = new URL(res.headers.get('location')!)
  expect(loc.protocol).toBe('perch:')
  expect(loc.host).toBe('auth')
  expect(loc.pathname).toBe('/callback')
  expect(loc.searchParams.get('pending')).toStartWith('ppend_')
  expect(r.db.query('select count(*) as n from accounts').get()).toEqual({ n: 1 })
  expect(r.db.query('select count(*) as n from pending_identities').get()).toEqual({ n: 1 })
  r.stop()
})

test('OAuth: the immutable id wins over later login renames and reclaims', async () => {
  let user = { id: 42, login: 'octo' }
  const r = relay(OAUTH_CFG, { fetch: fakeGithub(() => user).fetchFn })
  await addAccount(r.db, 'alice', { github: 'octo' })
  expect((await githubLogin(r)).res.status).toBe(302) // binds 42

  user = { id: 42, login: 'octo-renamed' } // renamed: still alice
  const renamed = await githubLogin(r)
  expect(renamed.res.status).toBe(302)

  user = { id: 99, login: 'octo' } // someone reclaimed the old login: pending, not alice
  const reclaimed = await githubLogin(r)
  expect(reclaimed.res.status).toBe(302)
  expect(new URL(reclaimed.res.headers.get('location')!).searchParams.get('pending')).toStartWith('ppend_')

  await addAccount(r.db, 'bob', { github: 'octo' }) // the operator may bind the reclaimed login anew
  const bob = await githubLogin(r)
  expect(bob.res.status).toBe(302)
  const s = ((await (await r.post('/v1/auth/exchange', { code: handoffCode(bob.res), verifier })).json()) as any).session
  const acct = r.db.query(`select a.name from sessions s join accounts a on a.id = s.account_id where s.token_hash = ?`).get(sha(s))
  expect(acct).toEqual({ name: 'bob' })
  r.stop()
})

test('OAuth: disabled providers, bad challenges, provider failures and the callback limit', async () => {
  const r = relay({ ...OAUTH_CFG, oauth: ['github'] }, { fetch: fakeGithub(() => ({ id: 1, login: 'x' })).fetchFn })
  expect((await r.call('GET', `/v1/auth/oauth/google/start?challenge=${challenge}`)).status).toBe(404)
  expect((await r.call('GET', '/v1/auth/oauth/github/start?challenge=nope')).status).toBe(400)
  const failed = await githubLogin(r, 'bad')
  expect(failed.res.status).toBe(502)
  const page = await failed.res.text()
  expect(page).not.toContain('bad_verification_code')
  for (let i = 0; i < 30; i++) await r.call('GET', `/v1/auth/oauth/github/callback?state=x${i}&code=<b>`, undefined, undefined, { 'x-real-ip': '10.6.6.6' })
  const limited = await r.call('GET', '/v1/auth/oauth/github/callback?state=y&code=z', undefined, undefined, { 'x-real-ip': '10.6.6.6' })
  expect(limited.status).toBe(429)
  r.stop()
})

test('Google ID tokens are checked for signature, issuer, audience and expiry', async () => {
  const { generateKeyPairSync, sign } = await import('node:crypto')
  const { verifyGoogleIdToken } = await import('../auth')
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' } as JsonWebKey
  const now = Date.now()
  const token = (claims: object, key = privateKey) => {
    const h = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'k1' })).toString('base64url')
    const p = Buffer.from(JSON.stringify(claims)).toString('base64url')
    return `${h}.${p}.${sign('RSA-SHA256', Buffer.from(`${h}.${p}`), key).toString('base64url')}`
  }
  const good = { iss: 'https://accounts.google.com', aud: 'g-id', exp: now / 1000 + 600, sub: '1234', email: 'A@Gmail.com', email_verified: true }
  expect(verifyGoogleIdToken(token(good), 'g-id', [jwk], now)).toEqual({ externalId: '1234', subject: 'a@gmail.com' })
  expect(() => verifyGoogleIdToken(token({ ...good, iss: 'https://evil.example' }), 'g-id', [jwk], now)).toThrow(/issuer/)
  expect(() => verifyGoogleIdToken(token({ ...good, aud: 'other' }), 'g-id', [jwk], now)).toThrow(/audience/)
  expect(() => verifyGoogleIdToken(token({ ...good, exp: now / 1000 - 1 }), 'g-id', [jwk], now)).toThrow(/expired/)
  expect(() => verifyGoogleIdToken(token({ ...good, email_verified: false }), 'g-id', [jwk], now)).toThrow(/verified/)
  const other = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey
  expect(() => verifyGoogleIdToken(token(good, other), 'g-id', [jwk], now)).toThrow(/signature/)

  // End to end through the callback with Google's endpoints stubbed.
  const fetchFn = (async (input: string | URL | Request) => {
    const url = String(input)
    if (url === 'https://oauth2.googleapis.com/token') return Response.json({ id_token: token(good) })
    if (url === 'https://www.googleapis.com/oauth2/v3/certs') return Response.json({ keys: [jwk] })
    return new Response('', { status: 404 })
  }) as typeof fetch
  const r = relay(OAUTH_CFG, { fetch: fetchFn })
  await addAccount(r.db, 'alice', { google: 'a@gmail.com' })
  const start = await r.call('GET', `/v1/auth/oauth/google/start?challenge=${challenge}`)
  const state = new URL(start.headers.get('location')!).searchParams.get('state')!
  const res = await r.call('GET', `/v1/auth/oauth/google/callback?code=c&state=${encodeURIComponent(state)}`)
  expect(res.status).toBe(302)
  expect(r.db.query(`select external_id from identities`).get()).toEqual({ external_id: '1234' })
  r.stop()
})

test('one noisy IP cannot spend the relay-wide password budget', async () => {
  const r = relay()
  const pw = await withPassword(r, 'alice')
  for (let i = 0; i < 120; i++) await r.login(`spray${i % 5}`, 'x', '10.7.7.7')
  expect((await r.login('alice', pw, '10.8.8.8')).status).toBe(200)
  r.stop()
})

test('rate limits and backoff survive a relay restart and store no addresses', async () => {
  const { app: makeApp } = await import('../server')
  const r = relay()
  const pw = await withPassword(r, 'alice')
  for (let i = 0; i < 5; i++) await r.login('alice', 'nope', '10.4.4.4')
  for (let i = 0; i < 5; i++) await r.login(`x${i}`, 'nope', '10.4.4.5')
  r.stop()
  // A new process on the same database: same budgets, same backoff.
  const again = Bun.serve({ port: 0, ...makeApp(r.db, undefined, authConfig({})) })
  const login = (u: string, p: string, ip: string) => fetch(`http://localhost:${again.port}/v1/auth/password`, {
    method: 'POST', headers: { 'x-real-ip': ip }, body: JSON.stringify({ username: u, password: p }),
  })
  expect((await login('alice', pw, '10.4.4.4')).status).toBe(429)
  for (let i = 0; i < 5; i++) await login(`y${i}`, 'nope', '10.4.4.5')
  expect((await login('z', 'nope', '10.4.4.5')).status).toBe(429)
  const stored = JSON.stringify(r.db.query('select * from rate_limits').all()) + JSON.stringify(r.db.query('select * from auth_failures').all())
  expect(stored).not.toContain('10.4.4')
  expect(stored).not.toContain('alice')
  again.stop(true)
})

test('a one-time password signs in but must be replaced before registering a phone', async () => {
  const r = relay()
  const otp = (await addAccount(r.db, 'alice', { password: true })).password!
  const first = (await (await r.login('alice', otp)).json()) as any
  expect(first.must_change_password).toBe(true)
  const blocked = await r.register(first.session)
  expect([blocked.status, ((await blocked.json()) as any).error]).toEqual([403, 'change the one-time password first'])

  const change = (body: object) => r.post('/v1/auth/password/change', body, undefined, { 'x-real-ip': '10.9.0.1' })
  expect((await change({ username: 'alice', password: otp, new_password: 'short' })).status).toBe(400)
  expect((await change({ username: 'alice', password: otp, new_password: otp })).status).toBe(400)
  expect((await change({ username: 'alice', password: 'wrong-current', new_password: 'a-much-better-one' })).status).toBe(401)
  const ok = await change({ username: 'alice', password: otp, new_password: 'a-much-better-one' })
  const { session } = (await ok.json()) as any
  expect((await r.register(session)).status).toBe(200)
  expect((await r.register(first.session)).status).toBe(401) // the old session ended with the change

  expect((await r.login('alice', otp)).status).toBe(401)
  const again = (await (await r.login('alice', 'a-much-better-one')).json()) as any
  expect(again.must_change_password).toBeUndefined()
  r.stop()
})

test('changing a password from Settings needs the current one and shares the sign-in limits', async () => {
  const r = relay()
  const pw = await withPassword(r, 'bob')
  for (let i = 0; i < 5; i++) {
    await r.post('/v1/auth/password/change', { username: 'bob', password: 'guess', new_password: 'whatever-long' }, undefined, { 'x-real-ip': '10.9.0.2' })
  }
  const held = await r.post('/v1/auth/password/change', { username: 'bob', password: pw, new_password: 'whatever-long' }, undefined, { 'x-real-ip': '10.9.0.2' })
  expect(held.status).toBe(429) // same backoff as sign-in
  expect((await r.post('/v1/auth/password/change', { username: 'bob', password: pw, new_password: 'whatever-long' }, undefined, { 'x-real-ip': '10.9.0.3' })).status).toBe(200)
  r.stop()
})

test('account passwd issues a new one-time password that must be changed again', async () => {
  const { setPassword } = await import('../accounts')
  const r = relay()
  await withPassword(r, 'carol')
  const otp = await setPassword(r.db, 'carol')
  expect(((await (await r.login('carol', otp)).json()) as any).must_change_password).toBe(true)
  r.stop()
})

test('a device that unpairs removes itself from the relay, and only itself', async () => {
  const r = relay()
  const legacy = legacyPhone(r)
  const mac = ((await (await r.post('/v1/pair', { code: pairCode(r.db), name: 'mac', pubkey: KEY })).json()) as any).token
  const pw = await withPassword(r, 'alice', true)
  const phone = ((await (await r.register(await r.session('alice', pw))).json()) as any).token
  r.db.run(`update devices set push_token = 'ab' where token_hash = ?`, [sha(phone)])

  expect((await r.post('/v1/sync', { after: 0 }, mac).then((x) => x.json()) as any).phones).toHaveLength(2)
  expect((await r.post('/v1/unpair', {}, 'pses_whatever')).status).toBe(401)
  expect((await r.post('/v1/unpair', {}, phone)).status).toBe(200)
  expect((await r.post('/v1/sync', { after: 0 }, phone)).status).toBe(401) // its token is dead
  expect(r.db.query(`select revoked, push_token from devices where token_hash = ?`).get(sha(phone))).toEqual({ revoked: 1, push_token: null })
  expect((await r.post('/v1/unpair', {}, phone)).status).toBe(401) // already gone

  const peers = ((await r.post('/v1/sync', { after: 0 }, mac).then((x) => x.json())) as any).phones
  expect(peers.map((p: any) => p.name)).toEqual(['old']) // the laptop stops sealing for it
  expect((await r.post('/v1/unpair', {}, legacy)).status).toBe(200) // code-paired phones can too
  expect((await r.post('/v1/sync', { after: 0 }, mac)).status).toBe(200) // the laptop is untouched
  r.stop()
})

test('a phone unpairs a computer in its tenant, and no other device', async () => {
  const r = relay()
  const pw = await withPassword(r, 'alice', true)
  const s = await r.session('alice', pw)
  const phone = ((await (await r.register(s)).json()) as any).token
  const tenant = relayTenant(r.db)
  const insert = (name: string, token: string, at: string) =>
    r.db.run(`insert into devices (kind, name, token_hash, pubkey, tenant_id) values ('machine', ?, ?, ?, ?)`, [name, sha(token), KEY, at])
  insert('mac', 'own-mac-token', tenant)
  insert('laptop', 'laptop-token', tenant)
  insert('mac', 'foreign-mac-token', 'another-tenant')

  expect((await r.post('/v1/devices/revoke', { name: 'mac' }, s)).status).toBe(401) // a session is not a phone
  expect((await r.post('/v1/devices/revoke', { name: 'laptop' }, 'laptop-token')).status).toBe(403) // a computer cannot revoke another
  expect((await r.post('/v1/devices/revoke', {}, phone)).status).toBe(400)
  expect((await r.post('/v1/devices/revoke', { name: 'missing' }, phone)).status).toBe(404)

  expect((await r.post('/v1/devices/revoke', { name: 'mac' }, phone)).status).toBe(200)
  expect(r.db.query(`select revoked from devices where token_hash = ?`).get(sha('own-mac-token'))).toEqual({ revoked: 1 })
  expect(r.db.query(`select revoked from devices where token_hash = ?`).get(sha('foreign-mac-token'))).toEqual({ revoked: 0 })
  expect(r.db.query(`select revoked from devices where token_hash = ?`).get(sha('laptop-token'))).toEqual({ revoked: 0 })
  expect(r.db.query(`select revoked from devices where token_hash = ?`).get(sha(phone))).toEqual({ revoked: 0 })
  expect((await r.post('/v1/devices/revoke', { name: 'mac' }, phone)).status).toBe(404) // already gone
  r.stop()
})

test('a code-paired phone links to its account: same device, new pdev_ token, old token dead', async () => {
  const r = relay()
  const old = legacyPhone(r)
  const before = r.db.query(`select id, pubkey, acked from devices where token_hash = ?`).get(sha(old)) as any
  const pw = await withPassword(r, 'alice', true) // owns the relay tenant the phone is in
  const s = await r.session('alice', pw)

  const res = await r.post('/v1/devices/link', { token: old }, s)
  expect(res.status).toBe(200)
  const { token, device_id } = (await res.json()) as any
  expect(token).toMatch(/^pdev_/)
  expect(device_id).toMatch(/^dev_[0-9a-f]{32}$/)
  expect(r.db.query(`select id, pubkey, acked from devices where token_hash = ?`).get(sha(token))).toEqual(before)
  expect(r.db.query(`select device_id from devices where token_hash = ?`).get(sha(token))).toEqual({ device_id })
  expect((await r.post('/v1/sync', { after: 0 }, old)).status).toBe(401)
  expect((await r.post('/v1/sync', { after: 0 }, token)).status).toBe(200)
  expect((await r.post('/v1/pair/machine', {}, token)).status).toBe(200) // Add a Laptop works now
  expect((await r.post('/v1/devices/link', { token }, s)).status).toBe(400) // already signed in
  r.stop()
})

test('linking refuses other tenants, machines, bad sessions and one-time passwords', async () => {
  const r = relay()
  const old = legacyPhone(r)
  const bobPw = await withPassword(r, 'bob') // a separate tenant
  expect((await r.post('/v1/devices/link', { token: old }, await r.session('bob', bobPw))).status).toBe(403)
  expect((await r.post('/v1/devices/link', { token: old }, 'pses_nope')).status).toBe(401)
  expect((await r.post('/v1/devices/link', { token: old }, old)).status).toBe(401) // a device token is not a session
  const otp = (await addAccount(r.db, 'alice', { adopt: true, password: true })).password!
  const s = ((await (await r.login('alice', otp)).json()) as any).session
  expect((await r.post('/v1/devices/link', { token: old }, s)).status).toBe(403) // replace it first
  r.db.run(`update identities set must_change = 0`)
  const fresh = ((await (await r.login('alice', otp)).json()) as any).session
  const mac = ((await (await r.post('/v1/pair', { code: pairCode(r.db), name: 'mac', pubkey: KEY })).json()) as any).token
  expect((await r.post('/v1/devices/link', { token: mac }, fresh)).status).toBe(403) // laptops stay as they are
  expect((await r.post('/v1/devices/link', { token: 'unknown' }, fresh)).status).toBe(403)
  expect((await r.post('/v1/devices/link', { token: old }, fresh)).status).toBe(200)
  r.stop()
})

test('successful auth and device responses include the stable account id', async () => {
  const r = relay()
  const pw = await withPassword(r, 'alice')
  const login = (await (await r.login('alice', pw)).json()) as any
  expect(login.account_id).toBe(r.db.query(`select id from accounts where name = 'alice'`).get()!.id)
  const accountId = login.account_id

  const reg = (await (await r.register(login.session)).json()) as any
  expect(reg.account_id).toBe(accountId)

  const info = (await (await r.call('GET', '/v1/auth/account', undefined, reg.token)).json()) as any
  expect(info).toMatchObject({ id: accountId, name: 'alice' })

  const renamed = await r.post('/v1/auth/account/rename', { name: 'alice-renamed' }, reg.token)
  expect(renamed.status).toBe(200)
  const after = (await (await r.call('GET', '/v1/auth/account', undefined, reg.token)).json()) as any
  expect(after.id).toBe(accountId)
  r.stop()
})

test('a one-time password response still proves the account id', async () => {
  const r = relay()
  const pw = (await addAccount(r.db, 'newbie', { password: true })).password!
  const login = (await (await r.login('newbie', pw)).json()) as any
  expect(login.account_id).toBe(r.db.query(`select id from accounts where name = 'newbie'`).get()!.id)
  expect(login.must_change_password).toBe(true)
  r.stop()
})
