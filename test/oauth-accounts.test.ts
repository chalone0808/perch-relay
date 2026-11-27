import { test, expect } from 'bun:test'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { open, app } from '../server'
import { addAccount, createInvites, inviteCli, sha, sweep } from '../accounts'
import { authConfig, challengeOf, verifyAppleIdToken, type AuthConfig, type AuthDeps } from '../auth'

const KEY = 'A'.repeat(43)
const verifier = 'v'.repeat(43)
const challenge = challengeOf(verifier)
const APPLE_ID = 'com.chalone.perch'

function relay(cfg: Partial<AuthConfig> = {}, deps: AuthDeps = {}) {
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
  return { db, server, url, call, post, login, session, register, tick: (ms: number) => { clock += ms }, stop: () => server.stop(true) }
}

async function withPassword(r: ReturnType<typeof relay>, name: string) {
  const pw = (await addAccount(r.db, name, { password: true })).password!
  r.db.run(`update identities set must_change = 0 where subject = ?`, [name])
  return pw
}

function fakeGithub(user: () => { id: number; login: string }) {
  const fetchFn = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input)
    if (url === 'https://github.com/login/oauth/access_token') {
      const b = JSON.parse(String(init?.body))
      return Response.json(b.code === 'good' ? { access_token: 'gho_x' } : { error: 'bad_verification_code' })
    }
    if (url === 'https://api.github.com/user') return Response.json(user())
    return new Response('nope', { status: 404 })
  }) as typeof fetch
  return { fetchFn }
}

const OAUTH = {
  publicUrl: 'https://relay.example',
  oauth: ['github'] as ('github' | 'google' | 'apple')[],
  clients: { github: { id: 'gh-id', secret: 'gh-secret' } },
}

async function githubLogin(r: ReturnType<typeof relay>, code = 'good') {
  const start = await r.call('GET', `/v1/auth/oauth/github/start?challenge=${challenge}`)
  const state = new URL(start.headers.get('location')!).searchParams.get('state')!
  return r.call('GET', `/v1/auth/oauth/github/callback?code=${code}&state=${encodeURIComponent(state)}`)
}
const pendingOf = (res: Response) => new URL(res.headers.get('location')!).searchParams.get('pending')!
const handoffOf = (res: Response) => new URL(res.headers.get('location')!).searchParams.get('code')!

function appleKeys(kid = 'apple-k1') {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' } as JsonWebKey
  return { privateKey, jwk }
}
function appleToken(privateKey: ReturnType<typeof generateKeyPairSync>['privateKey'], claims: object, kid = 'apple-k1') {
  const h = Buffer.from(JSON.stringify({ alg: 'RS256', kid })).toString('base64url')
  const p = Buffer.from(JSON.stringify(claims)).toString('base64url')
  return `${h}.${p}.${sign('RSA-SHA256', Buffer.from(`${h}.${p}`), privateKey).toString('base64url')}`
}

test('invite claim creates the account with the key as username, binds identity and consumes both tokens', async () => {
  const gh = fakeGithub(() => ({ id: 42, login: 'newbie' }))
  const r = relay(OAUTH, { fetch: gh.fetchFn })
  const [invite] = createInvites(r.db, { count: 1 })
  expect(invite).toMatch(/^pinv_[A-Za-z0-9_-]{43}$/)

  const pending = pendingOf(await githubLogin(r))
  const claim = await r.post('/v1/auth/claim', { pending, verifier, invite })
  expect(claim.status).toBe(200)
  const body = (await claim.json()) as any
  expect(body.name).toBe(invite.toLowerCase())
  expect(r.db.query('select count(*) as n from accounts').get()).toEqual({ n: 1 })
  expect(r.db.query(`select external_id from identities where provider = 'oauth:github'`).get()).toEqual({ external_id: '42' })
  expect(r.db.query('select used, claimed_by from invites').get()).toMatchObject({ used: 1, claimed_by: 1 })
  expect(r.db.query('select used from pending_identities').get()).toEqual({ used: 1 })
  expect((await r.register(body.session)).status).toBe(200)

  const again = await r.post('/v1/auth/claim', { pending, verifier, invite })
  expect(again.status).toBe(403)
  const second = await githubLogin(r)
  expect(second.status).toBe(302)
  expect(handoffOf(second)).toStartWith('pauth_')
  r.stop()
})

test('claim failures consume nothing and a retry with another key succeeds', async () => {
  const gh = fakeGithub(() => ({ id: 7, login: 'stranger' }))
  const r = relay(OAUTH, { fetch: gh.fetchFn })
  const [first, second] = createInvites(r.db, { count: 2 })
  const pending = pendingOf(await githubLogin(r))

  expect((await r.post('/v1/auth/claim', { pending, verifier: 'x'.repeat(43), invite: first })).status).toBe(403)
  expect((await r.post('/v1/auth/claim', { pending, verifier, invite: 'pinv_' + 'x'.repeat(43) })).status).toBe(403)
  expect(r.db.query('select used from invites where token_hash = ?').get(sha(first))).toEqual({ used: 0 })
  expect(r.db.query('select used from pending_identities').get()).toEqual({ used: 0 })

  await addAccount(r.db, first.toLowerCase()) // name collision: must not burn either token
  expect((await r.post('/v1/auth/claim', { pending, verifier, invite: first })).status).toBe(409)
  expect(r.db.query('select used from invites where token_hash = ?').get(sha(first))).toEqual({ used: 0 })
  expect(r.db.query('select used from pending_identities').get()).toEqual({ used: 0 })
  expect(r.db.query('select count(*) as n from accounts').get()).toEqual({ n: 1 })

  const ok = await r.post('/v1/auth/claim', { pending, verifier, invite: second })
  expect(ok.status).toBe(200)
  expect(r.db.query('select count(*) as n from accounts').get()).toEqual({ n: 2 })
  r.stop()
})

test('claim session can rename immediately, without changing the identity or tenant', async () => {
  const gh = fakeGithub(() => ({ id: 9, login: 'fresh' }))
  const r = relay(OAUTH, { fetch: gh.fetchFn })
  const [invite] = createInvites(r.db, { count: 1 })
  const pending = pendingOf(await githubLogin(r))
  const claim = (await (await r.post('/v1/auth/claim', { pending, verifier, invite })).json()) as any
  const before = r.db.query('select id, tenant_id from accounts where name = ?').get(invite.toLowerCase())
  const rename = await r.post('/v1/auth/account/rename', { name: 'FreshName' }, claim.session)
  expect(rename.status).toBe(200)
  expect(await rename.json()).toEqual({ name: 'freshname' })
  expect(r.db.query('select id, tenant_id from accounts where name = ?').get('freshname')).toEqual(before)
  expect(r.db.query(`select external_id from identities where provider = 'oauth:github'`).get()).toEqual({ external_id: '9' })
  r.stop()
})

test('Apple identity tokens are verified and an unbound identity becomes a pending claim', async () => {
  const { privateKey, jwk } = appleKeys()
  const rawNonce = 'N'.repeat(32)
  const nonce = createHash('sha256').update(rawNonce).digest('hex')
  const now = Date.now()
  const claims = { iss: 'https://appleid.apple.com', aud: APPLE_ID, exp: now / 1000 + 600, sub: 'apple-sub', nonce }
  const token = appleToken(privateKey, claims)
  expect(verifyAppleIdToken(token, APPLE_ID, [jwk], now, rawNonce)).toEqual({ externalId: 'apple-sub', subject: 'apple-sub' })
  expect(() => verifyAppleIdToken(token, APPLE_ID, [jwk], now, 'other')).toThrow(/nonce/)
  expect(() => verifyAppleIdToken(appleToken(privateKey, { ...claims, iss: 'https://evil.example' }), APPLE_ID, [jwk], now, rawNonce)).toThrow(/issuer/)
  expect(() => verifyAppleIdToken(appleToken(privateKey, { ...claims, aud: 'other' }), APPLE_ID, [jwk], now, rawNonce)).toThrow(/audience/)
  expect(() => verifyAppleIdToken(appleToken(privateKey, { ...claims, exp: now / 1000 - 1 }), APPLE_ID, [jwk], now, rawNonce)).toThrow(/expired/)

  const fetchFn = (async (input: string | URL | Request) => {
    if (String(input) === 'https://appleid.apple.com/auth/keys') return Response.json({ keys: [jwk] })
    return new Response('', { status: 404 })
  }) as typeof fetch
  const r = relay({ ...OAUTH, oauth: ['apple'], appleClientId: APPLE_ID }, { fetch: fetchFn })
  const first = await r.post('/v1/auth/apple', { identity_token: token, nonce: rawNonce, challenge })
  expect(first.status).toBe(200)
  const pending = ((await first.json()) as any).pending as string
  expect(pending).toStartWith('ppend_')
  const [invite] = createInvites(r.db, { count: 1 })
  const claim = await r.post('/v1/auth/claim', { pending, verifier, invite })
  expect(claim.status).toBe(200)
  const name = ((await claim.json()) as any).name
  expect(name).toBe(invite.toLowerCase())
  const second = await r.post('/v1/auth/apple', { identity_token: token, nonce: rawNonce, challenge })
  expect(second.status).toBe(200)
  expect(((await second.json()) as any).name).toBe(name)
  expect(r.db.query(`select external_id from identities where provider = 'oauth:apple'`).get()).toEqual({ external_id: 'apple-sub' })
  r.stop()
})

test('Settings account info, GitHub link, guarded unlink and rename', async () => {
  const gh = fakeGithub(() => ({ id: 55, login: 'linked' }))
  const r = relay(OAUTH, { fetch: gh.fetchFn })
  const pw = await withPassword(r, 'alice')
  const phone = ((await (await r.register(await r.session('alice', pw))).json()) as any).token as string

  let info = (await (await r.call('GET', '/v1/auth/account', undefined, phone)).json()) as any
  expect(info).toEqual({ id: r.db.query(`select id from accounts where name = 'alice'`).get()!.id, name: 'alice', providers: ['password'] })

  const start = await r.post('/v1/auth/account/link/start', { provider: 'github' }, phone)
  expect(start.status).toBe(200)
  const state = new URL(((await start.json()) as any).url).searchParams.get('state')!
  const cb = await r.call('GET', `/v1/auth/oauth/github/callback?code=good&state=${encodeURIComponent(state)}`)
  expect(cb.status).toBe(302)
  expect(cb.headers.get('location')).toBe('perch://auth/link?done=1')
  info = (await (await r.call('GET', '/v1/auth/account', undefined, phone)).json()) as any
  expect(info.providers).toEqual(['password', 'github'])

  expect((await r.post('/v1/auth/account/link/start', { provider: 'github' }, phone)).status).toBe(409)
  expect((await r.post('/v1/auth/account/unlink', { provider: 'github' }, phone)).status).toBe(200)
  expect((await r.post('/v1/auth/account/unlink', { provider: 'password' }, phone)).status).toBe(409)

  const before = r.db.query('select id, tenant_id from accounts where name = ?').get('alice') as any
  const rename = await r.post('/v1/auth/account/rename', { name: 'AliceNew' }, phone)
  expect(rename.status).toBe(200)
  expect(await rename.json()).toEqual({ name: 'alicenew' })
  expect(r.db.query('select id, tenant_id from accounts where name = ?').get('alicenew')).toEqual(before)
  expect((await r.login('alice', pw)).status).toBe(401)
  expect((await r.login('alicenew', pw)).status).toBe(200)
  const bob = await withPassword(r, 'bob')
  expect((await r.post('/v1/auth/account/rename', { name: 'bob' }, phone)).status).toBe(409)
  expect((await r.login('alicenew', pw)).status).toBe(200)
  void bob
  r.stop()
})

test('Apple linking is idempotent for its account and refused for another', async () => {
  const { privateKey, jwk } = appleKeys('apple-link')
  const rawNonce = 'L'.repeat(32)
  const nonce = createHash('sha256').update(rawNonce).digest('hex')
  const token = appleToken(
    privateKey,
    { iss: 'https://appleid.apple.com', aud: APPLE_ID, exp: Date.now() / 1000 + 600, sub: 'apple-link-sub', nonce },
    'apple-link',
  )
  const fetchFn = (async (input: string | URL | Request) => {
    if (String(input) === 'https://appleid.apple.com/auth/keys') return Response.json({ keys: [jwk] })
    return new Response('', { status: 404 })
  }) as typeof fetch
  const r = relay({ ...OAUTH, oauth: ['apple'], appleClientId: APPLE_ID }, { fetch: fetchFn })
  const alicePw = await withPassword(r, 'alice')
  const alicePhone = ((await (await r.register(await r.session('alice', alicePw))).json()) as any).token as string
  const bobPw = await withPassword(r, 'bob')
  const bobPhone = ((await (await r.register(await r.session('bob', bobPw))).json()) as any).token as string

  const link = (phone: string) =>
    r.post('/v1/auth/account/link/apple', { identity_token: token, nonce: rawNonce }, phone)
  expect((await link(alicePhone)).status).toBe(200)
  expect((await link(alicePhone)).status).toBe(200) // already linked to this account: still fine
  const alice = (await (await r.call('GET', '/v1/auth/account', undefined, alicePhone)).json()) as any
  expect(alice.providers).toEqual(['password', 'apple'])

  expect((await link(bobPhone)).status).toBe(409)
  const bob = (await (await r.call('GET', '/v1/auth/account', undefined, bobPhone)).json()) as any
  expect(bob.providers).toEqual(['password'])
  expect(r.db.query(`select count(*) as n from identities where provider = 'oauth:apple'`).get()).toEqual({ n: 1 })
  r.stop()
})

test('invite keys are stored only as hashes, expire, and are swept', () => {
  const db = open(':memory:', { owner: 'owner@test', salt: 'salt' })
  const now = Date.now()
  expect(() => createInvites(db, { count: 0 })).toThrow(/1-100/)
  expect(() => createInvites(db, { ttlMs: 1000 })).toThrow(/1-720/)
  const keys = createInvites(db, { count: 2, ttlMs: 3600_000, now })
  expect(keys).toHaveLength(2)
  for (const key of keys) {
    expect(key).toMatch(/^pinv_[A-Za-z0-9_-]{43}$/)
    expect(db.query('select 1 from invites where token_hash = ?').get(key)).toBeNull()
    expect(db.query('select expires from invites where token_hash = ?').get(sha(key))).toEqual({ expires: now + 3600_000 })
  }
  const listed = inviteCli(db, ['list'])
  for (const key of keys) expect(listed).not.toContain(key)
  sweep(db, now + 3600_001)
  expect(db.query('select count(*) as n from invites').get()).toEqual({ n: 0 })
})

test('linking an identity already on another account never merges accounts', async () => {
  const gh = fakeGithub(() => ({ id: 77, login: 'shared' }))
  const r = relay(OAUTH, { fetch: gh.fetchFn })
  const pw = await withPassword(r, 'alice')
  const phone = ((await (await r.register(await r.session('alice', pw))).json()) as any).token as string
  await addAccount(r.db, 'bob', { github: 'shared' })
  const bobLogin = await githubLogin(r)
  expect(bobLogin.status).toBe(302)
  expect(handoffOf(bobLogin)).toStartWith('pauth_')

  const start = await r.post('/v1/auth/account/link/start', { provider: 'github' }, phone)
  const state = new URL(((await start.json()) as any).url).searchParams.get('state')!
  const cb = await r.call('GET', `/v1/auth/oauth/github/callback?code=good&state=${encodeURIComponent(state)}`)
  expect(cb.headers.get('location')).toBe('perch://auth/link?error=taken')
  const acct = r.db.query(`select a.name from identities i join accounts a on a.id = i.account_id where i.provider = 'oauth:github' and i.external_id = '77'`).get()
  expect(acct).toEqual({ name: 'bob' })
  r.stop()
})
