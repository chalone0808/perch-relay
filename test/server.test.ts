import { test, expect } from 'bun:test'
import { Database } from 'bun:sqlite'
import { mkdtempSync } from 'node:fs'
import { createHash, randomBytes } from 'node:crypto'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { open, pairCode, app, relayTenant, tenantFor, legacyTenantFor, relayId, VERSION, PROTOCOL } from '../server'
import type { PushSender } from '../apns'
import { HEAD } from '../accounts'

const SALT = 'test-salt'

const setup = (push?: PushSender) => {
  const db = open(':memory:', { owner: 'relay@test', salt: SALT })
  const server = Bun.serve({ port: 0, ...app(db, push) })
  const url = `http://localhost:${server.port}`
  const post = (path: string, body: unknown, token?: string) =>
    fetch(url + path, { method: 'POST', headers: token ? { authorization: `Bearer ${token}` } : {}, body: JSON.stringify(body) })
  const tenantOf = (owner?: string) => (owner ? tenantFor(owner, SALT) : relayTenant(db))
  const pair = async (kind: 'machine' | 'phone', name: string, owner?: string, key = randomBytes(32).toString('base64url')) => {
    if (kind === 'machine') return ((await (await post('/v1/pair', { code: pairCode(db, owner), name, pubkey: key })).json()) as any).token as string
    // Phones sign in (auth.ts); a stored row stands in for a registered or code-paired phone.
    const token = randomBytes(32).toString('base64url')
    db.run(`insert into devices (kind, name, token_hash, pubkey, tenant_id, acked, served) values (?, ?, ?, ?, ?, (${HEAD}), (${HEAD}))`,
      ['phone', name, createHash('sha256').update(token).digest('hex'), key, tenantOf(owner)])
    return token
  }
  const sync = async (token: string, body: any) => (await (await post('/v1/sync', body, token)).json()) as any
  return { db, server, post, pair, sync }
}

test('reports its version and a stable relay id without auth', async () => {
  const { db, server } = setup()
  const url = `http://localhost:${server.port}`
  const res = await fetch(`${url}/v1/version`)
  expect(res.status).toBe(200)
  const body = (await res.json()) as any
  expect(body).toMatchObject({ name: 'perch-relay', version: VERSION, protocol: PROTOCOL })
  expect(body.id).toBe(relayId(db))
  expect(body.id).toMatch(/^[0-9a-f]{32}$/)
  expect((await fetch(`${url}/v1/version`, { method: 'POST' })).status).toBe(405)
  server.stop(true)
})

test('the relay id is stable across reopen and differs with a different salt', () => {
  const path = join(mkdtempSync(join(tmpdir(), 'perch-relay-id-')), 'relay.db')
  const a = open(path, { owner: 'relay@test', salt: SALT })
  const first = relayId(a)
  a.close()
  const b = open(path, { owner: 'relay@test', salt: SALT })
  expect(relayId(b)).toBe(first)
  b.close()
  const c = open(':memory:', { owner: 'relay@test', salt: 'other-salt' })
  expect(relayId(c)).not.toBe(first)
  c.close()
})

test('laptops report version and protocol to their phones', async () => {
  const { server, pair, sync } = setup()
  const mac = await pair('machine', 'mac')
  await pair('machine', 'old')
  await sync(mac, { after: 0, version: '0.2.0', protocol: 1 })
  const phone = await pair('phone', 'iphone')
  let r = await sync(phone, { after: 0 })
  expect(r.machines.find((m: any) => m.name === 'mac')).toMatchObject({ version: '0.2.0', protocol: 1 })
  // A machine that never reported them stays exactly as before: no version fields at all.
  expect(r.machines.find((m: any) => m.name === 'old').version).toBeUndefined()
  expect(r.machines.find((m: any) => m.name === 'old').protocol).toBeUndefined()
  // Malformed or missing values keep the last good report.
  await sync(mac, { after: 0, version: 'x'.repeat(33), protocol: 'nope' })
  r = await sync(phone, { after: 0 })
  expect(r.machines.find((m: any) => m.name === 'mac')).toMatchObject({ version: '0.2.0', protocol: 1 })
  server.stop(true)
})

test('the relay tenant comes from its owner and a per-relay salt', () => {
  const db = open(':memory:', { owner: 'Owner@Example.com', salt: SALT })
  expect(relayTenant(db)).toBe(tenantFor('owner@example.com', SALT))
  expect(relayTenant(db)).toMatch(/^[0-9a-f]{32}$/)
  expect(relayTenant(db)).not.toBe('default')
  expect(tenantFor('same@example.com', 'salt-a')).not.toBe(tenantFor('same@example.com', 'salt-b'))
  db.close()
})

test('pairing codes are single use, laptop-only and need a key; bad tokens are refused', async () => {
  const { db, server, post } = setup()
  const pubkey = 'K'.repeat(43)
  const code = pairCode(db)
  expect((await post('/v1/pair', { code: pairCode(db), name: 'mac' })).status).toBe(400) // no key
  expect((await post('/v1/pair', { code, name: 'mac', pubkey })).status).toBe(200)
  expect((await post('/v1/pair', { code, name: 'mac2', pubkey })).status).toBe(403)
  // A phone code minted before phones signed in is refused.
  db.run(`insert into codes (code_hash, kind, expires, tenant_id) values (?, 'phone', ?, ?)`,
    [createHash('sha256').update('old').digest('hex'), Date.now() + 60_000, relayTenant(db)])
  expect((await post('/v1/pair', { code: 'old', name: 'iphone', pubkey })).status).toBe(403)
  expect((await post('/v1/sync', { after: 0 }, 'nope')).status).toBe(401)
  server.stop(true)
})

test('laptop ↔ phone round trip with routing, dedupe and type rules', async () => {
  const { server, pair, sync } = setup()
  const mac = await pair('machine', 'mac')
  const other = await pair('machine', 'other')
  const phone = await pair('phone', 'iphone')

  const reply = { id: 'r1', type: 'agent_reply', session_id: 's1', body: { text: 'done' } }
  const forged = { id: 'f1', type: 'prompt', session_id: 's1', body: { text: 'rm -rf ~' } } // laptop may not send prompts
  let r = await sync(mac, { after: 0, outbox: [reply, reply, forged] })
  expect(r.acked).toEqual(['r1', 'r1'])

  r = await sync(phone, { after: 0, outbox: [] })
  expect(r.inbox.map((m: any) => [m.id, m.machine])).toEqual([['r1', 'mac']])
  expect(r.machines.map((m: any) => m.name)).toEqual(['mac', 'other'])
  const phoneCursor = r.cursor

  const prompt = { id: 'p1', type: 'prompt', machine: 'mac', session_id: 's1', body: { text: 'continue' } }
  const fake = { id: 'f2', type: 'agent_reply', machine: 'mac', session_id: 's1' } // phone may not forge replies
  r = await sync(phone, { after: phoneCursor, outbox: [prompt, fake] })
  expect(r.acked).toEqual(['p1'])

  expect((await sync(other, { after: 0 })).inbox).toEqual([]) // routed to mac only
  r = await sync(mac, { after: 0 })
  expect(r.inbox.map((m: any) => m.id)).toEqual(['p1'])
  expect((await sync(mac, { after: r.cursor })).inbox).toEqual([])
  server.stop(true)
})

test('a phone registered later does not receive the pre-registration backlog', async () => {
  const { pair, sync } = setup()
  const mac = await pair('machine', 'mac')
  const old = { id: 'old1', type: 'agent_reply', machine: 'mac', body: { text: 'before this phone' } }
  await sync(mac, { outbox: [old] })
  const phone = await pair('phone', 'new-phone') // registered with acked at the current head
  expect((await sync(phone, { after: 0 })).inbox).toEqual([])
  const fresh = { id: 'fresh1', type: 'agent_reply', machine: 'mac', body: { text: 'after pairing' } }
  await sync(mac, { outbox: [fresh] })
  expect((await sync(phone, { after: 0 })).inbox.map((m: any) => m.id)).toEqual(['fresh1'])
})

test('laptop prompts and session lifecycle are mirrored to the phone', async () => {
  const { server, pair, sync } = setup()
  const mac = await pair('machine', 'mac')
  const phone = await pair('phone', 'iphone')
  await sync(mac, { outbox: [
    { id: 'u1', type: 'user_prompt', session_id: 's1', body: { text: 'typed' } },
    { id: 'u2', type: 'session_end', session_id: 's1', body: { reason: 'replaced' } },
    { id: 'u3', type: 'task_note', session_id: 's1', body: { status: 'completed', summary: 'Background task done' } },
  ] })
  expect((await sync(phone, { after: 0 })).inbox.map((m: any) => m.id)).toEqual(['u1', 'u2', 'u3'])
  server.stop(true)
})

test('laptop can publish session commands; phones cannot forge them', async () => {
  const { server, pair, sync } = setup()
  const mac = await pair('machine', 'mac')
  const phone = await pair('phone', 'iphone')
  await sync(mac, { outbox: [
    { id: 'c1', type: 'commands', session_id: 's1', body: { commands: [{ name: 'deploy', description: 'Ship it' }] } },
  ] })
  expect((await sync(phone, { after: 0 })).inbox.map((m: any) => m.id)).toEqual(['c1'])

  const forged = { id: 'c2', type: 'commands', machine: 'mac', session_id: 's1', body: { commands: [] } }
  expect((await sync(phone, { after: 10, outbox: [forged] })).acked).toEqual([])
  server.stop(true)
})

test('compact and request lifecycle events are laptop-only', async () => {
  const { server, pair, sync } = setup()
  const mac = await pair('machine', 'mac')
  const phone = await pair('phone', 'iphone')
  const msgs = [
    { id: 'e1', type: 'compact', session_id: 's1', body: {} },
    { id: 'e2', type: 'request_expired', session_id: 's1', body: { request_id: 'r1' } },
    { id: 'e3', type: 'decision_result', session_id: 's1', body: { ref: 'd1', ok: false } },
  ]
  await sync(mac, { outbox: msgs })
  expect((await sync(phone, { after: 0 })).inbox.map((m: any) => m.id)).toEqual(['e1', 'e2', 'e3'])
  expect((await sync(phone, { after: 10, outbox: [{ ...msgs[0], machine: 'mac' }] })).acked).toEqual([])
  server.stop(true)
})

test('APNs pushes are metadata-only and respect the notify flag', async () => {
  const calls: { token: string; payload: any }[] = []
  const push: PushSender = async (token, payload) => {
    calls.push({ token, payload })
    return { status: 200 }
  }
  const { server, pair, sync } = setup(push)
  const mac = await pair('machine', 'mac')
  const phone = await pair('phone', 'iphone')
  const apns = 'a'.repeat(64)
  await sync(phone, { after: 0, push_token: apns })

  await sync(mac, { outbox: [
    { id: 'p1', type: 'agent_reply', session_id: 's1', body: { text: 'partial' } },
    { id: 'p2', type: 'agent_reply', session_id: 's1', body: { text: 'done' }, notify: true },
    { id: 'p3', type: 'needs_attention', session_id: 's1', body: { request_id: 'r1' } },
    { id: 'p4', type: 'activity', session_id: 's1', body: { tool: 'Read' } },
    { id: 'p5', type: 'compact', session_id: 's1', body: {} },
    { id: 'p6', type: 'compact', session_id: 's1', body: {}, notify: true },
  ] })

  expect(calls.map((c) => c.payload.type)).toEqual(['agent_reply', 'needs_attention', 'compact'])
  expect(calls[0]).toMatchObject({
    token: apns,
    payload: { session_id: 's1', machine: 'mac', aps: { alert: { title: 'New reply' }, 'thread-id': 'mac:s1' } },
  })
  expect(calls[1].payload.aps.alert.title).toBe('Approval needed')
  expect(calls[2].payload.aps.alert.title).toBe('Context compacted')

  // A type the phone switched off is skipped; unknown types in the list are ignored.
  await sync(phone, { after: 0, push_off: ['agent_reply', 'bogus'] })
  await sync(mac, { outbox: [
    { id: 'q1', type: 'agent_reply', session_id: 's1', body: {}, notify: true },
    { id: 'q2', type: 'needs_attention', session_id: 's1', body: { request_id: 'r9' } },
  ] })
  expect(calls.slice(3).map((c) => c.payload.type)).toEqual(['needs_attention'])
  // Switching it back on (an empty list) restores it.
  await sync(phone, { after: 0, push_off: [] })
  await sync(mac, { outbox: [{ id: 'q3', type: 'agent_reply', session_id: 's1', body: {}, notify: true }] })
  expect(calls.slice(4).map((c) => c.payload.type)).toEqual(['agent_reply'])
  calls.splice(3)

  // A sealed preview reaches the phone it was sealed for, marked for the notification extension.
  const phoneKey = 'P'.repeat(43)
  const keyed = await pair('phone', 'keyed', undefined, phoneKey)
  await sync(keyed, { after: 0, push_token: 'b'.repeat(64) })
  const earlier = calls.splice(0)
  const preview = { e2e: 1, from: 'M'.repeat(43), to: { [phoneKey]: 'sealed-for-keyed' } }
  await sync(mac, { outbox: [{ id: 'v1', type: 'needs_attention', session_id: 's1', body: { request_id: 'r5' }, preview }] })
  const byToken = Object.fromEntries(calls.map((c) => [c.token, c.payload]))
  expect(byToken['b'.repeat(64)]).toMatchObject({ id: 'v1', from: 'M'.repeat(43), preview: 'sealed-for-keyed', aps: { 'mutable-content': 1 } })
  expect(byToken[apns].preview).toBeUndefined() // nothing sealed for that phone
  expect(byToken[apns].aps['mutable-content']).toBeUndefined()
  calls.splice(0, calls.length, ...earlier)

  // Replayed state for a newly paired phone is not a new event: no push.
  await sync(mac, { outbox: [
    { id: 'p7', type: 'needs_attention', session_id: 's1', body: { request_id: 'r2' }, snapshot: true },
  ] })
  expect(calls.map((c) => c.payload.type)).toEqual(['agent_reply', 'needs_attention', 'compact'])
  server.stop(true)
})

test('tenants cannot see or address each other', async () => {
  const { server, pair, sync } = setup()
  const macA = await pair('machine', 'mac-a', 'a')
  const phoneA = await pair('phone', 'phone-a', 'a')
  const macB = await pair('machine', 'mac-b', 'b')
  const phoneB = await pair('phone', 'phone-b', 'b')

  await sync(macA, { outbox: [{ id: 'a1', type: 'agent_reply', session_id: 's1', body: { text: 'A' } }] })
  await sync(macB, { outbox: [{ id: 'b1', type: 'agent_reply', session_id: 's2', body: { text: 'B' } }] })

  const a = await sync(phoneA, { after: 0 })
  expect(a.inbox.map((m: any) => m.id)).toEqual(['a1'])
  expect(a.machines.map((m: any) => m.name)).toEqual(['mac-a'])
  const b = await sync(phoneB, { after: 0 })
  expect(b.inbox.map((m: any) => m.id)).toEqual(['b1'])
  expect(b.machines.map((m: any) => m.name)).toEqual(['mac-b'])

  // A phone cannot address a machine in another tenant, even if it knows the name.
  const cross = { id: 'x1', type: 'prompt', machine: 'mac-b', session_id: 's2', body: { text: 'nope' } }
  expect((await sync(phoneA, { after: a.cursor, outbox: [cross] })).acked).toEqual([])
  expect((await sync(macB, { after: 0 })).inbox).toEqual([])

  // Nor can a machine make another tenant's phone see its reply.
  await sync(macA, { outbox: [{ id: 'a2', type: 'agent_reply', session_id: 's2', body: { text: 'nope' } }] })
  expect((await sync(phoneB, { after: b.cursor })).inbox).toEqual([])
  server.stop(true)
})

test('machine names are scoped by tenant', async () => {
  const { server, pair } = setup()
  expect(typeof await pair('machine', 'mac', 'a')).toBe('string')
  expect(typeof await pair('machine', 'mac', 'b')).toBe('string')
  server.stop(true)
})

test('an existing database migrates to the default tenant', () => {
  const path = join(mkdtempSync(join(tmpdir(), 'perch-relay-')), 'old.db')
  const old = new Database(path)
  old.exec(`
    create table devices (id integer primary key, kind text, name text, token_hash text unique, last_seen text, revoked integer default 0, pubkey text, push_token text);
    create table codes (code_hash text primary key, kind text, expires integer);
    create table messages (seq integer primary key autoincrement, id text unique, machine text, dir text, json text);
    insert into devices (kind, name, token_hash) values ('phone', 'iphone', 'h');
    insert into messages (id, machine, dir, json) values ('m1', 'mac', 'up', '{}');`)
  old.close()

  const db = open(path, { owner: 'relay@test', salt: SALT })
  const tenant = tenantFor('relay@test', SALT)
  expect(db.query('select tenant_id from devices').get()).toEqual({ tenant_id: tenant })
  expect(db.query('select tenant_id from messages').get()).toEqual({ tenant_id: tenant })
  expect((db.query(`pragma table_info('codes')`).all() as { name: string }[]).map((c) => c.name)).toContain('tenant_id')
  db.close()
})

test('a pre-salt relay migrates its owner tenant to the salted one', () => {
  const path = join(mkdtempSync(join(tmpdir(), 'perch-relay-')), 'legacy.db')
  const owner = 'legacy@example.com'
  const legacy = legacyTenantFor(owner)
  const old = new Database(path)
  old.exec(`
    create table devices (id integer primary key, kind text, name text, token_hash text unique, last_seen text, revoked integer default 0, pubkey text, push_token text, tenant_id text not null);
    create table codes (code_hash text primary key, kind text, expires integer, tenant_id text not null);
    create table messages (seq integer primary key autoincrement, id text unique, machine text, dir text, json text, tenant_id text not null);
    create table settings (k text primary key, v text);`)
  old.run(`insert into settings (k, v) values ('owner_tenant', ?)`, [legacy])
  old.run(`insert into devices (kind, name, token_hash, tenant_id) values ('phone', 'iphone', 'h', ?)`, [legacy])
  old.run(`insert into messages (id, machine, dir, json, tenant_id) values ('m1', 'mac', 'up', '{}', ?)`, [legacy])
  old.close()

  const db = open(path, { owner, salt: SALT })
  const tenant = tenantFor(owner, SALT)
  expect(relayTenant(db)).toBe(tenant)
  expect(relayTenant(db)).not.toBe(legacy)
  expect(db.query('select tenant_id from devices').get()).toEqual({ tenant_id: tenant })
  expect(db.query('select tenant_id from messages').get()).toEqual({ tenant_id: tenant })
  db.close()
})

test('long-poll returns as soon as a message arrives', async () => {
  const { server, pair, sync } = setup()
  const mac = await pair('machine', 'mac')
  const phone = await pair('phone', 'iphone')
  const t0 = Date.now()
  const waiting = sync(mac, { after: 0, wait: 20 })
  await Bun.sleep(100)
  await sync(phone, { outbox: [{ id: 'p1', type: 'prompt', machine: 'mac', session_id: 's1', body: { text: 'hi' } }] })
  expect((await waiting).inbox[0].id).toBe('p1')
  expect(Date.now() - t0).toBeLessThan(2000)
  server.stop(true)
})

test('a message wakes only devices that can see it', async () => {
  const { server, pair, sync } = setup()
  await pair('machine', 'mac-a', 'a')
  const phoneA = await pair('phone', 'phone-a', 'a')
  const macB = await pair('machine', 'mac-b', 'b')
  const waiting = sync(macB, { after: 0, wait: 1 }) // another tenant's laptop
  await Bun.sleep(100)
  const t0 = Date.now()
  await sync(phoneA, { outbox: [{ id: 'p1', type: 'prompt', machine: 'mac-a', session_id: 's1', body: { text: 'hi' } }] })
  const r = await waiting
  expect(r.inbox).toEqual([])
  expect(Date.now() - t0).toBeGreaterThan(800) // waited out its poll instead of waking early
  server.stop(true)
})

test('revoked devices are locked out', async () => {
  const { db, server, pair, post } = setup()
  const phone = await pair('phone', 'iphone')
  db.run(`update devices set revoked = 1 where name = 'iphone'`)
  expect((await post('/v1/sync', { after: 0 }, phone)).status).toBe(401)
  server.stop(true)
})

test('public keys are set at pairing and never replaced; each side sees the other side\'s', async () => {
  const { server, pair, sync } = setup()
  const K1 = 'A'.repeat(43), K2 = 'B'.repeat(43)
  const mac = await pair('machine', 'mac', undefined, K1)
  const phone = await pair('phone', 'iphone', undefined, K2)
  await sync(phone, { after: 0, pubkey: 'C'.repeat(43) }) // can't be swapped later
  await sync(mac, { after: 0, pubkey: 'C'.repeat(43) })
  expect((await sync(mac, { after: 0 })).phones).toEqual([{ name: 'iphone', pubkey: K2 }])
  expect((await sync(phone, { after: 0 })).machines.map((m: any) => m.pubkey)).toEqual([K1])
  server.stop(true)
})

test('machines advertise validated direct addresses to their phones', async () => {
  const { db, server, pair, sync } = setup()
  const mac = await pair('machine', 'mac')
  const phone = await pair('phone', 'iphone')

  await sync(mac, {
    direct: {
      port: 8789,
      addrs: [
        { host: '192.168.1.24', network: 'lan' },
        { host: '100.120.43.88', network: 'tailscale' },
        { host: '8.8.8.8', network: 'lan' },
        { host: '192.168.1.24', network: 'lan' },
      ],
    },
  })
  expect((await sync(phone, { after: 0 })).machines[0].direct).toEqual({
    port: 8789,
    addrs: [
      { host: '192.168.1.24', network: 'lan' },
      { host: '100.120.43.88', network: 'tailscale' },
    ],
  })

  await sync(mac, { direct: { port: 0, addrs: [{ host: '192.168.1.24', network: 'lan' }] } })
  expect((await sync(phone, { after: 0 })).machines[0].direct).toBeNull()

  await sync(mac, { direct: { port: 8790, addrs: [{ host: '10.0.0.5', network: 'lan' }] } })
  expect((await sync(phone, { after: 0 })).machines[0].direct).toEqual({
    port: 8790,
    addrs: [{ host: '10.0.0.5', network: 'lan' }],
  })

  await sync(mac, { direct: null })
  expect((await sync(phone, { after: 0 })).machines[0].direct).toBeNull()

  // A corrupt stored hint is reported as none instead of breaking the phone's sync.
  db.run(`update devices set direct = '{' where name = 'mac'`)
  expect((await sync(phone, { after: 0 })).machines[0].direct).toBeNull()
  server.stop(true)
})

test('direct hints are visible only inside the machine\'s own tenant', async () => {
  const { server, pair, sync } = setup()
  const macA = await pair('machine', 'mac-a', 'a')
  const phoneA = await pair('phone', 'phone-a', 'a')
  const phoneB = await pair('phone', 'phone-b', 'b')
  const hint = { port: 8789, addrs: [{ host: '192.168.1.24', network: 'lan' }] }

  await sync(macA, { direct: hint })
  expect((await sync(phoneA, { after: 0 })).machines).toMatchObject([{ name: 'mac-a', direct: hint }])

  const other = await sync(phoneB, { after: 0 })
  expect(other.machines).toEqual([])
  expect(other.inbox).toEqual([])
  server.stop(true)
})

test('the relay only forwards: delivered messages are deleted', async () => {
  const { db, server, pair, sync } = setup()
  const mac = await pair('machine', 'mac')
  const a = await pair('phone', 'a')
  const b = await pair('phone', 'b')
  const count = (dir: string) => (db.query('select count(*) as n from messages where dir = ?').get(dir) as any).n

  await sync(mac, { after: 0, outbox: [{ id: 'r1', type: 'agent_reply', session_id: 's', body: {} }] })
  const ra = await sync(a, { after: 0 })
  await sync(a, { after: ra.cursor })
  expect(count('up')).toBe(1) // phone b hasn't confirmed it yet
  const rb = await sync(b, { after: 0 })
  expect(rb.inbox.map((m: any) => m.id)).toEqual(['r1']) // sending alone doesn't delete
  await sync(b, { after: rb.cursor }) // the next `after` confirms receipt
  expect(count('up')).toBe(0)

  await sync(a, { after: ra.cursor, outbox: [{ id: 'p1', type: 'prompt', machine: 'mac', session_id: 's', body: {} }] })
  const rm = await sync(mac, { after: 0 })
  expect(rm.inbox.map((m: any) => m.id)).toEqual(['p1'])
  await sync(mac, { after: rm.cursor })
  expect(count('down')).toBe(0)

  // A phone that never comes back doesn't keep messages forever.
  await sync(mac, { after: rm.cursor, outbox: [{ id: 'r2', type: 'agent_reply', session_id: 's', body: {} }] })
  db.run('update messages set created = 0')
  await sync(a, { after: (await sync(a, { after: ra.cursor })).cursor })
  expect(count('up')).toBe(0)

  // A phone paired later doesn't hold back what was sent before it.
  await sync(mac, { after: rm.cursor, outbox: [{ id: 'r3', type: 'agent_reply', session_id: 's', body: {} }] })
  await pair('phone', 'c')
  db.run('update devices set revoked = 1 where name = ?', ['b'])
  const r3 = await sync(a, { after: 0 })
  await sync(a, { after: r3.cursor })
  expect(count('up')).toBe(0)
  server.stop(true)
})

test('an `after` beyond what was sent acks nothing (notification buttons send a huge one)', async () => {
  const { db, server, pair, sync } = setup()
  const mac = await pair('machine', 'mac')
  const phone = await pair('phone', 'iphone')
  await sync(mac, { outbox: [{ id: 'r1', type: 'agent_reply', session_id: 's', body: {} }] })
  await sync(phone, { after: 9_007_199_254_740_991, outbox: [] })
  expect((db.query('select count(*) as n from messages').get() as any).n).toBe(1) // still waiting for the phone
  const r = await sync(phone, { after: 0 })
  expect(r.inbox.map((m: any) => m.id)).toEqual(['r1'])
  await sync(phone, { after: r.cursor })
  expect((db.query('select count(*) as n from messages').get() as any).n).toBe(0)
  server.stop(true)
})

test('message ids are unique per tenant, not relay-wide', async () => {
  const { server, pair, sync } = setup()
  const macA = await pair('machine', 'mac', 'a'), phoneA = await pair('phone', 'pa', 'a')
  const macB = await pair('machine', 'mac', 'b'), phoneB = await pair('phone', 'pb', 'b')
  await sync(macA, { outbox: [{ id: 'same', type: 'agent_reply', session_id: 's', body: { t: 'A' } }] })
  await sync(macB, { outbox: [{ id: 'same', type: 'agent_reply', session_id: 's', body: { t: 'B' } }] })
  expect((await sync(phoneA, { after: 0 })).inbox.map((m: any) => m.body.t)).toEqual(['A'])
  expect((await sync(phoneB, { after: 0 })).inbox.map((m: any) => m.body.t)).toEqual(['B'])
  server.stop(true)
})

test('moving to per-tenant ids keeps the message sequence counting up', () => {
  const path = join(mkdtempSync(join(tmpdir(), 'perch-')), 'old.db')
  const old = new Database(path)
  old.exec(`create table messages (seq integer primary key autoincrement, id text unique, machine text, dir text, json text, tenant_id text not null);
    insert into messages (id, dir, json, tenant_id) values ('a', 'up', '{}', 't'), ('b', 'up', '{}', 't');
    delete from messages;`) // everything delivered: the table is empty but seq is at 2
  old.close()
  const db = open(path, { owner: 'o', salt: SALT })
  db.run(`insert into messages (id, dir, json, tenant_id) values ('c', 'up', '{}', 't')`)
  expect((db.query(`select seq from messages where id = 'c'`).get() as any).seq).toBe(3)
  db.close()
})

test('devices report the e2e format they read; peers see it only when newer', async () => {
  const { server, pair, sync } = setup()
  const mac = await pair('machine', 'mac')
  const phone = await pair('phone', 'iphone')
  expect((await sync(mac, { after: 0 })).phones[0].e2e).toBeUndefined()
  expect((await sync(phone, { after: 0, e2e: 2 })).machines[0].e2e).toBeUndefined()
  expect((await sync(mac, { after: 0, e2e: 2 })).phones[0].e2e).toBe(2)
  expect((await sync(phone, { after: 0 })).machines[0].e2e).toBe(2)
  server.stop(true)
})

test('a v2 preview reaches the phone marked as v2, with no session in the clear', async () => {
  const calls: { token: string; payload: any }[] = []
  const { server, pair, sync } = setup(async (token, payload) => { calls.push({ token, payload }); return { status: 200 } })
  const mac = await pair('machine', 'mac')
  const key = 'Q'.repeat(43)
  const phone = await pair('phone', 'iphone', undefined, key)
  await sync(phone, { after: 0, push_token: 'c'.repeat(64) })
  const preview = { e2e: 2, from: 'M'.repeat(43), to: { [key]: 'sealed' } }
  await sync(mac, { outbox: [{ id: 'n1', type: 'needs_attention', body: { e2e: 2 }, preview }] })
  expect(calls[0].payload).toMatchObject({ e2e: 2, preview: 'sealed', session_id: null, aps: { 'thread-id': 'mac:' } })
  server.stop(true)
})

const pairModern = async (post: any, db: Database, name: string, owner?: string) => {
  const res = await post('/v1/pair', { code: pairCode(db, owner), name, pubkey: randomBytes(32).toString('base64url'), protocol: 2 })
  return (await res.json()) as { token: string; device_id: string; kind: string }
}

test('modern clients get a device id and a cursor token; legacy responses stay unchanged', async () => {
  const { db, server, post, pair, sync } = setup()
  const mac = await pairModern(post, db, 'mac')
  expect(mac.device_id).toMatch(/^dev_[0-9a-f]{32}$/)
  expect(Object.keys(mac).sort()).toEqual(['device_id', 'kind', 'token'])
  const phone = await pair('phone', 'iphone')
  let r = await sync(phone, { after: 0, protocol: 2 })
  expect(r.device_id).toMatch(/^dev_[0-9a-f]{32}$/)
  expect(r.cursor_token).toBe(`${relayId(db)}:${r.device_id}:${r.cursor}`)
  expect(r.machines[0].device_id).toBe(mac.device_id)
  // Without protocol 2 the old shape is exactly what it was (the frozen compat test covers the rest).
  r = await sync(phone, { after: r.cursor })
  expect(r.device_id).toBeUndefined()
  expect(r.cursor_token).toBeUndefined()
  expect(r.machines[0].device_id).toBeUndefined()
  server.stop(true)
})

test('a cursor token acks only its own device and rebases a foreign one', async () => {
  const { db, server, pair, sync } = setup()
  const mac = await pair('machine', 'mac')
  const phone = await pair('phone', 'one')
  await sync(mac, { outbox: [{ id: 'u1', type: 'agent_reply', session_id: 's', body: {} }] })
  const acked = () => (db.query('select acked, served from devices where name = ?').get('one') as any).acked as number
  const first = await sync(phone, { after: 0, protocol: 2 })
  expect(first.inbox.map((m: any) => m.id)).toEqual(['u1'])
  const token = first.cursor_token as string
  expect(acked()).toBe(0)
  // A token from another device (here the laptop's) is rebased to this row's acked and never acks.
  const foreignToken = (await sync(mac, { after: 0, protocol: 2 })).cursor_token as string
  const foreign = await sync(phone, { after: 1_000_000, cursor_token: foreignToken, protocol: 2 })
  expect(foreign.inbox.map((m: any) => m.id)).toEqual(['u1'])
  expect(acked()).toBe(0)
  expect(db.query(`select count(*) n from messages where id = 'u1'`).get() as any).toMatchObject({ n: 1 })
  // A malformed token is treated as absent, so the numeric cursor still works.
  expect((await sync(phone, { after: 0, cursor_token: 'nonsense', protocol: 2 })).inbox.map((m: any) => m.id)).toEqual(['u1'])
  // Its own token acknowledges the served position and the relay can forget the message.
  const own = await sync(phone, { after: 0, cursor_token: token, protocol: 2 })
  expect(own.inbox).toEqual([])
  expect(acked()).toBe(first.cursor)
  expect(db.query(`select count(*) n from messages where id = 'u1'`).get() as any).toMatchObject({ n: 0 })
  server.stop(true)
})

test('an after beyond what was served cannot suppress delivery', async () => {
  const { db, server, pair, sync } = setup()
  const mac = await pair('machine', 'mac')
  const phone = await pair('phone', 'iphone')
  await sync(mac, { outbox: [{ id: 'a', type: 'agent_reply', body: {} }] })
  const first = await sync(phone, { after: 0 })
  expect(first.inbox.map((m: any) => m.id)).toEqual(['a'])
  await sync(mac, { outbox: [{ id: 'b', type: 'agent_reply', body: {} }] })
  const r = await sync(phone, { after: 999 })
  expect(r.inbox.map((m: any) => m.id)).toEqual(['b'])
  expect(r.cursor).toBeGreaterThan(first.cursor)
  // The huge after still acks nothing: it is beyond what this row was served.
  expect((db.query('select acked from devices where name = ?').get('iphone') as any).acked).toBe(0)
  server.stop(true)
})

test('a machine id addresses one pairing; a reused name does not inherit its messages', async () => {
  const { db, server, post, pair, sync } = setup()
  const first = await pairModern(post, db, 'mac')
  const phone = await pair('phone', 'iphone')
  const machines = (await sync(phone, { after: 0, protocol: 2 })).machines
  expect(machines).toMatchObject([{ name: 'mac', device_id: first.device_id }])
  // The phone addresses the exact pairing by id; a wrong display name is ignored.
  let r = await sync(phone, { after: 0, outbox: [{ id: 'd1', type: 'prompt', machine: 'not-mac', machine_id: first.device_id, body: { text: 'x' } }] })
  expect(r.acked).toEqual(['d1'])
  const got = await sync(first.token, { after: 0, protocol: 2 })
  expect(got.inbox.map((m: any) => m.id)).toEqual(['d1'])
  expect(got.inbox[0]).toMatchObject({ machine: 'mac', machine_id: first.device_id })
  // Unpair, then re-pair under the same name: a different device.
  expect((await post('/v1/devices/revoke', { machine_id: first.device_id }, phone)).status).toBe(200)
  const second = await pairModern(post, db, 'mac')
  expect(second.device_id).not.toBe(first.device_id)
  // A message addressed to the old id is not delivered (and not acked); the live id is.
  const stale = { id: 'd2', type: 'prompt', machine: 'mac', machine_id: first.device_id, body: { text: 'old' } }
  const live = { id: 'd3', type: 'prompt', machine: 'mac', machine_id: second.device_id, body: { text: 'new' } }
  r = await sync(phone, { after: 0, outbox: [stale, live] })
  expect(r.acked).toEqual(['d3'])
  const started = await sync(second.token, { after: 0, protocol: 2 })
  expect(started.inbox.map((m: any) => m.id)).toEqual(['d3'])
  expect(started.inbox[0]).toMatchObject({ machine: 'mac', machine_id: second.device_id })
  await sync(second.token, { after: started.cursor, protocol: 2 })
  // Legacy name addressing still works for old phones.
  r = await sync(phone, { after: 0, outbox: [{ id: 'd4', type: 'prompt', machine: 'mac', body: { text: 'by name' } }] })
  expect(r.acked).toEqual(['d4'])
  expect((await sync(second.token, { after: 0, protocol: 2 })).inbox.map((m: any) => m.id)).toEqual(['d4'])
  server.stop(true)
})

test('revoking by a stale machine id never falls back to the name', async () => {
  const { db, server, post, pair } = setup()
  const first = await pairModern(post, db, 'mac')
  const phone = await pair('phone', 'iphone')
  expect((await post('/v1/devices/revoke', { machine_id: first.device_id }, phone)).status).toBe(200)
  const second = await pairModern(post, db, 'mac')
  expect((await post('/v1/devices/revoke', { machine_id: first.device_id, name: 'mac' }, phone)).status).toBe(404)
  expect((db.query('select revoked from devices where device_id = ?').get(second.device_id) as any).revoked).toBe(0)
  expect((await post('/v1/devices/revoke', { name: 'mac' }, phone)).status).toBe(200)
  server.stop(true)
})

test('a machine id from another tenant cannot be addressed', async () => {
  const { server, post, db, pair, sync } = setup()
  const a = await pairModern(post, db, 'mac', 'a@test')
  const bPhone = await pair('phone', 'p', 'b@test')
  const r = await sync(bPhone, { after: 0, outbox: [{ id: 'x', type: 'prompt', machine_id: a.device_id, body: {} }] })
  expect(r.acked).toEqual([])
  server.stop(true)
})

test('a modern laptop stamps machine_id on up messages and pushes', async () => {
  const calls: any[] = []
  const { server, post, db, pair, sync } = setup(async (_token, payload) => { calls.push(payload); return { status: 200 } })
  const mac = await pairModern(post, db, 'mac')
  const phone = await pair('phone', 'iphone')
  await sync(phone, { after: 0, push_token: 'a'.repeat(64) })
  await sync(mac.token, { after: 0, protocol: 2, outbox: [{ id: 'r1', type: 'agent_reply', session_id: 's1', body: {}, notify: true }] })
  expect(calls[0]).toMatchObject({ machine: 'mac', machine_id: mac.device_id })
  expect((await sync(phone, { after: 0, protocol: 2 })).inbox[0]).toMatchObject({ machine: 'mac', machine_id: mac.device_id })
  server.stop(true)
})

test('opening an old relay backfills device ids and rewrites stored machine names', () => {
  const path = join(mkdtempSync(join(tmpdir(), 'perch-relay-devids-')), 'relay.db')
  const raw = new Database(path)
  raw.exec(`
    create table settings (k text primary key, v text);
    create table devices (id integer primary key, kind text, name text, token_hash text unique, tenant_id text not null, acked integer not null default 0, revoked integer default 0);
    create table messages (seq integer primary key autoincrement, id text, machine text, dir text, json text, tenant_id text not null, created integer, unique(tenant_id, id));`)
  raw.run(`insert into settings (k, v) values ('tenant_salt', ?)`, [SALT])
  raw.run(`insert into settings (k, v) values ('owner_tenant', 't1')`)
  raw.run(`insert into devices (kind, name, token_hash, tenant_id, acked) values ('machine', 'mac', 'h1', 't1', 0)`)
  raw.run(`insert into devices (kind, name, token_hash, tenant_id, acked, revoked) values ('machine', 'mac', 'h2', 't1', 0, 1)`)
  raw.run(`insert into messages (id, machine, dir, json, tenant_id, created) values ('d1', 'mac', 'down', '{"id":"d1"}', 't1', 0)`)
  raw.close()

  const db = open(path)
  const active = db.query(`select device_id from devices where token_hash = 'h1'`).get() as any
  const revoked = db.query(`select device_id from devices where token_hash = 'h2'`).get() as any
  expect(active.device_id).toMatch(/^dev_[0-9a-f]{32}$/)
  expect(revoked.device_id).toMatch(/^dev_[0-9a-f]{32}$/)
  expect(revoked.device_id).not.toBe(active.device_id)
  const row = db.query(`select machine, json from messages where id = 'd1'`).get() as any
  expect(row.machine).toBe(active.device_id) // an active row wins over the revoked one
  expect(JSON.parse(row.json)).toMatchObject({ id: 'd1', machine_id: active.device_id })
  db.close()

  const again = open(path)
  expect((again.query(`select device_id from devices where token_hash = 'h1'`).get() as any).device_id).toBe(active.device_id)
  again.close()
})

test('a laptop reports its client update check; only modern phones see it', async () => {
  const { server, pair, sync } = setup()
  const mac = await pair('machine', 'mac')
  const phone = await pair('phone', 'iphone')
  await sync(mac, { after: 0, protocol: 2, update: { available: true, latest: 'abc12345', checked: 123 } })
  let r = await sync(phone, { after: 0, protocol: 2 })
  expect(r.machines[0].update).toEqual({ available: true, latest: 'abc12345', checked: 123 })
  // A legacy phone keeps the old machine entry shape.
  r = await sync(phone, { after: r.cursor })
  expect(r.machines[0].update).toBeUndefined()
  server.stop(true)
})

test('a phone can ask a laptop to update and gets the result', async () => {
  const { server, pair, sync } = setup()
  const mac = await pair('machine', 'mac')
  const phone = await pair('phone', 'iphone')
  const ask = { id: 'u1', type: 'update', machine: 'mac', body: {} }
  let r = await sync(phone, { after: 0, outbox: [ask] })
  const phoneCursor = r.cursor
  expect(r.acked).toEqual(['u1'])
  r = await sync(mac, { after: 0 })
  const machineCursor = r.cursor
  expect(r.inbox.map((m: any) => [m.id, m.type])).toEqual([['u1', 'update']])
  await sync(mac, { after: machineCursor, outbox: [{ id: 'u2', type: 'update_result', session_id: 's1', body: { ref: 'u1', ok: true } }] })
  r = await sync(phone, { after: phoneCursor })
  expect(r.inbox.map((m: any) => [m.id, m.type])).toEqual([['u2', 'update_result']])
  server.stop(true)
})
