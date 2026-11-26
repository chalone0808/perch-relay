import { test, expect } from 'bun:test'
import { Database } from 'bun:sqlite'
import { mkdtempSync } from 'node:fs'
import { createHash, randomBytes } from 'node:crypto'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { open, pairCode, app, relayTenant, tenantFor, legacyTenantFor, VERSION, PROTOCOL } from '../server'
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

test('reports its version without auth', async () => {
  const { server } = setup()
  const url = `http://localhost:${server.port}`
  const res = await fetch(`${url}/v1/version`)
  expect(res.status).toBe(200)
  expect(await res.json()).toEqual({ name: 'perch-relay', version: VERSION, protocol: PROTOCOL })
  expect((await fetch(`${url}/v1/version`, { method: 'POST' })).status).toBe(405)
  server.stop(true)
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
