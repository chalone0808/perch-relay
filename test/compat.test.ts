// Replays the frozen pre-accounts pair and sync bodies (fixtures/compat.json): /v1/sync must answer
// code-paired phones and laptops exactly as before, with or without accounts configured. Laptops
// still pair by code; phone pairing codes were retired on 2026-11-25 (phones sign in), so the
// frozen phone pair request must now be refused, while phones already paired that way keep working.
import { test, expect } from 'bun:test'
import { open, app, pairCode, relayTenant } from '../server'
import { addAccount, sha } from '../accounts'
import { authConfig } from '../auth'
import fixtures from '../fixtures/compat.json'

for (const accounts of [false, true]) {
  test(`frozen pair and sync bodies replay unchanged (accounts ${accounts ? 'on' : 'off'})`, async () => {
    const db = open(':memory:', { owner: 'owner@test', salt: 'salt' })
    if (accounts) await addAccount(db, 'owner', { adopt: true, password: true, email: 'o@example.com' })
    const cfg = accounts ? authConfig({ PERCH_PUBLIC_URL: 'https://r.example', AUTH_EMAIL: '1', SMTP_URL: 'smtp://m', AUTH_EMAIL_FROM: 'p@r' }) : authConfig({ AUTH_PASSWORD: '0' })
    const server = Bun.serve({ port: 0, ...app(db, undefined, cfg) })
    const send = (path: string, body: unknown, token?: string) =>
      fetch(`http://localhost:${server.port}${path}`, { method: 'POST', headers: token ? { authorization: `Bearer ${token}` } : {}, body: JSON.stringify(body) })
    const post = async (path: string, body: unknown, token?: string) => {
      const res = await send(path, body, token)
      expect(res.status).toBe(200)
      return (await res.json()) as any
    }
    db.run(`insert into codes (code_hash, kind, expires, tenant_id) values (?, 'phone', ?, ?)`, [sha('phone-code'), Date.now() + 60_000, relayTenant(db)])
    expect((await send('/v1/pair', { ...fixtures.pair_request, code: 'phone-code' })).status).toBe(403)
    // A phone paired by code before the retirement: an unprefixed token and its key, as stored then.
    const phonePair = { token: 'old-phone-token' }
    db.run(`insert into devices (kind, name, token_hash, pubkey, tenant_id) values ('phone', 'iPhone', ?, ?, ?)`, [sha(phonePair.token), fixtures.pair_request.pubkey, relayTenant(db)])
    const machinePair = await post('/v1/pair', { ...fixtures.machine_pair_request, code: pairCode(db) })
    expect(Object.keys(machinePair).sort()).toEqual(fixtures.pair_response_keys)

    const up = await post('/v1/sync', fixtures.machine_sync_request, machinePair.token)
    expect(Object.keys(up).sort()).toEqual(fixtures.machine_sync_response_keys)
    expect(up.acked).toEqual(['u1'])

    const down = await post('/v1/sync', fixtures.phone_sync_request, phonePair.token)
    const expected = structuredClone(fixtures.phone_sync_response) as any
    expected.machines[0].last_seen = down.machines[0]?.last_seen
    expect(down).toEqual(expected)
    server.stop(true)
  })
}
