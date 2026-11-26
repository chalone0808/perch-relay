#!/usr/bin/env bun
// perch push gateway: holds the APNs key so relays don't have to. A relay POSTs a device token and
// a ready-made payload; the gateway signs it and forwards it to Apple. Payloads are content-free
// (previews are sealed to the phone), so the gateway learns only tokens, types and timing.
//
//   bun gateway.ts        run (PORT, HOST, APNS_* as for the relay, PUSH_KEYS)
//
// PUSH_KEYS="name=secret,name2=secret2": one secret per relay, revoked by removing it.
//   POST /v1/push  Authorization: Bearer <secret>  { token, payload }  → { status, reason? }
import { makeApnsSender, type PushSender } from './apns'

const MAX_PER_MINUTE = 120

export function gatewayKeys(spec = ''): Map<string, string> {
  const keys = new Map<string, string>()
  for (const pair of spec.split(',')) {
    const [name, secret] = pair.split('=').map((s) => s?.trim())
    if (name && secret && secret.length >= 16) keys.set(secret, name)
  }
  return keys
}

export function gateway(keys: Map<string, string>, push: PushSender, now = () => Date.now()) {
  // ponytail: in-memory fixed window per key; resets on restart, fine for a handful of relays.
  const used = new Map<string, { minute: number; count: number }>()
  const bad = (status: number, error: string) => Response.json({ error }, { status })
  return {
    async fetch(req: Request) {
      const url = new URL(req.url)
      if (url.pathname !== '/v1/push' || req.method !== 'POST') return bad(404, 'not found')
      const name = keys.get(req.headers.get('authorization')?.replace(/^Bearer /, '') ?? '')
      if (!name) return bad(401, 'unauthorized')
      const minute = Math.floor(now() / 60_000)
      const u = used.get(name)
      const window = u && u.minute === minute ? u : { minute, count: 0 }
      if (++window.count > MAX_PER_MINUTE) return bad(429, 'slow down')
      used.set(name, window)
      const text = await req.text()
      if (text.length > 8192) return bad(413, 'too large')
      let body: any
      try { body = JSON.parse(text) } catch { return bad(400, 'bad json') }
      if (typeof body?.token !== 'string' || !/^[0-9a-fA-F]{32,200}$/.test(body.token)) return bad(400, 'bad token')
      if (!body.payload || typeof body.payload !== 'object') return bad(400, 'bad payload')
      const r = await push(body.token, body.payload)
      if (r.status !== 200) console.error(`apns for ${name}: ${r.status} ${r.reason ?? ''}`)
      return Response.json(r)
    },
  }
}

if (import.meta.main) {
  const push = makeApnsSender(process.env)
  const keys = gatewayKeys(process.env.PUSH_KEYS)
  if (!push) { console.error('APNS_KEY_FILE/APNS_KEY, APNS_KEY_ID, APNS_TEAM_ID and APNS_TOPIC are required'); process.exit(1) }
  if (!keys.size) { console.error('PUSH_KEYS="relay=secret" is required (secrets ≥16 chars)'); process.exit(1) }
  const server = Bun.serve({ port: Number(process.env.PORT ?? 8788), hostname: process.env.HOST ?? '127.0.0.1', ...gateway(keys, push) })
  console.log(`perch push gateway on ${server.url} for ${[...keys.values()].join(', ')}`)
}
