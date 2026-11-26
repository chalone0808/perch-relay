import { test, expect } from 'bun:test'
import { gateway, gatewayKeys } from '../gateway'
import { makePushSender } from '../apns'

const TOKEN = 'ab'.repeat(32)
const SECRET = 'relay-secret-0123456789'

test('a relay pushes through the gateway with its key, and Apple\'s verdict comes back', async () => {
  const sent: [string, unknown][] = []
  let clock = 0
  const g = gateway(gatewayKeys(`friend=${SECRET},short=abc`), async (t, p) => {
    sent.push([t, p])
    return t === TOKEN ? { status: 200 } : { status: 410, reason: 'Unregistered' }
  }, () => clock)
  const server = Bun.serve({ port: 0, ...g })
  const url = server.url.href
  try {
    const push = makePushSender({ PUSH_GATEWAY: url, PUSH_GATEWAY_KEY: SECRET })!
    expect(await push(TOKEN, { aps: { alert: 'hi' } })).toEqual({ status: 200, reason: undefined })
    expect(sent).toEqual([[TOKEN, { aps: { alert: 'hi' } }]])
    // 410 must reach the relay so it forgets the token.
    expect(await push('cd'.repeat(32), { aps: {} })).toEqual({ status: 410, reason: 'Unregistered' })

    // Wrong or too-short keys are refused, and nothing reaches Apple.
    const before = sent.length
    expect((await makePushSender({ PUSH_GATEWAY: url, PUSH_GATEWAY_KEY: 'nope' })!(TOKEN, {})).reason).toBe('gateway 401 unauthorized')
    expect((await makePushSender({ PUSH_GATEWAY: url, PUSH_GATEWAY_KEY: 'abc' })!(TOKEN, {})).status).toBe(0)
    expect((await push('not-hex', {})).reason).toBe('gateway 400 bad token')
    expect(sent.length).toBe(before)

    // Rate limit per key per minute.
    for (let i = 0; i < 117; i++) await push(TOKEN, {})
    expect((await push(TOKEN, {})).reason).toBe('gateway 429 slow down')
    clock = 60_000
    expect((await push(TOKEN, {})).status).toBe(200)
  } finally {
    server.stop(true)
  }
})

test('an unreachable gateway reports status 0 instead of throwing', async () => {
  const r = await makePushSender({ PUSH_GATEWAY: 'http://127.0.0.1:1', PUSH_GATEWAY_KEY: SECRET })!(TOKEN, {})
  expect(r.status).toBe(0)
})
