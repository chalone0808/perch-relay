// APNs sender for the relay. The relay only sees routing metadata and message type, never the
// end-to-end encrypted body, so notifications are deliberately content-free.
import { createPrivateKey, sign, type KeyObject } from 'node:crypto'
import { readFileSync } from 'node:fs'
import http2 from 'node:http2'

export type ApnsConfig = {
  key: KeyObject
  keyId: string
  teamId: string
  topic: string
  production: boolean
}

export type ApnsResult = { status: number; reason?: string }
export type PushSender = (deviceToken: string, payload: unknown) => Promise<ApnsResult>

const b64url = (v: string | Buffer) => Buffer.from(v).toString('base64url')
let cached: { jwt: string; at: number; keyId: string } | null = null

/// Reads APNS_KEY (PEM) or APNS_KEY_FILE, plus APNS_KEY_ID, APNS_TEAM_ID and APNS_TOPIC.
export function apnsConfig(env: Record<string, string | undefined> = process.env): ApnsConfig | null {
  const keyId = env.APNS_KEY_ID?.trim()
  const teamId = env.APNS_TEAM_ID?.trim()
  const topic = env.APNS_TOPIC?.trim()
  let pem = env.APNS_KEY
  if (!pem && env.APNS_KEY_FILE) {
    try { pem = readFileSync(env.APNS_KEY_FILE, 'utf8') } catch { return null }
  }
  if (!keyId || !teamId || !topic || !pem) return null
  try {
    return { key: createPrivateKey(pem), keyId, teamId, topic, production: env.APNS_ENV === 'production' }
  } catch {
    return null
  }
}

/// Apple wants a fresh provider token at least hourly; 50 minutes keeps it comfortably valid.
export function apnsJwt(config: ApnsConfig, now = Math.floor(Date.now() / 1000)): string {
  if (cached && cached.keyId === config.keyId && now - cached.at < 50 * 60) return cached.jwt
  const header = b64url(JSON.stringify({ alg: 'ES256', kid: config.keyId }))
  const claims = b64url(JSON.stringify({ iss: config.teamId, iat: now }))
  const signature = sign('sha256', Buffer.from(`${header}.${claims}`), {
    key: config.key,
    dsaEncoding: 'ieee-p1363',
  })
  const jwt = `${header}.${claims}.${b64url(signature)}`
  cached = { jwt, at: now, keyId: config.keyId }
  return jwt
}

export function makeApnsSender(env: Record<string, string | undefined> = process.env): PushSender | undefined {
  const config = apnsConfig(env)
  if (!config) return undefined
  return bothEnvironments((token, payload, production) => sendApns({ ...config, production }, token, payload), config.production)
}

/// Xcode builds get sandbox device tokens; TestFlight and App Store builds get production ones, and
/// each APNs environment rejects the other's with BadDeviceToken. Start in APNS_ENV's environment,
/// retry once in the other, and remember where each token lives.
export function bothEnvironments(
  send: (token: string, payload: unknown, production: boolean) => Promise<ApnsResult>,
  preferProduction: boolean,
): PushSender {
  const home = new Map<string, boolean>() // ponytail: in memory; relearned with one retry after a restart
  return async (token, payload) => {
    const first = home.get(token) ?? preferProduction
    let r = await send(token, payload, first)
    let used = first
    if (r.status === 400 && r.reason === 'BadDeviceToken') {
      r = await send(token, payload, !first)
      used = !first
    }
    if (r.status === 200) {
      if (home.size > 10_000) home.clear()
      home.set(token, used)
    }
    return r
  }
}

/// The relay's sender: a push gateway (PUSH_GATEWAY + PUSH_GATEWAY_KEY) if set, else APNs directly.
export function makePushSender(env: Record<string, string | undefined> = process.env): PushSender | undefined {
  const url = env.PUSH_GATEWAY?.trim()
  const key = env.PUSH_GATEWAY_KEY?.trim()
  if (!url || !key) return makeApnsSender(env)
  const endpoint = `${url.replace(/\/+$/, '')}/v1/push`
  return async (token, payload) => {
    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' },
        body: JSON.stringify({ token, payload }),
        signal: AbortSignal.timeout(15_000),
      })
      const body = (await res.json().catch(() => ({}))) as { status?: number; reason?: string; error?: string }
      // Apple's verdict when the gateway reached Apple; otherwise the gateway's own refusal.
      return res.ok ? { status: Number(body.status), reason: body.reason } : { status: 0, reason: `gateway ${res.status} ${body.error ?? ''}`.trim() }
    } catch (e) {
      return { status: 0, reason: `gateway: ${(e as Error).message}` }
    }
  }
}

export function sendApns(
  config: ApnsConfig,
  deviceToken: string,
  payload: unknown,
): Promise<ApnsResult> {
  const host = config.production ? 'api.push.apple.com' : 'api.sandbox.push.apple.com'
  return new Promise((resolve) => {
    let settled = false
    let timer: ReturnType<typeof setTimeout> | undefined
    const done = (result: ApnsResult) => {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer)
      resolve(result)
    }
    let client
    try {
      client = http2.connect(`https://${host}:443`)
    } catch (e) {
      done({ status: 0, reason: (e as Error).message })
      return
    }
    timer = setTimeout(() => {
      try { client.close() } catch {}
      done({ status: 0, reason: 'timeout' })
    }, 10_000)
    client.on('error', (e: Error) => done({ status: 0, reason: e.message }))
    const headers: Record<string, string> = {
      ':method': 'POST',
      ':path': `/3/device/${deviceToken}`,
      authorization: `bearer ${apnsJwt(config)}`,
      'apns-topic': config.topic,
      'apns-push-type': 'alert',
      'apns-priority': '10',
      'apns-expiration': `${Math.floor(Date.now() / 1000) + 3600}`,
      'content-type': 'application/json',
    }
    const req = client.request(headers)
    let status = 0
    let body = ''
    req.setEncoding('utf8')
    req.on('response', (h: Record<string, unknown>) => { status = Number(h[':status']) })
    req.on('data', (chunk: string) => { body += chunk })
    req.on('error', (e: Error) => {
      client.close()
      done({ status: 0, reason: e.message })
    })
    req.on('end', () => {
      client.close()
      let reason: string | undefined
      try { reason = JSON.parse(body)?.reason } catch {}
      done({ status, reason })
    })
    req.end(JSON.stringify(payload))
  })
}
