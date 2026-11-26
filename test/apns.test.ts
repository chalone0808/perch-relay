import { test, expect } from 'bun:test'
import { generateKeyPairSync, verify } from 'node:crypto'
import { apnsConfig, apnsJwt, bothEnvironments } from '../apns'

test('APNs provider token is ES256-signed with the key id and team id', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()
  const config = apnsConfig({
    APNS_KEY: pem,
    APNS_KEY_ID: 'KEY123',
    APNS_TEAM_ID: 'TEAM123',
    APNS_TOPIC: 'com.example.perch',
  })
  expect(config).not.toBeNull()
  expect(config!.topic).toBe('com.example.perch')

  const jwt = apnsJwt(config!, 1_700_000_000)
  const [header, claims, signature] = jwt.split('.')
  expect(JSON.parse(Buffer.from(header, 'base64url').toString())).toEqual({ alg: 'ES256', kid: 'KEY123' })
  expect(JSON.parse(Buffer.from(claims, 'base64url').toString())).toEqual({ iss: 'TEAM123', iat: 1_700_000_000 })
  expect(
    verify(
      'sha256',
      Buffer.from(`${header}.${claims}`),
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      Buffer.from(signature, 'base64url'),
    ),
  ).toBe(true)

  expect(apnsConfig({})).toBeNull()
  expect(apnsConfig({ APNS_KEY: 'not a key', APNS_KEY_ID: 'K', APNS_TEAM_ID: 'T', APNS_TOPIC: 'com.example.perch' })).toBeNull()
  expect(apnsConfig({ APNS_KEY: pem, APNS_KEY_ID: 'KEY123', APNS_TEAM_ID: 'TEAM123' })).toBeNull()
})

test('a token from the other APNs environment is retried there once, then remembered', async () => {
  const calls: [string, boolean][] = []
  // dev-1 is an Xcode build's token (sandbox), prod-1 a TestFlight build's (production).
  const apple = async (token: string, _payload: unknown, production: boolean) => {
    calls.push([token, production])
    return token.startsWith('prod') === production ? { status: 200 } : { status: 400, reason: 'BadDeviceToken' }
  }
  const push = bothEnvironments(apple, false) // APNS_ENV=development
  expect(await push('dev-1', {})).toEqual({ status: 200 })
  expect(await push('prod-1', {})).toEqual({ status: 200 })
  expect(await push('prod-1', {})).toEqual({ status: 200 })
  expect(calls).toEqual([['dev-1', false], ['prod-1', false], ['prod-1', true], ['prod-1', true]])
  // A token neither environment knows still reports Apple's answer, so the relay can drop it.
  const dead = bothEnvironments(async () => ({ status: 400, reason: 'BadDeviceToken' }), false)
  expect(await dead('gone', {})).toEqual({ status: 400, reason: 'BadDeviceToken' })
})
