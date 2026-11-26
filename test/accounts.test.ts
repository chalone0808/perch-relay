import { test, expect } from 'bun:test'
import { open, relayTenant, tenantFor } from '../server'
import { accountCli, addAccount, bindIdentity, canonicalName, disableAccount, hashPassword, insertWithToken, verifyPassword } from '../accounts'

const db = () => open(':memory:', { owner: 'owner@test', salt: 'salt' })

test('passwords are salted scrypt in the documented format', async () => {
  const stored = await hashPassword('hunter2-hunter2')
  expect(stored).toMatch(/^scrypt\$32768\$8\$1\$[A-Za-z0-9+/=]{44}\$[A-Za-z0-9+/=]{44}$/)
  expect(stored).not.toBe(await hashPassword('hunter2-hunter2'))
  expect(await verifyPassword('hunter2-hunter2', stored)).toBe(true)
  expect(await verifyPassword('wrong', stored)).toBe(false)
  expect(await verifyPassword('anything', null)).toBe(false) // still runs the dummy hash
})

test('account names are canonical', () => {
  expect(canonicalName('  Alice ')).toBe('alice')
  expect(canonicalName('a b')).toBeNull()
  expect(canonicalName('')).toBeNull()
  expect(canonicalName('x'.repeat(65))).toBeNull()
  expect(canonicalName('tab\there')).toBeNull()
})

test('a token collision retries once, then fails loudly', () => {
  const d = db()
  d.exec('create table t (h text primary key)')
  const same = () => Buffer.alloc(32, 7)
  const first = insertWithToken('pdev_', (h) => d.run('insert into t values (?)', [h]), same)
  expect(first.startsWith('pdev_')).toBe(true)
  let calls = 0
  const flaky = (n: number) => (calls++ ? Buffer.alloc(n, 8) : Buffer.alloc(n, 7))
  expect(insertWithToken('pdev_', (h) => d.run('insert into t values (?)', [h]), flaky)).not.toBe(first)
  expect(() => insertWithToken('pdev_', (h) => d.run('insert into t values (?)', [h]), same)).toThrow(/UNIQUE/)
})

test('--adopt takes the relay tenant once; plain accounts get their own', async () => {
  const d = db()
  const owner = await addAccount(d, 'Owner', { adopt: true })
  expect(owner.tenant).toBe(relayTenant(d))
  await expect(addAccount(d, 'second', { adopt: true })).rejects.toThrow(/already holds/)
  const bob = await addAccount(d, 'bob')
  expect(bob.tenant).toBe(tenantFor('bob', 'salt'))
  await expect(addAccount(d, 'BOB')).rejects.toThrow()
})

test('a plain account cannot silently take over a tenant that has devices', async () => {
  const d = db()
  d.run(`insert into devices (kind, name, token_hash, tenant_id) values ('phone', 'p', 'h', ?)`, [tenantFor('carol', 'salt')])
  await expect(addAccount(d, 'carol')).rejects.toThrow(/--adopt/)
})

test('identities bind once per unbound subject', async () => {
  const d = db()
  await addAccount(d, 'a', { email: 'A@Example.com', github: 'Octo' })
  await addAccount(d, 'b')
  expect(() => bindIdentity(d, 'b', { email: 'a@example.com' })).toThrow()
  const rows = d.query('select provider, subject from identities order by id').all()
  expect(rows).toEqual([{ provider: 'email', subject: 'a@example.com' }, { provider: 'oauth:github', subject: 'octo' }])
})

test('disable revokes sessions and devices unless asked to keep devices', async () => {
  const d = db()
  const { tenant } = await addAccount(d, 'a', { adopt: true })
  const id = (d.query('select id from accounts').get() as any).id
  d.run(`insert into devices (kind, name, token_hash, tenant_id) values ('phone', 'p', 'h1', ?)`, [tenant])
  d.run(`insert into sessions (token_hash, account_id, expires, created) values ('s', ?, ?, '')`, [id, Date.now() + 1e6])
  disableAccount(d, 'a', { keepDevices: true })
  expect(d.query('select count(*) as n from sessions').get()).toEqual({ n: 0 })
  expect(d.query('select revoked from devices').get()).toEqual({ revoked: 0 })
  disableAccount(d, 'a')
  expect(d.query('select revoked from devices').get()).toEqual({ revoked: 1 })
  expect(d.query('select disabled from accounts').get()).toEqual({ disabled: 1 })
})

test('the account CLI prints a one-time password and rejects unknown options', async () => {
  const d = db()
  const out = await accountCli(d, ['add', 'dana', '--password', '--github', 'dana-gh'])
  const password = out.match(/one-time password: (\S+)/)![1]
  expect(password).toHaveLength(16)
  const stored = (d.query(`select secret_hash from identities where provider = 'password'`).get() as any).secret_hash
  expect(await verifyPassword(password, stored)).toBe(true)
  expect(stored).not.toContain(password)
  await expect(accountCli(d, ['add', 'x', '--admin'])).rejects.toThrow(/unknown option/)
  expect(await accountCli(d, ['list'])).toContain('oauth:github:dana-gh')
})
