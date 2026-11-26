// Just enough SMTP to send a sign-in link, so the relay needs no mail dependency.
//   smtps://user:pass@host:465   implicit TLS
//   smtp://user:pass@host:587    STARTTLS, required unless the host is loopback (a local MTA)
import { connect as tcpConnect, type Socket } from 'node:net'
import { connect as tlsConnect } from 'node:tls'

export type Mail = { to: string; subject: string; text: string }
export type SendMail = (mail: Mail) => Promise<void>

const loopback = (h: string) => h === 'localhost' || h === '::1' || h === '[::1]' || h.startsWith('127.')
const clean = (s: string) => s.replace(/[\r\n]/g, ' ')

export function smtpSender(url: string, from: string): SendMail {
  const u = new URL(url)
  const secure = u.protocol === 'smtps:'
  if (!secure && u.protocol !== 'smtp:') throw new Error('SMTP_URL must be smtps:// or smtp://')
  const host = u.hostname
  const port = Number(u.port || (secure ? 465 : 587))
  const user = decodeURIComponent(u.username)
  const pass = decodeURIComponent(u.password)

  return (mail) => new Promise<void>((resolve, reject) => {
    let sock: Socket = secure ? tlsConnect({ host, port, servername: host }) : tcpConnect({ host, port })
    let buf = ''
    let waiting: ((reply: string) => void) | null = null
    const fail = (e: Error) => { sock.destroy(); reject(e) }
    const onData = (d: Buffer) => {
      buf += d.toString('utf8')
      const lines = buf.split('\r\n')
      // A reply is complete when its last line is "NNN text" (continuations are "NNN-text").
      if (waiting && buf.endsWith('\r\n') && /^\d{3}( |$)/.test(lines[lines.length - 2])) {
        const reply = buf
        buf = ''
        const w = waiting
        waiting = null
        w(reply)
      }
    }
    const watch = (s: Socket) => {
      s.on('data', onData)
      s.on('error', fail)
      s.setTimeout(20_000, () => fail(new Error('smtp timeout')))
    }
    watch(sock)
    const step = (line: string | null, ok: string) => new Promise<string>((res, rej) => {
      waiting = (reply) => (reply.startsWith(ok) ? res(reply) : rej(new Error(`smtp ${reply.slice(0, 3)} after ${line?.split(' ')[0] ?? 'connect'}`)))
      if (line !== null) sock.write(`${line}\r\n`)
    })

    ;(async () => {
      await step(null, '220')
      let ehlo = await step('EHLO perch', '250')
      if (!secure) {
        if (/[- ]STARTTLS/i.test(ehlo)) {
          await step('STARTTLS', '220')
          sock.removeListener('data', onData)
          sock = tlsConnect({ socket: sock, servername: host })
          watch(sock)
          ehlo = await step('EHLO perch', '250')
        } else if (!loopback(host)) {
          throw new Error('smtp server offers no STARTTLS; refusing to send in the clear')
        }
      }
      if (user) await step(`AUTH PLAIN ${Buffer.from(`\0${user}\0${pass}`).toString('base64')}`, '235')
      await step(`MAIL FROM:<${clean(from).replace(/^.*<|>.*$/g, '')}>`, '250')
      await step(`RCPT TO:<${clean(mail.to)}>`, '250')
      await step('DATA', '354')
      const body = mail.text.replace(/\r?\n/g, '\r\n').replace(/^\./gm, '..')
      const message = [
        `From: ${clean(from)}`, `To: <${clean(mail.to)}>`, `Subject: ${clean(mail.subject)}`,
        `Date: ${new Date().toUTCString()}`, 'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: 8bit', '', body,
      ].join('\r\n')
      await step(`${message}\r\n.`, '250')
      sock.end('QUIT\r\n')
      resolve()
    })().catch(fail)
  })
}
