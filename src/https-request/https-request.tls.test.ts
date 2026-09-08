/**
 * Certificate verification is the client's decision, written into every
 * request -- not Node's process-wide fallback.
 *
 * An `https.request` that OMITS `rejectUnauthorized` inherits
 * `NODE_TLS_REJECT_UNAUTHORIZED`, so on an agent where that is `0` (set
 * machine-wide, or by an unrelated job in the same process) every request this
 * transport makes would silently stop verifying the server -- including the
 * ones carrying an OAuth secret, a bearer token or a Basic password
 * (azure-pipelines-terraform#1106 finding 4). The tests below hold the default
 * to `true` against that switch, and keep the explicit opt-out working for the
 * private-CA case that motivates it.
 */
import * as https from 'node:https'
import { type AddressInfo } from 'node:net'
import { afterEach, describe, expect, it } from 'vitest'

import { httpsRequest } from './https-request'
import { TLS_CERT, TLS_KEY } from './loopback-tls.fixture'

const servers: https.Server[] = []
let savedSwitch: string | undefined

afterEach(async () => {
  if (savedSwitch === undefined) {
    delete process.env['NODE_TLS_REJECT_UNAUTHORIZED']
  } else {
    process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = savedSwitch
  }
  savedSwitch = undefined
  await Promise.all(
    servers
      .splice(0)
      .map((server) => new Promise<void>((resolve) => server.close(() => resolve()))),
  )
})

/** A loopback HTTPS server presenting the untrusted self-signed certificate. */
async function untrustedServer(): Promise<URL> {
  const server = https.createServer({ cert: TLS_CERT, key: TLS_KEY }, (_req, res) => {
    res.statusCode = 200
    res.end('{"ok":true}')
  })
  servers.push(server)
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  return new URL(`https://127.0.0.1:${(server.address() as AddressInfo).port}/x`)
}

function disableVerificationProcessWide(): void {
  savedSwitch = process.env['NODE_TLS_REJECT_UNAUTHORIZED']
  process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0'
}

describe('httpsRequest: certificate verification', () => {
  it('refuses an untrusted certificate by default', async () => {
    const url = await untrustedServer()
    await expect(httpsRequest({ method: 'GET', url })).rejects.toThrow(/self.signed|certificate/i)
  })

  it('still refuses it when NODE_TLS_REJECT_UNAUTHORIZED=0 is set process-wide', async () => {
    const url = await untrustedServer()
    disableVerificationProcessWide()
    await expect(httpsRequest({ method: 'GET', url })).rejects.toThrow(/self.signed|certificate/i)
  })

  it('honours an explicit opt-out, which is how a private CA is reached', async () => {
    const url = await untrustedServer()
    const response = await httpsRequest({ method: 'GET', url, rejectUnauthorized: false })
    expect(response.status).toBe(200)
  })
})
