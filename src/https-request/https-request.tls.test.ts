/**
 * Certificate verification is the client's decision, written into every
 * request -- not Node's process-wide fallback.
 *
 * An `https.request` that OMITS `rejectUnauthorized` inherits
 * `NODE_TLS_REJECT_UNAUTHORIZED`, so on an agent where that is `0` (set
 * machine-wide, or by an unrelated job in the same process) every request this
 * transport makes would silently stop verifying the server -- including the
 * ones carrying an OAuth secret, a bearer token or a Basic password
 * (azure-pipelines-terraform#1106 finding 4).
 *
 * The two ends are asserted behaviourally, against a real loopback server
 * presenting an untrusted certificate; the middle by inspecting the options
 * handed to `https.request`. Node consults the process switch only when the key
 * is absent, so its presence is the property -- and asserting it this way does
 * not require turning verification off inside the test runner's own process.
 */
import * as https from 'node:https'
import { type AddressInfo } from 'node:net'
import { afterEach, describe, expect, it } from 'vitest'

import { httpsRequest } from './https-request'
import { TLS_CERT, TLS_KEY } from './loopback-tls.fixture'

const servers: https.Server[] = []

afterEach(async () => {
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

/**
 * An agent that records the options it is asked to connect with.
 *
 * Node merges the request options into the ones it hands the agent, so this
 * sees `rejectUnauthorized` exactly as the TLS layer will. It is the half of
 * the property a test can ask about without turning verification off inside the
 * runner's own process, where it would stay off for whatever runs next: Node
 * consults `NODE_TLS_REJECT_UNAUTHORIZED` only when the key is ABSENT, so the
 * key being present and `true` is what makes the switch irrelevant.
 */
class RecordingAgent extends https.Agent {
  readonly seen: https.AgentOptions[] = []

  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- Node types createConnection loosely
  override createConnection(options: any, callback: any): any {
    this.seen.push(options as https.AgentOptions)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return (https.Agent.prototype as any).createConnection.call(this, options, callback)
  }
}

describe('httpsRequest: certificate verification', () => {
  it('refuses an untrusted certificate by default', async () => {
    const url = await untrustedServer()
    await expect(httpsRequest({ method: 'GET', url })).rejects.toThrow(/self.signed|certificate/i)
  })

  it('writes the decision into the request rather than leaving it to the process switch', async () => {
    const url = await untrustedServer()
    const agent = new RecordingAgent()
    await expect(httpsRequest({ method: 'GET', url, agent })).rejects.toThrow(
      /self.signed|certificate/i,
    )
    // Present, not merely truthy: an absent key is what makes Node consult
    // NODE_TLS_REJECT_UNAUTHORIZED, so its presence IS the fix.
    expect(Object.hasOwn(agent.seen[0] ?? {}, 'rejectUnauthorized')).toBe(true)
    expect(agent.seen[0]?.rejectUnauthorized).toBe(true)
  })

  it('honours an explicit opt-out, which is how a private CA is reached', async () => {
    const url = await untrustedServer()
    const agent = new RecordingAgent()
    const response = await httpsRequest({ method: 'GET', url, rejectUnauthorized: false, agent })
    expect(response.status).toBe(200)
    expect(agent.seen[0]?.rejectUnauthorized).toBe(false)
  })
})
