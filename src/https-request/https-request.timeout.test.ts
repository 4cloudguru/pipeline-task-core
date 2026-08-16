/**
 * The socket timeout, against a REAL socket.
 *
 * Its own file, for two reasons that are both about not testing a fiction:
 *
 *  - nock's replacement socket does not honour `req.setTimeout`, so a delayed
 *    interceptor simply hangs. An assertion against one would prove nothing
 *    about the timer this module arms.
 *  - importing `node:https` here would, under Vitest's ESM interop, freeze the
 *    unpatched `request` into the namespace the module under test resolves
 *    through — silently disarming every nock assertion in the sibling file. See
 *    the note at the top of `https-request.test.ts`.
 */
import { Agent } from 'node:https'
import { type AddressInfo, connect, createServer, type Server, type Socket } from 'node:net'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { httpsRequest } from './https-request'

describe('httpsRequest — socket timeout', () => {
  let server: Server
  let port: number
  const accepted: Socket[] = []

  beforeAll(async () => {
    // Accepts the connection and then says nothing at all, ever.
    server = createServer((socket) => {
      accepted.push(socket)
      socket.resume()
      socket.on('error', () => undefined)
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    port = (server.address() as AddressInfo).port
  })

  afterAll(async () => {
    // close() alone waits for every accepted connection to end, and a socket
    // stalled on purpose never does.
    for (const socket of accepted) socket.destroy()
    await new Promise<void>((resolve) => server.close(() => resolve()))
  })

  it('destroys a stalled request and rejects with the configured bound', async () => {
    // `req.setTimeout` is an INACTIVITY timer, and this is the shape it exists
    // for: the connection is accepted and nothing ever comes back. Without it
    // the request runs to the CI job's own timeout, which is the only other
    // bound a stalled request has.
    //
    // The connection is supplied by an `agent` that hands back a PLAIN socket
    // rather than a TLS one — the same seam `createProxyTunnelAgent` uses, and
    // the reason this needs no certificate. It also keeps TLS out of a test
    // that is not about TLS: tearing down a half-open handshake completes its
    // pending ClientHello write with ECANCELED after the request has already
    // rejected and stopped listening, which surfaces as a process-level
    // unhandled error and says nothing about this module.
    await expect(
      httpsRequest({
        method: 'GET',
        url: new URL(`https://127.0.0.1:${port}/stalled`),
        timeoutMs: 150,
        agent: plainSocketAgent(port),
      }),
    ).rejects.toThrow(`Request to 127.0.0.1:${port} timed out after 150ms.`)
  })
})

/** An `https.Agent` that connects without TLS. Test-only; see the caller. */
function plainSocketAgent(targetPort: number): Agent {
  const agent = new Agent()
  agent.createConnection = () => connect({ host: '127.0.0.1', port: targetPort })
  return agent
}
