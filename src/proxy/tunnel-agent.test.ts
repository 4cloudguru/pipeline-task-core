/**
 * The CONNECT half of the tunnel, end to end against a real proxy socket.
 *
 * Deliberately stops short of the TLS upgrade: completing the inner handshake
 * would need a certificate, and every property worth pinning here — that a
 * tunnel is opened at all, to the right target, carrying the right
 * `Proxy-Authorization`, and bounded by its own deadline — is decided before
 * TLS starts. The consumers' suites carry the full tunnel-plus-TLS round trip
 * against their own loopback certificates.
 */
import * as http from 'node:http'
import * as https from 'node:https'
import { type AddressInfo, type Socket } from 'node:net'
import { afterEach, describe, expect, it } from 'vitest'

import { createProxyTunnelAgent } from './tunnel-agent'

interface SeenConnect {
  target: string
  proxyAuthorization: string | undefined
}

const servers: http.Server[] = []
/**
 * Every socket a test proxy accepted. `server.close()` waits for each open
 * connection to end, and a connection a test wedges ON PURPOSE never does — so
 * they are torn down explicitly rather than hanging the teardown hook.
 */
const openSockets: Socket[] = []

afterEach(async () => {
  for (const socket of openSockets.splice(0)) socket.destroy()
  await Promise.all(
    servers
      .splice(0)
      .map((server) => new Promise<void>((resolve) => server.close(() => resolve()))),
  )
})

async function listen(server: http.Server): Promise<number> {
  servers.push(server)
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  return (server.address() as AddressInfo).port
}

/** A proxy that records the CONNECT it saw and then answers with `status`. */
function recordingProxy(status: number): { server: http.Server; seen: SeenConnect[] } {
  const seen: SeenConnect[] = []
  const server = http.createServer()
  server.on('connect', (req, clientSocket: Socket) => {
    openSockets.push(clientSocket)
    seen.push({
      target: req.url ?? '',
      proxyAuthorization: req.headers['proxy-authorization'],
    })
    clientSocket.on('error', () => undefined)
    clientSocket.end(`HTTP/1.1 ${status} Refused\r\n\r\n`)
  })
  return { server, seen }
}

/**
 * A proxy that ESTABLISHES the tunnel and then speaks something that is not
 * TLS, so the inner handshake fails. Reaches the half of createConnection past
 * the CONNECT response — the SNI decision and the TLS error path — without
 * needing a certificate.
 */
function garbageTunnelProxy(): http.Server {
  const server = http.createServer()
  server.on('connect', (_req, clientSocket: Socket) => {
    openSockets.push(clientSocket)
    clientSocket.on('error', () => undefined)
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
    clientSocket.end('definitely not a ServerHello')
  })
  return server
}

/** A wedged proxy: accepts the socket, never answers the CONNECT. */
function hangingProxy(): http.Server {
  const server = http.createServer()
  server.on('connect', (_req, clientSocket: Socket) => {
    openSockets.push(clientSocket)
    clientSocket.on('error', () => undefined)
  })
  return server
}

/** Issues a request through `agent` and resolves with however it failed. */
function requestThrough(agent: https.Agent): Promise<Error> {
  return new Promise<Error>((resolve, reject) => {
    const req = https.request(
      { hostname: 'registry.example.com', port: 443, path: '/v1/modules', agent },
      () => reject(new Error('the request unexpectedly succeeded')),
    )
    req.on('error', resolve)
    req.end()
  })
}

describe('createProxyTunnelAgent', () => {
  const ignoreSecret = (): void => undefined

  it('returns undefined when no proxy is configured, so a caller can pass it straight through', () => {
    for (const config of [undefined, null, { proxyUrl: '' }]) {
      expect(
        createProxyTunnelAgent(config, { tunnelTimeoutMs: 1_000, registerSecret: ignoreSecret }),
      ).toBeUndefined()
    }
  })

  it('throws on an unparseable proxy URL rather than silently going direct', () => {
    // Going direct is the failure that puts a credential outside the egress
    // chokepoint the operator configured, so this must never degrade quietly.
    expect(() =>
      createProxyTunnelAgent(
        { proxyUrl: 'not a url' },
        {
          tunnelTimeoutMs: 1_000,
          registerSecret: ignoreSecret,
        },
      ),
    ).toThrow(/Invalid proxy URL configured on the agent/)
  })

  it('opens a CONNECT tunnel to the target host and port', async () => {
    const { server, seen } = recordingProxy(502)
    const port = await listen(server)

    const agent = createProxyTunnelAgent(
      { proxyUrl: `http://127.0.0.1:${port}` },
      {
        tunnelTimeoutMs: 2_000,
        registerSecret: ignoreSecret,
      },
    )
    const error = await requestThrough(agent!)

    expect(seen).toEqual([{ target: 'registry.example.com:443', proxyAuthorization: undefined }])
    expect(error.message).toBe('Proxy CONNECT to registry.example.com:443 failed with status 502.')
  })

  describe('credentials', () => {
    it('sends a Basic Proxy-Authorization derived from the configured username', async () => {
      const { server, seen } = recordingProxy(407)
      const port = await listen(server)
      const secrets: string[] = []

      const agent = createProxyTunnelAgent(
        {
          proxyUrl: `http://127.0.0.1:${port}`,
          proxyUsername: 'proxyuser',
          proxyPassword: 'p@ss',
        },
        { tunnelTimeoutMs: 2_000, registerSecret: (secret) => secrets.push(secret) },
      )
      await requestThrough(agent!)

      const encoded = Buffer.from('proxyuser:p@ss').toString('base64')
      expect(seen[0]?.proxyAuthorization).toBe(`Basic ${encoded}`)
      // A masker matches registered literals, never derivations of them, so the
      // base64 form has to be registered separately from the password itself.
      expect(secrets).toContain('p@ss')
      expect(secrets).toContain(encoded)
    })

    it('registers every secret BEFORE the agent that would send it exists', () => {
      // Ordering is the whole guarantee: a literal registered after the request
      // went out is a literal that was already logged in the clear.
      const secrets: string[] = []
      const agent = createProxyTunnelAgent(
        { proxyUrl: 'http://proxy.internal:8080', proxyUsername: 'u', proxyPassword: 'pw' },
        { tunnelTimeoutMs: 1_000, registerSecret: (secret) => secrets.push(secret) },
      )
      expect(agent).toBeDefined()
      expect(secrets).toEqual(['pw', Buffer.from('u:pw').toString('base64')])
    })

    it('masks a credential embedded in the proxy URL, without turning it into a header', async () => {
      const { server, seen } = recordingProxy(502)
      const port = await listen(server)
      const secrets: string[] = []

      const agent = createProxyTunnelAgent(
        { proxyUrl: `http://user:p%40ss@127.0.0.1:${port}` },
        { tunnelTimeoutMs: 2_000, registerSecret: (secret) => secrets.push(secret) },
      )
      await requestThrough(agent!)

      // Masked in both the raw and percent-decoded spellings...
      expect(secrets).toContain('p%40ss')
      expect(secrets).toContain('p@ss')
      // ...but NOT promoted into a Proxy-Authorization. No call site this was
      // taken from ever sent one for this configuration, and starting to would
      // put a credential on the wire that has never been on it.
      expect(seen[0]?.proxyAuthorization).toBeUndefined()
    })

    it('sends no Proxy-Authorization and registers nothing when no credential is configured', async () => {
      const { server, seen } = recordingProxy(502)
      const port = await listen(server)
      const secrets: string[] = []

      const agent = createProxyTunnelAgent(
        { proxyUrl: `http://127.0.0.1:${port}` },
        {
          tunnelTimeoutMs: 2_000,
          registerSecret: (secret) => secrets.push(secret),
        },
      )
      await requestThrough(agent!)

      expect(seen[0]?.proxyAuthorization).toBeUndefined()
      expect(secrets).toEqual([])
    })
  })

  it('bounds a wedged CONNECT with its own deadline', async () => {
    // The outer request's req.setTimeout only arms once createConnection invokes
    // its callback, so a proxy that accepts the TCP connection and never answers
    // the CONNECT sits in a phase no other timer covers. Without this deadline
    // it hangs until the CI job's own timeout.
    const port = await listen(hangingProxy())

    const agent = createProxyTunnelAgent(
      { proxyUrl: `http://127.0.0.1:${port}` },
      {
        tunnelTimeoutMs: 150,
        registerSecret: ignoreSecret,
      },
    )
    const error = await requestThrough(agent!)

    expect(error.message).toBe(
      `Proxy CONNECT tunnel to registry.example.com:443 via 127.0.0.1:${port} timed out after 150ms.`,
    )
  })

  describe('once the tunnel is established', () => {
    it('upgrades the tunnelled socket to TLS and surfaces a handshake failure', async () => {
      // The tunnel opening is not the same as the request succeeding: what comes
      // back through it still has to be TLS. A CONNECT 200 followed by anything
      // else must fail, not be treated as a connected socket.
      const port = await listen(garbageTunnelProxy())

      const agent = createProxyTunnelAgent(
        { proxyUrl: `http://127.0.0.1:${port}` },
        { tunnelTimeoutMs: 2_000, registerSecret: ignoreSecret },
      )
      const error = await requestThrough(agent!)

      expect(error.message).not.toMatch(/Proxy CONNECT/)
      expect(error.message).toMatch(/SSL|TLS|wrong version|packet length|socket disconnected/i)
    })

    it('omits SNI for an IP-literal target, which RFC 6066 forbids carrying', async () => {
      // Node throws synchronously if asked to put an address literal in
      // servername, so getting this wrong is not a subtle degradation — it is an
      // exception from inside the agent. The assertion is that the failure is a
      // TLS one (the handshake was attempted) and not that throw.
      const port = await listen(garbageTunnelProxy())

      const agent = createProxyTunnelAgent(
        { proxyUrl: `http://127.0.0.1:${port}` },
        { tunnelTimeoutMs: 2_000, registerSecret: ignoreSecret },
      )
      const error = await new Promise<Error>((resolve, reject) => {
        const req = https.request(
          { hostname: '127.0.0.1', port: 8443, path: '/', agent: agent! },
          () => reject(new Error('the request unexpectedly succeeded')),
        )
        req.on('error', resolve)
        req.end()
      })

      expect(error.message).not.toMatch(/servername|IP address/i)
      expect(error.message).toMatch(/SSL|TLS|wrong version|packet length|socket disconnected/i)
    })
  })

  it('surfaces a proxy that cannot be reached at all', async () => {
    // Port 1 on loopback: nothing listens, so the CONNECT request itself errors
    // before any tunnel exists.
    const agent = createProxyTunnelAgent(
      { proxyUrl: 'http://127.0.0.1:1' },
      {
        tunnelTimeoutMs: 2_000,
        registerSecret: ignoreSecret,
      },
    )
    const error = await requestThrough(agent!)

    expect(error.message).toMatch(/ECONNREFUSED/)
  })

  it('defaults the proxy port from the proxy scheme', async () => {
    // No explicit port: http -> 80, https -> 443. Getting this wrong would send
    // every CONNECT to the wrong place, which fails as a connection error and
    // reads like an unreachable proxy.
    const agent = createProxyTunnelAgent(
      { proxyUrl: 'https://127.0.0.1' },
      {
        tunnelTimeoutMs: 2_000,
        registerSecret: ignoreSecret,
      },
    )
    const error = await requestThrough(agent!)
    expect(error.message).toMatch(/127\.0\.0\.1:443/)
  })
})
