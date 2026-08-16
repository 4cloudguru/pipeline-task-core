// `nock` FIRST, and deliberately so. It intercepts by reassigning `request` on
// the `node:http`/`node:https` module objects, and Vitest's ESM interop snapshots
// a builtin's namespace the first time anything imports it. Importing `node:https`
// ahead of nock in this file would freeze the UNPATCHED function into the
// namespace the module under test resolves through, and every assertion below
// would quietly start dialling the real internet. (The published CommonJS build
// re-reads the property on every call and has no such ordering, which is why the
// socket-timeout case — the one that needs `node:https` — lives in its own file.)
import nock from 'nock'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'

import { DEFAULT_REQUEST_TIMEOUT_MS, httpsRequest } from './https-request'

/**
 * `nock` is the point, not a convenience: the consumers that own this transport
 * mock their HTTP with it, and it is why the raw-`https.request` shape is a
 * contract rather than an implementation detail.
 *
 * WHAT THIS FILE DOES AND DOES NOT PROVE — measured, not assumed. `scope.isDone()`
 * is NOT by itself evidence that the transport is still raw https. nock 14 —
 * which is the version the ServiceNow task pins — intercepts `fetch` as well, so
 * a rewrite onto undici still satisfies a scope here. Mutating the body of
 * `httpsRequest` to call `fetch()` was run, and four of these cases stayed green.
 *
 * The five that went red are the ones asserting things this transport does and a
 * `fetch` port would have to re-earn: the `Content-Length` it derives, the raw
 * `IncomingHttpHeaders` it hands back, and the byte cap it enforces while
 * streaming. The load-bearing structural check is in
 * `https-request.timeout.test.ts`, which drives the request through an injected
 * `agent` — `fetch` has no such option, so that case cannot pass under a port,
 * and it did not.
 */
describe('httpsRequest — nock intercepts the transport', () => {
  beforeAll(() => {
    // Any request this file fails to intercept must fail loudly rather than
    // reach the network, or "nock stopped matching" reads as "the endpoint is
    // down".
    nock.disableNetConnect()
  })

  afterAll(() => {
    nock.cleanAll()
    nock.enableNetConnect()
  })

  afterEach(() => {
    nock.cleanAll()
  })

  it('is intercepted, so the consumers that mock with nock keep working', async () => {
    const scope = nock('https://registry.example.com').get('/v1/modules').reply(200, 'ok')

    const response = await httpsRequest({
      method: 'GET',
      url: new URL('https://registry.example.com/v1/modules'),
    })

    expect(response.status).toBe(200)
    expect(response.body).toBe('ok')
    expect(scope.isDone()).toBe(true)
  })

  it('sends the method, path, query and headers it was given', async () => {
    let seenAuthorization: string | undefined
    nock('https://instance.service-now.com')
      .patch('/api/now/table/kb_knowledge/sys_id')
      .query({ sysparm_fields: 'number,sys_id' })
      .reply(function (_uri, _body) {
        seenAuthorization = this.req.headers.authorization as string | undefined
        return [200, '{}']
      })

    const url = new URL('https://instance.service-now.com/api/now/table/kb_knowledge/sys_id')
    url.searchParams.set('sysparm_fields', 'number,sys_id')

    const response = await httpsRequest({
      method: 'PATCH',
      url,
      headers: { Authorization: 'Bearer token-value' },
      body: Buffer.from('{}', 'utf8'),
    })

    expect(response.status).toBe(200)
    expect(seenAuthorization).toBe('Bearer token-value')
  })

  it('returns the response headers, so a caller can read Retry-After itself', async () => {
    nock('https://instance.service-now.com')
      .post('/api/now/table/kb_knowledge')
      .reply(429, 'slow down', { 'retry-after': '7' })

    const response = await httpsRequest({
      method: 'POST',
      url: new URL('https://instance.service-now.com/api/now/table/kb_knowledge'),
      body: Buffer.from('{}', 'utf8'),
    })

    // A non-2xx is a result, not a rejection: the callers differ on what to do
    // with one, so the decision is theirs.
    expect(response.status).toBe(429)
    expect(response.headers['retry-after']).toBe('7')
  })

  describe('Content-Length', () => {
    it('is set from the encoded body', async () => {
      let seenLength: string | undefined
      nock('https://registry.example.com')
        .post('/v1/modules')
        .reply(function () {
          seenLength = this.req.headers['content-length'] as string | undefined
          return [201, '']
        })

      // Multi-byte on purpose: a byte length, never a character count.
      const body = Buffer.from('{"name":"café"}', 'utf8')
      await httpsRequest({
        method: 'POST',
        url: new URL('https://registry.example.com/v1/modules'),
        body,
      })

      expect(seenLength).toBe(String(body.length))
      expect(body.length).toBe(16)
    })

    it('is absent when no body is supplied, and zero for an empty one', async () => {
      const seen: (string | undefined)[] = []
      const record = function (this: {
        req: { headers: Record<string, unknown> }
      }): [number, string] {
        seen.push(this.req.headers['content-length'] as string | undefined)
        return [200, '']
      }
      nock('https://registry.example.com').get('/none').reply(record)
      nock('https://registry.example.com').post('/empty').reply(record)

      await httpsRequest({ method: 'GET', url: new URL('https://registry.example.com/none') })
      await httpsRequest({
        method: 'POST',
        url: new URL('https://registry.example.com/empty'),
        body: Buffer.alloc(0),
      })

      // An empty buffer is still a body: `Content-Length: 0` is a different
      // request from one with no entity at all, and a caller that encoded an
      // empty JSON payload meant the former.
      expect(seen).toEqual([undefined, '0'])
    })
  })

  it('refuses to send a credential over a non-HTTPS URL, before any socket is opened', async () => {
    const scope = nock('http://registry.example.com').post('/v1/modules').reply(200, 'ok')

    await expect(
      httpsRequest({
        method: 'POST',
        url: new URL('http://registry.example.com/v1/modules'),
        headers: { Authorization: 'Bearer token-value' },
        body: Buffer.from('{}', 'utf8'),
      }),
    ).rejects.toThrow(
      "Refusing to send credentials over a non-HTTPS URL (scheme 'http://' on host 'registry.example.com'). Use an https:// URL.",
    )

    // The refusal is not "the request failed": nothing was ever dispatched.
    expect(scope.isDone()).toBe(false)
  })

  it('rejects a response that exceeds the byte cap rather than buffering it', async () => {
    nock('https://registry.example.com').get('/big').reply(200, 'x'.repeat(4096))

    await expect(
      httpsRequest({
        method: 'GET',
        url: new URL('https://registry.example.com/big'),
        maxResponseBytes: 64,
      }),
    ).rejects.toThrow('Response from registry.example.com exceeded 64 bytes.')
  })

  it('surfaces a transport failure', async () => {
    nock('https://registry.example.com').get('/boom').replyWithError(new Error('socket hang up'))

    await expect(
      httpsRequest({ method: 'GET', url: new URL('https://registry.example.com/boom') }),
    ).rejects.toThrow('socket hang up')
  })

  it('defaults the socket timeout to DEFAULT_REQUEST_TIMEOUT_MS', () => {
    // Asserted as a constant rather than by waiting 100 seconds. The behaviour
    // that the timeout FIRES is covered in https-request.timeout.test.ts.
    expect(DEFAULT_REQUEST_TIMEOUT_MS).toBe(100_000)
  })
})
