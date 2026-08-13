/**
 * SCOPE — what a green run here does and does not claim.
 *
 * DOES claim: the scheme pin holds on the initial URL and on every redirect
 * hop; the hop budget is enforced; a hop is authorized against the ORIGINAL
 * host rather than the previous hop; the GitHub asset exception is narrow in
 * both directions (origin and target); EVERY buffering accessor enforces the
 * byte cap, including `fetchStatusText`; retry classification distinguishes
 * deterministic from transient, and an egress refusal is never repeated; a
 * failed download leaves no partial file.
 *
 * Does NOT claim: that the redirect policy survives DNS rebinding — the host
 * is authorized at check time and is not pinned into the socket, so a name
 * that resolves differently between the check and the connection defeats it.
 * Nor that TLS is verified: certificate validation is Node's, exercised
 * nowhere here because every test injects `fetchImpl`. Nor that the streamed
 * download path is byte-capped — only buffered reads are, by design, since a
 * release archive legitimately exceeds MAX_RESPONSE_BYTES. Nor that a CALLER's
 * own `consume` passed to `fetchWithTimeout` is capped: that callback owns the
 * body and can buffer it unbounded, which is precisely why `fetchStatusText`
 * exists — a caller wanting status-plus-body must not have to hand-roll one.
 * Nor that the timeout is pre-emptive: it aborts a signal, so it bounds the
 * connection and a fetch body stream, but not consume work that ignores it.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import * as httpModule from './http'
import {
  DOWNLOAD_TIMEOUT_MS,
  HttpError,
  MAX_REDIRECTS,
  MAX_RESPONSE_BYTES,
  METADATA_TIMEOUT_MS,
  anyRedirectPolicy,
  createHttpClient,
  githubAssetRedirects,
  isRetryableHttpStatus,
  retryAfterMsFromResponse,
  sameHostOnly,
  type RedirectPolicy,
} from './http'

/** A fetch that replays a fixed script and records what it was asked for. */
function scriptedFetch(script: readonly (() => Response)[]): {
  fetchImpl: typeof fetch
  calls: string[]
} {
  const calls: string[] = []
  let index = 0
  const fetchImpl = (async (input: string | URL) => {
    calls.push(String(input))
    const step = script[Math.min(index, script.length - 1)]
    index += 1
    if (!step) throw new Error('scripted fetch exhausted')
    return step()
  }) as unknown as typeof fetch
  return { fetchImpl, calls }
}

const ok = (body: string, status = 200, headers: Record<string, string> = {}) =>
  new Response(body, { status, headers })
const redirect = (location: string) => new Response(null, { status: 302, headers: { location } })
const status = (code: number, headers: Record<string, string> = {}) =>
  new Response(code === 204 ? null : 'x', { status: code, headers })

const FAST = { attempts: 3, baseDelayMs: 0 } as const

describe('http — scheme pinning', () => {
  it.each([
    ['http://example.com/a', 'plaintext'],
    ['ftp://example.com/a', 'non-http scheme'],
    ['file:///etc/passwd', 'local file scheme'],
    ['HTTPS://example.com/a', 'uppercase scheme is not accepted as https'],
    ['//example.com/a', 'scheme-relative'],
  ])('refuses %s (%s)', async (url) => {
    const { fetchImpl, calls } = scriptedFetch([() => ok('never')])
    const client = createHttpClient({ fetchImpl, ...FAST })
    await expect(client.fetchText(url)).rejects.toThrow(/only https/i)
    expect(calls, 'refusal must precede any network call').toEqual([])
  })

  it('classifies a scheme refusal as deterministic, so it is not retried', async () => {
    const { fetchImpl } = scriptedFetch([() => ok('never')])
    const client = createHttpClient({ fetchImpl, ...FAST })
    const error = await client.fetchText('http://example.com').catch((e: unknown) => e)
    expect(error).toBeInstanceOf(HttpError)
    expect((error as HttpError).retryable).toBe(false)
  })
})

describe('http — redirect handling', () => {
  it('follows exactly MAX_REDIRECTS hops', async () => {
    const script = [
      ...Array.from(
        { length: MAX_REDIRECTS },
        (_, i) => () => redirect(`https://a.example/${i + 1}`),
      ),
      () => ok('arrived'),
    ]
    const { fetchImpl } = scriptedFetch(script)
    const client = createHttpClient({ fetchImpl, ...FAST })
    await expect(client.fetchText('https://a.example/0')).resolves.toBe('arrived')
  })

  it('refuses the hop one past the budget, even though it would have succeeded', async () => {
    // The chain ENDS in a success. A budget loosened by one would reach it, so
    // this pins the boundary rather than just "an endless chain eventually stops".
    const script = [
      ...Array.from(
        { length: MAX_REDIRECTS + 1 },
        (_, i) => () => redirect(`https://a.example/${i + 1}`),
      ),
      () => ok('should never be reached'),
    ]
    const { fetchImpl } = scriptedFetch(script)
    const client = createHttpClient({ fetchImpl, ...FAST })
    await expect(client.fetchText('https://a.example/0')).rejects.toThrow(/too many redirects/i)
  })

  it('re-checks the scheme on each hop, refusing an https -> http downgrade', async () => {
    const { fetchImpl } = scriptedFetch([() => redirect('http://a.example/plain')])
    const client = createHttpClient({ fetchImpl, ...FAST })
    await expect(client.fetchText('https://a.example/start')).rejects.toThrow(/only https/i)
  })

  it('refuses an off-host hop under the default policy', async () => {
    const { fetchImpl } = scriptedFetch([() => redirect('https://elsewhere.example/x')])
    const client = createHttpClient({ fetchImpl, ...FAST })
    await expect(client.fetchText('https://a.example/start')).rejects.toThrow(/off-host redirect/i)
  })

  it('authorizes each hop against the ORIGINAL host, not the previous hop', async () => {
    // Chain across three hosts with an allow-all policy, so BOTH hops are
    // observed. A same-host chain cannot distinguish the two anchorings.
    const seen: string[] = []
    const recordAll: RedirectPolicy = (originHost, next) => {
      seen.push(`${originHost}->${next.host}`)
      return true
    }
    const { fetchImpl } = scriptedFetch([
      () => redirect('https://cdn.example/two'),
      () => redirect('https://third.example/three'),
      () => ok('arrived'),
    ])
    const client = createHttpClient({ fetchImpl, redirectPolicy: recordAll, ...FAST })
    await expect(client.fetchText('https://a.example/one')).resolves.toBe('arrived')
    expect(seen, 'hop 2 anchored on cdn.example would let a chain walk anywhere').toEqual([
      'a.example->cdn.example',
      'a.example->third.example',
    ])
  })

  it('treats a 3xx without a Location header as the final response', async () => {
    const { fetchImpl, calls } = scriptedFetch([() => new Response('body', { status: 302 })])
    const client = createHttpClient({ fetchImpl, ...FAST })
    await expect(client.fetchText('https://a.example/x')).rejects.toThrow(/HTTP 302/)
    expect(calls).toHaveLength(1)
  })

  it('resolves a relative Location against the current hop', async () => {
    const { fetchImpl, calls } = scriptedFetch([() => redirect('/moved'), () => ok('arrived')])
    const client = createHttpClient({ fetchImpl, ...FAST })
    await expect(client.fetchText('https://a.example/deep/path')).resolves.toBe('arrived')
    expect(calls[1]).toBe('https://a.example/moved')
  })
})

describe('http — sameHostOnly', () => {
  it.each([
    ['a.example', 'https://a.example/x', true, 'identical host'],
    ['a.example', 'https://A.EXAMPLE/x', true, 'host comparison is case-insensitive via URL'],
    ['a.example', 'https://b.example/x', false, 'different host'],
    ['a.example', 'https://sub.a.example/x', false, 'subdomain is a different host'],
    ['a.example:8443', 'https://a.example/x', false, 'port is part of the host'],
    ['a.example', 'https://a.example.evil.test/x', false, 'suffix-extension host'],
  ])('%s -> %s = %s (%s)', (origin, next, expected) => {
    expect(sameHostOnly(origin, new URL(next))).toBe(expected)
  })
})

describe('http — githubAssetRedirects (opt-in)', () => {
  it.each([
    ['github.com', 'https://objects.githubusercontent.com/a', true, 'the real asset CDN'],
    ['github.com', 'https://release-assets.githubusercontent.com/a', true, 'a rotated CDN label'],
    ['www.github.com', 'https://objects.githubusercontent.com/a', true, 'www origin'],
    ['github.com', 'http://objects.githubusercontent.com/a', false, 'no protocol downgrade'],
    ['evil.test', 'https://objects.githubusercontent.com/a', false, 'origin must be github.com'],
    [
      'github.com.evil.test',
      'https://objects.githubusercontent.com/a',
      false,
      'origin suffix-extension',
    ],
    ['github.com', 'https://githubusercontent.com.evil.test/a', false, 'target suffix-extension'],
    ['github.com', 'https://evilgithubusercontent.com/a', false, 'target needs the separating dot'],
    ['github.com', 'https://elsewhere.test/a', false, 'unrelated target'],
  ])('%s -> %s = %s (%s)', (origin, next, expected) => {
    expect(githubAssetRedirects(origin, new URL(next))).toBe(expected)
  })

  it('is NOT enabled by default — a client must opt in', async () => {
    const { fetchImpl } = scriptedFetch([() => redirect('https://objects.githubusercontent.com/a')])
    const strict = createHttpClient({ fetchImpl, ...FAST })
    await expect(strict.fetchText('https://github.com/o/r/releases/download/v1/f')).rejects.toThrow(
      /off-host/i,
    )
  })

  it('permits the GitHub hop once composed in', async () => {
    const { fetchImpl } = scriptedFetch([
      () => redirect('https://objects.githubusercontent.com/a'),
      () => ok('SHA256SUMS'),
    ])
    const client = createHttpClient({
      fetchImpl,
      redirectPolicy: anyRedirectPolicy(sameHostOnly, githubAssetRedirects),
      ...FAST,
    })
    await expect(client.fetchText('https://github.com/o/r/releases/download/v1/f')).resolves.toBe(
      'SHA256SUMS',
    )
  })
})

describe('http — anyRedirectPolicy', () => {
  const yes: RedirectPolicy = () => true
  const no: RedirectPolicy = () => false
  const asyncYes: RedirectPolicy = async () => true

  it.each([
    [[], false, 'no policies denies everything'],
    [[no], false, 'single deny'],
    [[yes], true, 'single allow'],
    [[no, yes], true, 'later allow wins'],
    [[no, no], false, 'all deny'],
    [[no, asyncYes], true, 'async policies are awaited'],
  ])('%#: %s (%s)', async (policies, expected) => {
    expect(
      await anyRedirectPolicy(...(policies as RedirectPolicy[]))(
        'a.example',
        new URL('https://b.example'),
      ),
    ).toBe(expected)
  })
})

describe('http — status classification', () => {
  it.each([
    [200, false],
    [400, false],
    [401, false],
    [404, false],
    [429, true],
    [499, false],
    [500, true],
    [502, true],
    [503, true],
  ])('HTTP %i retryable = %s', (code, expected) => {
    expect(isRetryableHttpStatus(code)).toBe(expected)
  })

  it.each([
    [429, { 'retry-after': '5' }, 5_000, 'delta-seconds honoured'],
    [429, { 'retry-after': '99999' }, 30_000, 'capped, so a hostile server cannot stall the job'],
    [429, { 'retry-after': 'garbage' }, undefined, 'unparseable falls back to backoff'],
    [429, {}, undefined, 'absent header falls back to backoff'],
    [503, { 'retry-after': '5' }, undefined, 'only 429 carries a Retry-After here'],
  ])('%i %j -> %s (%s)', (code, headers, expected, _why) => {
    expect(retryAfterMsFromResponse(status(code, headers as Record<string, string>))).toBe(expected)
  })
})

describe('http — retry behaviour', () => {
  it('repeats a 5xx and returns the eventual success', async () => {
    let n = 0
    const fetchImpl = (async () => {
      n += 1
      return n < 3 ? status(503) : ok('recovered')
    }) as unknown as typeof fetch
    const client = createHttpClient({ fetchImpl, ...FAST })
    await expect(client.fetchText('https://a.example/x')).resolves.toBe('recovered')
    expect(n).toBe(3)
  })

  it('repeats a 429 whose Retry-After is satisfiable immediately', async () => {
    let n = 0
    const fetchImpl = (async () => {
      n += 1
      return n < 2 ? status(429, { 'retry-after': '0' }) : ok('recovered')
    }) as unknown as typeof fetch
    const client = createHttpClient({ fetchImpl, ...FAST })
    await expect(client.fetchText('https://a.example/x')).resolves.toBe('recovered')
    expect(n).toBe(2)
  })

  it('does NOT repeat a 4xx', async () => {
    let n = 0
    const fetchImpl = (async () => {
      n += 1
      return status(403)
    }) as unknown as typeof fetch
    const client = createHttpClient({ fetchImpl, ...FAST })
    await expect(client.fetchText('https://a.example/x')).rejects.toThrow(/HTTP 403/)
    expect(n).toBe(1)
  })

  it('repeats a transport failure, which carries no status to classify', async () => {
    let n = 0
    const fetchImpl = (async () => {
      n += 1
      if (n < 3) throw new TypeError('fetch failed')
      return ok('recovered')
    }) as unknown as typeof fetch
    const client = createHttpClient({ fetchImpl, ...FAST })
    await expect(client.fetchText('https://a.example/x')).resolves.toBe('recovered')
    expect(n).toBe(3)
  })

  it('stops at the configured attempt count', async () => {
    let n = 0
    const fetchImpl = (async () => {
      n += 1
      return status(500)
    }) as unknown as typeof fetch
    const client = createHttpClient({ fetchImpl, attempts: 2, baseDelayMs: 0 })
    await expect(client.fetchText('https://a.example/x')).rejects.toThrow(/HTTP 500/)
    expect(n).toBe(2)
  })

  it('re-evaluates fetchOptions per attempt, so a rotated proxy is picked up', async () => {
    const seen: string[] = []
    let n = 0
    const fetchImpl = (async (_u: unknown, init: RequestInit & { tag?: string }) => {
      seen.push(String(init.tag))
      n += 1
      return n < 2 ? status(500) : ok('ok')
    }) as unknown as typeof fetch
    const client = createHttpClient({
      fetchImpl,
      fetchOptions: () => ({ tag: `call-${seen.length}` }) as RequestInit,
      ...FAST,
    })
    await client.fetchText('https://a.example/x')
    expect(seen).toEqual(['call-0', 'call-1'])
  })
})

/**
 * The cap is a property of the CLIENT, not of one convenience method. Every
 * accessor that buffers a body into memory has to honour it, or a caller who
 * picks the wrong one silently opts out of the control. `fetchStatusText`
 * exists because the two GitHub Actions in this family each hand-rolled
 * `fetchWithTimeout(url, t, async (r) => ({ status: r.status, body: await
 * r.text() }))` to get a status alongside a body, and that `consume` never
 * reaches `readBounded`. Table-driven over the accessors so a newly added one
 * that forgets the cap fails here.
 */
describe('http — the byte cap applies to every buffering accessor', () => {
  const OVERSIZE = 'x'.repeat(2048)
  it.each([
    ['fetchText', (c: ReturnType<typeof createHttpClient>) => c.fetchText('https://a.example/x')],
    ['fetchJson', (c: ReturnType<typeof createHttpClient>) => c.fetchJson('https://a.example/x')],
    [
      'fetchBuffer',
      (c: ReturnType<typeof createHttpClient>) => c.fetchBuffer('https://a.example/x'),
    ],
    [
      'fetchTextAllow404',
      (c: ReturnType<typeof createHttpClient>) => c.fetchTextAllow404('https://a.example/x'),
    ],
    [
      'fetchBufferAllow404',
      (c: ReturnType<typeof createHttpClient>) => c.fetchBufferAllow404('https://a.example/x'),
    ],
    [
      'fetchStatusText',
      (c: ReturnType<typeof createHttpClient>) => c.fetchStatusText('https://a.example/x'),
    ],
  ])('%s refuses a body over the cap', async (_name, call) => {
    const { fetchImpl } = scriptedFetch([() => ok(OVERSIZE)])
    const client = createHttpClient({ fetchImpl, maxResponseBytes: 1024, ...FAST })
    await expect(call(client)).rejects.toThrow(/exceeded 1024 bytes/)
  })
})

describe('http — fetchStatusText', () => {
  /**
   * The reason the hand-rolled `consume` existed: these callers need the status
   * as a VALUE (they poll on it, or format their own message from it), so an
   * accessor that throws on non-2xx does not serve them.
   */
  it.each([
    [200, 'ok-body'],
    [404, 'missing'],
    [409, 'conflict'],
    [500, 'server error'],
  ])('returns status %i and its body instead of throwing', async (code, body) => {
    const { fetchImpl } = scriptedFetch([() => ok(body, code)])
    const client = createHttpClient({ fetchImpl, ...FAST })
    await expect(client.fetchStatusText('https://a.example/x')).resolves.toEqual({
      status: code,
      body,
    })
  })

  it('accepts a body exactly at the cap', async () => {
    const { fetchImpl } = scriptedFetch([() => ok('x'.repeat(64), 503)])
    const client = createHttpClient({ fetchImpl, maxResponseBytes: 64, ...FAST })
    await expect(client.fetchStatusText('https://a.example/x')).resolves.toEqual({
      status: 503,
      body: 'x'.repeat(64),
    })
  })

  it('classifies an oversize body as deterministic, not transient', async () => {
    const { fetchImpl } = scriptedFetch([() => ok('x'.repeat(100))])
    const client = createHttpClient({ fetchImpl, maxResponseBytes: 10, ...FAST })
    const error = await client.fetchStatusText('https://a.example/x').catch((e: unknown) => e)
    expect((error as HttpError).retryable).toBe(false)
  })

  it('does not repeat a 5xx — the status is a result, not a failure', async () => {
    const { fetchImpl, calls } = scriptedFetch([() => ok('down', 500)])
    const client = createHttpClient({ fetchImpl, ...FAST })
    await expect(client.fetchStatusText('https://a.example/x')).resolves.toEqual({
      status: 500,
      body: 'down',
    })
    expect(calls).toHaveLength(1)
  })

  it('still repeats a transport failure', async () => {
    let n = 0
    const fetchImpl = (async () => {
      n += 1
      if (n < 2) throw new Error('ECONNRESET')
      return ok('recovered', 200)
    }) as unknown as typeof fetch
    const client = createHttpClient({ fetchImpl, ...FAST })
    await expect(client.fetchStatusText('https://a.example/x')).resolves.toEqual({
      status: 200,
      body: 'recovered',
    })
    expect(n).toBe(2)
  })

  it('keeps the scheme pin', async () => {
    const { fetchImpl } = scriptedFetch([() => ok('never')])
    const client = createHttpClient({ fetchImpl, ...FAST })
    await expect(client.fetchStatusText('http://a.example/x')).rejects.toThrow(/only https/i)
  })
})

describe('http — bounded bodies', () => {
  it('refuses a body over the cap', async () => {
    const big = 'x'.repeat(2048)
    const { fetchImpl } = scriptedFetch([() => ok(big)])
    const client = createHttpClient({ fetchImpl, maxResponseBytes: 1024, ...FAST })
    await expect(client.fetchText('https://a.example/x')).rejects.toThrow(/exceeded 1024 bytes/)
  })

  it('classifies an oversize body as deterministic, not transient', async () => {
    const { fetchImpl } = scriptedFetch([() => ok('x'.repeat(100))])
    const client = createHttpClient({ fetchImpl, maxResponseBytes: 10, ...FAST })
    const error = await client.fetchText('https://a.example/x').catch((e: unknown) => e)
    expect((error as HttpError).retryable).toBe(false)
  })

  it('accepts a body exactly at the cap', async () => {
    const { fetchImpl } = scriptedFetch([() => ok('x'.repeat(64))])
    const client = createHttpClient({ fetchImpl, maxResponseBytes: 64, ...FAST })
    await expect(client.fetchText('https://a.example/x')).resolves.toHaveLength(64)
  })

  it('reassembles a multi-chunk body in order', async () => {
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('alpha-'))
        controller.enqueue(new TextEncoder().encode('beta-'))
        controller.enqueue(new TextEncoder().encode('gamma'))
        controller.close()
      },
    })
    const fetchImpl = (async () => new Response(body)) as unknown as typeof fetch
    const client = createHttpClient({ fetchImpl, ...FAST })
    await expect(client.fetchText('https://a.example/x')).resolves.toBe('alpha-beta-gamma')
  })
})

describe('http — fetchJson', () => {
  it('parses a JSON body', async () => {
    const { fetchImpl } = scriptedFetch([() => ok('{"version":"1.2.3"}')])
    const client = createHttpClient({ fetchImpl, ...FAST })
    await expect(client.fetchJson('https://a.example/x')).resolves.toEqual({ version: '1.2.3' })
  })

  it('treats a 2xx non-JSON body as deterministic, not transient', async () => {
    let n = 0
    const fetchImpl = (async () => {
      n += 1
      return ok('<html>captive portal</html>')
    }) as unknown as typeof fetch
    const client = createHttpClient({ fetchImpl, ...FAST })
    const error = await client.fetchJson('https://a.example/x').catch((e: unknown) => e)
    expect((error as HttpError).retryable).toBe(false)
    expect(n, 'a SyntaxError defaulting to retryable would burn the budget').toBe(1)
  })

  it('truncates the echoed body, so a credential-bearing page is not logged whole', async () => {
    const { fetchImpl } = scriptedFetch([() => ok('N'.repeat(5000))])
    const client = createHttpClient({ fetchImpl, ...FAST })
    const error = await client.fetchJson('https://a.example/x').catch((e: unknown) => e)
    expect((error as Error).message).toContain('N'.repeat(512))
    expect((error as Error).message).not.toContain('N'.repeat(513))
  })
})

describe('http — allow404 variants', () => {
  it.each([['fetchTextAllow404' as const], ['fetchBufferAllow404' as const]])(
    '%s returns null on 404 rather than throwing',
    async (method) => {
      const { fetchImpl } = scriptedFetch([() => status(404)])
      const client = createHttpClient({ fetchImpl, ...FAST })
      await expect(client[method]('https://a.example/x')).resolves.toBeNull()
    },
  )

  it.each([['fetchTextAllow404' as const], ['fetchBufferAllow404' as const]])(
    '%s still throws on a 500',
    async (method) => {
      const { fetchImpl } = scriptedFetch([() => status(500)])
      const client = createHttpClient({ fetchImpl, ...FAST })
      await expect(client[method]('https://a.example/x')).rejects.toThrow(/HTTP 500/)
    },
  )

  it('fetchBuffer returns the bytes', async () => {
    const { fetchImpl } = scriptedFetch([() => ok('bytes')])
    const client = createHttpClient({ fetchImpl, ...FAST })
    const buf = await client.fetchBuffer('https://a.example/x')
    expect(Buffer.from(buf).toString('utf8')).toBe('bytes')
  })
})

describe('http — timeout', () => {
  it('aborts a hung request and reports it as transient', async () => {
    const fetchImpl = (async (_u: unknown, init: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init.signal?.addEventListener('abort', () => {
          reject(new Error('The operation was aborted'))
        })
      })) as unknown as typeof fetch
    const client = createHttpClient({ fetchImpl, ...FAST })
    const error = await client
      .fetchWithTimeout('https://a.example/x', 10, async (r) => r.text())
      .catch((e: unknown) => e)
    expect((error as Error).message).toMatch(/timed out after 10ms/)
    expect((error as HttpError).retryable).toBe(true)
  })

  it('bounds a stalled body, because a fetch body stream honours the signal', async () => {
    const fetchImpl = (async (_u: unknown, init: RequestInit) => {
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('first'))
          // Never closed. Real fetch wires the request signal into the body
          // stream, which is what actually makes consumption interruptible.
          init.signal?.addEventListener('abort', () => {
            controller.error(new Error('The operation was aborted'))
          })
        },
      })
      return new Response(body)
    }) as unknown as typeof fetch
    const client = createHttpClient({ fetchImpl, ...FAST })
    const error = await client
      .fetchWithTimeout('https://a.example/x', 25, async (r) => r.text())
      .catch((e: unknown) => e)
    expect((error as Error).message).toMatch(/timed out/)
  })

  it('does NOT interrupt consume work that ignores the signal', async () => {
    // The guard is lexical, not pre-emptive: it aborts the controller, and only
    // work wired to that signal notices. Caller-supplied consume work that is
    // not — a pipeline() to a stalled network share in downloadToFile — runs to
    // completion past the deadline. Pinned so the guarantee is not overstated.
    const fetchImpl = (async () => new Response('body')) as unknown as typeof fetch
    const client = createHttpClient({ fetchImpl, ...FAST })
    await expect(
      client.fetchWithTimeout('https://a.example/x', 10, async () => {
        await new Promise((r) => setTimeout(r, 60))
        return 'finished anyway'
      }),
    ).resolves.toBe('finished anyway')
  })
})

describe('http — downloadToFile', () => {
  let dir: string
  let dest: string

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'ptc-http-'))
    dest = join(dir, 'artifact.bin')
  })
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  it('streams the body to disk', async () => {
    const { fetchImpl } = scriptedFetch([() => ok('payload')])
    const client = createHttpClient({ fetchImpl, ...FAST })
    await client.downloadToFile('https://a.example/f', dest, DOWNLOAD_TIMEOUT_MS, () => undefined)
    expect(readFileSync(dest, 'utf8')).toBe('payload')
  })

  it('authorizes the initial host before any network call', async () => {
    const seen: string[] = []
    const { fetchImpl, calls } = scriptedFetch([() => ok('payload')])
    const client = createHttpClient({ fetchImpl, ...FAST })
    await client.downloadToFile('https://a.example/f', dest, 1000, (h) => {
      seen.push(h)
      if (calls.length > 0) throw new Error('authorized after the request was issued')
    })
    expect(seen).toEqual(['a.example'])
  })

  it('re-authorizes every redirect hop, carrying the port with the host', async () => {
    const seen: string[] = []
    const { fetchImpl } = scriptedFetch([
      () => redirect('https://cdn.example:8443/f'),
      () => ok('payload'),
    ])
    const client = createHttpClient({ fetchImpl, ...FAST })
    await client.downloadToFile('https://a.example/f', dest, 1000, (h) => {
      seen.push(h)
    })
    expect(seen).toEqual(['a.example', 'cdn.example:8443'])
  })

  it('refuses a hop the allowlist rejects, even when the first host passed', async () => {
    const { fetchImpl } = scriptedFetch([
      () => redirect('https://evil.test/f'),
      () => ok('payload'),
    ])
    const client = createHttpClient({ fetchImpl, ...FAST })
    await expect(
      client.downloadToFile('https://a.example/f', dest, 1000, (h) => {
        if (h !== 'a.example') throw new Error(`host ${h} is not allowlisted`)
      }),
    ).rejects.toThrow(/evil\.test is not allowlisted/)
    expect(existsSync(dest)).toBe(false)
  })

  it('does NOT repeat an authorization refusal', async () => {
    let checks = 0
    const { fetchImpl } = scriptedFetch([() => ok('payload')])
    const client = createHttpClient({ fetchImpl, ...FAST })
    await expect(
      client.downloadToFile('https://a.example/f', dest, 1000, () => {
        checks += 1
        throw new Error('refused')
      }),
    ).rejects.toThrow(/refused/)
    expect(
      checks,
      'repeating gives a host that resolves differently per lookup extra chances to flip to allowed',
    ).toBe(1)
  })

  it('clears a stale file from a prior attempt before writing', async () => {
    writeFileSync(dest, 'STALE-FROM-A-PREVIOUS-RUN')
    let n = 0
    const fetchImpl = (async () => {
      n += 1
      return n < 2 ? status(500) : ok('fresh')
    }) as unknown as typeof fetch
    const client = createHttpClient({ fetchImpl, ...FAST })
    await client.downloadToFile('https://a.example/f', dest, 1000, () => undefined)
    expect(readFileSync(dest, 'utf8')).toBe('fresh')
  })

  it('leaves no file behind when the response is an error', async () => {
    writeFileSync(dest, 'STALE')
    const { fetchImpl } = scriptedFetch([() => status(404)])
    const client = createHttpClient({ fetchImpl, ...FAST })
    await expect(
      client.downloadToFile('https://a.example/f', dest, 1000, () => undefined),
    ).rejects.toThrow(/HTTP 404/)
    expect(existsSync(dest), 'a stale file must not survive as a "successful" download').toBe(false)
  })

  it('rejects a bodyless 200 rather than writing an empty file', async () => {
    const fetchImpl = (async () => new Response(null, { status: 200 })) as unknown as typeof fetch
    const client = createHttpClient({ fetchImpl, ...FAST })
    await expect(
      client.downloadToFile('https://a.example/f', dest, 1000, () => undefined),
    ).rejects.toThrow(/empty response body/)
    expect(existsSync(dest)).toBe(false)
  })

  it('is not subject to the buffered-body cap, which a release archive would exceed', async () => {
    const oversize = 'z'.repeat(4096)
    const { fetchImpl } = scriptedFetch([() => ok(oversize)])
    const client = createHttpClient({ fetchImpl, maxResponseBytes: 16, ...FAST })
    await client.downloadToFile('https://a.example/f', dest, 1000, () => undefined)
    expect(readFileSync(dest, 'utf8')).toHaveLength(4096)
  })

  it('awaits an async authorization rather than racing it', async () => {
    let resolved = false
    const { fetchImpl, calls } = scriptedFetch([() => ok('payload')])
    const client = createHttpClient({ fetchImpl, ...FAST })
    await client.downloadToFile('https://a.example/f', dest, 1000, async () => {
      await new Promise((r) => setTimeout(r, 5))
      resolved = true
    })
    expect(resolved).toBe(true)
    expect(calls, 'the request must not have been issued before the check settled').toHaveLength(1)
  })

  it('surfaces an async authorization rejection instead of downloading anyway', async () => {
    // A stale file plus a refusal of the INITIAL host is the one path the
    // failure-cleanup cannot cover, because that check runs before the try.
    // Only the pre-attempt clear removes it.
    writeFileSync(dest, 'STALE-FROM-A-PREVIOUS-RUN')
    const { fetchImpl, calls } = scriptedFetch([() => ok('payload')])
    const client = createHttpClient({ fetchImpl, ...FAST })
    await expect(
      client.downloadToFile('https://a.example/f', dest, 1000, async () => {
        await new Promise((r) => setTimeout(r, 5))
        throw new Error('resolves to a private address')
      }),
    ).rejects.toThrow(/private address/)
    expect(calls).toEqual([])
    expect(existsSync(dest), 'a refused download must not leave readable bytes behind').toBe(false)
  })
})

describe('http — injected message text', () => {
  it('uses the caller’s strings so a task can localize and name its own inputs', async () => {
    const { fetchImpl } = scriptedFetch([() => status(500)])
    const client = createHttpClient({
      fetchImpl,
      messages: {
        requestFailed: (url, code) => `LOC_REGISTRY_FAILED|${url}|${code}`,
        insecureUrl: (url) => `LOC_INSECURE|${url}`,
      },
      ...FAST,
    })
    await expect(client.fetchText('https://a.example/x')).rejects.toThrow(
      'LOC_REGISTRY_FAILED|https://a.example/x|500',
    )
    await expect(client.fetchText('http://a.example/x')).rejects.toThrow(
      'LOC_INSECURE|http://a.example/x',
    )
  })

  it('keeps default text for any message the caller omits', async () => {
    const { fetchImpl } = scriptedFetch([() => status(500)])
    const client = createHttpClient({
      fetchImpl,
      messages: { insecureUrl: (url) => `LOC_INSECURE|${url}` },
      ...FAST,
    })
    await expect(client.fetchText('https://a.example/x')).rejects.toThrow(/failed with HTTP 500/)
  })
})

/**
 * TABLE B — export inventory, verdicted by hand.
 *
 * A drive-by `export` is how a private helper silently becomes public API. This
 * pins the surface so adding one is a deliberate, reviewed edit to this list.
 */
describe('http — public surface', () => {
  it('exports exactly the reviewed set', () => {
    expect(Object.keys(httpModule).sort()).toEqual([
      'DOWNLOAD_TIMEOUT_MS',
      'HttpError',
      'MAX_REDIRECTS',
      'MAX_RESPONSE_BYTES',
      'METADATA_TIMEOUT_MS',
      'anyRedirectPolicy',
      'createHttpClient',
      'githubAssetRedirects',
      'isRetryableHttpStatus',
      'retryAfterMsFromResponse',
      'sameHostOnly',
    ])
  })

  it('pins the timeout and cap constants callers depend on', () => {
    expect(METADATA_TIMEOUT_MS).toBe(60_000)
    expect(DOWNLOAD_TIMEOUT_MS).toBe(600_000)
    expect(MAX_REDIRECTS).toBe(5)
    expect(MAX_RESPONSE_BYTES).toBe(10 * 1024 * 1024)
  })

  it('gives the client exactly the reviewed methods', () => {
    const client = createHttpClient()
    expect(Object.keys(client).sort()).toEqual([
      'downloadToFile',
      'fetchBuffer',
      'fetchBufferAllow404',
      'fetchJson',
      'fetchStatusText',
      'fetchText',
      'fetchTextAllow404',
      'fetchWithTimeout',
    ])
  })
})
