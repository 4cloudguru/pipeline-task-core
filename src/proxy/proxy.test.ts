/**
 * SCOPE — what a green run here does and does not claim.
 *
 * DOES claim: every representation of the proxy credential that could reach a
 * log is returned for registration — the raw password, the percent-encoded
 * form the URL setter produces, and credentials already embedded in the
 * configured proxy URL; a username is never returned as a secret; and an
 * unparseable proxy URL fails loudly rather than silently disabling the proxy.
 *
 * For `resolveEnvProxy` it ALSO claims: the proxy variable is chosen by the
 * DESTINATION's scheme; `NO_PROXY` is matched against the DESTINATION and never
 * against the proxy; the matching conventions (bare name plus subdomains,
 * leading dot, `*.` wildcard, `*`, explicit ports) hold in both directions; and
 * routing through a proxy does not move the egress-authorization decision off
 * the destination.
 *
 * Does NOT claim: that anything is actually masked. This returns strings for
 * the CALLER to register with the agent's masker, and a forgotten setSecret()
 * is invisible from here. Nor that the proxy works: no dispatcher is built and
 * no connection is made — `undici` stays a task-side dependency. Nor that the
 * default-deny arm of `assertEgressHostAllowed` still sees the truth through a
 * proxy: that arm resolves DNS on the AGENT, while a proxied connection is
 * resolved at the proxy, so the two can disagree. The allowlist arm — the one
 * an operator behind a proxy actually configures — is unaffected, and is what
 * the interaction tests below use.
 */
import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { assertEgressHostAllowed, parseAllowedHosts } from '../egress/egress'
import { createHttpClient } from '../http/http'
import * as proxyModule from './proxy'
import { resolveEnvProxy, resolveProxy } from './proxy'

describe('proxy — no proxy configured', () => {
  it.each([
    [null, 'null'],
    [undefined, 'undefined'],
    [{ proxyUrl: '' }, 'empty url'],
  ])('returns null for %j (%s)', (config, _why) => {
    expect(resolveProxy(config as never)).toBeNull()
  })
})

describe('proxy — credentials in the separate username/password variables', () => {
  it('embeds them into the URL', () => {
    const resolved = resolveProxy({
      proxyUrl: 'http://proxy.internal:8080',
      proxyUsername: 'svc',
      proxyPassword: 'plain',
    })
    expect(resolved?.proxyUrl).toBe('http://svc:plain@proxy.internal:8080/')
  })

  it('returns BOTH the raw and the percent-encoded password', () => {
    // The URL setter stores 'p%40ss'; the agent's masker matches registered
    // literals, so the raw registration does not cover the encoded form.
    const resolved = resolveProxy({
      proxyUrl: 'http://proxy.internal:8080',
      proxyUsername: 'svc',
      proxyPassword: 'p@ss',
    })
    expect(resolved?.secrets).toContain('p@ss')
    expect(resolved?.secrets).toContain('p%40ss')
    expect(resolved?.proxyUrl).toContain('p%40ss')
  })

  it.each([
    ['p@ss', 'p%40ss', 'at sign'],
    ['p:ss', 'p%3Ass', 'colon'],
    ['p/ss', 'p%2Fss', 'slash'],
    ['p ss', 'p%20ss', 'space'],
  ])('registers the encoded form of %s (%s)', (raw, encoded) => {
    const resolved = resolveProxy({
      proxyUrl: 'http://proxy.internal:8080',
      proxyUsername: 'svc',
      proxyPassword: raw,
    })
    expect(resolved?.secrets).toEqual(expect.arrayContaining([raw, encoded]))
  })

  it('does not duplicate when the password needs no encoding', () => {
    const resolved = resolveProxy({
      proxyUrl: 'http://proxy.internal:8080',
      proxyUsername: 'svc',
      proxyPassword: 'plain',
    })
    expect(resolved?.secrets.filter((s) => s === 'plain')).toHaveLength(1)
  })

  it('never registers the username, which would redact unrelated log lines', () => {
    const resolved = resolveProxy({
      proxyUrl: 'http://proxy.internal:8080',
      proxyUsername: 'admin',
      proxyPassword: 'secret',
    })
    expect(resolved?.secrets).not.toContain('admin')
  })

  it('handles a username with no password', () => {
    const resolved = resolveProxy({
      proxyUrl: 'http://proxy.internal:8080',
      proxyUsername: 'svc',
    })
    expect(resolved?.proxyUrl).toBe('http://svc@proxy.internal:8080/')
    expect(resolved?.secrets).toEqual([])
  })

  it('throws on an unparseable URL rather than silently dropping the proxy', () => {
    expect(() =>
      resolveProxy({ proxyUrl: 'not a url', proxyUsername: 'svc', proxyPassword: 'p' }),
    ).toThrow(/Invalid proxy URL configured on the agent/)
  })
})

describe('proxy — credentials already embedded in the proxy URL', () => {
  it('registers them even though no username variable is set', () => {
    // The sources only masked when proxyUsername was set, so this spelling
    // went through entirely unmasked.
    const resolved = resolveProxy({ proxyUrl: 'http://svc:s3cret@proxy.internal:8080' })
    expect(resolved?.secrets).toContain('svc:s3cret')
    expect(resolved?.secrets).toContain('s3cret')
  })

  it('passes the URL through untouched when there is nothing to embed', () => {
    const resolved = resolveProxy({ proxyUrl: 'http://svc:s3cret@proxy.internal:8080' })
    expect(resolved?.proxyUrl).toBe('http://svc:s3cret@proxy.internal:8080')
  })

  it('returns no secrets for a proxy URL with no credentials', () => {
    const resolved = resolveProxy({ proxyUrl: 'http://proxy.internal:8080' })
    expect(resolved).toEqual({ proxyUrl: 'http://proxy.internal:8080', secrets: [] })
  })

  it('covers an embedded credential that the username variable then overrides', () => {
    const resolved = resolveProxy({
      proxyUrl: 'http://old:stale@proxy.internal:8080',
      proxyUsername: 'svc',
      proxyPassword: 'fresh',
    })
    // The stale credential is gone from the URL but was still configured, so
    // it stays registered.
    expect(resolved?.proxyUrl).toBe('http://svc:fresh@proxy.internal:8080/')
    expect(resolved?.secrets).toEqual(expect.arrayContaining(['old:stale', 'stale', 'fresh']))
  })

  it('registers the decoded form of an embedded credential too', () => {
    const resolved = resolveProxy({ proxyUrl: 'http://svc:p%40ss@proxy.internal:8080' })
    expect(resolved?.secrets).toEqual(expect.arrayContaining(['p%40ss', 'p@ss']))
  })
})

describe('proxy — secret list hygiene', () => {
  it('contains no empty strings, which would mask every character of a log line', () => {
    // No filter is needed for this: every push site is already guarded by a
    // truthiness check. Pinned so a future push site cannot quietly break it.
    const resolved = resolveProxy({
      proxyUrl: 'http://proxy.internal:8080',
      proxyUsername: 'svc',
      proxyPassword: '',
    })
    expect(resolved?.secrets).not.toContain('')
  })

  it('contains no duplicates', () => {
    const resolved = resolveProxy({
      proxyUrl: 'http://svc:same@proxy.internal:8080',
      proxyUsername: 'svc',
      proxyPassword: 'same',
    })
    expect(new Set(resolved?.secrets).size).toBe(resolved?.secrets.length)
  })
})

describe('resolveEnvProxy — which variable answers for a destination', () => {
  it.each([
    ['https://registry.example.com/v1', { https_proxy: 'http://p:8080' }, 'http://p:8080'],
    ['http://registry.example.com/v1', { http_proxy: 'http://p:8080' }, 'http://p:8080'],
    [
      'https://registry.example.com/v1',
      { https_proxy: 'http://lower:8080', HTTPS_PROXY: 'http://upper:8080' },
      'http://lower:8080',
    ],
    ['https://registry.example.com/v1', { HTTPS_PROXY: 'http://upper:8080' }, 'http://upper:8080'],
    [
      'http://registry.example.com/v1',
      { http_proxy: 'http://lower:8080', HTTP_PROXY: 'http://upper:8080' },
      'http://lower:8080',
    ],
    ['https://registry.example.com/v1', { https_proxy: '  http://p:8080  ' }, 'http://p:8080'],
  ])('%s with %j -> %s', (url, env, expected) => {
    expect(resolveEnvProxy(url, env)?.proxyUrl).toBe(expected)
  })

  it.each([
    ['https://registry.example.com/v1', {}, 'nothing configured'],
    ['https://registry.example.com/v1', { https_proxy: '' }, 'empty is unset, not a proxy'],
    ['https://registry.example.com/v1', { https_proxy: '   ' }, 'whitespace is unset too'],
    [
      'https://registry.example.com/v1',
      { http_proxy: 'http://p:8080' },
      'HTTP_PROXY must not capture an https destination',
    ],
    [
      'http://registry.example.com/v1',
      { https_proxy: 'http://p:8080' },
      'nor HTTPS_PROXY an http one',
    ],
    [
      'file:///etc/hosts',
      { https_proxy: 'http://p:8080', http_proxy: 'http://p:8080' },
      'a non-http scheme has nothing to proxy',
    ],
  ])('%s with %j returns null (%s)', (url, env, _why) => {
    expect(resolveEnvProxy(url, env)).toBeNull()
  })

  it('throws on an unparseable destination rather than silently going direct', () => {
    expect(() => resolveEnvProxy('not a url', { https_proxy: 'http://p:8080' })).toThrow(
      /absolute destination URL/,
    )
  })
})

/**
 * TABLE — NO_PROXY, matched against the DESTINATION.
 *
 * The conventions are curl's and Go's: a bare name covers itself and its
 * subdomains, a leading dot covers subdomains ONLY, `*.` is accepted as the
 * spelling several tools use for the same thing, `*` disables proxying
 * outright, and an entry may pin a port. The suffix rows are the load-bearing
 * ones: a plain `endsWith` would let `notexample.com` and `example.com.evil.test`
 * match `example.com`, and matching NO_PROXY means LEAVING the proxy — the one
 * direction where an over-broad rule costs an operator their egress chokepoint.
 */
describe('resolveEnvProxy — NO_PROXY matching', () => {
  const proxied = (url: string, noProxy: string): boolean =>
    resolveEnvProxy(url, { https_proxy: 'http://p:8080', no_proxy: noProxy }) !== null

  it.each([
    ['example.com', 'https://example.com/x', false, 'exact name'],
    ['example.com', 'https://api.example.com/x', false, 'a bare name covers subdomains'],
    ['example.com', 'https://deep.api.example.com/x', false, 'at any depth'],
    ['example.com', 'https://notexample.com/x', true, 'suffix extension is NOT a subdomain'],
    ['example.com', 'https://example.com.evil.test/x', true, 'nor is a suffixed parent'],
    ['.example.com', 'https://api.example.com/x', false, 'leading dot covers subdomains'],
    ['.example.com', 'https://example.com/x', true, 'leading dot covers ONLY subdomains'],
    ['*.example.com', 'https://api.example.com/x', false, 'the wildcard spelling of the same rule'],
    ['*', 'https://anything.test/x', false, 'a lone asterisk disables proxying'],
    ['EXAMPLE.COM', 'https://example.com/x', false, 'entries are case-insensitive'],
    ['example.com', 'https://EXAMPLE.com/x', false, 'and so is the destination'],
    ['example.com', 'https://example.com./x', false, 'a trailing FQDN dot still matches'],
    ['example.com:8443', 'https://example.com:8443/x', false, 'an explicit port matches'],
    ['example.com:8443', 'https://example.com/x', true, 'a pinned port does not match another'],
    ['example.com:443', 'https://example.com/x', false, 'against the scheme default port'],
    ['a.test, example.com , b.test', 'https://example.com/x', false, 'comma list with whitespace'],
    ['a.test,,b.test', 'https://example.com/x', true, 'blank entries match nothing'],
    ['10.0.0.5', 'https://10.0.0.5/x', false, 'an IPv4 literal'],
    ['10.0.0.5', 'https://10.0.0.50/x', true, 'and not one it is a prefix of'],
    ['[::1]', 'https://[::1]/x', false, 'a bracketed IPv6 literal'],
    ['::1', 'https://[::1]/x', false, 'and the unbracketed spelling of it'],
  ])('%s vs %s -> proxied=%s (%s)', (noProxy, url, expected, _why) => {
    expect(proxied(url, noProxy)).toBe(expected)
  })

  it('prefers the lowercase spelling', () => {
    expect(
      resolveEnvProxy('https://example.com/x', {
        https_proxy: 'http://p:8080',
        no_proxy: 'other.test',
        NO_PROXY: 'example.com',
      }),
    ).not.toBeNull()
  })

  /**
   * The subject of the rule is the destination. Matched against the PROXY host
   * instead, an operator whose proxy happens to be inside a NO_PROXY domain —
   * the normal case, since the proxy is on the internal network the entries
   * describe — would silently stop proxying every request.
   */
  it('is matched against the destination, never against the proxy host', () => {
    const resolved = resolveEnvProxy('https://registry.example.com/v1', {
      https_proxy: 'http://proxy.internal:8080',
      no_proxy: 'proxy.internal',
    })
    expect(resolved?.proxyUrl).toBe('http://proxy.internal:8080')
  })
})

describe('resolveEnvProxy — credentials in the proxy URL are secrets', () => {
  it('returns every representation for the masker', () => {
    const resolved = resolveEnvProxy('https://registry.example.com/v1', {
      https_proxy: 'http://svc:p%40ss@proxy.internal:8080',
    })
    expect(resolved?.secrets).toEqual(
      expect.arrayContaining(['svc:p%40ss', 'svc:p@ss', 'p%40ss', 'p@ss']),
    )
  })

  it('never returns the username on its own', () => {
    const resolved = resolveEnvProxy('https://registry.example.com/v1', {
      https_proxy: 'http://admin:secret@proxy.internal:8080',
    })
    expect(resolved?.secrets).not.toContain('admin')
  })

  it('returns no secrets when there is no credential', () => {
    expect(
      resolveEnvProxy('https://registry.example.com/v1', { https_proxy: 'http://p:8080' }),
    ).toEqual({ proxyUrl: 'http://p:8080', secrets: [] })
  })

  it.each([
    ['http://svc:s3cret@:::not a url', 'unparseable'],
    ['socks5://svc:s3cret@proxy.internal:1080', 'an unsupported scheme'],
  ])('rejects %s (%s) without echoing the credential', (value) => {
    // The value is the one thing in this function that carries a password, and
    // a rejection message is logged. It names the VARIABLE so an operator can
    // find the misconfiguration, and nothing else.
    const call = (): unknown => resolveEnvProxy('https://a.example/x', { https_proxy: value })
    expect(call).toThrow(/https_proxy/)
    let message = ''
    try {
      call()
    } catch (error) {
      message = error instanceof Error ? error.message : String(error)
    }
    expect(message).not.toContain('s3cret')
    expect(message).not.toContain('proxy.internal')
  })
})

/**
 * The interaction the feature had to not break: a proxy changes WHICH SOCKET
 * carries the request, never WHICH DESTINATION is permitted. A CONNECT tunnel
 * to a refused host is still refused egress, so the allowlist keeps being
 * evaluated against the destination on the initial URL and on every hop, while
 * the proxy host is never its subject.
 *
 * These wire the real pieces together — `resolveEnvProxy` into the client's
 * `fetchOptions`, and the real `assertEgressHostAllowed` as `authorizeHost` —
 * because the failure mode is a composition, invisible to either unit alone.
 */
describe('resolveEnvProxy — a proxy is not a way around egress authorization', () => {
  const ENV = { https_proxy: 'http://proxy.internal:8080' }
  const MESSAGES = {
    notAllowed: (host: string, allowed: string) => `${host} is not in the allowlist (${allowed}).`,
    isPrivate: (host: string) => `${host} is private.`,
  }
  // The proxy host, and ONLY the proxy host: if authorization ever moved onto
  // the connection's peer, every destination below would pass.
  const ALLOW_PROXY_ONLY = parseAllowedHosts('proxy.internal')

  let dir: string
  let dest: string
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'ptc-proxy-'))
    dest = join(dir, 'artifact.bin')
  })
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  /** Records the dispatcher each hop was issued with, so "was it proxied?" is observable. */
  function proxiedClient(script: readonly (() => Response)[]): {
    client: ReturnType<typeof createHttpClient>
    dispatchers: (string | undefined)[]
  } {
    const dispatchers: (string | undefined)[] = []
    let index = 0
    const fetchImpl = (async (_input: string | URL, init: RequestInit & { proxy?: string }) => {
      dispatchers.push(init.proxy)
      const step = script[Math.min(index, script.length - 1)]
      index += 1
      if (!step) throw new Error('scripted fetch exhausted')
      return step()
    }) as unknown as typeof fetch
    const client = createHttpClient({
      fetchImpl,
      attempts: 1,
      baseDelayMs: 0,
      // What a consumer writes: resolve per hop, then hand the dispatcher to
      // fetch. `new ProxyAgent(...)` in a real task; a tag here, since undici
      // is a task-side dependency and this package never builds one.
      fetchOptions: (url) => {
        const resolved = resolveEnvProxy(url, ENV)
        return (resolved ? { proxy: resolved.proxyUrl } : {}) as RequestInit
      },
    })
    return { client, dispatchers }
  }

  it('refuses a destination the allowlist rejects, though the proxy itself is allowlisted', async () => {
    const { client, dispatchers } = proxiedClient([() => new Response('payload')])
    await expect(
      client.downloadToFile('https://registry.example.com/f', dest, 1000, (host) =>
        assertEgressHostAllowed(host, ALLOW_PROXY_ONLY, MESSAGES),
      ),
    ).rejects.toThrow(/registry\.example\.com is not in the allowlist/)
    expect(dispatchers, 'the refusal must precede the CONNECT').toEqual([])
    expect(existsSync(dest)).toBe(false)
  })

  it('refuses a redirect hop to an unauthorized destination inside the same tunnel', async () => {
    const { client, dispatchers } = proxiedClient([
      () => new Response(null, { status: 302, headers: { location: 'https://evil.test/f' } }),
      () => new Response('payload'),
    ])
    await expect(
      client.downloadToFile(
        'https://registry.example.com/f',
        dest,
        1000,
        (host) =>
          assertEgressHostAllowed(host, parseAllowedHosts('registry.example.com'), MESSAGES),
        // The hop was already tunnelled through the allowlisted proxy; the
        // decision still belongs to the destination.
      ),
    ).rejects.toThrow(/evil\.test is not in the allowlist/)
    expect(dispatchers).toEqual(['http://proxy.internal:8080'])
    expect(existsSync(dest)).toBe(false)
  })

  /**
   * The positive control. Without it the two refusals above would still pass
   * with proxying entirely broken — they would simply be refusing a request
   * that was never going to be proxied.
   */
  it('does proxy an authorized destination, on every hop', async () => {
    const { client, dispatchers } = proxiedClient([
      () =>
        new Response(null, {
          status: 302,
          headers: { location: 'https://cdn.registry.example.com/f' },
        }),
      () => new Response('payload'),
    ])
    await client.downloadToFile('https://registry.example.com/f', dest, 1000, (host) =>
      assertEgressHostAllowed(
        host,
        parseAllowedHosts('registry.example.com,cdn.registry.example.com'),
        MESSAGES,
      ),
    )
    expect(dispatchers).toEqual(['http://proxy.internal:8080', 'http://proxy.internal:8080'])
    expect(existsSync(dest)).toBe(true)
  })

  /**
   * Re-resolution per hop is the point of handing `fetchOptions` the current
   * URL: a chain that leaves the proxied origin for a NO_PROXY destination must
   * stop tunnelling, and the reverse must start.
   */
  it('re-resolves the proxy for each hop, since the destination changes', async () => {
    const dispatchers: (string | undefined)[] = []
    const script = [
      () => new Response(null, { status: 302, headers: { location: 'https://internal.corp/f' } }),
      () => new Response('payload'),
    ]
    let index = 0
    const fetchImpl = (async (_input: string | URL, init: RequestInit & { proxy?: string }) => {
      dispatchers.push(init.proxy)
      const step = script[Math.min(index, script.length - 1)]!
      index += 1
      return step()
    }) as unknown as typeof fetch
    const client = createHttpClient({
      fetchImpl,
      attempts: 1,
      baseDelayMs: 0,
      fetchOptions: (url) => {
        const resolved = resolveEnvProxy(url, { ...ENV, no_proxy: 'internal.corp' })
        return (resolved ? { proxy: resolved.proxyUrl } : {}) as RequestInit
      },
    })
    await client.downloadToFile('https://registry.example.com/f', dest, 1000, () => undefined)
    expect(dispatchers).toEqual(['http://proxy.internal:8080', undefined])
  })
})

/**
 * TABLE B — export inventory, verdicted by hand.
 */
describe('proxy — public surface', () => {
  it('exports exactly the reviewed set', () => {
    expect(Object.keys(proxyModule).sort()).toEqual(['resolveEnvProxy', 'resolveProxy'])
  })
})
