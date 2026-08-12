/**
 * SCOPE — what a green run here does and does not claim.
 *
 * DOES claim: every representation of the proxy credential that could reach a
 * log is returned for registration — the raw password, the percent-encoded
 * form the URL setter produces, and credentials already embedded in the
 * configured proxy URL; a username is never returned as a secret; and an
 * unparseable proxy URL fails loudly rather than silently disabling the proxy.
 *
 * Does NOT claim: that anything is actually masked. This returns strings for
 * the CALLER to register with the agent's masker, and a forgotten setSecret()
 * is invisible from here. Nor that the proxy works: no dispatcher is built and
 * no connection is made — `undici` stays a task-side dependency.
 */
import { describe, expect, it } from 'vitest'
import * as proxyModule from './proxy'
import { resolveProxy } from './proxy'

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

/**
 * TABLE B — export inventory, verdicted by hand.
 */
describe('proxy — public surface', () => {
  it('exports exactly the reviewed set', () => {
    expect(Object.keys(proxyModule).sort()).toEqual(['resolveProxy'])
  })
})
