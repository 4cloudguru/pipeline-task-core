import { describe, expect, it } from 'vitest'

import {
  TlsOptOutDestinationError,
  assertTlsOptOutDestinationIsPrivate,
  normalizeDestinationHost,
} from './tls-opt-out'

/**
 * CLASS TEST — defect class `tls-opt-out-destination` (azure-pipelines-terraform#588).
 *
 * SCOPE. What a green run here claims: an operator switch that disables TLS
 * certificate verification is honoured only against a destination this module
 * can PROVE is private, that the proof survives every spelling of the same
 * destination (trailing dot, mixed case, IP literal, bracketed IPv6), and that
 * a refusal never echoes userinfo. It claims nothing about whether a given task
 * actually calls this — that is the replay signature's job.
 *
 * The table below is the class: each row is a destination shape, not a call
 * site, so a new task adopting the guard inherits every case at once.
 */

/** Deterministic resolver: the network is never touched by this file. */
const ZONE: Record<string, string[]> = {
  'app.terraform.io': ['75.2.98.97'],
  'registry.terraform.io': ['104.16.4.1'],
  'registry.internal': ['10.4.5.6'],
  'tsm.corp.example': ['172.16.9.9'],
  'metadata.example': ['169.254.169.254'],
  'split.example': ['93.184.216.34', '10.0.0.7'],
}

const lookup = async (host: string): Promise<{ address: string }[]> => {
  const addresses = ZONE[host]
  if (!addresses) {
    const error = new Error(`getaddrinfo ENOTFOUND ${host}`) as Error & { code?: string }
    error.code = 'ENOTFOUND'
    throw error
  }
  return addresses.map((address) => ({ address }))
}

async function rejection(url: string): Promise<TlsOptOutDestinationError> {
  try {
    await assertTlsOptOutDestinationIsPrivate('registryUrl', url, lookup)
  } catch (error) {
    if (error instanceof TlsOptOutDestinationError) return error
    throw error
  }
  throw new Error(`expected '${url}' to be refused, but it was accepted`)
}

describe('normalizeDestinationHost', () => {
  it.each([
    ['app.terraform.io.', 'app.terraform.io'],
    ['APP.Terraform.IO.', 'app.terraform.io'],
    ['app.terraform.io', 'app.terraform.io'],
    ['app.terraform.io..', 'app.terraform.io.'], // ONE dot, deliberately
    ['[::1]', '[::1]'],
    ['.', '.'],
  ])('normalizes %s to %s', (input, expected) => {
    expect(normalizeDestinationHost(input)).toBe(expected)
  })
})

describe('assertTlsOptOutDestinationIsPrivate — accepted destinations', () => {
  it.each([
    ['private IPv4 literal', 'https://10.0.0.1/v1/modules'],
    ['loopback IPv4 in a short spelling', 'https://127.1/v1/modules'],
    ['bracketed IPv6 loopback', 'https://[::1]/v1/modules'],
    ['IPv4-mapped IPv6 loopback', 'https://[::ffff:127.0.0.1]/v1/modules'],
    ['link-local metadata address', 'https://169.254.169.254/v1/modules'],
    ['localhost by name', 'https://localhost/v1/modules'],
    ['name that resolves privately', 'https://registry.internal/v1/modules'],
    ['ROOTED name that resolves privately', 'https://registry.internal./v1/modules'],
    ['name resolving into RFC1918 space', 'https://tsm.corp.example/v1/modules'],
    ['name whose resolution includes a private address', 'https://split.example/v1/modules'],
  ])('accepts a %s', async (_label, url) => {
    await expect(
      assertTlsOptOutDestinationIsPrivate('registryUrl', url, lookup),
    ).resolves.toBeUndefined()
  })
})

describe('assertTlsOptOutDestinationIsPrivate — refused destinations', () => {
  it.each([
    // The #588 bypass: WHATWG URL keeps the trailing dot, so a denylist compare
    // misses it while DNS resolves the rooted FQDN to the real public registry.
    [
      'rooted public FQDN',
      'https://app.terraform.io./v1/modules',
      'not-private',
      'app.terraform.io',
    ],
    [
      'upper-case rooted public FQDN',
      'https://APP.TERRAFORM.IO./v1/modules',
      'not-private',
      'app.terraform.io',
    ],
    [
      'public registry by name',
      'https://registry.terraform.io/v1/modules',
      'not-private',
      'registry.terraform.io',
    ],
    ['public IPv4 literal', 'https://8.8.8.8/v1/modules', 'not-private', '8.8.8.8'],
    [
      'public IPv6 literal',
      'https://[2001:4860:4860::8888]/v1/modules',
      'not-private',
      '[2001:4860:4860::8888]',
    ],
  ])('refuses a %s', async (_label, url, reason, host) => {
    const error = await rejection(url)
    expect(error.reason).toBe(reason)
    expect(error.safeDestination).toBe(host)
  })

  it('refuses a value the URL parser rejects, rather than letting it through', async () => {
    const error = await rejection('not a url')
    expect(error.reason).toBe('unparseable')
    expect(error.safeDestination).toBe('not a url')
  })

  it('refuses a URL that parses but carries no host at all', async () => {
    // A non-special scheme keeps an empty authority instead of collapsing it,
    // so there is nothing to classify and nothing to resolve — refuse rather
    // than hand '' to the resolver.
    const error = await rejection('tsm:///drift')
    expect(error.reason).toBe('unparseable')
  })

  it('refuses userinfo in the base and never echoes it', async () => {
    const error = await rejection('https://svc:s3cr3t@10.0.0.1/v1/modules')
    expect(error.reason).toBe('userinfo')
    expect(error.safeDestination).toBe('10.0.0.1')
    expect(error.message).not.toContain('s3cr3t')
    expect(error.message).not.toContain('svc:')
  })

  it('describes rather than echoes an unparseable value that carries userinfo', async () => {
    const error = await rejection('svc:s3cr3t@registry.internal/v1')
    expect(error.reason).toBe('unparseable')
    expect(error.message).not.toContain('s3cr3t')
    expect(error.safeDestination).toBe('(value with userinfo, redacted)')
  })

  it('bounds the echoed unparseable value', async () => {
    const error = await rejection(`ht tp://${'a'.repeat(400)}`)
    expect(error.safeDestination.length).toBeLessThanOrEqual(103)
    expect(error.safeDestination.endsWith('...')).toBe(true)
  })
})

describe('assertTlsOptOutDestinationIsPrivate — failure modes', () => {
  it('propagates a DNS failure instead of reporting the host as public', async () => {
    await expect(
      assertTlsOptOutDestinationIsPrivate('registryUrl', 'https://unknown.example/v1', lookup),
    ).rejects.toThrow(/ENOTFOUND/)
  })

  it('never hands an IP literal to the resolver', async () => {
    const exploding = async (): Promise<{ address: string }[]> => {
      throw new Error('DNS must not be consulted for an IP literal')
    }
    const error = await (async () => {
      try {
        await assertTlsOptOutDestinationIsPrivate('registryUrl', 'https://8.8.8.8/v1', exploding)
      } catch (e) {
        return e as TlsOptOutDestinationError
      }
      throw new Error('expected a refusal')
    })()
    expect(error).toBeInstanceOf(TlsOptOutDestinationError)
    expect(error.reason).toBe('not-private')
  })

  it('names the input it was called for, so a task can localise per input', async () => {
    try {
      await assertTlsOptOutDestinationIsPrivate('callbackUrl', 'https://8.8.8.8/drift', lookup)
      throw new Error('expected a refusal')
    } catch (error) {
      expect((error as TlsOptOutDestinationError).inputName).toBe('callbackUrl')
    }
  })
})
