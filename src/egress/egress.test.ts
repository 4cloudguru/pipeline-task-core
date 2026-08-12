import { describe, expect, it } from 'vitest'

import {
  assertEgressHostAllowed,
  bareHost,
  isHostAllowed,
  isIpLiteral,
  isPrivateIpv4Address,
  isPrivateOrLinkLocalHost,
  looseSuffixOnlyMatch,
  parseAllowedHosts,
  parseIpv4,
  parseIpv6,
  resolvesToPrivateOrLinkLocalAddress,
} from './egress'

/**
 * CLASS TEST — defect class `egress-authorization` (ledger #161).
 *
 * SCOPE. What a green run here claims: a destination host is classified from its
 * RESOLVED NUMERIC ADDRESS rather than its textual form, across every legal
 * spelling an OS resolver accepts; wildcard pins match exactly one label; and
 * the default-deny path refuses private, link-local, CGNAT and reserved
 * destinations including via DNS.
 *
 * What it claims NOTHING about: DNS rebinding. The check resolves at check time
 * and does not pin the resolved address into the connection, so it is
 * defence-in-depth against a statically-private destination, not a complete
 * rebinding defence. It also claims nothing about whether a given CONSUMER
 * routes its calls through here — that is the signature's job — nor about
 * destinations reached by a child process.
 *
 * #161 is a REGRESSION (closed 2026-07-25, reopened 2026-08-06), which is why
 * Table A weights the numeric-spelling rows so heavily: the textual form of the
 * check is exactly what regressed.
 */

const messages = {
  notAllowed: (h: string, a: string) => `Host ${h} is not in the allowlist (${a}).`,
  isPrivate: (h: string) => `Host ${h} is private.`,
}

describe('Table A — loopback reached by every legal spelling', () => {
  // The regression this class exists to prevent: all of these connect to
  // 127.0.0.1 but match no dotted-quad regex.
  const loopbackSpellings = [
    '127.0.0.1',
    '127.1',
    '127.0.1',
    '2130706433',
    '0x7f000001',
    '017700000001',
    '0177.0.0.1',
    '[::ffff:127.0.0.1]',
    '[::ffff:7f00:1]',
    'localhost',
    'anything.localhost',
  ]

  it.each(loopbackSpellings)('refuses %s', (host) => {
    expect(isPrivateOrLinkLocalHost(host)).toBe(true)
  })
})

describe('Table A — non-public ranges are classified numerically', () => {
  const nonPublic: Array<[string, string]> = [
    ['169.254.169.254', 'cloud metadata'],
    ['169.254.0.1', 'link-local'],
    ['10.0.0.5', 'RFC1918'],
    ['172.16.0.1', 'RFC1918 (high bit set — int32 coercion trap)'],
    ['172.31.255.255', 'RFC1918 upper bound'],
    ['192.168.1.1', 'RFC1918'],
    ['100.64.0.1', 'RFC6598 CGNAT'],
    ['0.0.0.0', 'this network'],
    ['192.0.0.1', 'IETF protocol assignments'],
    ['198.18.0.1', 'RFC2544 benchmarking'],
    ['224.0.0.1', 'multicast'],
    ['255.255.255.255', 'broadcast'],
    ['[::1]', 'IPv6 loopback'],
    ['[::]', 'IPv6 unspecified'],
    ['[fc00::1]', 'IPv6 ULA'],
    ['[fe80::1]', 'IPv6 link-local'],
    ['[ff02::1]', 'IPv6 multicast'],
    ['[64:ff9b::a9fe:a9fe]', 'NAT64 wrapping metadata'],
    ['[2002:a9fe:a9fe::]', '6to4 wrapping metadata'],
  ]

  it.each(nonPublic)('refuses %s (%s)', (host) => {
    expect(isPrivateOrLinkLocalHost(host)).toBe(true)
  })

  it.each([['93.184.216.34'], ['8.8.8.8'], ['example.com'], ['[2606:2800:220:1::]']])(
    'permits public %s',
    (host) => {
      expect(isPrivateOrLinkLocalHost(host)).toBe(false)
    },
  )
})

describe('Table A — a port or zone id cannot smuggle a private host past the check', () => {
  it('strips an explicit port', () => {
    expect(bareHost('10.0.0.5:8443')).toBe('10.0.0.5')
    expect(isPrivateOrLinkLocalHost('10.0.0.5:8443')).toBe(true)
  })

  it('strips brackets and a port from IPv6', () => {
    expect(bareHost('[::1]:8443')).toBe('::1')
    expect(isPrivateOrLinkLocalHost('[::1]:8443')).toBe(true)
  })

  it('strips an IPv6 zone id', () => {
    expect(bareHost('[fe80::1%eth0]')).toBe('fe80::1')
    expect(isPrivateOrLinkLocalHost('[fe80::1%eth0]')).toBe(true)
  })

  it('does not mistake a bare IPv6 address for host:port', () => {
    expect(bareHost('::1')).toBe('::1')
  })
})

describe('Table A — wildcard pins match exactly one label (RFC 6125)', () => {
  const allow = ['*.s3.amazonaws.com']

  it('matches a single label', () => {
    expect(isHostAllowed('bucket.s3.amazonaws.com', allow)).toBe(true)
  })

  it('does NOT match multiple labels', () => {
    expect(isHostAllowed('a.bucket.s3.amazonaws.com', allow)).toBe(false)
  })

  it('does NOT match the bare domain', () => {
    expect(isHostAllowed('s3.amazonaws.com', allow)).toBe(false)
  })

  it('does not match a lookalike suffix', () => {
    expect(isHostAllowed('evils3.amazonaws.com', allow)).toBe(false)
  })

  it('names the near-miss so the tightening is actionable, not opaque', () => {
    expect(looseSuffixOnlyMatch('a.bucket.s3.amazonaws.com', allow)).toBe('*.s3.amazonaws.com')
    expect(looseSuffixOnlyMatch('bucket.s3.amazonaws.com', allow)).toBeUndefined()
    expect(looseSuffixOnlyMatch('elsewhere.example.com', allow)).toBeUndefined()
  })
})

describe('Table A — allowlist entries that cannot mean what was intended are refused', () => {
  it.each([['*.com'], ['example.com*'], ['*'], ['*.']])('rejects %s', (entry) => {
    expect(() => parseAllowedHosts(entry)).toThrow()
  })

  it('treats empty input as "no allowlist", not as an error', () => {
    // This is the default-deny path, not a malformed pin: an unset input must
    // fall through to numeric classification rather than failing the task.
    expect(parseAllowedHosts('')).toEqual([])
    expect(parseAllowedHosts(undefined)).toEqual([])
    expect(parseAllowedHosts('  ,  \n ')).toEqual([])
  })

  it('accepts hostnames, IP literals and two-label wildcards', () => {
    expect(parseAllowedHosts('registry.example.com, *.s3.amazonaws.com, 10.0.0.5')).toEqual([
      'registry.example.com',
      '*.s3.amazonaws.com',
      '10.0.0.5',
    ])
  })

  it('brackets a bare IPv6 pin so it can actually match a URL host', () => {
    expect(parseAllowedHosts('::1')).toEqual(['[::1]'])
  })

  it('splits on both commas and newlines, and lowercases', () => {
    expect(parseAllowedHosts('A.example.com\nB.example.com')).toEqual([
      'a.example.com',
      'b.example.com',
    ])
  })
})

describe('Table A — assertEgressHostAllowed is the single decision point', () => {
  it('enforces only the pin when an allowlist is set, even for a private host', async () => {
    // An air-gapped mirror on a private address is legitimate when pinned.
    await expect(assertEgressHostAllowed('10.0.0.5', ['10.0.0.5'], messages)).resolves.toBeUndefined()
  })

  it('refuses a host outside the pin', async () => {
    await expect(
      assertEgressHostAllowed('evil.example.com', ['registry.example.com'], messages),
    ).rejects.toThrow(/not in the allowlist/)
  })

  it('explains an RFC 6125 near-miss in the rejection', async () => {
    await expect(
      assertEgressHostAllowed('a.bucket.s3.amazonaws.com', ['*.s3.amazonaws.com'], messages),
    ).rejects.toThrow(/exactly one label/)
  })

  it('default-denies a private literal when no allowlist is set', async () => {
    await expect(assertEgressHostAllowed('169.254.169.254', [], messages)).rejects.toThrow(/is private/)
  })

  it('default-denies a NAME that resolves to a private address', async () => {
    const lookup = async () => [{ address: '169.254.169.254' }]
    await expect(assertEgressHostAllowed('metadata.example.com', [], messages, lookup)).rejects.toThrow(
      /is private/,
    )
  })

  it('refuses when ANY resolved address is private, not just the first', async () => {
    const lookup = async () => [{ address: '93.184.216.34' }, { address: '10.0.0.5' }]
    await expect(assertEgressHostAllowed('mixed.example.com', [], messages, lookup)).rejects.toThrow(
      /is private/,
    )
  })

  it('permits a public name that resolves publicly', async () => {
    const lookup = async () => [{ address: '93.184.216.34' }]
    await expect(
      assertEgressHostAllowed('example.com', [], messages, lookup),
    ).resolves.toBeUndefined()
  })

  it('does not resolve an IP literal that already passed the numeric check', async () => {
    let called = false
    const lookup = async () => {
      called = true
      return [{ address: '10.0.0.5' }]
    }
    await assertEgressHostAllowed('93.184.216.34', [], messages, lookup)
    expect(called).toBe(false)
  })

  it('propagates a DNS failure rather than reporting it as private', async () => {
    const lookup = async () => {
      throw new Error('ENOTFOUND')
    }
    await expect(
      assertEgressHostAllowed('nope.example.com', [], messages, lookup),
    ).rejects.toThrow('ENOTFOUND')
  })
})

describe('Table A — parser edge cases', () => {
  it('rejects out-of-range and malformed IPv4', () => {
    expect(parseIpv4('256.0.0.1')).toBeNull()
    expect(parseIpv4('1.2.3.4.5')).toBeNull()
    expect(parseIpv4('08')).toBeNull() // 8 is not a legal octal digit
    expect(parseIpv4('example.com')).toBeNull()
  })

  it('accepts inet_aton short forms', () => {
    expect(parseIpv4('127.0.0.1')).toBe(parseIpv4('2130706433'))
    expect(parseIpv4('127.1')).toBe(parseIpv4('127.0.0.1'))
  })

  it('rejects malformed IPv6', () => {
    expect(parseIpv6('::1::2')).toBeNull()
    expect(parseIpv6('gggg::1')).toBeNull()
    expect(parseIpv6('1:2:3:4:5:6:7')).toBeNull()
    expect(parseIpv6('example.com')).toBeNull()
  })

  it('classifies the int32-coercion boundary correctly', () => {
    // 172.16.0.0/12 and 169.254.0.0/16 have the high bit set; a signed compare
    // would report these as public.
    expect(isPrivateIpv4Address(parseIpv4('172.16.0.1')!)).toBe(true)
    expect(isPrivateIpv4Address(parseIpv4('169.254.169.254')!)).toBe(true)
    expect(isPrivateIpv4Address(parseIpv4('93.184.216.34')!)).toBe(false)
  })

  it('recognises IP literals in any spelling', () => {
    expect(isIpLiteral('0x7f000001')).toBe(true)
    expect(isIpLiteral('[::1]')).toBe(true)
    expect(isIpLiteral('example.com')).toBe(false)
  })

  it('resolvesToPrivateOrLinkLocalAddress strips decorations before resolving', async () => {
    let asked = ''
    const lookup = async (h: string) => {
      asked = h
      return [{ address: '93.184.216.34' }]
    }
    await resolvesToPrivateOrLinkLocalAddress('example.com:8443', lookup)
    expect(asked).toBe('example.com')
  })
})

/**
 * Table B — hand-verdicted export inventory. The signature proves consumers route
 * through this module; this proves nothing is exported from it without a stated
 * egress contract.
 */
describe('Table B — exported surface is fully accounted for', () => {
  const VERDICTS: Record<string, string> = {
    parseAllowedHosts: 'validates and normalises operator input; throws on an entry that cannot match',
    isHostAllowed: 'pure match; RFC 6125 single-label wildcards',
    looseSuffixOnlyMatch: 'diagnostic only; never widens a decision',
    bareHost: 'strips port/brackets/zone so numeric checks cannot be bypassed',
    parseIpv4: 'inet_aton radix parsing, all short forms',
    parseIpv6: 'full/compressed/embedded-IPv4 forms',
    isPrivateIpv4Address: 'range check over the reserved table',
    isPrivateOrLinkLocalHost: 'numeric classification of a literal; no DNS',
    isIpLiteral: 'decides whether DNS resolution is meaningful',
    resolvesToPrivateOrLinkLocalAddress: 'check-time DNS; explicitly NOT a rebinding defence',
    assertEgressHostAllowed: 'THE decision point; throws, never returns a bare boolean',
  }

  it('every runtime export has a verdict', async () => {
    const mod = await import('./egress')
    expect(Object.keys(mod).sort()).toEqual(Object.keys(VERDICTS).sort())
  })
})
