import { promises as dnsPromises } from 'node:dns'

/**
 * One DNS label. Underscores are permitted deliberately: this validates the
 * operator's PATTERN for obvious nonsense, it does not police DNS legality, and
 * underscore-bearing labels occur in real internal zones that the exact-match
 * arm below can legitimately pin.
 */
const HOST_LABEL = /^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$/

/**
 * Rejects an allowlist entry that cannot mean what the operator intended, rather
 * than carrying it as a pin that silently matches nothing (`example.com*`) or
 * spans an entire public suffix (`*.com`). This is the operator's only control
 * over a compromised registry, so an unparseable pin fails loudly instead of
 * degrading to a weaker allowlist.
 */
function assertValidAllowlistEntry(entry: string): string {
  const isWildcard = entry.startsWith('*.')
  const host = isWildcard ? entry.slice(2) : entry
  const labels = host.split('.')
  const valid =
    host.length > 0 &&
    ((!isWildcard && isIpLiteral(host)) ||
      ((!isWildcard || labels.length >= 2) && labels.every((label) => HOST_LABEL.test(label))))

  if (!valid) {
    throw new Error(
      `Invalid allowed-hosts entry '${entry}'. Expected a hostname such as ` +
        `'registry.example.com', an IP literal, or a single-label wildcard covering ` +
        `at least two labels such as '*.s3.amazonaws.com'.`,
    )
  }

  // A WHATWG URL always renders an IPv6 host bracketed, so an unbracketed IPv6
  // pin would validate here and then never equal a real request's hostname —
  // the silently-dead pin this validation exists to prevent.
  if (!isWildcard && !host.startsWith('[') && parseIpv6(bareHost(host)) !== null) {
    return `[${host}]`
  }
  return entry
}

/** Parses a comma/newline-separated allowlist input, throwing on any invalid entry. */
export function parseAllowedHosts(raw: string | undefined): string[] {
  if (!raw) return []
  return raw
    .split(/[\n,]/)
    .map((h) => h.trim().toLowerCase())
    .filter((h) => h.length > 0)
    .map(assertValidAllowlistEntry)
}

/**
 * Matches a hostname against the allowlist. A `*.` prefix matches EXACTLY ONE
 * label — `*.s3.amazonaws.com` covers `bucket.s3.amazonaws.com` but neither
 * `a.bucket.s3.amazonaws.com` nor the bare `s3.amazonaws.com` — which is TLS
 * wildcard-SAN (RFC 6125) semantics. A plain suffix match would silently widen
 * an operator's corporate-domain pin to every subdomain at any depth.
 */
export function isHostAllowed(hostname: string, allowedHosts: string[]): boolean {
  const host = hostname.toLowerCase()
  return allowedHosts.some((allowed) => {
    if (!allowed.startsWith('*.')) return host === allowed
    const suffix = allowed.slice(1)
    if (!host.endsWith(suffix)) return false
    const label = host.slice(0, host.length - suffix.length)
    return label.length > 0 && !label.includes('.')
  })
}

/**
 * The allowlist entry a host would have matched under a LOOSE suffix rule but
 * does not under RFC 6125, or undefined when there is no such near-miss.
 *
 * Single-label matching is the stricter, correct rule, but it is also a silent
 * tightening for anyone who had relied on multi-label matching (a dotted S3
 * bucket, say). Naming the near-miss turns an opaque refusal into an actionable
 * one; it never widens the decision.
 */
export function looseSuffixOnlyMatch(hostname: string, allowedHosts: string[]): string | undefined {
  if (isHostAllowed(hostname, allowedHosts)) return undefined
  const host = hostname.toLowerCase()
  return allowedHosts.find((allowed) => allowed.startsWith('*.') && host.endsWith(allowed.slice(1)))
}

/**
 * Strips the decorations a WHATWG `URL.host`/`URL.hostname` (or an operator-typed
 * host) can carry — bracketed IPv6, an explicit port, an IPv6 zone id — leaving
 * the bare address the range checks operate on.
 *
 * `URL.host` includes an explicit non-default port, and per-hop redirect checks
 * are invoked with `.host`, so `https://10.0.0.5:8443/` would otherwise bypass
 * every numeric check (the parsers below are anchored and never match
 * `address:port`). A bare IPv6 address always has at least two colons, while a
 * real `host:port` has exactly one, so the port is only stripped when there is
 * exactly one colon and the tail is digits.
 */
export function bareHost(hostname: string): string {
  let host = hostname.trim().toLowerCase()
  if (host.startsWith('[')) {
    const closeBracket = host.indexOf(']')
    host = closeBracket >= 0 ? host.slice(1, closeBracket) : host.slice(1)
  } else {
    const colonCount = (host.match(/:/g) ?? []).length
    if (colonCount === 1) {
      const lastColon = host.lastIndexOf(':')
      if (/^\d+$/.test(host.slice(lastColon + 1))) {
        host = host.slice(0, lastColon)
      }
    }
  }
  const percent = host.indexOf('%')
  return percent >= 0 ? host.slice(0, percent) : host
}

/**
 * Parses ONE dotted part of an IPv4 literal using inet_aton() radix rules, which
 * are what an OS resolver actually applies: `0x` is hex, a bare leading `0` is
 * octal, everything else decimal.
 *
 * This is why a purely TEXTUAL blocklist is the wrong shape: `127.1`,
 * `2130706433`, `0x7f000001` and `017700000001` are all 127.0.0.1 to the
 * connecting socket but match no dotted-quad regex.
 */
function parseIpv4Part(part: string): number | null {
  if (part.length === 0) return null
  if (/^0[xX][0-9a-fA-F]+$/.test(part)) return Number.parseInt(part.slice(2), 16)
  if (/^0[0-7]*$/.test(part)) return Number.parseInt(part, 8)
  if (/^[1-9][0-9]*$/.test(part)) return Number.parseInt(part, 10)
  return null
}

/**
 * Parses an IPv4 literal in any legal spelling — dotted-quad, the short forms
 * (`a.b.c`, `a.b`, `a`) whose final part absorbs the remaining octets, and
 * hex/octal/decimal parts — into one unsigned 32-bit address.
 */
export function parseIpv4(host: string): number | null {
  const parts = host.split('.')
  if (parts.length < 1 || parts.length > 4) return null

  const values: number[] = []
  for (const part of parts) {
    const value = parseIpv4Part(part)
    if (value === null || !Number.isSafeInteger(value) || value < 0) return null
    values.push(value)
  }

  // Every part but the last is a single octet; the last absorbs the rest.
  for (let i = 0; i < values.length - 1; i++) {
    if (values[i]! > 0xff) return null
  }

  const tailBits = (5 - values.length) * 8
  const tailMax = tailBits >= 32 ? 0xffffffff : Math.pow(2, tailBits) - 1
  const tail = values[values.length - 1]!
  if (tail > tailMax) return null

  let address = tail
  for (let i = 0; i < values.length - 1; i++) {
    address += values[i]! * Math.pow(2, 8 * (3 - i))
  }
  return address >>> 0
}

/**
 * Parses an IPv6 literal (full, `::`-compressed, or with a trailing embedded
 * IPv4 dotted-quad) into its eight 16-bit groups.
 */
export function parseIpv6(host: string): number[] | null {
  if (!host.includes(':')) return null
  const doubleColon = host.indexOf('::')
  if (doubleColon !== host.lastIndexOf('::')) return null

  const [headText, tailText] =
    doubleColon >= 0 ? [host.slice(0, doubleColon), host.slice(doubleColon + 2)] : [host, null]

  const expand = (text: string, allowEmbeddedIpv4: boolean): number[] | null => {
    if (text === '') return []
    const chunks = text.split(':')
    const groups: number[] = []
    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i]!
      const isLast = i === chunks.length - 1
      if (isLast && allowEmbeddedIpv4 && chunk.includes('.')) {
        // A trailing dotted-quad occupies the final two groups, and only the
        // strict spelling is legal inside an IPv6 literal.
        if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(chunk)) return null
        const embedded = parseIpv4(chunk)
        if (embedded === null) return null
        groups.push((embedded >>> 16) & 0xffff, embedded & 0xffff)
        continue
      }
      if (!/^[0-9a-f]{1,4}$/.test(chunk)) return null
      groups.push(Number.parseInt(chunk, 16))
    }
    return groups
  }

  const head = expand(headText, tailText === null)
  if (head === null) return null
  if (tailText === null) return head.length === 8 ? head : null

  const tail = expand(tailText, true)
  if (tail === null || head.length + tail.length > 7) return null
  return [...head, ...new Array<number>(8 - head.length - tail.length).fill(0), ...tail]
}

/** [network, prefixLength] pairs, as unsigned 32-bit IPv4 addresses. */
const PRIVATE_IPV4_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x00000000, 8], // 0.0.0.0/8        "this network"
  [0x0a000000, 8], // 10.0.0.0/8       RFC1918
  [0x64400000, 10], // 100.64.0.0/10   RFC6598 carrier-grade NAT
  [0x7f000000, 8], // 127.0.0.0/8      loopback
  [0xa9fe0000, 16], // 169.254.0.0/16  link-local, incl. cloud metadata (169.254.169.254)
  [0xac100000, 12], // 172.16.0.0/12   RFC1918
  [0xc0000000, 24], // 192.0.0.0/24    IETF protocol assignments
  [0xc0a80000, 16], // 192.168.0.0/16  RFC1918
  [0xc6120000, 15], // 198.18.0.0/15   RFC2544 benchmarking
  [0xe0000000, 4], // 224.0.0.0/4      multicast
  [0xf0000000, 4], // 240.0.0.0/4      reserved, incl. 255.255.255.255 broadcast
]

/** True when a 32-bit IPv4 address falls inside any non-public range above. */
export function isPrivateIpv4Address(address: number): boolean {
  return PRIVATE_IPV4_RANGES.some(([network, prefix]) => {
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0
    // `&` coerces to int32, so re-normalise before comparing: 172.16.0.0/12 and
    // 169.254.0.0/16 both have the high bit set and would otherwise compare as
    // negative against a positive network.
    return ((address >>> 0) & mask) >>> 0 === network
  })
}

/**
 * The IPv4 address embedded in an IPv6 group array for the transition formats
 * that put a routable-as-IPv4 destination inside an IPv6 literal: `::ffff:a.b.c.d`
 * (IPv4-mapped — what `https://[::ffff:127.0.0.1]/` normalises to, and what a
 * textual blocklist misses entirely), `::a.b.c.d` (IPv4-compatible),
 * `64:ff9b::/96` (NAT64) and `2002::/16` (6to4).
 */
function embeddedIpv4(groups: number[]): number | null {
  const low32 = (groups[6]! * 0x10000 + groups[7]!) >>> 0
  const isZeroPrefix = groups.slice(0, 5).every((g) => g === 0)

  if (isZeroPrefix && groups[5] === 0xffff) return low32 // ::ffff:0:0/96 IPv4-mapped
  if (isZeroPrefix && groups[5] === 0 && low32 !== 0 && low32 !== 1) return low32 // ::/96
  if (
    groups[0] === 0x0064 &&
    groups[1] === 0xff9b &&
    groups[2] === 0 &&
    groups[3] === 0 &&
    groups[4] === 0 &&
    groups[5] === 0
  ) {
    return low32 // 64:ff9b::/96 NAT64
  }
  if (groups[0] === 0x2002) return (groups[1]! * 0x10000 + groups[2]!) >>> 0 // 2002::/16 6to4
  return null
}

/** True when the eight-group IPv6 address is loopback/unspecified/ULA/link-local/multicast. */
function isPrivateIpv6Address(groups: number[]): boolean {
  if (groups.every((g) => g === 0)) return true // ::
  if (groups.slice(0, 7).every((g) => g === 0) && groups[7] === 1) return true // ::1
  if ((groups[0]! & 0xfe00) === 0xfc00) return true // fc00::/7 unique local
  if ((groups[0]! & 0xffc0) === 0xfe80) return true // fe80::/10 link-local
  if ((groups[0]! & 0xff00) === 0xff00) return true // ff00::/8 multicast
  const embedded = embeddedIpv4(groups)
  return embedded !== null && isPrivateIpv4Address(embedded)
}

/**
 * True when `hostname` denotes a loopback, link-local, carrier-grade-NAT,
 * RFC1918/ULA private or otherwise non-public address — the common SSRF targets,
 * notably the cloud instance-metadata service at 169.254.169.254.
 *
 * The classification is NUMERIC, not textual: the host is parsed into an actual
 * address — accepting every legal spelling an OS resolver accepts — and only
 * then range-checked. A textual dotted-quad blocklist is bypassed by `127.1`,
 * `2130706433`, `0x7f000001`, `017700000001` and `[::ffff:127.0.0.1]`, all of
 * which connect to loopback, and misses whole ranges (RFC 6598) outright.
 *
 * A name that is not an IP literal returns false here; pair it with
 * `resolvesToPrivateOrLinkLocalAddress` (or `assertEgressHostAllowed`, which
 * does both) so a DNS name pointing at a private address is caught too.
 */
export function isPrivateOrLinkLocalHost(hostname: string): boolean {
  const host = bareHost(hostname)
  if (host === 'localhost' || host.endsWith('.localhost')) return true
  const ipv6 = parseIpv6(host)
  if (ipv6) return isPrivateIpv6Address(ipv6)
  const ipv4 = parseIpv4(host)
  return ipv4 !== null && isPrivateIpv4Address(ipv4)
}

/** True when `host` is an IP literal in any spelling, so DNS resolution would be pointless. */
export function isIpLiteral(host: string): boolean {
  const bare = bareHost(host)
  return parseIpv6(bare) !== null || parseIpv4(bare) !== null
}

/**
 * Resolves `hostname` and returns true if ANY resolved address is non-public.
 * The literal check alone only catches an IP appearing directly in the URL; a
 * malicious registry can instead return an ordinary-looking DNS name that
 * resolves to a private address.
 *
 * This is a check-time resolution, NOT an IP pin — the subsequent download
 * re-resolves independently, so an attacker controlling authoritative DNS could
 * rebind between check and connection. Defence-in-depth against the static case,
 * not a complete rebinding defence.
 *
 * A lookup failure is deliberately not caught: it propagates and fails with an
 * accurate DNS error rather than a misleading "host is private".
 */
export async function resolvesToPrivateOrLinkLocalAddress(
  hostname: string,
  lookup: (host: string) => Promise<{ address: string }[]> = (host) =>
    dnsPromises.lookup(host, { all: true }),
): Promise<boolean> {
  const addresses = await lookup(bareHost(hostname))
  return addresses.some((a) => isPrivateOrLinkLocalHost(a.address))
}

/** Caller-supplied rejection text, so each call site keeps its own wording. */
export interface EgressHostMessages {
  /** Host is not in the operator's explicit allowlist. */
  notAllowed: (hostname: string, allowedHosts: string) => string
  /** Host is (or resolves to) a private/link-local/reserved address on the default-deny path. */
  isPrivate: (hostname: string) => string
}

/**
 * THE egress-authorization decision for a destination. Every call site — the
 * initial URL AND every redirect hop — must route through this one function
 * rather than open-coding the branches, which is how a mirror path once ended up
 * re-checking only the textual blocklist per hop while its initial check also
 * resolved DNS.
 *
 *  - allowedHosts non-empty → the operator has explicitly pinned the trusted
 *    hosts, including a deliberately-private air-gapped mirror; only the pin is
 *    enforced, on every hop.
 *  - allowedHosts empty → default deny: refuse a host that IS a private/
 *    link-local/reserved address in any spelling, or that RESOLVES to one.
 *
 * Throws rather than returning a boolean, so the rejection carries the call
 * site's own message naming the offending host.
 */
export async function assertEgressHostAllowed(
  hostname: string,
  allowedHosts: string[],
  messages: EgressHostMessages,
  lookup?: (host: string) => Promise<{ address: string }[]>,
): Promise<void> {
  if (allowedHosts.length > 0) {
    if (!isHostAllowed(hostname, allowedHosts)) {
      const nearMiss = looseSuffixOnlyMatch(hostname, allowedHosts)
      const hint = nearMiss
        ? ` Note: '${nearMiss}' matches exactly one label (RFC 6125 wildcard semantics), so it does` +
          ` not cover the additional label(s) in '${hostname}'. Pin the host explicitly if it is intended.`
        : ''
      throw new Error(messages.notAllowed(hostname, allowedHosts.join(', ')) + hint)
    }
    return
  }
  if (isPrivateOrLinkLocalHost(hostname)) {
    throw new Error(messages.isPrivate(hostname))
  }
  // An IP literal was already decided above; only a DNS name needs resolving.
  if (isIpLiteral(hostname)) return
  if (await resolvesToPrivateOrLinkLocalAddress(hostname, lookup)) {
    throw new Error(messages.isPrivate(hostname))
  }
}
