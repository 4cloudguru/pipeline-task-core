/**
 * The destination test an operator's "turn TLS verification off" switch has to
 * pass before the task will honour it.
 *
 * A task input such as `skipTlsVerify` or `rejectUnauthorized=false` disables
 * certificate verification on a connection that then carries a bearer
 * credential (a registry API key, a one-shot callback token). The only case
 * that legitimately needs it is an INTERNAL endpoint fronted by a private CA
 * the agent does not trust, so the control is expressed as exactly that: the
 * destination must be provably private, not merely absent from a list of
 * well-known public hosts.
 *
 * A denylist is the wrong shape here and was bypassed in practice: WHATWG URL
 * parsing preserves a trailing dot, so `https://app.terraform.io./v1/modules`
 * has hostname `app.terraform.io.` — neither equal to `terraform.io` nor a
 * suffix match for `.terraform.io` — while DNS resolves the rooted FQDN to the
 * real public registry (azure-pipelines-terraform#588). Enumerating the public
 * internet is not a control; proving the destination private is.
 *
 * Kept next to `assertEgressHostAllowed`: that decides whether a destination
 * may be contacted at all, this decides whether it may be contacted with
 * certificate verification switched off.
 */
import { stripControlCharacters, redactUrlUserInfo } from '../url/redaction'
import {
  isIpLiteral,
  isPrivateOrLinkLocalHost,
  resolvesToPrivateOrLinkLocalAddress,
} from './egress'

/** Why a TLS-verification opt-out was refused. */
export type TlsOptOutRejection = 'unparseable' | 'userinfo' | 'not-private'

/** Bound on the rejected value echoed back, so an oversized input cannot flood the log. */
const MAX_ECHOED_VALUE_CHARS = 100

/**
 * A refusal carrying the reason and a destination string that is SAFE to log.
 *
 * Typed rather than a bare `Error` so each task can map the reason onto its own
 * localised message key without re-deriving the decision, and so a genuine
 * failure on the way to the decision (a DNS outage) stays distinguishable from
 * a refusal.
 */
export class TlsOptOutDestinationError extends Error {
  readonly inputName: string
  readonly reason: TlsOptOutRejection
  /** Never carries userinfo: a hostname, or a redacted/bounded rendering of an unparseable value. */
  readonly safeDestination: string

  constructor(inputName: string, reason: TlsOptOutRejection, safeDestination: string) {
    super(
      `${inputName} may not have TLS certificate verification disabled against '${safeDestination}' ` +
        `(${reason}): disabling verification is only appropriate for a private/internal endpoint ` +
        `fronted by a CA the agent does not trust.`,
    )
    this.name = 'TlsOptOutDestinationError'
    this.inputName = inputName
    this.reason = reason
    this.safeDestination = safeDestination
  }
}

/**
 * Lowercases and strips ONE trailing dot from a host before any comparison.
 *
 * The rooted-FQDN form (`app.terraform.io.`) resolves identically to the
 * unrooted one, so any decision that compares the raw `URL.hostname` decides
 * differently for two spellings of the same destination. A bracketed IPv6
 * literal has no trailing dot to strip and is left alone.
 */
export function normalizeDestinationHost(hostname: string): string {
  const host = stripControlCharacters(hostname).trim().toLowerCase()
  return host.length > 1 && host.endsWith('.') ? host.slice(0, -1) : host
}

/** Bounded, userinfo-free rendering of a value the URL parser rejected. */
function describeUnparseable(value: string): string {
  // A value `new URL()` rejected may still be a scheme-less `user:token@host/...`,
  // which the URL-shaped redactor cannot see — so anything with an '@' is
  // described rather than echoed.
  if (value.includes('@')) return '(value with userinfo, redacted)'
  const stripped = redactUrlUserInfo(stripControlCharacters(value))
  return stripped.length > MAX_ECHOED_VALUE_CHARS
    ? `${stripped.slice(0, MAX_ECHOED_VALUE_CHARS)}...`
    : stripped
}

/**
 * Throws unless `url`'s destination is provably private, and therefore a
 * destination on which disabling TLS certificate verification is defensible.
 *
 * Fail-closed at every step:
 *  - a value the WHATWG parser rejects, or one with no host, is `unparseable`
 *    (it cannot be confirmed safe, so it is not accepted);
 *  - userinfo in the base is refused outright — these requests carry their own
 *    token, and a second credential riding in the URL would be sent to a server
 *    whose certificate is not being checked;
 *  - the host is lowercased with ONE trailing dot stripped before EVERY
 *    comparison;
 *  - an IP literal is accepted only when it is private/link-local/reserved, in
 *    any spelling `isPrivateOrLinkLocalHost` understands (`127.1`, `0x7f000001`
 *    and `[::ffff:127.0.0.1]` all reach loopback);
 *  - any other name must RESOLVE to a private/link-local address.
 *
 * A DNS lookup failure is deliberately not caught: it propagates as its own
 * accurate error, which still fails the caller closed, rather than being
 * reported as "this host is public". `lookup` is injectable so a test can
 * decide the answer without touching the network.
 */
export async function assertTlsOptOutDestinationIsPrivate(
  inputName: string,
  url: string,
  lookup?: (host: string) => Promise<{ address: string }[]>,
): Promise<void> {
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    throw new TlsOptOutDestinationError(inputName, 'unparseable', describeUnparseable(url))
  }
  const host = normalizeDestinationHost(parsed.hostname)
  if (host.length === 0) {
    throw new TlsOptOutDestinationError(inputName, 'unparseable', describeUnparseable(url))
  }
  if (parsed.username || parsed.password) {
    throw new TlsOptOutDestinationError(inputName, 'userinfo', host)
  }
  if (isPrivateOrLinkLocalHost(host)) return
  // An IP literal was already decided above; only a name needs resolving, and a
  // literal that is not private must never be handed to DNS as if it were one.
  if (isIpLiteral(host)) {
    throw new TlsOptOutDestinationError(inputName, 'not-private', host)
  }
  if (!(await resolvesToPrivateOrLinkLocalAddress(host, lookup))) {
    throw new TlsOptOutDestinationError(inputName, 'not-private', host)
  }
}
