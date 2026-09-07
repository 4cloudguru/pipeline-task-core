/**
 * Validation for an operator-supplied URL that a task appends a path to.
 *
 * A registry or mirror base such as `https://registry.example.com` is only a
 * base if it ends where the task thinks it does. `${base}/api/v1/modules/x`
 * with a base of `https://registry.example.com/?x=` produces
 * `https://registry.example.com/?x=/api/v1/modules/x` — a request to `/` with
 * the whole intended path demoted to a query value — and a `#` swallows the
 * path entirely. Both parse, both pass a host allowlist (the host is unchanged),
 * and a bearer token or basic credential goes out on the retargeted request.
 * Raised as azure-pipelines-terraform#1110 finding 2 against one task; the same
 * concatenation exists in every installer of both extensions.
 *
 * Kept next to `validateUrlPathSegment`: that guards what goes AFTER the base,
 * this guards the base itself.
 */
import { stripControlCharacters } from './redaction'

/**
 * Whether `user:password@` in the base is acceptable. Explicit at every call
 * site, with no default, because the two real answers differ: a private mirror
 * behind basic auth is a documented pattern for the installers (`'allow'`),
 * while a registry API called with its own bearer token must not also carry a
 * second credential in the URL (`'reject'`).
 */
export type UrlBaseUserinfoPolicy = 'allow' | 'reject'

/** Bound on the rejected value echoed back, so an oversized input cannot flood the log. */
const MAX_ECHOED_VALUE_CHARS = 100

/**
 * Rejects a base that is not an absolute `https://` URL, or that carries a
 * query string, a fragment, or (under `'reject'`) userinfo — returning the
 * value unchanged so a call site can validate and assign in one step. Trailing
 * slashes are the caller's concern, as they were before.
 *
 * The message never echoes the value itself: it may hold a credential in its
 * userinfo or a token in its query, and the message is headed for the build
 * log. Only the parsed origin and path are shown.
 */
export function assertPlainUrlBase(
  inputName: string,
  value: string,
  userinfo: UrlBaseUserinfoPolicy,
): string {
  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    throw new Error(`${inputName} is not a valid absolute URL (${describeUnparseable(value)}).`)
  }
  const shown = `${parsed.protocol}//${parsed.host}${parsed.pathname}`
  if (parsed.protocol !== 'https:') {
    throw new Error(`${inputName} must use https:// (got ${parsed.protocol}// in ${shown}).`)
  }
  if (parsed.search || parsed.hash || value.endsWith('?') || value.endsWith('#')) {
    throw new Error(
      `${inputName} must not carry a query string or fragment: a path is appended to it, and ` +
        `'?' or '#' in the base would silently retarget the request (got ${shown} with ` +
        `${parsed.search || value.endsWith('?') ? 'a query string' : 'a fragment'}).`,
    )
  }
  if (userinfo === 'reject' && (parsed.username || parsed.password)) {
    throw new Error(
      `${inputName} must not carry user:password@ credentials: requests to it are authenticated ` +
        `separately (got ${shown} with userinfo).`,
    )
  }
  return value
}

/**
 * An unparseable value is echoed, bounded and with control characters removed,
 * because it has no origin to show instead — and a value the WHATWG parser
 * rejects cannot be carrying a credential it would have parsed as userinfo.
 */
function describeUnparseable(value: string): string {
  const stripped = stripControlCharacters(value)
  const shown =
    stripped.length > MAX_ECHOED_VALUE_CHARS
      ? `${stripped.slice(0, MAX_ECHOED_VALUE_CHARS)}...`
      : stripped
  return shown.length === 0 ? 'empty' : `'${shown}'`
}
