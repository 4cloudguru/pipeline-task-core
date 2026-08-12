/**
 * Validation for an operator-supplied value before it is interpolated into a
 * URL path.
 *
 * Ported from the `url-path-segment.ts` copies in azure-pipelines-terraform and
 * azure-pipelines-packer.
 */
import { stripControlCharacters } from './redaction'

/**
 * Must start with a letter or digit — which alone rejects `.` and `..` — and
 * may then contain only letters, digits, `.`, `_` and `-`.
 */
const URL_PATH_SEGMENT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/

/** Bound on the rejected value echoed back, so an oversized input cannot flood the log. */
const MAX_ECHOED_VALUE_CHARS = 100

/**
 * Rejects path separators and traversal shapes, returning the value unchanged
 * so a call site can validate and assign in one step.
 *
 * A charset-only pattern is not enough: `/^[A-Za-z0-9._-]+$/` matches the
 * literal `..`, so a mirror name of `..` produced
 * `https://registry.example.com/terraform/binaries/../versions/latest`, which
 * the WHATWG parser normalizes to `/terraform/versions/latest` before the
 * request goes out — a one-segment escape from the intended API namespace.
 * Both the leading-alphanumeric anchor and the explicit `..` rejection are
 * enforced, so an embedded traversal pair is caught too.
 */
export function validateUrlPathSegment(inputName: string, value: string): string {
  if (!URL_PATH_SEGMENT_PATTERN.test(value) || value.includes('..')) {
    throw new Error(
      `${inputName} '${echoable(value)}' is not a valid URL path segment: it must start with a letter ` +
        `or digit, contain only letters, digits, '.', '_', '-', and must not contain '..'.`,
    )
  }
  return value
}

/**
 * The rejected value is attacker-influenced and this message gets logged, so a
 * CR/LF in it would forge a `##vso[...]` command on the next line — the same
 * hazard the redaction module neutralizes on the way to `setVariable`.
 */
function echoable(value: string): string {
  const stripped = stripControlCharacters(value)
  return stripped.length > MAX_ECHOED_VALUE_CHARS
    ? `${stripped.slice(0, MAX_ECHOED_VALUE_CHARS)}...`
    : stripped
}
