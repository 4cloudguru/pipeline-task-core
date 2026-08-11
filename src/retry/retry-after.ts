/**
 * Parses an HTTP `Retry-After` header into milliseconds.
 *
 * Accepts both forms permitted by RFC 9110 §10.2.3: delta-seconds, and an
 * HTTP-date. The result is clamped to `capMs` so a hostile or misconfigured
 * origin cannot park a pipeline agent for hours on a single 429.
 *
 * Returns `undefined` when the header is absent, malformed, or in the past —
 * callers fall back to their own backoff schedule.
 */
export function parseRetryAfterMs(
  value: string | null | undefined,
  capMs: number = DEFAULT_RETRY_AFTER_CAP_MS,
  now: number = Date.now(),
): number | undefined {
  if (value == null) return undefined

  const trimmed = value.trim()
  if (trimmed === '') return undefined

  // delta-seconds: digits only. Number() would accept '0x10', '1e3' and ' 12 '.
  if (/^\d+$/.test(trimmed)) {
    const seconds = Number(trimmed)
    if (!Number.isFinite(seconds)) return undefined
    return clamp(seconds * 1000, capMs)
  }

  const at = Date.parse(trimmed)
  if (Number.isNaN(at)) return undefined

  const delta = at - now
  if (delta <= 0) return undefined

  return clamp(delta, capMs)
}

/** Default ceiling applied to any server-supplied `Retry-After`. */
export const DEFAULT_RETRY_AFTER_CAP_MS = 30_000

function clamp(ms: number, capMs: number): number {
  const ceiling = capMs > 0 ? capMs : 0
  return Math.min(Math.max(Math.trunc(ms), 0), ceiling)
}
