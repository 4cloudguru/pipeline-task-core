import { RETRY_AFTER_CAP_MS } from './retry-after'

/** What triggered a retry: a resolved value the caller deemed retryable, or a thrown error. */
export type RetryOutcome<T> =
  | { readonly kind: 'result'; readonly result: T }
  | { readonly kind: 'error'; readonly error: unknown }

export interface RetryController<T> {
  /** Retries AFTER the first attempt (total attempts = retries + 1). Default 3. */
  retries?: number
  /** Exponential-backoff base in ms; the default jittered delay is never below this. Default 500. */
  baseDelayMs?: number
  /** Upper bound (ms) on the default jittered delay. Default RETRY_AFTER_CAP_MS. */
  maxBackoffMs?: number
  /** Entropy source for the jittered delay, injectable so tests are deterministic. Default Math.random. */
  random?: () => number
  /**
   * Wall-clock budget (ms) across ALL attempts. Once spent, no further retry is
   * scheduled even if the attempt count and predicates would allow one. Without
   * it, a slow-failing call can outlive any useful deadline.
   */
  maxElapsedMs?: number
  /** Whether a resolved value is worth retrying. Default: never. */
  retryResult?: (result: T) => boolean
  /** Whether a thrown error is worth retrying. Default: always. */
  retryError?: (error: unknown) => boolean
  /** Override the pre-retry delay for one attempt; the default is decorrelated jitter. */
  delayMs?: (attempt: number, backoffMs: number, outcome: RetryOutcome<T>) => number
  /** Invoked once before each retry's delay, never on the final give-up. */
  onRetry?: (attempt: number, delayMs: number, outcome: RetryOutcome<T>) => void
}

/**
 * Run `call` with bounded, jittered-backoff retry. `attempt` is 0-based; a retry
 * is scheduled only while attempt < retries AND the elapsed-time budget (when
 * set) has not run out.
 *
 * The default delay uses decorrelated jitter (AWS, "Exponential Backoff And
 * Jitter"): `min(maxBackoffMs, baseDelayMs + random() * (max(baseDelayMs,
 * previousDelay * 3) - baseDelayMs))`, seeded at `baseDelayMs`. A plain
 * `baseDelayMs * 2**attempt` schedule would make every concurrent caller retry
 * a rate-limited endpoint in lockstep; jitter spreads them out.
 *
 * Policy lives in the predicates, not here: `retryResult` decides whether a
 * resolved value is worth repeating (default never — a received response may
 * carry server-side state, and repeating it can duplicate work), `retryError`
 * decides whether a thrown error is (default always — a transport failure
 * carries none).
 */
export async function retryAsync<T>(
  call: () => Promise<T>,
  controller: RetryController<T> = {},
): Promise<T> {
  const retries = controller.retries ?? 3
  const baseDelayMs = controller.baseDelayMs ?? 500
  const maxBackoffMs = controller.maxBackoffMs ?? RETRY_AFTER_CAP_MS
  const random = controller.random ?? Math.random
  const retryResult = controller.retryResult ?? (() => false)
  const retryError = controller.retryError ?? (() => true)
  const deadline =
    controller.maxElapsedMs !== undefined ? Date.now() + controller.maxElapsedMs : undefined

  let previousDelayMs = baseDelayMs

  for (let attempt = 0; ; attempt++) {
    const spent = deadline !== undefined && Date.now() >= deadline
    let outcome: RetryOutcome<T>

    try {
      const result = await call()
      if (attempt >= retries || spent || !retryResult(result)) {
        return result
      }
      outcome = { kind: 'result', result }
    } catch (error) {
      if (attempt >= retries || spent || !retryError(error)) {
        throw error
      }
      outcome = { kind: 'error', error }
    }

    const upperBound = Math.max(baseDelayMs, previousDelayMs * 3)
    const backoffMs = Math.min(maxBackoffMs, baseDelayMs + random() * (upperBound - baseDelayMs))
    previousDelayMs = backoffMs

    const wait = controller.delayMs ? controller.delayMs(attempt, backoffMs, outcome) : backoffMs
    controller.onRetry?.(attempt, wait, outcome)
    await new Promise<void>((resolve) => setTimeout(resolve, wait))
  }
}
