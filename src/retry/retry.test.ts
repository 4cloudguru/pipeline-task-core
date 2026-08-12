import { describe, expect, it, vi } from 'vitest'

import { RETRY_AFTER_CAP_MS, parseRetryAfterMs } from './retry-after'
import { retryAsync } from './retry'

/**
 * CLASS TEST — defect class `network-retry` (ledger #879).
 *
 * SCOPE. What a green run here claims: for every retry primitive this module
 * exports, the backoff schedule, the wall-clock budget, the retry/terminal
 * predicates and the Retry-After cap behave as documented, and a caller cannot
 * be stalled indefinitely by a hostile server.
 *
 * What it claims NOTHING about: whether a given CONSUMER actually routes its
 * network calls through here — that is the signature's job, not the test's;
 * retries performed inside dependencies; or transport-level concerns (TLS,
 * redirects, response caps) which belong to the egress and http modules.
 *
 * Table A drives behaviour. Table B hand-verdicts the exported surface, so a
 * new export cannot be added without a deliberate decision about its retry
 * semantics.
 */

// A deterministic entropy source, so jitter assertions are exact rather than ranged.
const fixedRandom = (value: number) => () => value

describe('Table A — retryAsync behaviour', () => {
  it('returns the first successful result without retrying', async () => {
    const call = vi.fn().mockResolvedValue('ok')
    await expect(retryAsync(call)).resolves.toBe('ok')
    expect(call).toHaveBeenCalledTimes(1)
  })

  it('retries a transient failure and then succeeds', async () => {
    const call = vi
      .fn()
      .mockRejectedValueOnce(new Error('transient'))
      .mockResolvedValue('ok')
    await expect(retryAsync(call, { baseDelayMs: 0, maxBackoffMs: 0 })).resolves.toBe('ok')
    expect(call).toHaveBeenCalledTimes(2)
  })

  it('gives up after `retries` and rethrows the final error', async () => {
    const call = vi.fn().mockRejectedValue(new Error('always'))
    await expect(retryAsync(call, { retries: 2, baseDelayMs: 0, maxBackoffMs: 0 })).rejects.toThrow('always')
    // retries + 1 total attempts
    expect(call).toHaveBeenCalledTimes(3)
  })

  it('does NOT retry an error the predicate calls terminal', async () => {
    const call = vi.fn().mockRejectedValue(new Error('egress rejected'))
    await expect(
      retryAsync(call, { baseDelayMs: 0, retryError: () => false }),
    ).rejects.toThrow('egress rejected')
    expect(call).toHaveBeenCalledTimes(1)
  })

  it('retries a resolved value only when retryResult says so', async () => {
    const call = vi.fn().mockResolvedValueOnce(429).mockResolvedValue(200)
    const result = await retryAsync(call, {
      baseDelayMs: 0,
      maxBackoffMs: 0,
      retryResult: (status) => status === 429,
    })
    expect(result).toBe(200)
    expect(call).toHaveBeenCalledTimes(2)
  })

  it('never retries a resolved value by default', async () => {
    const call = vi.fn().mockResolvedValue(500)
    await expect(retryAsync(call, { baseDelayMs: 0 })).resolves.toBe(500)
    expect(call).toHaveBeenCalledTimes(1)
  })

  it('uses decorrelated jitter, not a fixed exponential schedule', async () => {
    const delays: number[] = []
    const call = vi.fn().mockRejectedValue(new Error('x'))
    await expect(
      retryAsync(call, {
        retries: 3,
        baseDelayMs: 100,
        random: fixedRandom(1), // take the top of each jitter window
        onRetry: (_attempt, delayMs) => delays.push(delayMs),
      }),
    ).rejects.toThrow()
    // previousDelay seeds at base, window is [base, max(base, prev*3)]:
    // 100 -> 300 -> 900. A fixed base*2**attempt schedule would be 100/200/400.
    expect(delays).toEqual([300, 900, 2700])
  })

  it('clamps the jittered delay to maxBackoffMs', async () => {
    const delays: number[] = []
    const call = vi.fn().mockRejectedValue(new Error('x'))
    await expect(
      retryAsync(call, {
        retries: 3,
        baseDelayMs: 100,
        maxBackoffMs: 250,
        random: fixedRandom(1),
        onRetry: (_a, d) => delays.push(d),
      }),
    ).rejects.toThrow()
    expect(delays.every((d) => d <= 250)).toBe(true)
  })

  it('stops retrying once the wall-clock budget is spent', async () => {
    const call = vi.fn().mockRejectedValue(new Error('slow'))
    const started = Date.now()
    await expect(
      retryAsync(call, { retries: 50, baseDelayMs: 5, maxBackoffMs: 5, maxElapsedMs: 40 }),
    ).rejects.toThrow('slow')
    expect(Date.now() - started).toBeLessThan(1_000)
    // Far fewer than the 51 attempts the retry count alone would permit.
    expect(call.mock.calls.length).toBeLessThan(51)
  })

  it('lets delayMs override the backoff for a single attempt', async () => {
    const delays: number[] = []
    const call = vi.fn().mockRejectedValueOnce(new Error('x')).mockResolvedValue('ok')
    await retryAsync(call, {
      baseDelayMs: 1000,
      delayMs: () => 0,
      onRetry: (_a, d) => delays.push(d),
    })
    expect(delays).toEqual([0])
  })

  it('does not invoke onRetry on the final give-up', async () => {
    const onRetry = vi.fn()
    const call = vi.fn().mockRejectedValue(new Error('x'))
    await expect(retryAsync(call, { retries: 2, baseDelayMs: 0, maxBackoffMs: 0, onRetry })).rejects.toThrow()
    // 3 attempts, but only the 2 retries are announced.
    expect(onRetry).toHaveBeenCalledTimes(2)
  })

  it('reports which outcome triggered the retry', async () => {
    const outcomes: string[] = []
    const call = vi.fn().mockRejectedValueOnce(new Error('boom')).mockResolvedValueOnce(429).mockResolvedValue(200)
    await retryAsync(call, {
      baseDelayMs: 0,
      maxBackoffMs: 0,
      retryResult: (status) => status === 429,
      onRetry: (_a, _d, outcome) => outcomes.push(outcome.kind),
    })
    expect(outcomes).toEqual(['error', 'result'])
  })
})

describe('Table A — parseRetryAfterMs caps a hostile server', () => {
  it('caps delta-seconds at the ceiling', () => {
    expect(parseRetryAfterMs('86400')).toBe(RETRY_AFTER_CAP_MS)
  })

  it('caps an HTTP-date far in the future', () => {
    const now = Date.parse('2026-08-11T12:00:00Z')
    expect(parseRetryAfterMs('Wed, 12 Aug 2026 12:00:00 GMT', RETRY_AFTER_CAP_MS, now)).toBe(RETRY_AFTER_CAP_MS)
  })
})

/**
 * Table B — hand-verdicted export inventory.
 *
 * The signature proves consumers route through this module; this table proves
 * nothing is exported from it without a stated retry contract. Adding an export
 * without adding a row here fails the test.
 */
describe('Table B — exported surface is fully accounted for', () => {
  const VERDICTS: Record<string, string> = {
    retryAsync: 'schedules retries; bounded by both `retries` and the optional maxElapsedMs budget',
    parseRetryAfterMs: 'parses only; always clamped to capMs so a server cannot choose the delay',
    RETRY_AFTER_CAP_MS: 'the ceiling itself; a constant, no behaviour',
  }

  it('every runtime export has a verdict', async () => {
    const mod = { ...(await import('./retry')), ...(await import('./retry-after')) }
    const exported = Object.keys(mod).sort()
    expect(exported).toEqual(Object.keys(VERDICTS).sort())
  })
})
