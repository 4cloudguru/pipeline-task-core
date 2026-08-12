import { describe, expect, it } from 'vitest'

import { RETRY_AFTER_CAP_MS, parseRetryAfterMs } from './retry-after'

const NOW = Date.parse('2026-08-11T12:00:00Z')

describe('parseRetryAfterMs', () => {
  it('returns undefined when the header is absent', () => {
    expect(parseRetryAfterMs(null)).toBeUndefined()
    expect(parseRetryAfterMs(undefined)).toBeUndefined()
    expect(parseRetryAfterMs('   ')).toBeUndefined()
  })

  it('parses delta-seconds', () => {
    expect(parseRetryAfterMs('5')).toBe(5_000)
    expect(parseRetryAfterMs('0')).toBe(0)
  })

  it('rejects numeric forms Number() would otherwise accept', () => {
    for (const hostile of ['0x10', '1e3', '-5', '1.5', '+7', ' 12 x']) {
      expect(parseRetryAfterMs(hostile)).toBeUndefined()
    }
  })

  it('parses an HTTP-date in the future', () => {
    expect(parseRetryAfterMs('Tue, 11 Aug 2026 12:00:10 GMT', 30_000, NOW)).toBe(10_000)
  })

  it('ignores an HTTP-date at or before now', () => {
    expect(parseRetryAfterMs('Tue, 11 Aug 2026 12:00:00 GMT', 30_000, NOW)).toBeUndefined()
    expect(parseRetryAfterMs('Tue, 11 Aug 2026 11:59:00 GMT', 30_000, NOW)).toBeUndefined()
  })

  it('ignores an unparseable date', () => {
    expect(parseRetryAfterMs('not-a-date')).toBeUndefined()
  })

  it('clamps to the cap so an origin cannot park the agent', () => {
    expect(parseRetryAfterMs('86400')).toBe(RETRY_AFTER_CAP_MS)
    expect(parseRetryAfterMs('600', 1_000)).toBe(1_000)
    expect(parseRetryAfterMs('Wed, 12 Aug 2026 12:00:00 GMT', 30_000, NOW)).toBe(30_000)
  })

  it('treats a non-positive cap as zero rather than inverting the clamp', () => {
    expect(parseRetryAfterMs('60', 0)).toBe(0)
    expect(parseRetryAfterMs('60', -1)).toBe(0)
  })
})
