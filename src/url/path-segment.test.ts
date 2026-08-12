/**
 * SCOPE — what a green run here does and does not claim.
 *
 * DOES claim: the accepted charset is exactly the documented one; both dot-only
 * names and embedded traversal pairs are rejected; separators and encoded
 * separators are rejected; and the rejection message cannot itself forge a
 * logging command or flood the log.
 *
 * Does NOT claim: that a call site actually calls this before interpolating.
 * A value that never reaches the validator is not protected by it, and nothing
 * here can see that.
 */
import { describe, expect, it } from 'vitest'
import * as pathSegmentModule from './path-segment'
import { validateUrlPathSegment } from './path-segment'

const check = (value: string): string => validateUrlPathSegment('registryMirrorName', value)

describe('url/path-segment — accepted', () => {
  it.each([
    ['terraform', 'plain name'],
    ['terraform-docs', 'hyphen'],
    ['my_mirror', 'underscore'],
    ['mirror.v2', 'single dot'],
    ['0start', 'leading digit'],
    ['A', 'single character'],
    ['a1.b_c-d', 'every permitted class'],
  ])('accepts %s (%s)', (value) => {
    expect(check(value)).toBe(value)
  })

  it('returns the value unchanged, so a call site can validate and assign at once', () => {
    expect(check('mirror.v2')).toBe('mirror.v2')
  })
})

describe('url/path-segment — rejected', () => {
  it.each([
    ['..', 'the traversal segment itself'],
    ['.', 'single dot'],
    ['...', 'triple dot contains a pair'],
    ['a..b', 'embedded traversal pair'],
    ['..a', 'leading pair'],
    ['a..', 'trailing pair'],
    ['a/b', 'path separator'],
    ['a\\b', 'backslash separator'],
    ['../etc', 'classic traversal'],
    ['%2e%2e', 'percent-encoded dots'],
    ['%2f', 'percent-encoded slash'],
    ['a%2fb', 'embedded encoded slash'],
    ['.hidden', 'leading dot'],
    ['-lead', 'leading hyphen'],
    ['_lead', 'leading underscore'],
    ['', 'empty'],
    [' ', 'space'],
    ['a b', 'embedded space'],
    ['a?b', 'query separator'],
    ['a#b', 'fragment separator'],
    ['a:b', 'colon'],
    ['a@b', 'at sign'],
    ['ünïcode', 'non-ASCII'],
    ['a\nb', 'newline'],
  ])('rejects %j (%s)', (value) => {
    expect(() => check(value)).toThrow(/is not a valid URL path segment/)
  })

  it('rejects the exact shape that escaped the namespace', () => {
    // '..' matched the old charset-only pattern, and the WHATWG parser then
    // normalized /binaries/../versions away to /versions.
    expect(new URL('https://r.example/tf/binaries/../versions/latest').pathname).toBe(
      '/tf/versions/latest',
    )
    expect(() => check('..')).toThrow()
  })

  it('names the offending input so an operator can find it', () => {
    expect(() => validateUrlPathSegment('mirrorName', 'a/b')).toThrow(/mirrorName 'a\/b'/)
  })
})

describe('url/path-segment — the rejection message is itself safe', () => {
  it('cannot forge a logging command through the echoed value', () => {
    const forged = 'bad\n##vso[task.setvariable variable=owned]1'
    const message = (() => {
      try {
        check(forged)
        return ''
      } catch (error) {
        return (error as Error).message
      }
    })()
    expect(message).not.toMatch(/[\r\n]/)
    expect(message).toContain('##vso[task.setvariable variable=owned]1')
  })

  it('bounds an oversized value so it cannot flood the log', () => {
    const message = (() => {
      try {
        check('/'.repeat(10_000))
        return ''
      } catch (error) {
        return (error as Error).message
      }
    })()
    expect(message.length).toBeLessThan(400)
    expect(message).toContain('...')
  })
})

/**
 * TABLE B — export inventory, verdicted by hand.
 */
describe('url/path-segment — public surface', () => {
  it('exports exactly the reviewed set', () => {
    expect(Object.keys(pathSegmentModule).sort()).toEqual(['validateUrlPathSegment'])
  })
})
