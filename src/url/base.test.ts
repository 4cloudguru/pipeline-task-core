import { describe, expect, it } from 'vitest'

import { assertPlainUrlBase } from './base'

describe('assertPlainUrlBase', () => {
  it.each([
    'https://registry.example.com',
    'https://registry.example.com/',
    'https://registry.example.com/mirror/',
    'https://registry.example.com:8443/deep/path',
    'https://10.0.0.5/private',
  ])('returns a plain https base unchanged: %s', (value) => {
    expect(assertPlainUrlBase('registryUrl', value, 'reject')).toBe(value)
  })

  it.each([
    ['a query string', 'https://registry.example.com/?x='],
    ['a query string on a path', 'https://registry.example.com/mirror?token=abc'],
    ['a bare ?', 'https://registry.example.com/?'],
    ['a fragment', 'https://registry.example.com/#frag'],
    ['a bare #', 'https://registry.example.com/#'],
    ['both', 'https://registry.example.com/?x=1#y'],
  ])('rejects %s, naming the input', (_, value) => {
    expect(() => assertPlainUrlBase('mirrorBaseUrl', value, 'allow')).toThrow(
      /^mirrorBaseUrl must not carry a query string or fragment/,
    )
  })

  it('rejects a non-https scheme', () => {
    expect(() => assertPlainUrlBase('registryUrl', 'http://registry.example.com', 'allow')).toThrow(
      /^registryUrl must use https:\/\/ \(got http:\/\//,
    )
    expect(() => assertPlainUrlBase('registryUrl', 'ftp://registry.example.com', 'allow')).toThrow(
      /must use https/,
    )
  })

  it.each(['', 'registry.example.com', 'not a url', '//host/path', 'https://'])(
    'rejects an unparseable value: %j',
    (value) => {
      expect(() => assertPlainUrlBase('registryUrl', value, 'allow')).toThrow(
        /^registryUrl is not a valid absolute URL/,
      )
    },
  )

  it('applies the userinfo policy the caller declared', () => {
    const withCreds = 'https://user:pass@mirror.example.com/packer'
    expect(assertPlainUrlBase('mirrorBaseUrl', withCreds, 'allow')).toBe(withCreds)
    expect(() => assertPlainUrlBase('registryUrl', withCreds, 'reject')).toThrow(
      /^registryUrl must not carry user:password@ credentials/,
    )
    expect(() => assertPlainUrlBase('registryUrl', 'https://user@x.example.com', 'reject')).toThrow(
      /must not carry user:password@/,
    )
  })

  it('never echoes userinfo, query or fragment content in the message', () => {
    for (const [value, policy] of [
      ['https://alice:s3cr3t-pw@registry.example.com/?sig=TOKENVALUE#FRAGVALUE', 'allow'],
      ['https://alice:s3cr3t-pw@registry.example.com/', 'reject'],
    ] as const) {
      let message = ''
      try {
        assertPlainUrlBase('registryUrl', value, policy)
      } catch (err) {
        message = (err as Error).message
      }
      expect(message).not.toBe('')
      expect(message).not.toContain('s3cr3t-pw')
      expect(message).not.toContain('alice')
      expect(message).not.toContain('TOKENVALUE')
      expect(message).not.toContain('FRAGVALUE')
      expect(message).toContain('https://registry.example.com/')
    }
  })

  it('bounds and sanitizes an unparseable value before echoing it', () => {
    const long = 'x'.repeat(500)
    expect(() => assertPlainUrlBase('registryUrl', long, 'allow')).toThrow(/x{100}\.\.\./)
    let message = ''
    try {
      assertPlainUrlBase('registryUrl', 'bad\r\n##vso[task.setvariable variable=a]b', 'allow')
    } catch (err) {
      message = (err as Error).message
    }
    expect(message).not.toMatch(/[\r\n]/)
  })
})
