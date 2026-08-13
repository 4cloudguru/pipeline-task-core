/**
 * SCOPE — what a green run here does and does not claim.
 *
 * DOES claim: sensitive query parameters are recognized across the Azure, AWS
 * and GCS pre-signed spellings; extracted secrets cover both the raw and the
 * decoded byte sequence, since either can reach a log; the whole query string
 * is dropped rather than named parameters, so an unforeseen token cannot slip
 * through; userinfo is located the way the WHATWG parser locates it; and
 * control characters are neutralized on every path that reaches a log.
 *
 * Does NOT claim: that a credential is masked. These functions only IDENTIFY
 * material and produce display-safe strings — registering the secrets with the
 * agent's masker is the caller's job, and forgetting to call setSecret() is
 * invisible here. Nor that redacted output is safe to expose to an untrusted
 * reader: the host, path and structure of a URL survive by design, and that is
 * itself information.
 */
import { describe, expect, it } from 'vitest'
import * as redactionModule from './redaction'
import {
  LOG_EXCERPT_CHARS,
  extractUrlTokenSecrets,
  extractUrlUserInfoSecrets,
  redactUrl,
  redactUrlUserInfo,
  scrubSecretsFromMessage,
  stripControlCharacters,
  truncateForLog,
} from './redaction'

describe('url/redaction — sensitive query parameters', () => {
  it.each([
    ['https://s.blob.core.windows.net/c/b?sig=ABC123', ['ABC123'], 'Azure SAS sig'],
    ['https://s.blob.core.windows.net/c/b?SIG=ABC123', ['ABC123'], 'case-insensitive'],
    ['https://s3.amazonaws.com/b/k?X-Amz-Signature=DEAD', ['DEAD'], 'AWS signature'],
    [
      'https://s3.amazonaws.com/b/k?X-Amz-Credential=AKIA%2F1',
      ['AKIA%2F1', 'AKIA/1'],
      'AWS credential, both forms',
    ],
    ['https://s3.amazonaws.com/b/k?X-Amz-Security-Token=TOK', ['TOK'], 'AWS session token'],
    ['https://storage.googleapis.com/b/o?X-Goog-Signature=SIG', ['SIG'], 'GCS signature'],
    ['https://storage.googleapis.com/b/o?X-Goog-Credential=CRED', ['CRED'], 'GCS credential'],
    ['https://h/p?access_token=T', ['T'], 'generic token parameter'],
    ['https://h/p?se=2026-01-01&sp=r&sr=b', [], 'benign SAS parameters are left alone'],
    ['https://h/p?version=1.2.3', [], 'ordinary parameter'],
    ['https://h/p', [], 'no query at all'],
    ['https://h/p?sig=', [], 'empty value is not a secret'],
    ['https://h/p?sig', [], 'valueless parameter'],
  ])('%s -> %j (%s)', (url, expected) => {
    expect(extractUrlTokenSecrets(url)).toEqual(expected)
  })

  it('stops at the fragment, so a #-suffixed value is not swept in', () => {
    expect(extractUrlTokenSecrets('https://h/p?sig=REAL#sig=NOTAQUERY')).toEqual(['REAL'])
  })

  it('collects every sensitive parameter, not just the first', () => {
    expect(
      extractUrlTokenSecrets('https://h/p?X-Amz-Credential=C&other=x&X-Amz-Signature=S'),
    ).toEqual(['C', 'S'])
  })

  it('keeps a value whose percent-decoding fails, rather than dropping it', () => {
    expect(extractUrlTokenSecrets('https://h/p?sig=%E0%A4%A')).toEqual(['%E0%A4%A'])
  })
})

describe('url/redaction — redactUrl', () => {
  it.each([
    ['https://h/p?sig=ABC', 'https://h/p?<redacted>', 'query replaced wholesale'],
    ['https://h/p?benign=1', 'https://h/p?<redacted>', 'even a benign query goes'],
    ['https://h/p', 'https://h/p', 'no query, nothing to do'],
    ['https://h:8443/p?sig=A', 'https://h:8443/p?<redacted>', 'port retained'],
    ['https://h/p?sig=A#frag', 'https://h/p?<redacted>', 'fragment dropped'],
  ])('%s -> %s (%s)', (url, expected) => {
    expect(redactUrl(url)).toBe(expected)
  })

  it('drops the whole query rather than named parameters, so an unknown token cannot survive', () => {
    expect(redactUrl('https://h/p?X-Future-Auth-Blob=SECRET')).not.toContain('SECRET')
  })

  it('neutralizes control characters on the unparseable fallback path', () => {
    // The parse path is safe already: the parser strips CR/LF and
    // percent-encodes the rest. This is the branch that reaches a log raw.
    const forged = 'not a url\n##vso[task.setvariable variable=x]owned'
    const out = redactUrl(forged)
    expect(out).not.toMatch(/[\r\n]/)
    expect(out).toBe('not a url##vso[task.setvariable variable=x]owned')
  })

  it('still strips the query on the fallback path', () => {
    expect(redactUrl('::::?sig=ABC')).toBe('::::')
  })
})

describe('url/redaction — scrubSecretsFromMessage', () => {
  it('replaces every occurrence of the URL, not only the first', () => {
    const url = 'https://h/p?sig=ABC'
    const message = `failed ${url} while retrying ${url}`
    expect(scrubSecretsFromMessage(message, url, [])).toBe(
      'failed https://h/p?<redacted> while retrying https://h/p?<redacted>',
    )
  })

  it('scrubs the token even when the URL was transformed by something downstream', () => {
    const out = scrubSecretsFromMessage(
      'tool-lib logged sig=XXX partially',
      'https://h/p?sig=XXX',
      ['XXX'],
    )
    expect(out).toBe('tool-lib logged sig=<redacted> partially')
  })

  it('survives an empty URL instead of shredding the message', () => {
    // No guard is needed for this: redactUrl('') is also '', so splitting on ''
    // and rejoining with '' is the identity. Pinned because it looks unsafe.
    expect(scrubSecretsFromMessage('a normal message', '', [])).toBe('a normal message')
  })

  it('ignores an empty secret, which WOULD shred the message', () => {
    expect(scrubSecretsFromMessage('a normal message', 'https://h/p', [''])).toBe(
      'a normal message',
    )
  })
})

describe('url/redaction — userinfo extraction', () => {
  it.each([
    ['https://user:pass@h/p', ['user:pass', 'pass'], 'pair and password'],
    ['https://user:p%40ss@h/p', ['user:p%40ss', 'user:p@ss', 'p%40ss', 'p@ss'], 'raw and decoded'],
    ['https://token@h/p', ['token'], 'lone userinfo is treated as a token'],
    ['https://user:@h/p', ['user:'], 'empty password contributes nothing extra'],
    ['https://h/p', [], 'no userinfo'],
    ['https://h/p@notauthority', [], '@ after the path is not userinfo'],
    ['https://user:pa@ss@h/p', ['user:pa@ss', 'pa@ss'], 'last @ splits, so @ in password works'],
    ['not-a-url', [], 'no scheme separator'],
  ])('%s -> %j (%s)', (url, expected) => {
    expect(extractUrlUserInfoSecrets(url)).toEqual(expected)
  })

  it('does not mask a bare username, which would redact unrelated log lines', () => {
    expect(extractUrlUserInfoSecrets('https://admin:s3cret@h/p')).not.toContain('admin')
  })

  it('bounds the authority at the query, not just the path', () => {
    // No '/' before the '?', so the path delimiter cannot do the bounding here
    // and the query delimiter has to.
    expect(extractUrlUserInfoSecrets('https://h?next=a@b')).toEqual([])
    expect(extractUrlUserInfoSecrets('https://h/p?next=a@b')).toEqual([])
  })

  it('bounds the authority at the fragment too', () => {
    expect(extractUrlUserInfoSecrets('https://h#frag=a@b')).toEqual([])
  })
})

describe('url/redaction — redactUrlUserInfo', () => {
  it.each([
    ['https://user:pass@h/p', 'https://h/p', 'credential removed'],
    ['https://user:pass@h:8443/p?q=1', 'https://h:8443/p?q=1', 'port and query retained'],
    ['https://h/p?q=1', 'https://h/p?q=1', 'nothing to strip'],
    ['https://user:pa@ss@h/p', 'https://h/p', 'last @ splits'],
    ['https://token@h/', 'https://h/', 'lone userinfo'],
    ['not-a-url', 'not-a-url', 'unparseable passes through'],
  ])('%s -> %s (%s)', (url, expected) => {
    expect(redactUrlUserInfo(url)).toBe(expected)
  })

  it('keeps the query, unlike redactUrl, so the operator can still see which registry ran', () => {
    expect(redactUrlUserInfo('https://u:p@h/p?mirror=internal')).toBe('https://h/p?mirror=internal')
  })

  it('strips a newline that would forge a second logging command', () => {
    // This value is echoed via ##vso[task.setvariable variable=x]VALUE, where a
    // CR/LF starts a new command on the following line.
    const forged = 'https://h/p\n##vso[task.setvariable variable=owned]1'
    expect(redactUrlUserInfo(forged)).toBe('https://h/p##vso[task.setvariable variable=owned]1')
  })

  it('strips before locating the userinfo, so the offsets line up with what is returned', () => {
    expect(redactUrlUserInfo('https://us\ner:pass@h/p')).toBe('https://h/p')
  })

  it('is not fooled by a URL that new URL() would accept after silently stripping CR/LF', () => {
    // new URL('https://ex\nample.com') parses clean, which is why validation
    // upstream does not catch this.
    expect(new URL('https://ex\nample.com').host).toBe('example.com')
    expect(redactUrlUserInfo('https://ex\nample.com')).toBe('https://example.com')
  })
})

describe('url/redaction — stripControlCharacters', () => {
  it.each([
    ['a\nb', 'ab', 'LF'],
    ['a\rb', 'ab', 'CR'],
    ['a\tb', 'ab', 'TAB'],
    ['a\u0000b', 'ab', 'NUL'],
    ['a\u001Fb', 'ab', 'top of the C0 range'],
    ['a\u007Fb', 'ab', 'DEL'],
    ['a\u0020b', 'a b', 'space is not a control character'],
    ['plain', 'plain', 'nothing to do'],
  ])('%j -> %j (%s)', (input, expected) => {
    expect(stripControlCharacters(input)).toBe(expected)
  })
})

/**
 * TABLE B — export inventory, verdicted by hand.
 */
describe('url/redaction — public surface', () => {
  it('exports exactly the reviewed set', () => {
    expect(Object.keys(redactionModule).sort()).toEqual([
      'LOG_EXCERPT_CHARS',
      'extractUrlTokenSecrets',
      'extractUrlUserInfoSecrets',
      'redactUrl',
      'redactUrlUserInfo',
      'scrubSecretsFromMessage',
      'stripControlCharacters',
      'truncateForLog',
    ])
  })
})

/**
 * TABLE C — remote-controlled text bound for a log line or CI annotation.
 *
 * The defect this closes, present in both GitHub Actions in this family, is a
 * thrown Error whose message interpolates a response body straight off the
 * wire. `core.setFailed` percent-encodes only `%`, CR and LF, so the length
 * and every other control character were the remote peer's choice.
 *
 * Control characters are built with String.fromCharCode so the fixtures stay
 * readable and no literal C0 byte sits in this source file.
 */
const CTRL = (code: number): string => String.fromCharCode(code)
const CONTROL_CHAR_PATTERN = new RegExp('[\\u0000-\\u001F\\u007F]')

describe('url/redaction - truncateForLog', () => {
  it.each([
    ['short', 10, 'short', 'under the limit is returned unchanged'],
    ['exactly-ten', 11, 'exactly-ten', 'exactly at the limit is not truncated'],
    ['a' + CTRL(0) + 'bc', 10, 'abc', 'NUL is stripped'],
    ['a' + CTRL(13) + CTRL(10) + 'b', 10, 'ab', 'CR/LF cannot forge a second log line'],
    ['a' + CTRL(9) + 'b', 10, 'ab', 'TAB is stripped like the other C0 characters'],
    ['a' + CTRL(31) + 'b', 10, 'ab', 'top of the C0 range is stripped'],
    ['a' + CTRL(127) + 'b', 10, 'ab', 'DEL is stripped'],
    ['plain text', 100, 'plain text', 'nothing to do'],
    ['', 10, '', 'empty input'],
  ])('%j @%i -> %j (%s)', (input, max, expected) => {
    expect(truncateForLog(input as string, max as number)).toBe(expected)
  })

  it('truncates past the limit and states how much was dropped', () => {
    expect(truncateForLog('x'.repeat(20), 5)).toBe(
      'xxxxx... (15 more characters truncated)'.replace('...', '…'),
    )
  })

  it('counts DISPLAYED characters - stripping runs before truncating', () => {
    // 10 payload characters interleaved with control characters. A
    // truncate-then-strip order would keep fewer than 10 visible characters
    // and would mis-state the remainder.
    const noisy = 'abcdefghij'.split('').join(CTRL(0)) + 'TAIL'
    expect(truncateForLog(noisy, 10)).toBe('abcdefghij… (4 more characters truncated)')
  })

  it('cannot be made to emit a control character at the truncation boundary', () => {
    const attack = 'A'.repeat(511) + CTRL(10) + '::error::forged' + 'B'.repeat(2000)
    const out = truncateForLog(attack)
    expect(CONTROL_CHAR_PATTERN.test(out)).toBe(false)
    expect(out.startsWith('A'.repeat(511))).toBe(true)
  })

  it('defaults to LOG_EXCERPT_CHARS', () => {
    const out = truncateForLog('y'.repeat(LOG_EXCERPT_CHARS + 100))
    expect(out.startsWith('y'.repeat(LOG_EXCERPT_CHARS))).toBe(true)
    expect(out).toContain('(100 more characters truncated)')
  })
})
