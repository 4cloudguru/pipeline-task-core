/**
 * SCOPE — what a green run here does and does not claim.
 *
 * DOES claim: a PEM body is re-wrapped to standard 64-char LF-wrapped form
 * regardless of whether the input used spaces or CRLF instead of newlines;
 * malformed input (missing header/footer, empty body, non-base64 body,
 * mismatched header/footer labels, or a body that is valid base64 but not a
 * key crypto can parse) is rejected with a distinguishing message.
 *
 * Does NOT claim: that any particular key TYPE (RSA vs EC vs Ed25519) is
 * supported beyond what `crypto.createPrivateKey()` itself accepts — that is
 * Node's contract, not this module's.
 */
import { describe, expect, it } from 'vitest'
import { normalizePem } from './pem-normalizer'

// A PKCS#8 EC P-256 private key used ONLY in tests — it has zero access to
// any real infrastructure.
const TEST_KEY_PEM =
  '-----BEGIN PRIVATE KEY-----\n' +
  'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgIwyERSFzQgCvXZNB\n' +
  'OKG4XWPRXkZSEiTXPWIXcnbCciGhRANCAASwmlpLUCI6U52pVpbzAqXCbny9wTFc\n' +
  'iKZ0WdIidDIdA3L8AHgObTZlkx28C42vNqt375Sm0ix77WI1ej2YUgwk\n' +
  '-----END PRIVATE KEY-----\n'

// The same key delivered the way an Azure DevOps service connection
// multi-line secret input flattens it: newlines collapsed to single spaces.
const TEST_KEY_SPACES =
  '-----BEGIN PRIVATE KEY----- MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgIwyERSFzQgCvXZNB OKG4XWPRXkZSEiTXPWIXcnbCciGhRANCAASwmlpLUCI6U52pVpbzAqXCbny9wTFc iKZ0WdIidDIdA3L8AHgObTZlkx28C42vNqt375Sm0ix77WI1ej2YUgwk -----END PRIVATE KEY-----'

const TEST_KEY_CRLF =
  '-----BEGIN PRIVATE KEY-----\r\n' +
  'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgIwyERSFzQgCvXZNB\r\n' +
  'OKG4XWPRXkZSEiTXPWIXcnbCciGhRANCAASwmlpLUCI6U52pVpbzAqXCbny9wTFc\r\n' +
  'iKZ0WdIidDIdA3L8AHgObTZlkx28C42vNqt375Sm0ix77WI1ej2YUgwk\r\n' +
  '-----END PRIVATE KEY-----\r\n'

describe('pem-normalizer — accepted', () => {
  it.each([
    [TEST_KEY_PEM, 'already-standard LF-wrapped PEM'],
    [TEST_KEY_SPACES, 'newlines flattened to spaces (ADO service connection format)'],
    [TEST_KEY_CRLF, 'CRLF line endings'],
  ])('normalizes %s to the standard form (%s)', (input) => {
    expect(normalizePem(input)).toBe(TEST_KEY_PEM)
  })

  it('re-wraps a body wider than 64 characters at exactly 64 characters per line', () => {
    const result = normalizePem(TEST_KEY_SPACES)
    const bodyLines = result.split('\n').slice(1, -2)
    for (const line of bodyLines) {
      expect(line.length).toBeLessThanOrEqual(64)
    }
  })
})

describe('pem-normalizer — rejected', () => {
  it('rejects input missing a header or footer', () => {
    expect(() => normalizePem('MIGHAgEAMBMGByqG...')).toThrow('missing header or footer')
  })

  it('rejects an empty key body', () => {
    expect(() => normalizePem('-----BEGIN PRIVATE KEY----------END PRIVATE KEY-----')).toThrow(
      'empty key body',
    )
  })

  it('rejects a body containing non-base64 characters', () => {
    expect(() =>
      normalizePem('-----BEGIN PRIVATE KEY----- !!!invalid!!! -----END PRIVATE KEY-----'),
    ).toThrow('non-base64 characters')
  })

  it('rejects mismatched header/footer labels', () => {
    expect(() =>
      normalizePem('-----BEGIN RSA PRIVATE KEY----- abc -----END PRIVATE KEY-----'),
    ).toThrow('does not match footer label')
  })

  it('rejects a body that is valid base64 but not a key crypto can parse', () => {
    expect(() =>
      normalizePem(
        '-----BEGIN PRIVATE KEY----- dGhpcyBpcyBub3QgYSBrZXk= -----END PRIVATE KEY-----',
      ),
    ).toThrow('crypto validation failed')
  })
})
