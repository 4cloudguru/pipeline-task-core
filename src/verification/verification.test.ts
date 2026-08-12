/**
 * SCOPE — what a green run here does and does not claim.
 *
 * DOES claim: a policy failure is recognized across class identities, which
 * matters because this package ships dual CJS/ESM builds; an artifact that
 * fails verification is removed; and the removal never masks or replaces the
 * error that caused it.
 *
 * Does NOT claim: that callers draw the fail-closed / degrade line correctly.
 * This provides the marker and the classifier — whether an installer throws
 * VerificationFailure for a withheld-but-required checksum, or wraps the
 * comparison rather than the lookup, is decided at each call site and is
 * invisible here. Nor that a discarded artifact is unrecoverable: unlink is not
 * a secure erase.
 */
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import * as verificationModule from './verification'
import {
  VerificationFailure,
  discardArtifactOnFailure,
  isVerificationFailure,
} from './verification'

describe('verification — VerificationFailure', () => {
  it('is an Error with a stable name marker', () => {
    const error = new VerificationFailure('checksum mismatch')
    expect(error).toBeInstanceOf(Error)
    expect(error).toBeInstanceOf(VerificationFailure)
    expect(error.name).toBe('VerificationFailure')
    expect(error.message).toBe('checksum mismatch')
  })

  it('carries a usable stack', () => {
    expect(new VerificationFailure('x').stack).toContain('VerificationFailure')
  })
})

describe('verification — isVerificationFailure', () => {
  it('recognizes its own instances', () => {
    expect(isVerificationFailure(new VerificationFailure('x'))).toBe(true)
  })

  it('recognizes an equivalent error from a DIFFERENT class identity', () => {
    // This package ships dual CJS and ESM builds, so a consumer can hold the
    // class from one entrypoint while the error came from the other. An
    // identity-only check would misfile a real policy failure as a transport
    // failure and fall back to a never-verified cached copy.
    class VerificationFailure extends Error {
      constructor(message: string) {
        super(message)
        this.name = 'VerificationFailure'
      }
    }
    const fromOtherRealm = new VerificationFailure('checksum mismatch')
    expect(isVerificationFailure(fromOtherRealm)).toBe(true)
  })

  it('recognizes a SUBCLASS that carries its own name', () => {
    // The name check alone would not see this one; the instanceof branch is
    // what makes a more specific diagnostic still count as a policy failure.
    class ChecksumMismatch extends VerificationFailure {
      constructor(message: string) {
        super(message)
        this.name = 'ChecksumMismatch'
      }
    }
    expect(isVerificationFailure(new ChecksumMismatch('sha256 differs'))).toBe(true)
  })

  it.each([
    [new Error('network unreachable'), 'a plain transport error'],
    [new TypeError('fetch failed'), 'a TypeError'],
    [{ name: 'VerificationFailure' }, 'a bare object wearing the name'],
    ['VerificationFailure', 'a string'],
    [null, 'null'],
    [undefined, 'undefined'],
  ])('rejects %s (%s)', (value, _why) => {
    expect(isVerificationFailure(value)).toBe(false)
  })

  it('does not classify a transport failure as a policy failure', () => {
    // The whole cache-reuse behaviour hangs off this: a false positive here
    // turns an offline-tolerant install into a hard failure, and a false
    // negative silently accepts an unverified binary.
    const timeout = new Error('Request to https://releases.example timed out after 60000ms.')
    expect(isVerificationFailure(timeout)).toBe(false)
  })
})

describe('verification — discardArtifactOnFailure', () => {
  let dir: string
  let artifact: string

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'ptc-verify-'))
    artifact = join(dir, 'tool.zip')
    writeFileSync(artifact, 'archive bytes')
  })
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  it('leaves the artifact in place when verification passes', async () => {
    const result = await discardArtifactOnFailure(artifact, async () => 'verified')
    expect(result).toBe('verified')
    expect(existsSync(artifact)).toBe(true)
  })

  it('deletes the artifact when verification fails', async () => {
    await expect(
      discardArtifactOnFailure(artifact, async () => {
        throw new VerificationFailure('sha256 mismatch')
      }),
    ).rejects.toThrow(/sha256 mismatch/)
    expect(
      existsSync(artifact),
      'a rejected artifact must not outlive the check that rejected it',
    ).toBe(false)
  })

  it('rethrows the original error, not a cleanup error', async () => {
    const original = new VerificationFailure('bad signature')
    const thrown = await discardArtifactOnFailure(artifact, async () => {
      throw original
    }).catch((error: unknown) => error)
    expect(thrown).toBe(original)
  })

  it('still rethrows when the artifact is already gone', async () => {
    rmSync(artifact)
    await expect(
      discardArtifactOnFailure(artifact, async () => {
        throw new VerificationFailure('sha256 mismatch')
      }),
    ).rejects.toThrow(/sha256 mismatch/)
  })

  it('does not let an unlink failure mask the verification error', async () => {
    // A directory cannot be removed with unlink, which stands in for any
    // best-effort cleanup that fails.
    const undeletable = join(dir, 'subdir')
    mkdtempSync(join(dir, 'subdir'))
    await expect(
      discardArtifactOnFailure(undeletable, async () => {
        throw new VerificationFailure('wrong key')
      }),
    ).rejects.toThrow(/wrong key/)
  })

  it('discards on ANY throw, not only a VerificationFailure', async () => {
    // A verifier that crashes has not established the artifact is good, so the
    // artifact is no more trustworthy than one that failed outright.
    await expect(
      discardArtifactOnFailure(artifact, async () => {
        throw new TypeError('verifier crashed')
      }),
    ).rejects.toThrow(/verifier crashed/)
    expect(existsSync(artifact)).toBe(false)
  })

  it('reports the discard on the injected debug channel', async () => {
    const messages: string[] = []
    await discardArtifactOnFailure(
      artifact,
      async () => {
        throw new VerificationFailure('mismatch')
      },
      { debug: (message) => messages.push(message) },
    ).catch(() => undefined)
    expect(messages).toEqual([`Discarded ${artifact}: it failed integrity verification.`])
  })

  it('says nothing on the debug channel when verification passes', async () => {
    const messages: string[] = []
    await discardArtifactOnFailure(artifact, async () => 'ok', {
      debug: (message) => messages.push(message),
    })
    expect(messages).toEqual([])
  })

  it('passes the resolved value through untouched', async () => {
    const value = { sha256: 'abc', verified: true }
    await expect(discardArtifactOnFailure(artifact, async () => value)).resolves.toBe(value)
  })
})

/**
 * TABLE B — export inventory, verdicted by hand.
 */
describe('verification — public surface', () => {
  it('exports exactly the reviewed set', () => {
    expect(Object.keys(verificationModule).sort()).toEqual([
      'VerificationFailure',
      'discardArtifactOnFailure',
      'isVerificationFailure',
    ])
  })
})
