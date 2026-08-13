/**
 * `@4cloudguru/pipeline-task-core/gpg` — detached-signature verification.
 *
 * Split from the root entrypoint so `openpgp` (an optional peer dependency) is
 * only resolved by consumers that actually verify release signatures. Tasks
 * that never do must not vendor it into their `.vsix`.
 *
 * The armoured public key is deliberately **not** shipped here. A signing key is
 * a trust root, and a trust root belongs in the repository that relies on it —
 * vendoring one transitively through a package means a compromise of that
 * package silently replaces it. Callers pass their own key in, and keep their
 * own key-freshness checks.
 *
 * Ported from the `gpg-verifier.ts` copies in azure-pipelines-terraform and
 * azure-pipelines-packer, reduced to the cryptographic decision. Fetching the
 * `.sig` and deciding what its ABSENCE means stays with the caller — see the
 * scope note on `verifyDetached`.
 */
import { createMessage, readKey, readSignature, verify } from 'openpgp'

/** A detached-signature verification request. */
export interface VerifyDetachedRequest {
  /** The bytes that were signed — typically a `SHA256SUMS` file. */
  readonly message: Uint8Array
  /** The detached signature, armoured or binary. */
  readonly signature: Uint8Array
  /** Armoured public key(s) the caller trusts. Supplied by the caller, never bundled. */
  readonly armoredPublicKeys: readonly string[]
}

/** The outcome of a verification attempt. */
export interface VerifyDetachedResult {
  /** True only when at least one supplied key produced a valid signature. */
  readonly verified: boolean
  /** Key ID that verified, when one did. */
  readonly keyId?: string
  /**
   * Why each candidate signature was rejected, when none verified.
   *
   * Present only on failure, and only when the library gave a reason. A bad
   * signature is the outcome an operator most needs to diagnose, and "it did not
   * verify" does not distinguish a key-rotation miss from a tampered file — so a
   * caller building an operator-facing error is not forced to discard what the
   * library already knew.
   */
  readonly reasons?: readonly string[]
}

export type VerifyDetached = (request: VerifyDetachedRequest) => Promise<VerifyDetachedResult>

const ARMOR_PREFIX = '-----BEGIN PGP'

/** How far in to look for the armour header before treating the bytes as binary. */
const ARMOR_SNIFF_BYTES = 64

function isArmored(bytes: Uint8Array): boolean {
  return Buffer.from(bytes.subarray(0, ARMOR_SNIFF_BYTES)).toString('latin1').includes(ARMOR_PREFIX)
}

/**
 * Verifies a detached signature over `message` against the caller's trusted keys.
 *
 * Returns `{ verified: false }` when the material parses but no supplied key
 * validates it. THROWS when an input cannot be parsed at all, or when no key was
 * supplied — an empty trust set can never verify anything, and reporting that as
 * an ordinary verification failure would send the caller looking at the artifact
 * instead of at their configuration.
 *
 * Scope note: this decides only whether a signature is GOOD. It does not decide
 * what a MISSING signature means. That distinction — a genuine 404 may downgrade
 * when the operator opted out, but a transport failure must always fail, so an
 * attacker who can merely disrupt the `.sig` fetch cannot strip verification —
 * is carried by the HTTP client's `fetchBufferAllow404`, which returns null only
 * for a real 404 and throws on anything else. A caller fetching the signature by
 * other means must reproduce that distinction itself.
 */
export async function verifyDetached(
  request: VerifyDetachedRequest,
): Promise<VerifyDetachedResult> {
  if (request.armoredPublicKeys.length === 0) {
    throw new Error('verifyDetached requires at least one armoured public key.')
  }

  const verificationKeys = await Promise.all(
    request.armoredPublicKeys.map((armoredKey) => readKey({ armoredKey })),
  )
  const signature = isArmored(request.signature)
    ? await readSignature({ armoredSignature: Buffer.from(request.signature).toString('utf8') })
    : await readSignature({ binarySignature: request.signature })

  const result = await verify({
    message: await createMessage({ binary: request.message }),
    signature,
    verificationKeys,
  })

  // A detached .sig can carry more than one signature, e.g. during a signing-key
  // rotation window. Accept a valid one at ANY index: openpgp REJECTS the
  // `verified` promise rather than resolving false, so checking only the first
  // would discard a good signature sitting behind a stale one.
  const outcomes = await Promise.allSettled(result.signatures.map((entry) => entry.verified))
  const index = outcomes.findIndex((outcome) => outcome.status === 'fulfilled')
  if (index === -1) {
    const reasons = outcomes
      .filter((outcome): outcome is PromiseRejectedResult => outcome.status === 'rejected')
      .map((outcome) =>
        outcome.reason instanceof Error ? outcome.reason.message : String(outcome.reason),
      )
      .filter((reason) => reason.length > 0)
    return reasons.length === 0 ? { verified: false } : { verified: false, reasons }
  }

  const keyId = result.signatures[index]?.keyID.toHex()
  return keyId === undefined ? { verified: true } : { verified: true, keyId }
}
