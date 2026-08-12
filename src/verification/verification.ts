/**
 * The fail-closed / degrade-gracefully boundary for artifact verification, and
 * the cleanup that follows a failure.
 *
 * Ported from the `verification-failure.ts` and `artifact-discard.ts` copies in
 * azure-pipelines-terraform (three each, byte-identical) and
 * azure-pipelines-packer (in sync). Kept together because they are one rule
 * seen from two sides: what counts as a policy failure, and what must not
 * survive one.
 */
import { promises as fsPromises } from 'node:fs'

/**
 * A REACHABLE source failed a REQUIRED verification policy. Two cases:
 *
 * 1. Material was obtained and the artifact FAILED against it — a bad or
 *    wrong-key signature, a checksum mismatch, or a checksum file that does not
 *    list the requested asset.
 * 2. Material a require-flag makes MANDATORY was deterministically WITHHELD by
 *    a reachable source — an empty registry sha256, or a reachable release that
 *    404s a signature it is required to serve.
 *
 * Both are reproducible policy failures, so retrying, or falling back to a
 * never-verified cached copy, is never the right answer.
 *
 * Deliberately NOT for material that is unavailable for a non-deterministic or
 * non-source reason: a transport outage, a 404 for material that is not
 * required, or a missing local verifier binary. The cache re-verification path
 * keys on exactly this distinction — a `VerificationFailure` fails closed,
 * while an unreachable source degrades to the cached tool with a warning, which
 * is what preserves offline and air-gapped cache reuse.
 */
export class VerificationFailure extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'VerificationFailure'
  }
}

/**
 * `instanceof` with a name-based fallback. Both branches earn their place.
 *
 * The fallback exists because this package ships dual CJS and ESM builds, so a
 * consumer can hold the class from one entrypoint while the error was
 * constructed by the other. Those are different class identities for the same
 * logical type, and an identity-only check would misfile a real policy failure
 * as a transport failure — turning a fail-closed decision into a
 * fall-back-to-cache one.
 *
 * The `instanceof` branch covers the reverse: a SUBCLASS that sets its own
 * `name` for a more specific diagnostic is still a policy failure, and the name
 * check alone would not see it.
 */
export function isVerificationFailure(error: unknown): boolean {
  return (
    error instanceof VerificationFailure ||
    (error instanceof Error && error.name === 'VerificationFailure')
  )
}

export interface DiscardOptions {
  /** Receives a note when an artifact is discarded. Wire to the task's debug channel. */
  debug?: (message: string) => void
}

/**
 * Runs `verify` over a freshly downloaded artifact and DELETES it if any check
 * inside throws.
 *
 * The download path already unlinks on a failed TRANSFER, but verification is a
 * separate later step: an archive whose checksum does not match — one that may
 * have been tampered with — otherwise sits in the agent's temp directory
 * indefinitely on a persistent self-hosted agent. The unlink is best-effort and
 * never masks the verification error that triggered it.
 *
 * Deliberately NOT for the agent's CACHED executable: that file belongs to the
 * tool cache and other jobs may be using it, so a failed cache re-verification
 * fails the task without evicting it.
 *
 * Also NOT for a checksum that is merely UNAVAILABLE when the operator has
 * opted out of requiring one — that install legitimately proceeds and the
 * artifact must survive. Wrap the comparison, not the lookup.
 */
export async function discardArtifactOnFailure<T>(
  artifactPath: string,
  verify: () => Promise<T>,
  options: DiscardOptions = {},
): Promise<T> {
  try {
    return await verify()
  } catch (error) {
    try {
      await fsPromises.unlink(artifactPath)
      options.debug?.(`Discarded ${artifactPath}: it failed integrity verification.`)
    } catch {
      // Nothing to remove, or removal failed; either way the verification
      // error above is what the caller needs to see.
    }
    throw error
  }
}
