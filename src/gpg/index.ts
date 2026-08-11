/**
 * `@sethbacon/pipeline-task-core/gpg` — detached-signature verification.
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
 * Implementation lands in Phase 0; this entrypoint fixes the contract.
 */

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
}

export type VerifyDetached = (request: VerifyDetachedRequest) => Promise<VerifyDetachedResult>
