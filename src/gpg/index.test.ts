/**
 * SCOPE — what a green run here does and does not claim.
 *
 * DOES claim: a genuine signature over the exact bytes verifies; a signature
 * from an untrusted key, over tampered bytes, or truncated does not; a valid
 * signature is found at ANY index of a multi-signature file; and armoured and
 * binary signature encodings are both accepted. Every case uses real keys and
 * real signatures generated in-process — nothing here is mocked, so the tests
 * exercise the actual openpgp verification path.
 *
 * Does NOT claim: that the CALLER's trust set is correct. This verifies against
 * whatever keys it is handed and cannot know whether they are the right ones,
 * whether they are revoked, or whether they have expired upstream — key
 * freshness stays with the repository that owns the trust root. Nor does it
 * decide what a MISSING signature means; that lives in the fetch path.
 */
import { generateKey, readPrivateKey, sign, createMessage } from 'openpgp'
import { beforeAll, describe, expect, it } from 'vitest'
import * as gpgModule from './index'
import { verifyDetached } from './index'

interface Keypair {
  armoredPublic: string
  armoredPrivate: string
}

const CONTENT = new TextEncoder().encode(
  'a1b2c3  terraform_1.14.6_linux_amd64.zip\nd4e5f6  terraform_1.14.6_darwin_arm64.zip\n',
)

let trusted: Keypair
let untrusted: Keypair
let rotated: Keypair

async function makeKeypair(name: string): Promise<Keypair> {
  const { privateKey, publicKey } = await generateKey({
    userIDs: [{ name, email: `${name}@example.test` }],
    format: 'armored',
  })
  return { armoredPublic: publicKey, armoredPrivate: privateKey }
}

async function detachedSignature(
  content: Uint8Array,
  signers: Keypair[],
  format: 'binary' | 'armored' = 'binary',
): Promise<Uint8Array> {
  const signingKeys = await Promise.all(
    signers.map((pair) => readPrivateKey({ armoredKey: pair.armoredPrivate })),
  )
  const message = await createMessage({ binary: content })
  // Split rather than passing a union: openpgp's overloads key on the literal.
  if (format === 'armored') {
    const armored = await sign({ message, signingKeys, detached: true, format: 'armored' })
    return new TextEncoder().encode(armored)
  }
  return await sign({ message, signingKeys, detached: true, format: 'binary' })
}

beforeAll(async () => {
  ;[trusted, untrusted, rotated] = await Promise.all([
    makeKeypair('trusted'),
    makeKeypair('untrusted'),
    makeKeypair('rotated'),
  ])
}, 30_000)

describe('gpg — a good signature', () => {
  it('verifies against the signing key', async () => {
    const signature = await detachedSignature(CONTENT, [trusted])
    const result = await verifyDetached({
      message: CONTENT,
      signature,
      armoredPublicKeys: [trusted.armoredPublic],
    })
    expect(result.verified).toBe(true)
  })

  it('reports which key verified', async () => {
    const signature = await detachedSignature(CONTENT, [trusted])
    const result = await verifyDetached({
      message: CONTENT,
      signature,
      armoredPublicKeys: [trusted.armoredPublic],
    })
    expect(result.keyId).toMatch(/^[0-9a-f]{16}$/)
  })

  it('verifies when the trust set contains other keys too', async () => {
    const signature = await detachedSignature(CONTENT, [trusted])
    const result = await verifyDetached({
      message: CONTENT,
      signature,
      armoredPublicKeys: [untrusted.armoredPublic, trusted.armoredPublic],
    })
    expect(result.verified).toBe(true)
  })

  it('accepts an ARMOURED signature as well as a binary one', async () => {
    const armored = await detachedSignature(CONTENT, [trusted], 'armored')
    expect(Buffer.from(armored).toString('utf8')).toContain('-----BEGIN PGP SIGNATURE-----')
    const result = await verifyDetached({
      message: CONTENT,
      signature: armored,
      armoredPublicKeys: [trusted.armoredPublic],
    })
    expect(result.verified).toBe(true)
  })
})

describe('gpg — a signature that must not verify', () => {
  it('rejects a signature from a key outside the trust set', async () => {
    const signature = await detachedSignature(CONTENT, [untrusted])
    const result = await verifyDetached({
      message: CONTENT,
      signature,
      armoredPublicKeys: [trusted.armoredPublic],
    })
    expect(result.verified).toBe(false)
    expect(result.keyId).toBeUndefined()
  })

  it('rejects a signature over DIFFERENT bytes', async () => {
    const signature = await detachedSignature(CONTENT, [trusted])
    const tampered = new TextEncoder().encode(
      'deadbe  terraform_1.14.6_linux_amd64.zip\nd4e5f6  terraform_1.14.6_darwin_arm64.zip\n',
    )
    const result = await verifyDetached({
      message: tampered,
      signature,
      armoredPublicKeys: [trusted.armoredPublic],
    })
    expect(result.verified, 'a checksum swap is the exact attack this defends').toBe(false)
  })

  it('rejects a single flipped byte', async () => {
    const signature = await detachedSignature(CONTENT, [trusted])
    const tampered = Uint8Array.from(CONTENT)
    tampered[0] = (tampered[0] ?? 0) ^ 0x01
    const result = await verifyDetached({
      message: tampered,
      signature,
      armoredPublicKeys: [trusted.armoredPublic],
    })
    expect(result.verified).toBe(false)
  })

  it('rejects an appended byte', async () => {
    const signature = await detachedSignature(CONTENT, [trusted])
    const extended = new Uint8Array(CONTENT.length + 1)
    extended.set(CONTENT)
    extended[CONTENT.length] = 0x0a
    const result = await verifyDetached({
      message: extended,
      signature,
      armoredPublicKeys: [trusted.armoredPublic],
    })
    expect(result.verified).toBe(false)
  })
})

describe('gpg — multi-signature files', () => {
  it('accepts a valid signature at a NON-ZERO index', async () => {
    // A rotation window produces a .sig carrying both the old and new
    // signatures. Checking only signatures[0] would discard a good signature
    // sitting behind a stale one and fail a legitimate release.
    const signature = await detachedSignature(CONTENT, [rotated, trusted])
    const result = await verifyDetached({
      message: CONTENT,
      signature,
      armoredPublicKeys: [trusted.armoredPublic],
    })
    expect(result.verified).toBe(true)
  })

  it('accepts a valid signature at index zero when a later one is untrusted', async () => {
    const signature = await detachedSignature(CONTENT, [trusted, rotated])
    const result = await verifyDetached({
      message: CONTENT,
      signature,
      armoredPublicKeys: [trusted.armoredPublic],
    })
    expect(result.verified).toBe(true)
  })

  it('still rejects when NONE of the signatures is trusted', async () => {
    const signature = await detachedSignature(CONTENT, [rotated, untrusted])
    const result = await verifyDetached({
      message: CONTENT,
      signature,
      armoredPublicKeys: [trusted.armoredPublic],
    })
    expect(result.verified).toBe(false)
  })

  it('names the key that actually verified, not the first one present', async () => {
    const signature = await detachedSignature(CONTENT, [rotated, trusted])
    const result = await verifyDetached({
      message: CONTENT,
      signature,
      armoredPublicKeys: [trusted.armoredPublic],
    })
    const trustedOnly = await verifyDetached({
      message: CONTENT,
      signature: await detachedSignature(CONTENT, [trusted]),
      armoredPublicKeys: [trusted.armoredPublic],
    })
    expect(result.keyId).toBe(trustedOnly.keyId)
  })
})

describe('gpg — unusable input throws rather than reporting a bad artifact', () => {
  it('refuses an empty trust set', async () => {
    const signature = await detachedSignature(CONTENT, [trusted])
    await expect(
      verifyDetached({ message: CONTENT, signature, armoredPublicKeys: [] }),
    ).rejects.toThrow(/at least one armoured public key/)
  })

  it('throws on a malformed public key', async () => {
    const signature = await detachedSignature(CONTENT, [trusted])
    await expect(
      verifyDetached({ message: CONTENT, signature, armoredPublicKeys: ['not a key'] }),
    ).rejects.toThrow()
  })

  it('throws on a signature that is not a signature', async () => {
    await expect(
      verifyDetached({
        message: CONTENT,
        signature: new TextEncoder().encode('this is plainly not a signature'),
        armoredPublicKeys: [trusted.armoredPublic],
      }),
    ).rejects.toThrow()
  })

  it('throws on a truncated signature', async () => {
    const signature = await detachedSignature(CONTENT, [trusted])
    await expect(
      verifyDetached({
        message: CONTENT,
        signature: signature.subarray(0, Math.floor(signature.length / 2)),
        armoredPublicKeys: [trusted.armoredPublic],
      }),
    ).rejects.toThrow()
  })
})

describe('gpg — empty message', () => {
  it('verifies a signature over zero bytes rather than short-circuiting', async () => {
    const empty = new Uint8Array(0)
    const signature = await detachedSignature(empty, [trusted])
    const result = await verifyDetached({
      message: empty,
      signature,
      armoredPublicKeys: [trusted.armoredPublic],
    })
    expect(result.verified).toBe(true)
  })

  it('rejects an empty message against a signature over real content', async () => {
    const signature = await detachedSignature(CONTENT, [trusted])
    const result = await verifyDetached({
      message: new Uint8Array(0),
      signature,
      armoredPublicKeys: [trusted.armoredPublic],
    })
    expect(result.verified).toBe(false)
  })
})

/**
 * TABLE B — export inventory, verdicted by hand.
 *
 * This entrypoint is the one that costs a consumer the `openpgp` dependency, so
 * anything added here is added to that bill.
 */
describe('gpg — public surface', () => {
  it('exports exactly the reviewed set', () => {
    expect(Object.keys(gpgModule).sort()).toEqual(['verifyDetached'])
  })
})
