// Tests for the v0.2 hybrid (Ed25519 + ML-DSA-65) verification path — mirrors
// tests/test_verify_hybrid.py (Python reference) one-for-one. AND semantics,
// fail-closed: a v0.2 receipt is accepted only if BOTH its Ed25519 and
// ML-DSA-65 signatures verify. Every error literal asserted here is copied
// verbatim from the Python reference — never paraphrase.
import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { loadsStrict, canonicalBytes, JsonObject, JsonValue } from '../src/canon.js'
import { b64uEncode, b64uDecode } from '../src/b64u.js'
import { verify } from '../src/verify.js'
import type { TrustStore } from '../src/manifests.js'

const enc = (s: string) => new TextEncoder().encode(s)
const parse = (v: unknown): JsonObject => loadsStrict(enc(JSON.stringify(v))) as JsonObject

const ISSUER = 'store.example.com'
const KID = `${ISSUER}/keys/test#hybrid-1`
const VALID_FROM = '2025-01-01T00:00:00Z'

// TEST ONLY — fixed seeds, never use in production.
const edSeed = Uint8Array.from({ length: 32 }, () => 21)
const edPub = ed25519.getPublicKey(edSeed)
const { publicKey: mldsaPub, secretKey: mldsaSecret } = ml_dsa65.keygen(Uint8Array.from({ length: 32 }, () => 34))

function basePayload(attestVersion: string): JsonObject {
  return parse({
    attest_version: attestVersion, issued_at: '2025-06-01T00:00:00Z', receipt_id: '01J000000000000000000000AA',
    issuer: { display_name: 'Store', id: ISSUER },
    work: { title: 'T', publisher: 'P', identifiers: { issuer_sku: 'X' } },
    license: { grant: 'perpetual', revocability: 'policy', transferable: false, drm: 'drm-bound', terms_uri: 'https://x/t', legal_text_sha256: 'a'.repeat(64) },
    buyer: { commitment: 'A'.repeat(43), identifier_type: 'email', pubkey: null },
    survivability: { end_of_life: 'none', eol_commitment_sha256: null, eol_commitment_uri: null, redownload_right: false },
    supersedes: null,
  })
}

function signManifest(body: Record<string, unknown>, kid: string, hybrid: boolean): JsonObject {
  const b = parse(body)
  const bytes = canonicalBytes(b)
  const edSig = ed25519.sign(bytes, edSeed)
  const sigBlock: Record<string, unknown> = { kid, sig: b64uEncode(edSig) }
  if (hybrid) sigBlock['sig_ml_dsa_65'] = b64uEncode(ml_dsa65.sign(bytes, mldsaSecret))
  return parse({ ...body, manifest_signature: sigBlock })
}

function hybridManifest(): JsonObject {
  return signManifest(
    {
      issuer: ISSUER, manifest_version: 1, issued_at: VALID_FROM,
      keys: [{ kid: KID, pub: b64uEncode(edPub), valid_from: VALID_FROM, valid_to: null, status: 'active', pub_ml_dsa_65: b64uEncode(mldsaPub) }],
    },
    KID,
    true,
  )
}

// A manifest whose key entry has no `pub_ml_dsa_65` — self-signed with an
// Ed25519-only key so it stays independently valid, letting the hybrid
// envelope's own Ed25519 leg be re-signed with the same key.
function nonHybridManifest(): JsonObject {
  return signManifest(
    {
      issuer: ISSUER, manifest_version: 1, issued_at: VALID_FROM,
      keys: [{ kid: KID, pub: b64uEncode(edPub), valid_from: VALID_FROM, valid_to: null, status: 'active' }],
    },
    KID,
    false,
  )
}

function trustStore(manifest: JsonObject): TrustStore {
  return { manifests: { [ISSUER]: manifest }, provenance: { [ISSUER]: 'tls' } }
}

function envelopeBytes(envelope: unknown): Uint8Array {
  return enc(JSON.stringify(envelope))
}

function hybridEnvelope(): { payload: JsonObject; signatures: JsonValue[] } {
  const payload = basePayload('0.2')
  const bytes = canonicalBytes(payload)
  const edSig = ed25519.sign(bytes, edSeed)
  const mldsaSig = ml_dsa65.sign(bytes, mldsaSecret)
  return {
    payload,
    signatures: [
      parse({ kid: KID, alg: 'Ed25519', sig: b64uEncode(edSig) }),
      parse({ kid: KID, alg: 'ML-DSA-65', sig: b64uEncode(mldsaSig) }),
    ],
  }
}

describe('v0.2 hybrid verification', () => {
  it('a valid hybrid receipt verifies ok', () => {
    const envelope = hybridEnvelope()
    const result = verify(envelopeBytes(envelope), trustStore(hybridManifest()))
    expect(result.signature).toBe('valid')
    expect(result.errors).toEqual([])
  })

  it('a single signature is invalid', () => {
    const envelope = hybridEnvelope()
    const single = { payload: envelope.payload, signatures: [envelope.signatures[0]] }
    const result = verify(envelopeBytes(single), trustStore(hybridManifest()))
    expect(result.signature).toBe('invalid')
    expect(result.errors).toEqual(['hybrid envelope requires exactly two signatures'])
  })

  it('wrong alg order is invalid', () => {
    const envelope = hybridEnvelope()
    const reversed = { payload: envelope.payload, signatures: [...envelope.signatures].reverse() }
    const result = verify(envelopeBytes(reversed), trustStore(hybridManifest()))
    expect(result.signature).toBe('invalid')
    expect(result.errors).toEqual(['hybrid envelope requires algs Ed25519 and ML-DSA-65 in order'])
  })

  it('duplicate Ed25519 alg is invalid', () => {
    const envelope = hybridEnvelope()
    const edEntry = envelope.signatures[0]
    const duplicated = { payload: envelope.payload, signatures: [edEntry, edEntry] }
    const result = verify(envelopeBytes(duplicated), trustStore(hybridManifest()))
    expect(result.signature).toBe('invalid')
    expect(result.errors).toEqual(['hybrid envelope requires algs Ed25519 and ML-DSA-65 in order'])
  })

  it('kid mismatch between legs is invalid', () => {
    const envelope = hybridEnvelope()
    const sig1 = envelope.signatures[1] as JsonObject
    const mismatched = { ...sig1, kid: `${ISSUER}/keys/test#hybrid-other` }
    const result = verify(envelopeBytes({ payload: envelope.payload, signatures: [envelope.signatures[0], mismatched] }), trustStore(hybridManifest()))
    expect(result.signature).toBe('invalid')
    expect(result.errors).toEqual(['hybrid envelope signatures must share a single kid'])
  })

  it('a key entry without pub_ml_dsa_65 is invalid', () => {
    // The envelope's Ed25519 leg is re-signed with the same key that the
    // non-hybrid manifest lists, so the only thing that can fail is the
    // missing pub_ml_dsa_65 check itself.
    const payload = basePayload('0.2')
    const bytes = canonicalBytes(payload)
    const edSig = ed25519.sign(bytes, edSeed)
    const mldsaSig = ml_dsa65.sign(bytes, mldsaSecret)
    const envelope = {
      payload,
      signatures: [
        { kid: KID, alg: 'Ed25519', sig: b64uEncode(edSig) },
        { kid: KID, alg: 'ML-DSA-65', sig: b64uEncode(mldsaSig) },
      ],
    }
    const result = verify(envelopeBytes(envelope), trustStore(nonHybridManifest()))
    expect(result.signature).toBe('invalid')
    expect(result.errors).toEqual([`key entry for kid '${KID}' has no ML-DSA-65 public key`])
  })

  it('a tampered ML-DSA-65 leg is invalid', () => {
    const envelope = hybridEnvelope()
    const sig1 = envelope.signatures[1] as JsonObject
    const raw = b64uDecode(sig1['sig'] as string)
    raw[0] = raw[0]! ^ 0xff
    const tampered = { ...sig1, sig: b64uEncode(raw) }
    const result = verify(envelopeBytes({ payload: envelope.payload, signatures: [envelope.signatures[0], tampered] }), trustStore(hybridManifest()))
    expect(result.signature).toBe('invalid')
    expect(result.errors).toEqual(['ML-DSA-65 signature verification failed'])
  })

  it('a tampered Ed25519 leg is invalid', () => {
    const envelope = hybridEnvelope()
    const sig0 = envelope.signatures[0] as JsonObject
    const raw = b64uDecode(sig0['sig'] as string)
    raw[0] = raw[0]! ^ 0xff
    const tampered = { ...sig0, sig: b64uEncode(raw) }
    const result = verify(envelopeBytes({ payload: envelope.payload, signatures: [tampered, envelope.signatures[1]] }), trustStore(hybridManifest()))
    expect(result.signature).toBe('invalid')
    expect(result.errors).toEqual(['signature verification failed'])
  })

  it('a v0.1 receipt still verifies (v0.2 branch does not regress v0.1)', () => {
    const kid = `${ISSUER}/keys/test#ed25519-1`
    const seed = Uint8Array.from({ length: 32 }, () => 22)
    const pub = ed25519.getPublicKey(seed)
    const manifest = signManifest(
      { issuer: ISSUER, manifest_version: 1, issued_at: VALID_FROM, keys: [{ kid, pub: b64uEncode(pub), valid_from: VALID_FROM, valid_to: null, status: 'active' }] },
      kid,
      false,
    )
    const payload = basePayload('0.1')
    const sig = ed25519.sign(canonicalBytes(payload), seed)
    const envelope = { payload, signatures: [{ kid, alg: 'Ed25519', sig: b64uEncode(sig) }] }
    const result = verify(envelopeBytes(envelope), trustStore(manifest))
    expect(result.signature).toBe('valid')
    expect(result.errors).toEqual([])
  })

  it('an uncanonicalizable v0.2 payload is invalid, not thrown', () => {
    const envelope = hybridEnvelope()
    const mutatedPayload = { ...JSON.parse(JSON.stringify(envelope.payload)), out_of_range_int: 2 ** 53 }
    const mutated = { payload: mutatedPayload, signatures: envelope.signatures }
    expect(() => verify(envelopeBytes(mutated), trustStore(hybridManifest()))).not.toThrow()
    const result = verify(envelopeBytes(mutated), trustStore(hybridManifest()))
    expect(result.signature).toBe('invalid')
    expect(result.errors.length).toBe(1)
    expect(result.errors[0]!.startsWith('malformed signature material: ')).toBe(true)
  })

  it('a non-string attest_version is invalid, not thrown', () => {
    const envelope = hybridEnvelope()
    const mutatedPayload = { ...JSON.parse(JSON.stringify(envelope.payload)), attest_version: ['0.2'] }
    const mutated = { payload: mutatedPayload, signatures: envelope.signatures }
    expect(() => verify(envelopeBytes(mutated), trustStore(hybridManifest()))).not.toThrow()
    const result = verify(envelopeBytes(mutated), trustStore(hybridManifest()))
    expect(result.signature).toBe('invalid')
    expect(result.errors).toEqual(["unsupported attest_version: ['0.2']"])
  })
})
