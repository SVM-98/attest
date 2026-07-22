// I1 (2026-07-22 fix wave 2, review round-1): the G1 key-manifest ceiling
// must bound work BEFORE any cryptographic or schema work on the hostile
// manifest (spec v0.1 §11.3) — mirrors tests/test_verify.py's
// test_issuer_manifest_over_key_ceiling_rejected_before_canonicalization.
//
// canonicalBytes is wrapped in a call-counting spy that delegates to the
// real implementation (same pattern as revocation-bound.test.ts's
// verifyKeyManifest spy), so the ceiling check's ordering relative to
// transparency-claim canonicalization is directly observable. Fixture
// construction below also goes through the spy — that is fine, since the
// property under test is asserted with `mockClear()` right before the
// `verify()` call under test, not a total call count.
import { describe, it, expect, vi } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { loadsStrict, JsonObject } from '../src/canon.js'
import { b64uEncode } from '../src/b64u.js'
import { MAX_MANIFEST_KEYS } from '../src/manifests.js'
import type { TrustStore } from '../src/manifests.js'
import type { LogKey } from '../src/tlog.js'
import type { AnchorPolicy } from '../src/anchor.js'

vi.mock('../src/canon.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/canon.js')>()
  return { ...actual, canonicalBytes: vi.fn(actual.canonicalBytes), dumps: vi.fn(actual.dumps) }
})

import { canonicalBytes, dumps } from '../src/canon.js'
import { verify } from '../src/verify.js'

const enc = (s: string) => new TextEncoder().encode(s)
const parse = (v: unknown): JsonObject => loadsStrict(enc(JSON.stringify(v))) as JsonObject

const ISSUER = 'store.example.com'
const KID = `${ISSUER}/keys/test#ed25519-1`
const VALID_FROM = '2025-01-01T00:00:00Z'

// TEST ONLY — fixed seeds, never use in production.
const edSeed = Uint8Array.from({ length: 32 }, () => 9)
const edPub = ed25519.getPublicKey(edSeed)

function signManifest(body: Record<string, unknown>, kid: string, seed: Uint8Array): JsonObject {
  const b = parse(body)
  const sig = ed25519.sign(canonicalBytes(b), seed)
  return parse({ ...body, manifest_signature: { kid, sig: b64uEncode(sig) } })
}

function fillerKeyEntries(count: number, prefix: string): Record<string, unknown>[] {
  const entries: Record<string, unknown>[] = []
  for (let i = 0; i < count; i++) {
    const seed = Uint8Array.from({ length: 32 }, (_, j) => (i + j * 7 + prefix.length) % 256)
    const pub = ed25519.getPublicKey(seed)
    entries.push({
      kid: `${ISSUER}/keys/test#precanon-filler-${i}`,
      pub: b64uEncode(pub),
      valid_from: VALID_FROM,
      valid_to: null,
      status: 'active',
    })
  }
  return entries
}

function oversizedManifest(): JsonObject {
  const entries = [
    { kid: KID, pub: b64uEncode(edPub), valid_from: VALID_FROM, valid_to: null, status: 'active' },
    ...fillerKeyEntries(MAX_MANIFEST_KEYS, 'precanon'),
  ]
  return signManifest(
    { issuer: ISSUER, manifest_version: 1, issued_at: VALID_FROM, keys: entries },
    KID,
    edSeed,
  )
}

function trustStore(manifest: JsonObject): TrustStore {
  return { manifests: { [ISSUER]: manifest }, provenance: { [ISSUER]: 'tls' } }
}

function envelope(): { payload: JsonObject; signatures: unknown[] } {
  const payload = parse({
    attest_version: '0.1', issued_at: '2025-06-01T00:00:00Z', receipt_id: '01J000000000000000000000AA',
    issuer: { display_name: 'Store', id: ISSUER },
    work: { title: 'T', publisher: 'P', identifiers: { issuer_sku: 'X' } },
    license: { grant: 'perpetual', revocability: 'policy', transferable: false, drm: 'drm-bound', terms_uri: 'https://x/t', legal_text_sha256: 'a'.repeat(64) },
    buyer: { commitment: 'A'.repeat(43), identifier_type: 'email', pubkey: null },
    survivability: { end_of_life: 'none', eol_commitment_sha256: null, eol_commitment_uri: null, redownload_right: false },
    supersedes: null,
  })
  const sig = ed25519.sign(canonicalBytes(payload), edSeed)
  return { payload, signatures: [{ kid: KID, alg: 'Ed25519', sig: b64uEncode(sig) }] }
}

describe('I1: key-manifest ceiling hoisted before canonicalization', () => {
  it('rejects an oversized manifest without ever canonicalizing it', () => {
    const manifest = oversizedManifest()
    const env = envelope()

    // A key-manifest transparency claim is the concrete path (Stage 2) that
    // canonicalizes/hashes the issuer manifest — resolveTransparencyClaim
    // runs canonicalBytes(issuerManifest) unconditionally once it sees
    // entry.type === 'key-manifest', regardless of whether the rest of the
    // evidence is otherwise valid. Feeding one in makes the pre-fix ordering
    // (transparency resolved before the ceiling) observable.
    const mldsaSeed = Uint8Array.from({ length: 32 }, () => 40)
    const { publicKey: mldsaPub } = ml_dsa65.keygen(mldsaSeed)
    const logKey: LogKey = {
      origin: 'log.attest.example/2026',
      name: 'attest-log-1',
      ed25519Pub: ed25519.getPublicKey(Uint8Array.from({ length: 32 }, () => 41)),
      mldsaPub,
    }
    const anchorPolicy: AnchorPolicy = { pinnedHeaders: {}, crqcHorizon: null }

    vi.mocked(canonicalBytes).mockClear()

    const result = verify(
      enc(JSON.stringify(env)),
      trustStore(manifest),
      null,
      null,
      undefined,
      {
        transparency: parse({ entry: { type: 'key-manifest' } }),
        logKeys: [logKey],
        anchorPolicy,
      },
    )

    expect(result.schema).toBe('invalid')
    expect(result.signature).toBe('invalid')
    const calledWithManifest = vi.mocked(canonicalBytes).mock.calls.some((args) => args[0] === manifest)
    expect(calledWithManifest).toBe(false)
  })

  // Round-2 regression (review finding I1 residual): a NON-EMPTY rotation
  // chain used to canonicalize the resolved manifest via dumps() in the
  // chain-continuity tail compare BEFORE the ceiling ran. The ceiling must
  // reject first — dumps() must never see the oversized manifest.
  it('rejects an oversized manifest before chain handling canonicalizes it (non-empty chain)', () => {
    const manifest = oversizedManifest()
    const env = envelope()
    const store: TrustStore = {
      manifests: { [ISSUER]: manifest },
      provenance: { [ISSUER]: 'tls' },
      chains: { [ISSUER]: [manifest] },
    }

    vi.mocked(canonicalBytes).mockClear()
    vi.mocked(dumps).mockClear()

    const result = verify(enc(JSON.stringify(env)), store, null, null, undefined)

    expect(result.schema).toBe('invalid')
    expect(result.signature).toBe('invalid')
    const dumpsSawManifest = vi.mocked(dumps).mock.calls.some((args) => args[0] === manifest)
    expect(dumpsSawManifest).toBe(false)
    const canonSawManifest = vi.mocked(canonicalBytes).mock.calls.some((args) => args[0] === manifest)
    expect(canonSawManifest).toBe(false)
  })
})
