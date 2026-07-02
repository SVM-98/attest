import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { loadsStrict, canonicalBytes, JsonObject } from '../src/canon.js'
import { b64uEncode } from '../src/b64u.js'
import {
  findKey,
  verifyKeyManifest,
  withinValidity,
  checkContinuity,
  chainContinuous,
  verifyArtifactManifest,
} from '../src/manifests.js'

const enc = (s: string) => new TextEncoder().encode(s)
function signManifest(body: Record<string, unknown>, kid: string, seed: Uint8Array) {
  const b = loadsStrict(enc(JSON.stringify(body))) as JsonObject
  const sig = ed25519.sign(canonicalBytes(b), seed)
  return { ...body, manifest_signature: { kid, sig: b64uEncode(sig) } }
}
// Every manifest fed to manifests.ts functions MUST go through loadsStrict so that
// manifest_version parses as bigint (checkContinuity's `typeof tv !== 'bigint'` guard).
const parse = (m: unknown): JsonObject => loadsStrict(enc(JSON.stringify(m))) as JsonObject

const ISSUER = 'store.example.com'

const seed1 = Uint8Array.from({ length: 32 }, () => 7)
const pub1 = b64uEncode(ed25519.getPublicKey(seed1))
const kid1 = `${ISSUER}/keys/2025-01#ed25519-1`

const seed2 = Uint8Array.from({ length: 32 }, () => 8)
const pub2 = b64uEncode(ed25519.getPublicKey(seed2))
const kid2 = `${ISSUER}/keys/2025-06#ed25519-2`

const seed3 = Uint8Array.from({ length: 32 }, () => 9)
const pub3 = b64uEncode(ed25519.getPublicKey(seed3))
const kid3 = `${ISSUER}/keys/2025-06#ed25519-3`

// v1: single active key (kid1), open-ended validity — the brief's base fixture.
const v1 = signManifest(
  {
    issuer: ISSUER,
    manifest_version: 1,
    issued_at: '2025-01-01T00:00:00Z',
    keys: [{ kid: kid1, pub: pub1, valid_from: '2025-01-01T00:00:00Z', valid_to: null, status: 'active' }],
  },
  kid1,
  seed1,
)

describe('manifests', () => {
  describe('verifyKeyManifest', () => {
    it('self-verifies a pristine key manifest', () => {
      expect(verifyKeyManifest(parse(v1))).toBe(true)
    })

    it('fails self-verify after a signed-field tamper (status flip)', () => {
      const t = JSON.parse(JSON.stringify(v1))
      t.keys[0].status = 'compromised'
      expect(verifyKeyManifest(parse(t))).toBe(false)
    })

    it('a retired or compromised signer still self-verifies — status is enforced elsewhere', () => {
      // verifyKeyManifest checks ONLY that the signature matches the key material
      // listed in the manifest itself; it deliberately never inspects entry.status.
      const retired = signManifest(
        {
          issuer: ISSUER,
          manifest_version: 1,
          issued_at: '2025-01-01T00:00:00Z',
          keys: [{ kid: kid1, pub: pub1, valid_from: '2025-01-01T00:00:00Z', valid_to: null, status: 'retired' }],
        },
        kid1,
        seed1,
      )
      expect(verifyKeyManifest(parse(retired))).toBe(true)

      const compromised = signManifest(
        {
          issuer: ISSUER,
          manifest_version: 1,
          issued_at: '2025-01-01T00:00:00Z',
          keys: [{ kid: kid1, pub: pub1, valid_from: '2025-01-01T00:00:00Z', valid_to: null, status: 'compromised' }],
        },
        kid1,
        seed1,
      )
      expect(verifyKeyManifest(parse(compromised))).toBe(true)
    })
  })

  describe('findKey', () => {
    it('returns the first matching entry by kid, and null when absent', () => {
      const m = parse(v1)
      const e = findKey(m, kid1)!
      expect(e.status).toBe('active')
      expect(e.pub).toBe(pub1)
      expect(findKey(m, 'nope')).toBeNull()
    })
  })

  describe('withinValidity', () => {
    // Bounded window (valid_to set) so both ends of the inclusive range are testable.
    const bounded = signManifest(
      {
        issuer: ISSUER,
        manifest_version: 1,
        issued_at: '2025-01-01T00:00:00Z',
        keys: [
          {
            kid: kid1,
            pub: pub1,
            valid_from: '2025-01-01T00:00:00Z',
            valid_to: '2025-06-01T00:00:00Z',
            status: 'active',
          },
        ],
      },
      kid1,
      seed1,
    )
    const entry = findKey(parse(bounded), kid1)!

    it('true strictly inside the window', () => {
      expect(withinValidity('2025-03-01T00:00:00Z', entry)).toBe(true)
    })
    it('true at the exact valid_from boundary (inclusive)', () => {
      expect(withinValidity('2025-01-01T00:00:00Z', entry)).toBe(true)
    })
    it('true at the exact valid_to boundary (inclusive)', () => {
      expect(withinValidity('2025-06-01T00:00:00Z', entry)).toBe(true)
    })
    it('false before valid_from', () => {
      expect(withinValidity('2024-12-31T23:59:59Z', entry)).toBe(false)
    })
    it('false after valid_to', () => {
      expect(withinValidity('2025-06-01T00:00:01Z', entry)).toBe(false)
    })
    it('false on a malformed date (fail-closed)', () => {
      expect(withinValidity('garbage', entry)).toBe(false)
    })
    it('true on open-ended validity (valid_to null) well past valid_from', () => {
      const openEntry = findKey(parse(v1), kid1)!
      expect(withinValidity('2025-06-01T00:00:00Z', openEntry)).toBe(true)
    })
  })

  describe('checkContinuity / chainContinuous', () => {
    // v2: kid1 retired (bounded window), kid2 newly active — signed by kid1, which
    // IS active in v1 (the trusted manifest). Rotation-continuity happy path.
    const v2 = signManifest(
      {
        issuer: ISSUER,
        manifest_version: 2,
        issued_at: '2025-06-01T00:00:00Z',
        keys: [
          {
            kid: kid1,
            pub: pub1,
            valid_from: '2025-01-01T00:00:00Z',
            valid_to: '2025-06-01T00:00:00Z',
            status: 'retired',
          },
          { kid: kid2, pub: pub2, valid_from: '2025-06-01T00:00:00Z', valid_to: null, status: 'active' },
        ],
      },
      kid1,
      seed1,
    )

    // v2b (vector-14b discontinuity shape): self-consistent candidate whose signer
    // (kid3) is ABSENT from v1's keys[] — a new key with no chain of trust back.
    const v2b = signManifest(
      {
        issuer: ISSUER,
        manifest_version: 2,
        issued_at: '2025-06-01T00:00:00Z',
        keys: [{ kid: kid3, pub: pub3, valid_from: '2025-06-01T00:00:00Z', valid_to: null, status: 'active' }],
      },
      kid3,
      seed3,
    )

    // v3: version gap (manifest_version = 3, not trusted.manifest_version + 1),
    // otherwise well-formed and self-consistent, signed by kid1 (active in v1) —
    // isolates the version-increment check from every other continuity condition.
    const v3 = signManifest(
      {
        issuer: ISSUER,
        manifest_version: 3,
        issued_at: '2025-06-01T00:00:00Z',
        keys: [{ kid: kid1, pub: pub1, valid_from: '2025-01-01T00:00:00Z', valid_to: null, status: 'active' }],
      },
      kid1,
      seed1,
    )

    it('true for v1 -> v2 signed by a key active in v1', () => {
      expect(checkContinuity(parse(v1), parse(v2))).toBe(true)
      expect(chainContinuous([parse(v1), parse(v2)])).toBe(true)
    })

    it('false when the candidate signer is absent from the trusted manifest (vector 14b shape)', () => {
      expect(checkContinuity(parse(v1), parse(v2b))).toBe(false)
      expect(chainContinuous([parse(v1), parse(v2b)])).toBe(false)
    })

    it('false on a version gap (v1 -> v3, not +1)', () => {
      expect(checkContinuity(parse(v1), parse(v3))).toBe(false)
    })

    it('false when the candidate signer exists in trusted but only as retired (not active)', () => {
      const trustedRetired = signManifest(
        {
          issuer: ISSUER,
          manifest_version: 1,
          issued_at: '2025-01-01T00:00:00Z',
          keys: [
            {
              kid: kid1,
              pub: pub1,
              valid_from: '2025-01-01T00:00:00Z',
              valid_to: '2025-06-01T00:00:00Z',
              status: 'retired',
            },
          ],
        },
        kid1,
        seed1,
      )
      // candidate lists kid1 too (so it self-verifies), signed by kid1; only
      // trusted's view of kid1 (retired) is what checkContinuity must reject on.
      const candidateSignedByRetired = signManifest(
        {
          issuer: ISSUER,
          manifest_version: 2,
          issued_at: '2025-06-01T00:00:00Z',
          keys: [
            {
              kid: kid1,
              pub: pub1,
              valid_from: '2025-01-01T00:00:00Z',
              valid_to: '2025-06-01T00:00:00Z',
              status: 'retired',
            },
            { kid: kid2, pub: pub2, valid_from: '2025-06-01T00:00:00Z', valid_to: null, status: 'active' },
          ],
        },
        kid1,
        seed1,
      )
      expect(checkContinuity(parse(trustedRetired), parse(candidateSignedByRetired))).toBe(false)
    })

    it('a single-manifest chain is trivially continuous', () => {
      expect(chainContinuous([parse(v1)])).toBe(true)
    })
  })

  describe('verifyArtifactManifest', () => {
    const am = signManifest(
      {
        issuer: ISSUER,
        series: `${ISSUER}/works/EXG-001`,
        version: 1,
        released_at: '2025-03-01T00:00:00Z',
        artifacts: [
          {
            role: 'installer',
            platform: 'windows-x86_64',
            filename: 'example-game-1.0-setup.exe',
            size_bytes: 734003200,
            sha256: '0'.repeat(64),
          },
        ],
      },
      kid1,
      seed1,
    )

    it('verifies a pristine artifact manifest against its key manifest', () => {
      expect(verifyArtifactManifest(parse(am), parse(v1))).toBe(true)
    })

    it('fails after a signed-field tamper', () => {
      const t = JSON.parse(JSON.stringify(am))
      t.version = 2
      expect(verifyArtifactManifest(parse(t), parse(v1))).toBe(false)
    })
  })
})
