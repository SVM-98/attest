import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { loadsStrict, canonicalBytes, JsonObject } from '../src/canon.js'
import { b64uEncode } from '../src/b64u.js'
import { verifyRecord, classifyRevocation } from '../src/revocation.js'

const enc = (s: string) => new TextEncoder().encode(s)

// Reuses Task 10's self-signed-manifest pattern (see manifests.test.ts): sign JCS of
// the body (everything except the signature member itself), then attach the block.
function signManifest(body: Record<string, unknown>, kid: string, seed: Uint8Array) {
  const b = loadsStrict(enc(JSON.stringify(body))) as JsonObject
  const sig = ed25519.sign(canonicalBytes(b), seed)
  return { ...body, manifest_signature: { kid, sig: b64uEncode(sig) } }
}

// Same pattern, but for a revocation record: sign JCS of the record minus 'signature'.
function signRecord(body: Record<string, unknown>, kid: string, seed: Uint8Array) {
  const b = loadsStrict(enc(JSON.stringify(body))) as JsonObject
  const sig = ed25519.sign(canonicalBytes(b), seed)
  return { ...body, signature: { kid, sig: b64uEncode(sig) } }
}

// Every fixture fed to revocation.ts functions MUST go through loadsStrict so that
// integers (manifest_version, revocation_window_days, ...) parse as bigint.
const parse = (m: unknown): JsonObject => loadsStrict(enc(JSON.stringify(m))) as JsonObject

const ISSUER = 'store.example.com'

const seed1 = Uint8Array.from({ length: 32 }, () => 7)
const pub1 = b64uEncode(ed25519.getPublicKey(seed1))
const kid1 = `${ISSUER}/keys/2025-01#ed25519-1`

// Wrong/absent key: never listed in the key manifest at all — signs a record that
// looks otherwise identical to one signed by kid1, but cannot authenticate.
const seedWrong = Uint8Array.from({ length: 32 }, () => 99)
const kidWrong = `${ISSUER}/keys/2025-01#ed25519-wrong`

const seedCompromised = Uint8Array.from({ length: 32 }, () => 11)
const pubCompromised = b64uEncode(ed25519.getPublicKey(seedCompromised))
const kidCompromised = `${ISSUER}/keys/2025-01#ed25519-compromised`

const seedRetired = Uint8Array.from({ length: 32 }, () => 12)
const pubRetired = b64uEncode(ed25519.getPublicKey(seedRetired))
const kidRetired = `${ISSUER}/keys/2025-01#ed25519-retired`

// Key manifest self-signed by the active key (kid1); also lists a compromised and a
// retired key so a "record signed by a non-active key" can be tested without needing
// a second manifest.
const keyManifest = signManifest(
  {
    issuer: ISSUER,
    manifest_version: 1,
    issued_at: '2025-01-01T00:00:00Z',
    keys: [
      { kid: kid1, pub: pub1, valid_from: '2025-01-01T00:00:00Z', valid_to: null, status: 'active' },
      {
        kid: kidCompromised,
        pub: pubCompromised,
        valid_from: '2025-01-01T00:00:00Z',
        valid_to: null,
        status: 'compromised',
      },
      {
        kid: kidRetired,
        pub: pubRetired,
        valid_from: '2025-01-01T00:00:00Z',
        valid_to: null,
        status: 'retired',
      },
    ],
  },
  kid1,
  seed1,
)

const RECEIPT_ID = '01JZ5PDHT0000G40R40M30E209'

// Minimal payload shape: classifyRevocation only reads receipt_id and license.*.
function receiptPayload(license: Record<string, unknown>): JsonObject {
  return parse({
    issuer: { id: ISSUER, display_name: 'Example Games Store' },
    issued_at: '2025-07-02T13:50:00Z',
    receipt_id: RECEIPT_ID,
    license,
  })
}

// vector 15/16 shape: a single valid revoked record for RECEIPT_ID, signed by kid1.
const revokedRecord = signRecord(
  { receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: '2025-08-01T00:00:00Z' },
  kid1,
  seed1,
)

describe('revocation', () => {
  describe('verifyRecord', () => {
    it('verifies a record signed by the active key', () => {
      expect(verifyRecord(parse(revokedRecord), parse(keyManifest))).toBe(true)
    })

    it('rejects a record signed by a compromised key (a compromised key must not forge revocations)', () => {
      const record = signRecord(
        { receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: '2025-08-01T00:00:00Z' },
        kidCompromised,
        seedCompromised,
      )
      expect(verifyRecord(parse(record), parse(keyManifest))).toBe(false)
    })

    it('rejects a record signed by a retired key', () => {
      const record = signRecord(
        { receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: '2025-08-01T00:00:00Z' },
        kidRetired,
        seedRetired,
      )
      expect(verifyRecord(parse(record), parse(keyManifest))).toBe(false)
    })

    it('rejects a record signed by a key absent from the manifest entirely', () => {
      const record = signRecord(
        { receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: '2025-08-01T00:00:00Z' },
        kidWrong,
        seedWrong,
      )
      expect(verifyRecord(parse(record), parse(keyManifest))).toBe(false)
    })

    it('rejects a record whose revoked_at falls outside the signer key\'s validity window', () => {
      const boundedManifest = signManifest(
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
      const record = signRecord(
        { receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: '2025-08-01T00:00:00Z' },
        kid1,
        seed1,
      )
      expect(verifyRecord(parse(record), parse(boundedManifest))).toBe(false)
    })
  })

  describe('classifyRevocation', () => {
    it('policy receipt + authenticated matching revoked record -> revoked, no warnings (vector 15 shape)', () => {
      const warnings: string[] = []
      const errors: string[] = []
      const result = classifyRevocation(
        receiptPayload({ revocability: 'policy' }),
        [parse(revokedRecord)],
        parse(keyManifest),
        warnings,
        errors,
      )
      expect(result).toBe('revoked')
      expect(warnings).toEqual([])
    })

    it("none receipt + same record -> invalid_revocation_ignored + a warning containing \"revocability is 'none'\" (vector 16 shape)", () => {
      const warnings: string[] = []
      const errors: string[] = []
      const result = classifyRevocation(
        receiptPayload({ revocability: 'none' }),
        [parse(revokedRecord)],
        parse(keyManifest),
        warnings,
        errors,
      )
      expect(result).toBe('invalid_revocation_ignored')
      expect(warnings.some((w) => w.includes("revocability is 'none'"))).toBe(true)
    })

    it('an unauthenticated record (wrong/absent key) matching receipt_id is dropped with a "failed verification, ignored" warning', () => {
      const badRecord = signRecord(
        { receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: '2025-08-01T00:00:00Z' },
        kidWrong,
        seedWrong,
      )
      const warnings: string[] = []
      const errors: string[] = []
      const result = classifyRevocation(
        receiptPayload({ revocability: 'policy' }),
        [parse(badRecord)],
        parse(keyManifest),
        warnings,
        errors,
      )
      // Dropped -> no valid record, and no authenticated record to anchor T -> unknown.
      expect(result).toBe('unknown')
      expect(warnings.some((w) => w.includes('failed verification, ignored'))).toBe(true)
    })

    it('returns unknown for an empty view', () => {
      const warnings: string[] = []
      const errors: string[] = []
      const result = classifyRevocation(receiptPayload({ revocability: 'policy' }), [], parse(keyManifest), warnings, errors)
      expect(result).toBe('unknown')
      expect(warnings).toEqual([])
    })

    it('returns unknown for a null view', () => {
      const warnings: string[] = []
      const errors: string[] = []
      const result = classifyRevocation(
        receiptPayload({ revocability: 'policy' }),
        null,
        parse(keyManifest),
        warnings,
        errors,
      )
      expect(result).toBe('unknown')
      expect(warnings).toEqual([])
    })

    it('the freshness anchor uses ONLY authenticated records; an unauthenticated record must not move T', () => {
      // Neither record's receipt_id matches the payload's, so neither can become a
      // "valid" (effective) record for this receipt — this isolates the anchor
      // computation, which runs over ALL authenticated records regardless of
      // receipt_id, from the per-receipt matching logic.
      const authRecordEarlier = signRecord(
        { receipt_id: 'other-receipt-A', status: 'revoked', revoked_at: '2025-01-01T00:00:00Z' },
        kid1,
        seed1,
      )
      const unauthRecordLater = signRecord(
        { receipt_id: 'other-receipt-B', status: 'revoked', revoked_at: '2099-01-01T00:00:00Z' },
        kidWrong,
        seedWrong,
      )
      const warnings: string[] = []
      const errors: string[] = []
      const result = classifyRevocation(
        receiptPayload({ revocability: 'policy' }),
        [parse(authRecordEarlier), parse(unauthRecordLater)],
        parse(keyManifest),
        warnings,
        errors,
      )
      // If the unauthenticated 2099 record had moved T, this would read
      // 'not_revoked_as_of:2099-01-01T00:00:00Z' instead.
      expect(result).toBe('not_revoked_as_of:2025-01-01T00:00:00Z')
      // Neither record's receipt_id matches -> no "failed verification" warning either.
      expect(warnings).toEqual([])
    })

    describe('refund_window class', () => {
      function refundPayload(windowDays: number, issuedAt: string, receiptId = RECEIPT_ID): JsonObject {
        return parse({
          issuer: { id: ISSUER },
          issued_at: issuedAt,
          receipt_id: receiptId,
          license: { revocability: 'refund_window', revocation_window_days: windowDays },
        })
      }

      it('an effective (in-window) record -> revoked', () => {
        const payload = refundPayload(30, '2025-07-01T00:00:00Z')
        const record = signRecord(
          { receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: '2025-07-15T00:00:00Z' },
          kid1,
          seed1,
        )
        const warnings: string[] = []
        const errors: string[] = []
        expect(classifyRevocation(payload, [parse(record)], parse(keyManifest), warnings, errors)).toBe('revoked')
        expect(warnings).toEqual([])
      })

      it('a valid but out-of-window record -> invalid_revocation_ignored + outside-refund-window warning', () => {
        const payload = refundPayload(30, '2025-07-01T00:00:00Z')
        const record = signRecord(
          { receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: '2025-09-01T00:00:00Z' },
          kid1,
          seed1,
        )
        const warnings: string[] = []
        const errors: string[] = []
        const result = classifyRevocation(payload, [parse(record)], parse(keyManifest), warnings, errors)
        expect(result).toBe('invalid_revocation_ignored')
        expect(warnings.some((w) => w.includes('outside refund window, ignored'))).toBe(true)
      })

      it('no matching valid record -> not_revoked_as_of anchor from the authenticated record', () => {
        // revokedRecord authenticates (kid1, active) so it drives the freshness anchor,
        // but its receipt_id doesn't match this payload's, so it can never become
        // "valid" here -> falls through to the anchor-based not_revoked_as_of result.
        const noMatchPayload = refundPayload(30, '2025-07-01T00:00:00Z', 'no-such-receipt')
        const warnings: string[] = []
        const errors: string[] = []
        const result = classifyRevocation(noMatchPayload, [parse(revokedRecord)], parse(keyManifest), warnings, errors)
        expect(result).toBe('not_revoked_as_of:2025-08-01T00:00:00Z')
        expect(warnings).toEqual([])
      })

      it('a non-integer revocation_window_days (bool) is treated as no window -> not_revoked/unknown, never revoked', () => {
        const payload = parse({
          issuer: { id: ISSUER },
          issued_at: '2025-07-01T00:00:00Z',
          receipt_id: RECEIPT_ID,
          license: { revocability: 'refund_window', revocation_window_days: true },
        })
        const record = signRecord(
          { receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: '2025-07-15T00:00:00Z' },
          kid1,
          seed1,
        )
        const warnings: string[] = []
        const errors: string[] = []
        const result = classifyRevocation(payload, [parse(record)], parse(keyManifest), warnings, errors)
        // window_end is null -> record can never be "effective" -> falls through to the
        // "valid but no effective window" branch -> invalid_revocation_ignored.
        expect(result).toBe('invalid_revocation_ignored')
        expect(warnings.some((w) => w.includes('outside refund window, ignored'))).toBe(true)
      })
    })
  })
})
