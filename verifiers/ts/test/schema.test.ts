import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { validatePayload, SCHEMA_TOP_LEVEL_KEYS } from '../src/schema.js'
import { loadsStrict, JsonObject } from '../src/canon.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const enc = (s: string) => new TextEncoder().encode(s)

const MINIMAL = () => loadsStrict(enc(JSON.stringify({
  attest_version: '0.1', issued_at: '2025-06-01T00:00:00Z', receipt_id: '01J000000000000000000000AA',
  issuer: { display_name: 'Store', id: 'store.example.com' },
  work: { title: 'T', publisher: 'P', identifiers: { issuer_sku: 'X' } },
  license: { grant: 'perpetual', revocability: 'policy', transferable: false, drm: 'drm-bound', terms_uri: 'https://x/t', legal_text_sha256: 'a'.repeat(64) },
  buyer: { commitment: 'A'.repeat(43), identifier_type: 'email', pubkey: null },
  survivability: { end_of_life: 'none', eol_commitment_sha256: null, eol_commitment_uri: null, redownload_right: false },
  supersedes: null,
}))) as JsonObject

describe('validatePayload', () => {
  it('accepts a well-formed payload', () => { expect(validatePayload(MINIMAL())).toEqual([]) })
  it('rejects a missing required member', () => {
    const p = MINIMAL(); delete (p as any).issuer
    expect(validatePayload(p).length).toBeGreaterThan(0)
  })
  it('rejects an invalid drm enum', () => {
    const p = MINIMAL(); (p['license'] as any).drm = 'nope'
    expect(validatePayload(p).length).toBeGreaterThan(0)
  })
  it('top-level key set matches the schema (for unknown-field warnings)', () => {
    expect(SCHEMA_TOP_LEVEL_KEYS.has('attest_version')).toBe(true)
    expect(SCHEMA_TOP_LEVEL_KEYS.has('promo_code')).toBe(false)
  })
})

// v0.2 Stage 3 (§17): D1 conditional (buyer.pubkey required, non-null, when
// attest_version is 0.2 and license.transferable is true) + the
// not_transferable_before shape check.
const MINIMAL_V02_TRANSFERABLE = () => {
  const p = MINIMAL()
  ;(p as any).attest_version = '0.2'
  ;(p as any).license.transferable = true
  ;(p as any).buyer.pubkey = 'B'.repeat(43)
  return p
}

describe('validatePayload — D1 transferable conditional (v0.2 §17)', () => {
  it('accepts a well-formed v0.2 transferable payload', () => {
    expect(validatePayload(MINIMAL_V02_TRANSFERABLE())).toEqual([])
  })

  it('rejects a null buyer.pubkey when transferable is true (attest_version 0.2)', () => {
    const p = MINIMAL_V02_TRANSFERABLE()
    ;(p as any).buyer.pubkey = null
    expect(validatePayload(p)).toContain(
      'buyer.pubkey: must be a non-null 43-char base64url string when license.transferable is true (attest_version 0.2)',
    )
  })

  it('rejects a missing buyer.pubkey when transferable is true (attest_version 0.2)', () => {
    const p = MINIMAL_V02_TRANSFERABLE()
    delete (p as any).buyer.pubkey
    expect(validatePayload(p)).toContain(
      'buyer.pubkey: must be a non-null 43-char base64url string when license.transferable is true (attest_version 0.2)',
    )
  })

  it('does not apply the conditional under attest_version 0.1, even if transferable is true', () => {
    const p = MINIMAL_V02_TRANSFERABLE()
    ;(p as any).attest_version = '0.1'
    ;(p as any).buyer.pubkey = null
    expect(validatePayload(p)).toEqual([])
  })

  it('does not apply the conditional when license.transferable is false', () => {
    const p = MINIMAL_V02_TRANSFERABLE()
    ;(p as any).license.transferable = false
    ;(p as any).buyer.pubkey = null
    expect(validatePayload(p)).toEqual([])
  })
})

describe('validatePayload — license.not_transferable_before (v0.2 §17.7)', () => {
  it('accepts a well-formed not_transferable_before', () => {
    const p = MINIMAL_V02_TRANSFERABLE()
    ;(p as any).license.not_transferable_before = '2026-08-01T00:00:00Z'
    expect(validatePayload(p)).toEqual([])
  })

  it('rejects a non-canonical not_transferable_before', () => {
    const p = MINIMAL_V02_TRANSFERABLE()
    ;(p as any).license.not_transferable_before = '2026-8-1T0:0:0Z'
    expect(validatePayload(p)).toContain(
      'license.not_transferable_before: must be an RFC3339 UTC date-time (YYYY-MM-DDTHH:MM:SSZ)',
    )
  })

  it.each(['2026-02-30T00:00:00Z', '2026-13-01T00:00:00Z', '2026-04-31T00:00:00Z'])(
    'keeps calendar-impossible not_transferable_before as schema-valid wire shape (%s)',
    (notTransferableBefore) => {
      const p = MINIMAL_V02_TRANSFERABLE()
      ;(p as any).license.not_transferable_before = notTransferableBefore
      expect(validatePayload(p)).toEqual([])
    },
  )
})

// De-risk the Task 14 conformance gate: every real vector payload must
// validate to []. If any of these fail, the validator is over-strict
// relative to the authoritative schema and must be relaxed (never edit
// the vector to make it pass).
describe('validatePayload against real conformance vectors', () => {
  const repoRoot = join(__dirname, '..', '..', '..')
  const vectors = [
    '01-valid-minimal',
    '02-valid-full',
    '10-unknown-field',
    '15-revoked-policy',
    '16-revocation-against-none-ignored',
    '18-drm-bound',
  ]
  for (const vector of vectors) {
    it(`${vector}/payload.json validates to []`, () => {
      const bytes = readFileSync(join(repoRoot, 'docs/spec/vectors', vector, 'payload.json'))
      const payload = loadsStrict(bytes) as JsonObject
      expect(validatePayload(payload)).toEqual([])
    })
  }
})
