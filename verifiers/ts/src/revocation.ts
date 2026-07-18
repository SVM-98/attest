import { JsonObject, JsonValue, canonicalBytes } from './canon.js'
import { verifyKeyManifest, findKey, verifySignatureBlock } from './manifests.js'
import { parseStrictUtc, parseIsoLenient } from './dates.js'
import { revocationFailedVerify, outsideRefundWindow, revocationViewOversize, revocationViewOversizeRevocable, WARN } from './messages.js'

function asObject(v: JsonValue | undefined): JsonObject | null {
  return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as JsonObject) : null
}

function signableRecordBytes(record: JsonObject): Uint8Array {
  const body: JsonObject = Object.create(null)
  for (const k of Object.keys(record)) if (k !== 'signature') body[k] = record[k]!
  return canonicalBytes(body)
}

// PRECONDITION: caller already established verifyKeyManifest(keyManifest) is
// true. Loop-over-records callers hoist that call — one manifest self-verify
// per classification, not per record (review improvement #17). To verify a
// single record, use verifyRecord, which composes both halves.
//
// AND rule (v0.2, mirrors manifests.py's verify_record_signature): if the
// signer's keyManifest entry is hybrid (carries pub_ml_dsa_65), `signature`
// MUST also carry a valid sig_ml_dsa_65 leg over the same signed bytes, or
// verification fails closed; an Ed25519-only entry with a stray
// sig_ml_dsa_65 leg likewise fails closed (see verifySignatureBlock).
// Ed25519-only signers keep v0.1 behavior byte-for-byte (Stage 2 Task 6/8
// sibling-patch parity).
export function verifyRecordSignature(record: JsonObject, keyManifest: JsonObject): boolean {
  try {
    const sig = asObject(record['signature'])
    if (!sig || typeof sig['kid'] !== 'string') return false
    const entry = findKey(keyManifest, sig['kid'])
    if (!entry || entry['status'] !== 'active') return false // active only: retired/compromised reject
    const at = parseStrictUtc(record['revoked_at'])
    const from = parseStrictUtc(entry['valid_from'])
    if (at === null || from === null || at < from) return false
    const to = entry['valid_to']
    if (to !== null && to !== undefined) { const toMs = parseStrictUtc(to); if (toMs === null || at > toMs) return false }
    return verifySignatureBlock(signableRecordBytes(record), sig, entry)
  } catch { return false }
}

export function verifyRecord(record: JsonObject, keyManifest: JsonObject): boolean {
  try { return verifyKeyManifest(keyManifest) && verifyRecordSignature(record, keyManifest) } catch { return false }
}

function refundWindowEnd(payload: JsonObject): number | null {
  const license = asObject(payload['license'])
  if (!license) return null
  const days = license['revocation_window_days']
  if (typeof days !== 'bigint') return null // integer only; bool/float/string -> null
  const issued = parseStrictUtc(payload['issued_at'])
  if (issued === null) return null
  return issued + Number(days) * 86_400_000
}

// Preflight bound on the untrusted revocation view (review improvement #17):
// a legitimate view for one verify() call is an issuer's records for one
// receipt — realistically single digits; 10k is far above any legitimate case
// and keeps hostile worst-case work bounded. Mirrors Python's
// _MAX_REVOCATION_RECORDS.
export const MAX_REVOCATION_RECORDS = 10_000

export function classifyRevocation(
  payload: JsonObject, view: JsonValue[] | null, issuerManifest: JsonObject, warnings: string[],
  errors: string[], maxRecords: number = MAX_REVOCATION_RECORDS,
): string {
  if (!view || view.length === 0) return 'unknown'

  const license = asObject(payload['license'])
  const revocability = license ? license['revocability'] : undefined

  // Oversized view: not evaluated — never truncate, never throw. Fail CLOSED
  // for revocable receipts (error → ok=false): an untrusted view too large to
  // evaluate cannot rule out a revocation, and "unknown"+ok would let an
  // append-only feed-poisoning attacker suppress a genuine revocation by
  // padding past the cap. Irrevocable ("none") receipts: non-fatal warning.
  if (view.length > maxRecords) {
    if (revocability === 'policy' || revocability === 'refund_window') {
      errors.push(revocationViewOversizeRevocable(view.length, maxRecords))
    } else {
      warnings.push(revocationViewOversize(view.length, maxRecords))
    }
    return 'unknown'
  }

  // One manifest self-verify per classification, not per record (improvement #17).
  const manifestOk = verifyKeyManifest(issuerManifest)
  const auth: boolean[] = view.map((r) => { const o = asObject(r); return manifestOk && o !== null && verifyRecordSignature(o, issuerManifest) })

  // freshness anchor T = max revoked_at over AUTHENTICATED records of ANY receipt_id
  let anchorMs = -Infinity, anchorRaw: string | null = null
  view.forEach((r, i) => {
    if (!auth[i]) return
    const o = asObject(r)!; const raw = o['revoked_at']
    const ms = parseIsoLenient(raw)
    if (ms !== null && ms > anchorMs) { anchorMs = ms; anchorRaw = typeof raw === 'string' ? raw : null }
  })
  const notRevoked = anchorRaw === null ? 'unknown' : `not_revoked_as_of:${anchorRaw}`

  const receiptId = payload['receipt_id']
  const valid: JsonObject[] = []
  view.forEach((r, i) => {
    const o = asObject(r)
    if (!o || o['receipt_id'] !== receiptId) return
    if (!auth[i]) { warnings.push(revocationFailedVerify(receiptId)); return }
    if (o['status'] === 'revoked') valid.push(o)
  })

  if (revocability === 'none') {
    if (valid.length > 0) { warnings.push(WARN.REVOCABILITY_NONE_IGNORED); return 'invalid_revocation_ignored' }
    return notRevoked
  }
  if (revocability === 'policy') return valid.length > 0 ? 'revoked' : notRevoked
  if (revocability === 'refund_window') {
    const end = refundWindowEnd(payload)
    const effective = valid.filter((r) => { const ms = parseIsoLenient(r['revoked_at']); return end !== null && ms !== null && ms <= end })
    if (effective.length > 0) return 'revoked'
    if (valid.length > 0) { warnings.push(outsideRefundWindow(receiptId)); return 'invalid_revocation_ignored' }
    return notRevoked
  }
  return notRevoked
}
