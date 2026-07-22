import { sha256 } from '@noble/hashes/sha2'
import { bytesToHex } from '@noble/curves/utils.js'
import { JsonObject, JsonValue, canonicalBytes, dumps, CanonError } from './canon.js'
import { verifyKeyManifest, findKey, verifySignatureBlock } from './manifests.js'
import { parseStrictUtc, parseIsoLenient } from './dates.js'
import { LogKey, encodeEntry, TlogError } from './tlog.js'
import { AnchorPolicy, validatePolicy } from './anchor.js'
import { evaluateTransparency, validateLogKeys, TransparencyError } from './transparency.js'
import {
  revocationFailedVerify, outsideRefundWindow, revocationViewOversize, revocationViewOversizeRevocable,
  WARN, VERIFY_TRANSPARENCY_WARN, pyRepr, codePointLength,
} from './messages.js'

function asObject(v: JsonValue | undefined): JsonObject | null {
  return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as JsonObject) : null
}

function signableRecordBytes(record: JsonObject): Uint8Array {
  const body: JsonObject = Object.create(null)
  for (const k of Object.keys(record)) if (k !== 'signature') body[k] = record[k]!
  return canonicalBytes(body)
}

// G5 (v0.2 §8, TM-47): `SHA-256(JCS(record))` over the ENTIRE signed record
// (including its `signature` member, unlike `signableRecordBytes` above,
// which excludes it to check the signature itself) — what a
// `revocation-record` transparency-log entry commits to. Python parity:
// `revocation.record_hash`.
export function recordHash(record: JsonObject): string {
  return bytesToHex(sha256(canonicalBytes(record)))
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

const CLAIM_TYPE_REVOCATION_RECORD = 'revocation-record'
// Mirrors verify.py's `_MAX_TRANSPARENCY_EVIDENCE_LEN` — this is the SAME
// class of untrusted per-claim evidence bundle, just for a revocation
// record's claim instead of a receipt/key-manifest claim.
const MAX_REVOCATION_EVIDENCE_LEN = 10_000_000

/** The single pinned origin shared by every entry in `logKeys` — trusted
 * verifier config, never derived from untrusted evidence (mirrors
 * verify.ts's own private `resolveLogOrigin`, duplicated here rather than
 * imported to avoid a revocation.ts <-> verify.ts import cycle). */
function resolveLogOrigin(logKeys: LogKey[]): string {
  const validated = validateLogKeys(logKeys)
  const origins = new Set(validated.map((key) => key.origin))
  if (origins.size !== 1) {
    throw new TransparencyError(
      `log_keys must be a non-empty list sharing a single origin, got ${pyRepr([...origins].sort())}`,
    )
  }
  return [...origins][0]!
}

function validatedRevocationEntry(candidate: Record<string, unknown>): Record<string, unknown> | null {
  try { encodeEntry(candidate); return candidate } catch (e) { if (e instanceof TlogError) return null; throw e }
}

function isPlainRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
}

/** G5 (v0.2 §8/§15, TM-47): True iff at least one of `effective`'s
 * refund_window revocation records has Stage 2 evidence proving it was
 * logged AND anchored no later than `windowEndMs` (the SAME refund-window
 * deadline `refundWindowEnd`/the caller's own `within-window` filter already
 * compute). Only called once the caller has established the verifier is
 * Stage-2 capable (`logKeys`/`anchorPolicy` both supplied) and `effective`
 * is non-empty; `revocationEvidence` may still be absent or fail to
 * resolve, in which case this returns `false`. Every warning the shared
 * evaluator returns for a candidate record (e.g. `anchor_note_only`,
 * malformed-evidence reasons, `log_equivocation_detected`) is appended to
 * `warnings` (dedup against identical strings already present) regardless
 * of whether that record ends up timely — mirrors the direct transparency
 * path's own `warnings.push(...result.warnings)`. Python parity:
 * `verify._revocation_deadline_satisfied`. */
function revocationDeadlineSatisfied(
  effective: JsonObject[], revocationEvidence: JsonValue | null, issuerId: string | null,
  logKeys: LogKey[], anchorPolicy: AnchorPolicy, windowEndMs: number | null, warnings: string[],
): boolean {
  if (revocationEvidence == null || windowEndMs === null) return false

  const origin = resolveLogOrigin(logKeys)
  validatePolicy(anchorPolicy)

  let materialized: unknown
  try {
    const serialized = dumps(revocationEvidence)
    if (codePointLength(serialized) > MAX_REVOCATION_EVIDENCE_LEN) return false
    materialized = JSON.parse(serialized)
    if (!isPlainRecord(materialized)) return false
  } catch { return false }

  for (const record of effective) {
    let hash: string
    try { hash = recordHash(record) } catch (e) { if (e instanceof CanonError) continue; throw e }
    const expectedEntry = validatedRevocationEntry({
      type: CLAIM_TYPE_REVOCATION_RECORD, issuer: issuerId, record_sha256: hash,
    })
    if (expectedEntry === null) continue
    const result = evaluateTransparency(materialized as JsonObject, {
      logKeys, expectedOrigin: origin, policy: anchorPolicy, expectedEntry,
    })
    for (const warning of result.warnings) {
      if (!warnings.includes(warning)) warnings.push(warning)
    }
    if (!result.transparency.startsWith('anchored_before:')) continue
    const anchoredMs = parseIsoLenient(result.transparency.slice('anchored_before:'.length))
    if (anchoredMs === null) continue
    if (anchoredMs <= windowEndMs) return true
  }
  return false
}

export function classifyRevocation(
  payload: JsonObject, view: JsonValue[] | null, issuerManifest: JsonObject, warnings: string[],
  errors: string[], maxRecords: number = MAX_REVOCATION_RECORDS,
  logKeys: LogKey[] | null = null, anchorPolicy: AnchorPolicy | null = null,
  revocationEvidence: JsonValue | null = null,
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
    if (effective.length > 0) {
      // G5 (TM-47): a Stage-2-capable verifier (logKeys AND anchorPolicy
      // both supplied — the same gate `evaluateTransparencyClaim` uses)
      // MUST additionally apply the deadline-effectiveness rule. A verifier
      // that never supplies them is not Stage-2 capable, so the rule does
      // not engage and v0.1 semantics stand.
      if (logKeys != null && anchorPolicy != null) {
        const issuerId = typeof issuerManifest['issuer'] === 'string' ? (issuerManifest['issuer'] as string) : null
        const timely = revocationDeadlineSatisfied(effective, revocationEvidence, issuerId, logKeys, anchorPolicy, end, warnings)
        if (!timely) { warnings.push(VERIFY_TRANSPARENCY_WARN.REVOCATION_UNLOGGED_DEADLINE); return 'invalid_revocation_ignored' }
      }
      return 'revoked'
    }
    if (valid.length > 0) { warnings.push(outsideRefundWindow(receiptId)); return 'invalid_revocation_ignored' }
    return notRevoked
  }
  return notRevoked
}
