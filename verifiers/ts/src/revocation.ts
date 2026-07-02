import { JsonObject, JsonValue, canonicalBytes } from './canon.js'
import { verifyKeyManifest, findKey } from './manifests.js'
import { verifyStrict } from './ed25519.js'
import { b64uDecode } from './b64u.js'
import { parseStrictUtc, parseIsoLenient } from './dates.js'
import { revocationFailedVerify, outsideRefundWindow, WARN } from './messages.js'

function asObject(v: JsonValue | undefined): JsonObject | null {
  return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as JsonObject) : null
}

function signableRecordBytes(record: JsonObject): Uint8Array {
  const body: JsonObject = Object.create(null)
  for (const k of Object.keys(record)) if (k !== 'signature') body[k] = record[k]!
  return canonicalBytes(body)
}

export function verifyRecord(record: JsonObject, keyManifest: JsonObject): boolean {
  try {
    if (!verifyKeyManifest(keyManifest)) return false
    const sig = asObject(record['signature'])
    if (!sig || typeof sig['kid'] !== 'string' || typeof sig['sig'] !== 'string') return false
    const entry = findKey(keyManifest, sig['kid'])
    if (!entry || entry['status'] !== 'active') return false // active only: retired/compromised reject
    const at = parseStrictUtc(record['revoked_at'])
    const from = parseStrictUtc(entry['valid_from'])
    if (at === null || from === null || at < from) return false
    const to = entry['valid_to']
    if (to !== null) { const toMs = parseStrictUtc(to); if (toMs === null || at > toMs) return false }
    const pub = entry['pub']
    if (typeof pub !== 'string') return false
    return verifyStrict(signableRecordBytes(record), b64uDecode(sig['sig']), b64uDecode(pub))
  } catch { return false }
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

export function classifyRevocation(
  payload: JsonObject, view: JsonValue[] | null, issuerManifest: JsonObject, warnings: string[],
): string {
  if (!view || view.length === 0) return 'unknown'

  const auth: boolean[] = view.map((r) => { const o = asObject(r); return o !== null && verifyRecord(o, issuerManifest) })

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

  const license = asObject(payload['license'])
  const revocability = license ? license['revocability'] : undefined
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
