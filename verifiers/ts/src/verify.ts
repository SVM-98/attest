import { JsonObject, JsonValue, canonicalBytes, CanonError, loadsStrict } from './canon.js'
import { TrustStore, findKey, withinValidity, chainContinuous } from './manifests.js'
import { verifyStrict, Ed25519LengthError } from './ed25519.js'
import { b64uDecode } from './b64u.js'
import { validatePayload, SCHEMA_TOP_LEVEL_KEYS } from './schema.js'
import { classifyRevocation } from './revocation.js'
import { computeCommitment, verifyChallenge } from './commitment.js'
import { b64uEncode } from './b64u.js'
import {
  ERR, WARN, unsupportedOprVersion, signaturesCount, unsupportedSigAlg, noTrustedManifest,
  noKeyInManifest, keyCompromised, keyRetired, issuedAtOutsideWindow, malformedKeyMaterial,
  malformedSigMaterial, unknownField, unknownEol,
} from './messages.js'

export type Signature = 'valid' | 'invalid'
export type Schema = 'valid' | 'invalid' | 'not_checked'
export type Binding = 'proven' | 'not_proven' | 'not_checked'
export type Trust = 'verified' | 'unauthenticated_tofu' | 'unverified_rotation'
export interface VerificationResult {
  signature: Signature; schema: Schema; revocation: string; binding: Binding; trust: Trust
  warnings: string[]; errors: string[]
}
export interface Disclosure {
  identifier?: string | null; identifier_type?: string | null
  salt?: Uint8Array | null; challenge?: [Uint8Array, Uint8Array] | null
}
const KNOWN_EOL = new Set(['artifacts-remain-redownloadable', 'escrow', 'none'])

export function isOk(r: VerificationResult): boolean {
  return r.signature === 'valid' && r.schema === 'valid' && r.revocation !== 'revoked' && r.errors.length === 0
}

function obj(v: JsonValue | undefined): JsonObject | null {
  return v !== null && v !== undefined && typeof v === 'object' && !Array.isArray(v) ? (v as JsonObject) : null
}

// Loud boundary guard: a loadsStrict-parsed structure never contains a JS `number`
// (integers are `bigint`; floats are rejected at parse time). A JS `number` therefore
// means the consumer built the trust store / revocation view with `JSON.parse` instead
// of loadsStrict. Left unguarded, `manifest_version` as a `number` makes the self-verify
// helpers' `serialize` throw CanonError(TYPE_NOT_JSON) → swallowed by their `catch { return
// false }` → every revocation record is treated as forged → a genuinely REVOKED receipt
// reports not_revoked (silent fail-open). Fail fast at the public boundary instead. Walks
// arrays and plain objects only; non-plain values (e.g. Uint8Array) are not walked.
function assertCanonParsed(value: unknown, label: string): void {
  if (typeof value === 'number')
    throw new TypeError(`${label} must be parsed with loadsStrict (bigint integers), not JSON.parse — found a JS number`)
  if (Array.isArray(value)) {
    for (const item of value) assertCanonParsed(item, label)
    return
  }
  if (value !== null && typeof value === 'object') {
    const proto = Object.getPrototypeOf(value)
    if (proto === Object.prototype || proto === null)
      for (const k of Object.keys(value)) assertCanonParsed((value as Record<string, unknown>)[k], label)
    // non-plain objects (Uint8Array, class instances, etc.) are intentionally not walked
  }
}

function contentWarnings(payload: JsonObject): string[] {
  const w: string[] = []
  for (const k of Object.keys(payload)) if (!SCHEMA_TOP_LEVEL_KEYS.has(k)) w.push(unknownField(k))
  const license = obj(payload['license'])
  if (license && license['drm'] === 'drm-bound') w.push(WARN.DRM_BOUND)
  const surv = obj(payload['survivability'])
  if (surv) { const eol = surv['end_of_life']; if (typeof eol !== 'string' || !KNOWN_EOL.has(eol)) w.push(unknownEol(eol)) }
  return w
}

function classifyBinding(payload: JsonObject, d: Disclosure): Binding {
  const buyer = obj(payload['buyer'])
  if (!buyer) return 'not_proven'
  if (d.salt != null && d.identifier != null && d.identifier_type != null) {
    const expected = buyer['commitment']
    if (typeof expected !== 'string') return 'not_proven'
    try { return b64uEncode(computeCommitment(d.identifier, d.identifier_type, d.salt)) === expected ? 'proven' : 'not_proven' }
    catch { return 'not_proven' }
  }
  if (d.challenge != null) {
    const pub = buyer['pubkey'], rid = payload['receipt_id']
    if (typeof pub !== 'string' || typeof rid !== 'string') return 'not_proven'
    try { return verifyChallenge(rid, d.challenge[0], d.challenge[1], b64uDecode(pub)) ? 'proven' : 'not_proven' }
    catch { return 'not_proven' }
  }
  return 'not_proven'
}

export function verify(
  envelopeBytes: Uint8Array, trustStore: TrustStore,
  revocationView: JsonValue[] | null = null, disclosure: Disclosure | null = null,
): VerificationResult {
  if (revocationView !== null && !Array.isArray(revocationView))
    throw new TypeError('revocation_view must be a list of records or None')

  // Fail loud if the trust store / revocation view was JSON.parse'd (JS numbers) rather
  // than loadsStrict-parsed (bigint). Prevents a silent revocation fail-open. Does NOT
  // walk envelopeBytes (parsed internally) or disclosure (holds raw Uint8Array fields).
  assertCanonParsed(trustStore.manifests, 'trustStore.manifests')
  if (trustStore.chains != null) assertCanonParsed(trustStore.chains, 'trustStore.chains')
  if (revocationView !== null) assertCanonParsed(revocationView, 'revocation_view')

  const errors: string[] = []
  const warnings: string[] = []
  let trust: Trust = 'unauthenticated_tofu'
  const invalid = (message: string, schema: Schema = 'not_checked'): VerificationResult => {
    errors.push(message)
    return { signature: 'invalid', schema, revocation: 'unknown', binding: 'not_checked', trust, warnings: [...warnings], errors: [...errors] }
  }

  // Step 0 — strict parse
  let parsed: JsonValue
  try { parsed = loadsStrict(envelopeBytes) }
  catch (e) { if (e instanceof CanonError) return invalid(e.message); throw e }
  const envelope = obj(parsed)
  if (!envelope) return invalid(ERR.ENVELOPE_NOT_OBJECT)
  const payload = obj(envelope['payload'])
  if (!payload) return invalid(ERR.MISSING_PAYLOAD)
  const signatures = envelope['signatures']
  if (!Array.isArray(signatures)) return invalid(ERR.MISSING_SIGNATURES)

  // Trust resolution — AFTER payload/signatures checks, BEFORE step 1. Never reset later.
  const issuerBlock = obj(payload['issuer'])
  const issuerId = issuerBlock ? issuerBlock['id'] : undefined
  if (typeof issuerId === 'string') {
    trust = trustStore.provenance[issuerId] === 'tls' ? 'verified' : 'unauthenticated_tofu'
    const chain = trustStore.chains?.[issuerId]
    if (chain && chain.length > 0 && !chainContinuous(chain)) trust = 'unverified_rotation'
  }

  // Step 1 — envelope shape
  const oprVersion = payload['opr_version']
  if (oprVersion !== '0.1') return invalid(unsupportedOprVersion(oprVersion))
  if (signatures.length !== 1) return invalid(signaturesCount(signatures.length))
  const sigBlock = obj(signatures[0])
  if (!sigBlock) return invalid(ERR.MALFORMED_SIG_BLOCK)
  const kid = sigBlock['kid'], alg = sigBlock['alg'], sigB64 = sigBlock['sig']
  if (typeof kid !== 'string' || typeof sigB64 !== 'string') return invalid(ERR.MALFORMED_SIG_BLOCK_TYPES)
  if (alg !== 'Ed25519') return invalid(unsupportedSigAlg(alg))

  // Step 2 — issuer binding
  if (typeof issuerId !== 'string') return invalid(ERR.MISSING_ISSUER_ID)
  const manifest = trustStore.manifests[issuerId]
  if (manifest == null) return invalid(noTrustedManifest(issuerId))
  if (kid.split('/')[0] !== issuerId || manifest['issuer'] !== issuerId) return invalid(ERR.ISSUER_MISMATCH)

  // Step 3 — key resolution + status + validity window
  const entry = findKey(manifest, kid)
  if (entry == null) return invalid(noKeyInManifest(kid))
  const status = entry['status']
  if (status === 'compromised') return invalid(keyCompromised(kid))
  const issuedAt = payload['issued_at']
  if (typeof issuedAt !== 'string' || !withinValidity(issuedAt, entry)) return invalid(issuedAtOutsideWindow(issuedAt))
  if (status === 'retired') warnings.push(keyRetired(kid))

  // Step 4 — signature
  let pub: Uint8Array, sig: Uint8Array
  try { const p = entry['pub']; if (typeof p !== 'string') throw new Error('pub not a string'); pub = b64uDecode(p); sig = b64uDecode(sigB64) }
  catch (e) { return invalid(malformedKeyMaterial(e instanceof Error ? e.message : String(e))) }
  let signatureOk: boolean
  try { signatureOk = verifyStrict(canonicalBytes(payload), sig, pub) }
  catch (e) {
    if (e instanceof CanonError || e instanceof Ed25519LengthError) return invalid(malformedSigMaterial(e.message))
    throw e
  }
  if (!signatureOk) return invalid(ERR.SIG_VERIFICATION_FAILED)

  // Step 5 — schema + content warnings
  const violations = validatePayload(payload)
  const schema: Schema = violations.length === 0 ? 'valid' : 'invalid'
  errors.push(...violations)
  warnings.push(...contentWarnings(payload))

  // Steps 6-7 — revocation + binding (only when schema valid)
  let revocation = 'unknown'
  let binding: Binding = 'not_checked'
  if (schema === 'valid') {
    revocation = classifyRevocation(payload, revocationView, manifest, warnings)
    binding = disclosure != null ? classifyBinding(payload, disclosure) : 'not_checked'
  }

  return { signature: 'valid', schema, revocation, binding, trust, warnings: [...warnings], errors: [...errors] }
}
