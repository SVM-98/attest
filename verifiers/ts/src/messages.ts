// Verbatim error/warning strings. Conformance vectors substring-match these,
// so DO NOT paraphrase. Interpolations reproduce Python repr (!r) exactly:
// strings single-quoted, None bare; kid is bare in compromised/retired, repr'd in "no key".

export function pyRepr(x: unknown): string {
  if (typeof x === 'string') return `'${x}'`
  if (x === null || x === undefined) return 'None'
  if (typeof x === 'boolean') return x ? 'True' : 'False'
  if (Array.isArray(x)) return `[${x.map(pyRepr).join(', ')}]`
  return String(x)
}

export const ERR = {
  ENVELOPE_NOT_OBJECT: 'envelope is not a JSON object',
  MISSING_PAYLOAD: "envelope missing object member 'payload'",
  MISSING_SIGNATURES: "envelope missing array member 'signatures'",
  MALFORMED_SIG_BLOCK: 'malformed signature block',
  MALFORMED_SIG_BLOCK_TYPES: "malformed signature block: 'kid'/'sig' must be strings",
  MISSING_ISSUER_ID: 'malformed payload: missing issuer.id',
  ISSUER_MISMATCH: 'issuer_mismatch: kid domain does not match payload issuer.id',
  SIG_VERIFICATION_FAILED: 'signature verification failed',
  FLOATS_NOT_ALLOWED: 'floats are not allowed in the attest-JCS profile',
  LONE_SURROGATE: 'lone surrogate not allowed in the attest-JCS profile',
  TYPE_NOT_JSON: 'type not representable in JSON',
  // v0.2 hybrid envelope (Ed25519 + ML-DSA-65) — byte-identical to verify.py.
  hybridSigCount: 'hybrid envelope requires exactly two signatures',
  hybridAlgs: 'hybrid envelope requires algs Ed25519 and ML-DSA-65 in order',
  hybridKidShared: 'hybrid envelope signatures must share a single kid',
  hybridKidType: "malformed signature block: 'kid' must be a string",
  hybridSigType: "malformed signature block: 'sig' must be a string",
  mldsaSigInvalid: 'ML-DSA-65 signature verification failed',
} as const

export const WARN = {
  DRM_BOUND: 'license.drm is drm-bound (design vector 18)',
  REVOCABILITY_NONE_IGNORED: "revocation record ignored: license.revocability is 'none' (irrevocable)",
} as const

export const unsupportedAttestVersion = (v: unknown) => `unsupported attest_version: ${pyRepr(v)}`
export const signaturesCount = (n: number) => `signatures must contain exactly one entry, got ${n}`
export const unsupportedSigAlg = (alg: unknown) => `unsupported signature algorithm: ${pyRepr(alg)}`
export const noTrustedManifest = (issuer: string) => `no trusted manifest for issuer ${pyRepr(issuer)}`
export const noKeyInManifest = (kid: string) => `no key ${pyRepr(kid)} in issuer manifest`
export const keyCompromised = (kid: string) => `key ${kid} is compromised`
export const keyRetired = (kid: string) => `key ${kid} is retired`
export const issuedAtOutsideWindow = (issuedAt: unknown) => `issued_at ${pyRepr(issuedAt)} outside key validity window`
export const malformedKeyMaterial = (msg: string) => `malformed key material: ${msg}`
export const malformedSigMaterial = (msg: string) => `malformed signature material: ${msg}`
export const keyEntryNotHybrid = (kid: string) => `key entry for kid ${pyRepr(kid)} has no ML-DSA-65 public key`

// canon (CanonError messages)
export const duplicateKey = (k: string) => `duplicate object key: ${pyRepr(k)}`
export const intOutOfRange = (n: bigint) => `integer out of I-JSON safe range: ${n.toString()}`
export const nonStringKey = (k: unknown) => `non-string object key: ${pyRepr(k)}`
export const notUtf8 = (msg: string) => `input is not valid UTF-8: ${msg}`
export const invalidJson = (msg: string) => `invalid JSON: ${msg}`

// content + revocation warnings
export const unknownField = (k: string) => `unknown payload field: ${pyRepr(k)}`
export const unknownEol = (v: unknown) => `unknown survivability.end_of_life value: ${pyRepr(v)}`
export const revocationFailedVerify = (rid: unknown) => `revocation record for ${pyRepr(rid)} failed verification, ignored`
export const outsideRefundWindow = (rid: unknown) => `revocation record for ${pyRepr(rid)} outside refund window, ignored`
export const revocationViewOversize = (n: number, max: number) =>
  `revocation view exceeds ${max} records (${n} supplied), not evaluated`
export const revocationViewOversizeRevocable = (n: number, max: number) =>
  `revocation view exceeds ${max} records (${n} supplied), cannot certify a revocable receipt`
