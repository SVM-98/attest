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

// Python `type(x).__name__` for the closed universe of values that ever cross
// the tlog/anchor/transparency untrusted-evidence boundary (already-JSON.parse'd
// data: null/bool/number/string/array/plain-object — never bigint, never a
// class instance). Stage 1's messages never needed this; Stage 2's fail-closed
// warnings interpolate it verbatim (e.g. anchor.py's `type(evidence).__name__`).
export function pyTypeName(x: unknown): string {
  if (x === null || x === undefined) return 'NoneType'
  if (typeof x === 'boolean') return 'bool'
  if (typeof x === 'number') return Number.isInteger(x) ? 'int' : 'float'
  if (typeof x === 'string') return 'str'
  if (Array.isArray(x)) return 'list'
  if (typeof x === 'object') return 'dict'
  return typeof x
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

// --------------------------------------------------------------------------
// Stage 2 (tlog/anchor/transparency): AnchorVerdict.warnings and
// TransparencyResult.warnings are a cross-language protocol surface — copied
// byte-for-byte from anchor.py/transparency.py (see those modules' docstrings).
// TlogError/AnchorError/TransparencyError *messages* are free-form developer
// diagnostics with no parity requirement and mostly stay inline in their
// module, except where reused/templated here for DRY.
// --------------------------------------------------------------------------

export const RFC3161_WARNING =
  'rfc3161 token accepted as opaque classical evidence, carries no post-horizon weight'

export const ANCHOR_WARN = {
  EVIDENCE_CHECKPOINT_REQUIRED: 'evidence.checkpoint is required',
  EVIDENCE_CHECKPOINT_NOT_STR: 'evidence.checkpoint must be a str',
  EVIDENCE_CHECKPOINT_INVALID: 'evidence.checkpoint is not a valid signed checkpoint',
  EVIDENCE_CHECKPOINT_MISMATCH: 'evidence.checkpoint does not match checkpoint argument',
  OTS_EMPTY_OPS: 'ots proof has empty op-chain',
  OTS_OPS_NOT_LIST: "ots proof 'ops' must be a list",
  OTS_HEADER_MERKLE_ROOT_INVALID: "ots proof 'header_merkle_root' must be 64 lowercase hex chars",
  OTS_HEADER_HASH_INVALID: "ots proof 'header_hash' must be 64 lowercase hex chars",
  OTS_CHAIN_MISMATCH: 'ots op-chain result does not match header_merkle_root',
  OTS_HEADER_NOT_PINNED: 'header_hash is not in policy.pinned_headers',
  OTS_PINNED_ROOT_MISMATCH: 'pinned header merkle_root does not match proof',
  OTS_PINNED_TIME_MISMATCH: 'pinned header time does not match proof',
  OTS_OP_SHAPE: 'ots op must be a non-empty list with a string opcode',
  OTS_SHA256_TAKES_NO_OPERAND: "ots 'sha256' op takes no operand",
} as const

export const evidenceNotObject = (v: unknown) => `evidence must be an object, got ${pyTypeName(v)}`
export const evidenceProofsNotList = (v: unknown) => `evidence.proofs must be a list, got ${pyTypeName(v)}`
export const evidenceCheckpointExceeds = (max: number) => `evidence.checkpoint exceeds max length ${max}`
export const evidenceProofsExceeds = (max: number) => `evidence.proofs exceeds max length ${max}`
export const proofNotObject = (i: number, v: unknown) => `proof[${i}]: must be an object, got ${pyTypeName(v)}`
export const proofPrefixed = (i: number, msg: string) => `proof[${i}]: ${msg}`
export const otsTooManyOps = (max: number) => `ots proof has more than ${max} ops`
export const otsUnknownOp = (op: string) => `unknown ots op ${pyRepr(op)}`
export const otsOperandInvalid = (op: string) => `ots ${pyRepr(op)} operand must be bounded, even-length lowercase hex`
export const otsOperandRequired = (op: string) => `ots ${pyRepr(op)} op needs exactly one hex operand`
export const otsHeaderTimeInvalid = (max: number) =>
  `ots proof 'header_time' must be a positive int no later than ${max}`
export const rfc3161TokenNotStr = (v: unknown) => `rfc3161 token_b64 must be a str, got ${pyTypeName(v)}`
export const unknownProofKind = (kind: unknown) => `unknown proof kind ${pyTruncRepr(kind)}, ignored`

// `anchor._trunc`: safely render an untrusted scalar for a bounded warning —
// never invoke a hostile object's own stringification, only these three cases.
export function pyTruncRepr(value: unknown, limit = 60): string {
  if (typeof value === 'string') {
    const text = pyRepr(value.slice(0, limit))
    return text.length <= limit ? text : text.slice(0, limit - 3) + '...'
  }
  if (value === null || value === undefined || typeof value === 'boolean') return pyRepr(value)
  if (typeof value === 'number' && Number.isInteger(value)) return String(value)
  const typeName = pyTypeName(value)
  return `<${typeName.slice(0, limit - 2)}>`
}

// transparency.py: fixed, short, snake_case tokens — a cross-language
// protocol surface (module docstring). Values are the literal wire strings;
// export names are UPPER_SNAKE for readability only.
export const TRANSPARENCY_WARN = {
  EVIDENCE_INVALID: 'evidence_invalid',
  ENTRY_INVALID: 'entry_invalid',
  ENTRY_MISMATCH: 'transparency_entry_mismatch',
  CHECKPOINT_INVALID: 'checkpoint_invalid',
  CHECKPOINT_VERIFICATION_FAILED: 'checkpoint_verification_failed',
  LEAF_INDEX_INVALID: 'leaf_index_invalid',
  TREE_SIZE_INVALID: 'tree_size_invalid',
  TREE_SIZE_MISMATCH: 'tree_size_mismatch',
  INCLUSION_PROOF_INVALID: 'inclusion_proof_invalid',
  INCLUSION_PROOF_TOO_LONG: 'inclusion_proof_too_long',
  PRIOR_CHECKPOINT_INVALID: 'prior_checkpoint_invalid',
  CONSISTENCY_PROOF_MISSING: 'consistency_proof_missing',
  CONSISTENCY_PROOF_INVALID: 'consistency_proof_invalid',
  CONSISTENCY_PROOF_TOO_LONG: 'consistency_proof_too_long',
  EQUIVOCATION_DETECTED: 'log_equivocation_detected',
  ANCHORS_INVALID: 'anchors_invalid',
  ANCHOR_TIME_INVALID: 'anchor_time_invalid',
  POST_HORIZON_UNANCHORED: 'post_horizon_unanchored',
  EVIDENCE_EVALUATION_FAILED: 'evidence_evaluation_failed',
} as const

// verify.py Stage 2 integration warnings (also fixed snake_case tokens).
export const VERIFY_TRANSPARENCY_WARN = {
  CONFIG_MISSING: 'transparency_config_missing',
  CLAIM_UNRESOLVABLE: 'transparency_claim_unresolvable',
  ROTATION_CHAIN_REQUIRED: 'corroboration_requires_rotation_chain',
} as const
