export const ATTEST_VERSION = '0.1'
export const SUPPORTED_ATTEST_VERSIONS = ['0.1', '0.2'] as const
export { MAX_REVOCATION_RECORDS } from './revocation.js'
export { verify, isOk } from './verify.js'
export type { VerificationResult, Disclosure, VerifyTransparencyOptions } from './verify.js'
export { loadsStrict, canonicalBytes, CanonError } from './canon.js'
export type { JsonValue, JsonObject } from './canon.js'
export type { TrustStore, KeyManifest, KeyEntry } from './manifests.js'

// Stage 2 (design doc "transparency/corroboration layer"): RFC 6962
// Merkle-tree verification + closed transparency-log entry schemas + C2SP
// hybrid signed-note checkpoints. Verify-only — no builder functions
// (build_tree/inclusion_proof/consistency_proof/sign_checkpoint) are part of
// this port's public surface.
export {
  TlogError,
  leafHash,
  nodeHash,
  verifyInclusion,
  verifyConsistency,
  encodeEntry,
  parseCheckpoint,
  verifyCheckpoint,
  receiptCoreHash,
} from './tlog.js'
export type { Checkpoint, LogKey } from './tlog.js'

// OpenTimestamps-style Bitcoin block-header anchoring + CRQC horizon gating.
export { AnchorError, verifyAnchor, passesHorizon } from './anchor.js'
export type { PinnedHeader, AnchorPolicy, AnchorVerdict } from './anchor.js'

// Transparency/corroboration evaluator: the glue between the log and the
// anchor layer for a single evidence bundle.
export {
  TransparencyError,
  TRANSPARENCY_NOT_CHECKED,
  TRANSPARENCY_LOGGED,
  TRANSPARENCY_EQUIVOCATION_DETECTED,
  CORROBORATION_NONE,
  CORROBORATION_LOGGED,
  CORROBORATION_WITNESSED,
  evaluateTransparency,
} from './transparency.js'
export type { TransparencyResult, EvaluateTransparencyOptions } from './transparency.js'
