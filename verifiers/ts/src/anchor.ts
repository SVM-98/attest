// OpenTimestamps-style Bitcoin block-header anchoring — mirrors
// src/attest/anchor.py (Python reference). Lets a verifier check that a
// tlog.Checkpoint was timestamped into a Bitcoin block header pinned in its
// own trust store (AnchorPolicy), and gate on whether that anchor lands
// early enough to still count as post-quantum-surviving evidence once a
// future CRQC horizon is reached.
//
// `verifyAnchor` NEVER throws on malformed `evidence` — it arrives from an
// untrusted bundle, so any shape violation degrades to a warning and that
// proof contributes nothing, rather than aborting verification of the rest
// of the bundle. `checkpoint`/`policy` are the trusted, verifier-config side
// (mirrors tlog.verifyCheckpoint's logKey/expectedOrigin split): malformed
// ones throw `AnchorError` instead, since that signals a caller bug.
import { equalBytes, concatBytes, hexToBytes } from '@noble/curves/utils.js'
import { sha256 } from '@noble/hashes/sha2'
import { Checkpoint, TlogError, parseCheckpoint } from './tlog.js'
import {
  ANCHOR_WARN,
  RFC3161_WARNING,
  pyRepr,
  pyTypeName,
  evidenceNotObject,
  evidenceProofsNotList,
  evidenceCheckpointExceeds,
  evidenceProofsExceeds,
  proofNotObject,
  proofPrefixed,
  otsTooManyOps,
  otsUnknownOp,
  otsOperandInvalid,
  otsOperandRequired,
  otsHeaderTimeInvalid,
  rfc3161TokenNotStr,
  unknownProofKind,
} from './messages.js'

const HEX64_RE = /^[0-9a-f]{64}$/
const HEX_RE = /^[0-9a-f]*$/

// Caps bounding attacker-controlled work while walking untrusted evidence.
const MAX_PROOFS_PER_EVIDENCE = 64
const MAX_OPS_PER_PROOF = 64
// A legitimate full note is ~400KB worst case — cap the evidence checkpoint
// text BEFORE it reaches tlog.parseCheckpoint, so a hostile multi-megabyte
// string cannot force large parse-time allocations.
const MAX_CHECKPOINT_TEXT_LEN = 500_000
const MAX_OP_HEX_LEN = 2048 // hex chars (1024 bytes) per append/prepend operand
// The latest Unix timestamp `Date`/`datetime` can render through
// 9999-12-31T23:59:59Z. Keep pinned and untrusted proof times inside that
// shared bound.
const MAX_RENDERABLE_UNIX_TIME = 253402300799

const KNOWN_OTS_OPS = new Set(['sha256', 'append', 'prepend'])

export const MAX_PROOFS_PER_EVIDENCE_ = MAX_PROOFS_PER_EVIDENCE
export const MAX_OPS_PER_PROOF_ = MAX_OPS_PER_PROOF
export const MAX_OP_HEX_LEN_ = MAX_OP_HEX_LEN
export const MAX_CHECKPOINT_TEXT_LEN_ = MAX_CHECKPOINT_TEXT_LEN
export const MAX_RENDERABLE_UNIX_TIME_ = MAX_RENDERABLE_UNIX_TIME

export class AnchorError extends Error {}

/** A Bitcoin block header pinned out-of-band into the verifier's trust
 * store — never taken from the untrusted evidence bundle itself. */
export interface PinnedHeader {
  headerHash: string
  merkleRoot: string
  time: number
}

/** The verifier's anchor trust store and CRQC cutoff. `pinnedHeaders` is
 * keyed by `headerHash` (each value's own `headerHash` must match its key).
 * `crqcHorizon` is a unix-seconds cutoff; `null` means no cutoff is
 * configured (every PQ-anchored checkpoint passes). */
export interface AnchorPolicy {
  pinnedHeaders: Record<string, PinnedHeader>
  crqcHorizon: number | null
}

/** The outcome of `verifyAnchor` over one evidence bundle. `anchoredBefore`
 * is the minimum pinned header time over verified `ots` (PQ-surviving)
 * proofs only — `rfc3161` proofs never set it. */
export interface AnchorVerdict {
  anchored: boolean
  anchoredBefore: number | null
  pqSurviving: boolean
  warnings: string[]
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
}

function isPinnedHeaderShape(v: unknown): v is PinnedHeader {
  return isPlainObject(v) && 'headerHash' in v && 'merkleRoot' in v && 'time' in v
}

function isCheckpointShape(v: unknown): v is Checkpoint {
  return isPlainObject(v) && 'origin' in v && 'treeSize' in v && 'root' in v && 'noteBytes' in v
}

function isAnchorVerdictShape(v: unknown): v is AnchorVerdict {
  return isPlainObject(v) && 'anchored' in v && 'anchoredBefore' in v && 'pqSurviving' in v && 'warnings' in v
}

/** Validate every `AnchorPolicy` field before it's trusted. Throws
 * `AnchorError` — `policy` is assembled by the verifier's own config, not
 * adversarial evidence, so a malformed policy is a caller bug to surface
 * loudly, not degrade gracefully. */
export function validatePolicy(policy: unknown): AnchorPolicy {
  if (!isPlainObject(policy) || !('pinnedHeaders' in policy) || !('crqcHorizon' in policy)) {
    throw new AnchorError(`policy must be an AnchorPolicy, got ${pyTypeName(policy)}`)
  }
  const pinnedHeadersRaw = policy['pinnedHeaders']
  if (!isPlainObject(pinnedHeadersRaw)) throw new AnchorError('policy.pinned_headers must be a dict')

  for (const [headerHash, header] of Object.entries(pinnedHeadersRaw)) {
    if (!HEX64_RE.test(headerHash)) {
      throw new AnchorError(`pinned_headers key must be 64 lowercase hex chars: ${pyRepr(headerHash)}`)
    }
    if (!isPinnedHeaderShape(header)) {
      throw new AnchorError(`pinned_headers[${pyRepr(headerHash)}] must be a PinnedHeader`)
    }
    if (typeof header.headerHash !== 'string' || !HEX64_RE.test(header.headerHash)) {
      throw new AnchorError(
        `PinnedHeader.header_hash must be 64 lowercase hex chars: ${pyRepr(header.headerHash)}`,
      )
    }
    if (header.headerHash !== headerHash) {
      throw new AnchorError(
        `pinned_headers key ${pyRepr(headerHash)} != PinnedHeader.header_hash ${pyRepr(header.headerHash)}`,
      )
    }
    if (typeof header.merkleRoot !== 'string' || !HEX64_RE.test(header.merkleRoot)) {
      throw new AnchorError(
        `PinnedHeader.merkle_root must be 64 lowercase hex chars: ${pyRepr(header.merkleRoot)}`,
      )
    }
    if (
      typeof header.time !== 'number' ||
      !Number.isInteger(header.time) ||
      header.time <= 0 ||
      header.time > MAX_RENDERABLE_UNIX_TIME
    ) {
      throw new AnchorError(
        `PinnedHeader.time must be a positive int no later than ${MAX_RENDERABLE_UNIX_TIME}: ${pyRepr(header.time)}`,
      )
    }
  }

  const crqcHorizon = policy['crqcHorizon']
  if (crqcHorizon !== null && (typeof crqcHorizon !== 'number' || !Number.isInteger(crqcHorizon))) {
    throw new AnchorError(`policy.crqc_horizon must be an int or None: ${pyRepr(crqcHorizon)}`)
  }
  return policy as unknown as AnchorPolicy
}

function hex64(value: unknown): Uint8Array | null {
  if (typeof value !== 'string' || !HEX64_RE.test(value)) return null
  return hexToBytes(value)
}

/** Decode a bounded, even-length, lowercase-hex op operand, or `null`. */
function opHex(value: unknown): Uint8Array | null {
  if (typeof value !== 'string' || value.length > MAX_OP_HEX_LEN || value.length % 2 !== 0 || !HEX_RE.test(value)) {
    return null
  }
  return hexToBytes(value)
}

interface OtsProofOutcome {
  verified: boolean
  headerTime: number
  warning: string | null
}

/** Evaluate one `ots` proof: replay its op-chain from `accumulatorStart`
 * and cross-check the result against a header pinned in `policy`. */
function verifyOtsProof(
  proof: Record<string, unknown>,
  accumulatorStart: Uint8Array,
  policy: AnchorPolicy,
): OtsProofOutcome {
  const ops = proof['ops']
  if (!Array.isArray(ops)) return { verified: false, headerTime: 0, warning: ANCHOR_WARN.OTS_OPS_NOT_LIST }
  if (ops.length === 0) return { verified: false, headerTime: 0, warning: ANCHOR_WARN.OTS_EMPTY_OPS }
  if (ops.length > MAX_OPS_PER_PROOF) {
    return { verified: false, headerTime: 0, warning: otsTooManyOps(MAX_OPS_PER_PROOF) }
  }

  const rootBytes = hex64(proof['header_merkle_root'])
  if (rootBytes === null) {
    return { verified: false, headerTime: 0, warning: ANCHOR_WARN.OTS_HEADER_MERKLE_ROOT_INVALID }
  }
  const headerHash = proof['header_hash']
  if (typeof headerHash !== 'string' || !HEX64_RE.test(headerHash)) {
    return { verified: false, headerTime: 0, warning: ANCHOR_WARN.OTS_HEADER_HASH_INVALID }
  }
  const headerTime = proof['header_time']
  if (
    typeof headerTime !== 'number' ||
    !Number.isInteger(headerTime) ||
    headerTime <= 0 ||
    headerTime > MAX_RENDERABLE_UNIX_TIME
  ) {
    return { verified: false, headerTime: 0, warning: otsHeaderTimeInvalid(MAX_RENDERABLE_UNIX_TIME) }
  }

  let accumulator = accumulatorStart
  for (const op of ops) {
    if (!Array.isArray(op) || op.length === 0 || typeof op[0] !== 'string') {
      return { verified: false, headerTime: 0, warning: ANCHOR_WARN.OTS_OP_SHAPE }
    }
    const opcode = op[0]
    if (!KNOWN_OTS_OPS.has(opcode)) {
      return { verified: false, headerTime: 0, warning: otsUnknownOp(opcode) }
    }
    if (opcode === 'sha256') {
      if (op.length !== 1) {
        return { verified: false, headerTime: 0, warning: ANCHOR_WARN.OTS_SHA256_TAKES_NO_OPERAND }
      }
      accumulator = sha256(accumulator)
    } else {
      if (op.length !== 2) return { verified: false, headerTime: 0, warning: otsOperandRequired(opcode) }
      const operand = opHex(op[1])
      if (operand === null) return { verified: false, headerTime: 0, warning: otsOperandInvalid(opcode) }
      accumulator = opcode === 'append' ? concatBytes(accumulator, operand) : concatBytes(operand, accumulator)
    }
  }

  if (!equalBytes(accumulator, rootBytes)) {
    return { verified: false, headerTime: 0, warning: ANCHOR_WARN.OTS_CHAIN_MISMATCH }
  }

  const pinned = policy.pinnedHeaders[headerHash]
  if (pinned === undefined) {
    return { verified: false, headerTime: 0, warning: ANCHOR_WARN.OTS_HEADER_NOT_PINNED }
  }
  if (pinned.merkleRoot !== proof['header_merkle_root']) {
    return { verified: false, headerTime: 0, warning: ANCHOR_WARN.OTS_PINNED_ROOT_MISMATCH }
  }
  if (pinned.time !== headerTime) {
    return { verified: false, headerTime: 0, warning: ANCHOR_WARN.OTS_PINNED_TIME_MISMATCH }
  }

  return { verified: true, headerTime: pinned.time, warning: null }
}

/** Verify an anchor-evidence bundle against `checkpoint` and `policy`.
 *
 * `evidence` is untrusted and this function NEVER throws because of it: any
 * malformation degrades to an `AnchorVerdict` with `anchored: false` and a
 * warning naming the problem, and per-proof malformations drop only that
 * one proof (forward-compat: an unrecognized `kind` must not brick an old
 * verifier reading a bundle produced by a newer one). `checkpoint`/`policy`
 * are the trusted, verifier-config side: malformed ones throw `AnchorError`.
 */
export function verifyAnchor(evidence: unknown, checkpoint: unknown, policy: unknown): AnchorVerdict {
  if (!isCheckpointShape(checkpoint)) {
    throw new AnchorError(`checkpoint must be a tlog.Checkpoint, got ${pyTypeName(checkpoint)}`)
  }
  const validatedPolicy = validatePolicy(policy)

  const warnings: string[] = []
  const fail = (): AnchorVerdict => ({ anchored: false, anchoredBefore: null, pqSurviving: false, warnings })

  if (!isPlainObject(evidence)) {
    warnings.push(evidenceNotObject(evidence))
    return fail()
  }
  if (!('checkpoint' in evidence)) {
    warnings.push(ANCHOR_WARN.EVIDENCE_CHECKPOINT_REQUIRED)
    return fail()
  }
  const checkpointText = evidence['checkpoint']
  if (typeof checkpointText !== 'string') {
    warnings.push(ANCHOR_WARN.EVIDENCE_CHECKPOINT_NOT_STR)
    return fail()
  }
  if (checkpointText.length > MAX_CHECKPOINT_TEXT_LEN) {
    warnings.push(evidenceCheckpointExceeds(MAX_CHECKPOINT_TEXT_LEN))
    return fail()
  }
  let evidenceCheckpoint: Checkpoint
  try {
    evidenceCheckpoint = parseCheckpoint(checkpointText)
  } catch (e) {
    if (e instanceof TlogError) {
      warnings.push(ANCHOR_WARN.EVIDENCE_CHECKPOINT_INVALID)
      return fail()
    }
    throw e
  }
  if (!equalBytes(evidenceCheckpoint.noteBytes, checkpoint.noteBytes)) {
    warnings.push(ANCHOR_WARN.EVIDENCE_CHECKPOINT_MISMATCH)
    return fail()
  }

  const proofs = evidence['proofs']
  if (!Array.isArray(proofs)) {
    warnings.push(evidenceProofsNotList(proofs))
    return fail()
  }
  if (proofs.length > MAX_PROOFS_PER_EVIDENCE) {
    warnings.push(evidenceProofsExceeds(MAX_PROOFS_PER_EVIDENCE))
    return fail()
  }

  const accumulatorStart = sha256(checkpoint.noteBytes)
  let anchored = false
  let pqSurviving = false
  let anchoredBefore: number | null = null

  proofs.forEach((proof: unknown, i: number) => {
    if (!isPlainObject(proof)) {
      warnings.push(proofNotObject(i, proof))
      return
    }
    const kind = proof['kind']
    if (kind === 'ots') {
      const outcome = verifyOtsProof(proof, accumulatorStart, validatedPolicy)
      if (outcome.warning !== null) warnings.push(proofPrefixed(i, outcome.warning))
      if (outcome.verified) {
        anchored = true
        pqSurviving = true
        if (anchoredBefore === null || outcome.headerTime < anchoredBefore) anchoredBefore = outcome.headerTime
      }
    } else if (kind === 'rfc3161') {
      const tokenB64 = proof['token_b64']
      if (typeof tokenB64 !== 'string') {
        warnings.push(proofPrefixed(i, rfc3161TokenNotStr(tokenB64)))
        return
      }
      anchored = true
      warnings.push(RFC3161_WARNING)
    } else {
      warnings.push(proofPrefixed(i, unknownProofKind(kind)))
    }
  })

  return { anchored, anchoredBefore, pqSurviving, warnings }
}

/** True iff `policy.crqcHorizon === null`, or `verdict` is a PQ-surviving
 * anchor whose time is strictly before the horizon. Pure function of
 * `(verdict, policy)`: throws `AnchorError` only on a malformed `policy`
 * (trusted, verifier-config side). Never throws on `verdict` — even a
 * malformed-content verdict degrades to `false` rather than throwing. */
export function passesHorizon(verdict: unknown, policy: unknown): boolean {
  const validatedPolicy = validatePolicy(policy)
  if (validatedPolicy.crqcHorizon === null) return true
  if (!isAnchorVerdictShape(verdict)) return false
  const anchoredBefore = verdict.anchoredBefore
  if (typeof anchoredBefore !== 'number' || !Number.isInteger(anchoredBefore)) return false
  return Boolean(verdict.pqSurviving) && anchoredBefore < validatedPolicy.crqcHorizon
}
