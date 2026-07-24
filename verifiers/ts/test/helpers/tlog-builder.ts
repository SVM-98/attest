// Minimal RFC 6962 Merkle-tree + C2SP hybrid signed-note checkpoint BUILDER,
// for test fixtures only. src/tlog.ts ships verify-only (no buildTree/
// inclusionProof/signCheckpoint — see that module's header comment): those
// are Python-side builder functions with no untrusted-input boundary, used
// only by the reference implementation's own gen_vectors/CLI tooling.
//
// This mirrors src/attest/tlog.py's build_tree/inclusion_proof/
// sign_checkpoint algorithms exactly, so genuine (not pre-committed)
// inclusion proofs and hybrid-signed checkpoints can be constructed directly
// in TS tests — the same idiom sibling-hybrid.test.ts already established
// for hybrid-signed side-documents (hand-sign in-memory with noble, no
// cross-language fixture needed since only docs/spec/vectors/ requires
// byte-for-byte Python reproducibility).
import { sha256 } from '@noble/hashes/sha2'
import { concatBytes } from '@noble/curves/utils.js'
import { ed25519 } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { keyHash } from '../../src/tlog.js'

const LEAF_PREFIX = Uint8Array.of(0x00) // RFC 6962 §2.1: MTH({d(0)}) = SHA-256(0x00 || d(0))
const NODE_PREFIX = Uint8Array.of(0x01) // RFC 6962 §2.1: MTH(D[n]) = SHA-256(0x01 || left || right)
const ED25519_SIG_TYPE = Uint8Array.of(0x01)
const ML_DSA_65_SIG_TYPE = concatBytes(Uint8Array.of(0xff), new TextEncoder().encode('attest-ml-dsa-65'))

function leafHash(data: Uint8Array): Uint8Array {
  return sha256(concatBytes(LEAF_PREFIX, data))
}
function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concatBytes(NODE_PREFIX, left, right))
}

function largestPowerOfTwoBelow(n: number): number {
  let k = 1
  while (k * 2 < n) k *= 2
  return k
}

/** RFC 6962 §2.1 Merkle Tree Hash (MTH) of `leaves`. Mirrors tlog.py's build_tree. */
export function buildTree(leaves: Uint8Array[]): Uint8Array {
  const n = leaves.length
  if (n === 0) return sha256(new Uint8Array(0))
  if (n === 1) return leafHash(leaves[0]!)
  const k = largestPowerOfTwoBelow(n)
  return nodeHash(buildTree(leaves.slice(0, k)), buildTree(leaves.slice(k)))
}

function path(leaves: Uint8Array[], m: number): Uint8Array[] {
  const n = leaves.length
  if (n === 1) return []
  const k = largestPowerOfTwoBelow(n)
  if (m < k) return [...path(leaves.slice(0, k), m), buildTree(leaves.slice(k))]
  return [...path(leaves.slice(k), m - k), buildTree(leaves.slice(0, k))]
}

/** RFC 6962 §2.1.1 audit path for `leaves[index]`. Mirrors tlog.py's inclusion_proof. */
export function inclusionProof(leaves: Uint8Array[], index: number): Uint8Array[] {
  const n = leaves.length
  if (index < 0 || index >= n) throw new Error(`index ${index} out of range for ${n} leaves`)
  return path(leaves, index)
}

export interface HybridTestKeys {
  edSeed: Uint8Array
  edPub: Uint8Array
  mldsaPub: Uint8Array
  mldsaSecret: Uint8Array
}

function toB64(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s)
}

/** Build and hybrid-sign a C2SP checkpoint note. Mirrors tlog.py's sign_checkpoint. */
export function signCheckpoint(origin: string, treeSize: number, root: Uint8Array, hk: HybridTestKeys, name: string): string {
  const header = [origin, String(treeSize), toB64(root)]
  const noteBytes = new TextEncoder().encode(header.join('\n') + '\n')
  const edBlob = concatBytes(keyHash(name, ED25519_SIG_TYPE, hk.edPub), ed25519.sign(noteBytes, hk.edSeed))
  const mldsaBlob = concatBytes(keyHash(name, ML_DSA_65_SIG_TYPE, hk.mldsaPub), ml_dsa65.sign(noteBytes, hk.mldsaSecret))
  const edLine = `— ${name} ${toB64(edBlob)}\n`
  const mldsaLine = `— ${name} ${toB64(mldsaBlob)}\n`
  return new TextDecoder().decode(noteBytes) + '\n' + edLine + mldsaLine
}
