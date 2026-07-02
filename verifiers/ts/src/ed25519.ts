// Pinned OPR Ed25519 ruleset (spec §10): cofactorless/strict RFC 8032, reject
// non-canonical S (S >= L), reject small-order/non-canonical A and R.
// Mirrors Python keys.verify_strict (PyNaCl/libsodium) with @noble/curves.
import { ed25519 } from '@noble/curves/ed25519'

export class Ed25519LengthError extends Error {}

const L = 2n ** 252n + 27742317777372353535851937790883648493n

function scalarLE(bytes: Uint8Array): bigint {
  let n = 0n
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]!)
  return n
}

export function verifyStrict(msg: Uint8Array, sig: Uint8Array, pub: Uint8Array): boolean {
  if (sig.length !== 64) throw new Ed25519LengthError('Ed25519 signature must be 64 bytes')
  if (pub.length !== 32) throw new Ed25519LengthError('Ed25519 public key must be 32 bytes')
  // Explicit non-canonical S guard (belt-and-suspenders; matches keys.py before libsodium).
  if (scalarLE(sig.subarray(32, 64)) >= L) return false
  try {
    // WATCH ARGUMENT ORDER: noble is verify(signature, message, publicKey) — the OPPOSITE of PyNaCl.
    // zip215:false => strict RFC 8032 (cofactorless), rejects non-canonical/small-order A and R.
    return ed25519.verify(sig, msg, pub, { zip215: false })
  } catch {
    return false // point/decode errors are a rejected signature, never an exception (like keys.py)
  }
}
