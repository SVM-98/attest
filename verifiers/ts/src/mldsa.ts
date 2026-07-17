import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'

export const ML_DSA_65_ALG = 'ML-DSA-65'
export const ML_DSA_65_PK_LEN = 1952
export const ML_DSA_65_SIG_LEN = 3309

/** Length-checked, exception-free ML-DSA-65 verification (fail-closed).
 *  noble argument order is (sig, msg, pub) — opposite of our Python wrapper. */
export function verifyStrict(msg: Uint8Array, sig: Uint8Array, pub: Uint8Array): boolean {
  if (sig.length !== ML_DSA_65_SIG_LEN || pub.length !== ML_DSA_65_PK_LEN) return false
  try {
    return ml_dsa65.verify(sig, msg, pub)
  } catch {
    return false
  }
}
