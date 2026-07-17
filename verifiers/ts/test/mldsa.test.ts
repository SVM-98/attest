import { describe, it, expect } from 'vitest'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { verifyStrict, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN } from '../src/mldsa.js'

const seed = Uint8Array.from({ length: 32 }, () => 1)
const { publicKey: pub, secretKey } = ml_dsa65.keygen(seed)
const msg = new TextEncoder().encode('attest test message')
const sig = ml_dsa65.sign(msg, secretKey)

describe('verifyStrict', () => {
  it('accepts a valid signature', () => { expect(verifyStrict(msg, sig, pub)).toBe(true) })
  it('rejects a tampered message', () => {
    const bad = new TextEncoder().encode('attest test messagE')
    expect(verifyStrict(bad, sig, pub)).toBe(false)
  })
  it('rejects a wrong-length signature without throwing', () => {
    expect(() => verifyStrict(msg, sig.slice(0, ML_DSA_65_SIG_LEN - 1), pub)).not.toThrow()
    expect(verifyStrict(msg, sig.slice(0, ML_DSA_65_SIG_LEN - 1), pub)).toBe(false)
  })
  it('rejects a wrong-length public key without throwing', () => {
    expect(() => verifyStrict(msg, sig, pub.slice(0, ML_DSA_65_PK_LEN - 1))).not.toThrow()
    expect(verifyStrict(msg, sig, pub.slice(0, ML_DSA_65_PK_LEN - 1))).toBe(false)
  })
  it('rejects a corrupted signature', () => {
    const corrupted = Uint8Array.from(sig)
    corrupted[0] = corrupted[0]! ^ 0xff
    expect(verifyStrict(msg, corrupted, pub)).toBe(false)
  })
})
