import { describe, it, expect } from 'vitest'
import { normalizeIdentifier, computeCommitment } from '../src/commitment.js'
import { b64uEncode } from '../src/b64u.js'
const salt = Uint8Array.from({ length: 16 }, (_, i) => i) // 00..0f

describe('commitment', () => {
  it('email: ASCII-only lowercase + NFC + ASCII-ws strip', () => {
    expect(normalizeIdentifier('Buyer@Example.com', 'email')).toBe('buyer@example.com')
    // accented chars already lowercase stay unchanged; only ASCII B,T lowered
    expect(normalizeIdentifier('Büyér+Tag@Example.com', 'email')).toBe('büyér+tag@example.com')
  })
  it('issuer-account: NFC only, case preserved', () => {
    expect(normalizeIdentifier('Zañy_ID-042', 'issuer-account')).toBe('Zañy_ID-042')
  })
  it('does not use String.trim (no wide-unicode strip)', () => {
    expect(normalizeIdentifier(' a@b.com', 'email')).toBe(' a@b.com') // NBSP kept
  })
  it('reproduces the reference commitments (09a/09b/09c)', () => {
    expect(b64uEncode(computeCommitment('Buyer@Example.com', 'email', salt)))
      .toBe('4-s9PgtuDL3ZR7tlAVZpQCfPVMntewAQyqdLxtICPvg')
    expect(b64uEncode(computeCommitment('Büyér+Tag@Example.com', 'email', salt)))
      .toBe('PlNdv5Y_WqRKtnoRa9ssAsz2e4lT8jxjCXJDC3MquV0')
    expect(b64uEncode(computeCommitment('Zañy_ID-042', 'issuer-account', salt)))
      .toBe('o8d7eFF6kEARvjqqsK_13BuWTdoaByHY7IKLYbhNMfk')
  })
  it('rejects wrong salt length and unknown type', () => {
    expect(() => computeCommitment('a@b.com', 'email', salt.slice(0, 8))).toThrow(/salt/)
    expect(() => computeCommitment('a', 'nope', salt)).toThrow(/identifier_type/)
  })
})
