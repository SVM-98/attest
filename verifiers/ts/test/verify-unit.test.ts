import { describe, it, expect } from 'vitest'
import { verify, isOk } from '../src/verify.js'
const enc = (s: string) => new TextEncoder().encode(s)
const emptyStore = { manifests: {}, provenance: {} }

describe('verify unit', () => {
  it('throws TypeError on non-array revocationView', () => {
    expect(() => verify(enc('{}'), emptyStore, {} as any)).toThrow(TypeError)
  })
  it('non-object envelope -> invalid/not_checked/tofu', () => {
    const r = verify(enc('123'), emptyStore)
    expect(r.signature).toBe('invalid')
    expect(r.schema).toBe('not_checked')
    expect(r.trust).toBe('unauthenticated_tofu')
    expect(isOk(r)).toBe(false)
  })
  it('isOk is the 4-gate rule', () => {
    expect(isOk({ signature: 'valid', schema: 'valid', revocation: 'revoked', binding: 'not_checked', trust: 'verified', warnings: [], errors: [] })).toBe(false)
    expect(isOk({ signature: 'valid', schema: 'valid', revocation: 'unknown', binding: 'not_checked', trust: 'unverified_rotation', warnings: [], errors: [] })).toBe(true)
  })
})
