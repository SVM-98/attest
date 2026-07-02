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

  it('throws TypeError on a JSON.parse-d (number-typed) trust store', () => {
    // Simulate the JSON.parse mistake: manifest_version is a JS number, not bigint.
    const store = { manifests: { 'ex.com': { issuer: 'ex.com', manifest_version: 3 } }, provenance: {} }
    expect(() => verify(enc('{}'), store as any)).toThrow(TypeError)
    expect(() => verify(enc('{}'), store as any)).toThrow(/loadsStrict|bigint/)
  })
  it('throws TypeError on a JSON.parse-d (number-typed) revocation view', () => {
    const view = [{ receipt_id: 'X', status: 'revoked', manifest_version: 2 }]
    expect(() => verify(enc('{}'), emptyStore, view as any)).toThrow(TypeError)
  })
  it('does not throw the guard for a loadsStrict-parsed (bigint) trust store', () => {
    const store = { manifests: { 'ex.com': { issuer: 'ex.com', manifest_version: 3n } }, provenance: {} }
    expect(() => verify(enc('{}'), store as any)).not.toThrow()
  })
})
