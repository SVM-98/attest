import { describe, it, expect } from 'vitest'
import { loadsStrict, verify, isOk } from 'attest-verifier'

describe('attest-verifier dependency', () => {
  it('parses integers as bigint (loadsStrict discipline)', () => {
    const v = loadsStrict(new TextEncoder().encode('{"n": 7}')) as { n: unknown }
    expect(typeof v.n).toBe('bigint')
  })
  it('fails closed against an empty trust store', () => {
    const r = verify(new TextEncoder().encode('{}'), { manifests: {}, provenance: {} })
    expect(r.signature).toBe('invalid')
    expect(isOk(r)).toBe(false)
  })
})
