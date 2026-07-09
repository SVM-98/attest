import { describe, it, expect } from 'vitest'
import { b64uDecode } from '../src/b64u.js'

describe('b64uDecode', () => {
  it('decodes unpadded base64url', () => {
    expect(Array.from(b64uDecode('AAECAw'))).toEqual([0, 1, 2, 3])
    expect(b64uDecode('')).toHaveLength(0)
  })
  it('decodes url-safe alphabet (- and _)', () => {
    expect(Array.from(b64uDecode('-_8'))).toEqual([0xfb, 0xff])
  })
  it('rejects non-base64url input', () => {
    expect(() => b64uDecode('AA==')).toThrow() // padding is not part of the encoding (§9.1)
    expect(() => b64uDecode('a+b/')).toThrow()
    expect(() => b64uDecode('salt with spaces')).toThrow()
  })
})
