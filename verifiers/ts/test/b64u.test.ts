import { describe, it, expect } from 'vitest'
import { b64uDecode, b64uEncode } from '../src/b64u.js'

describe('b64u', () => {
  it('decodes the vector salt to 0x00..0x0f', () => {
    expect([...b64uDecode('AAECAwQFBgcICQoLDA0ODw')]).toEqual([...Array(16).keys()])
  })
  it('round-trips arbitrary bytes without padding', () => {
    const bytes = Uint8Array.from({ length: 32 }, (_, i) => (i * 7) & 0xff)
    const s = b64uEncode(bytes)
    expect(s).not.toContain('=')
    expect([...b64uDecode(s)]).toEqual([...bytes])
  })
  it('uses URL alphabet (- and _), never + or /', () => {
    const s = b64uEncode(Uint8Array.from([0xfb, 0xff, 0xbf]))
    expect(s).toMatch(/^[A-Za-z0-9_-]+$/)
  })
})
