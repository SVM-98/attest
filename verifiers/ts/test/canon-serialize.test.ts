import { describe, it, expect } from 'vitest'
import { loadsStrict, dumps, canonicalBytes } from '../src/canon.js'
const enc = (s: string) => new TextEncoder().encode(s)
const dec = (b: Uint8Array) => new TextDecoder().decode(b)

describe('canonicalBytes / dumps', () => {
  it('sorts object keys by UTF-16 code units and drops whitespace', () => {
    expect(dumps(loadsStrict(enc('{ "b": 1, "a": 2 }')))).toBe('{"a":2,"b":1}')
  })
  it('accepts 2^53-1 but rejects 2^53', () => {
    expect(dumps(loadsStrict(enc('{"n":9007199254740991}')))).toBe('{"n":9007199254740991}')
    expect(() => canonicalBytes(loadsStrict(enc('{"n":9007199254740992}'))))
      .toThrow(/integer out of I-JSON safe range/)
  })
  it('serializes null/booleans and nested arrays without spaces', () => {
    expect(dumps(loadsStrict(enc('{"a":[true,false,null,1]}')))).toBe('{"a":[true,false,null,1]}')
  })
  it('applies the 7 short escapes and \\u00xx for other controls; leaves / unescaped', () => {
    // \t -> \t short escape;  -> ; '/' literal
    const v = loadsStrict(enc('{"s":"a\\tb\\u000b/"}'))
    expect(dumps(v)).toBe('{"s":"a\\tb\\u000b/"}')
  })
  it('preserves NFD bytes verbatim (no NFC)', () => {
    const bytes = canonicalBytes(loadsStrict(enc('{"t":"Cafe\\u0301"}')))
    expect(dec(bytes)).toBe('{"t":"Café"}')
  })
})
