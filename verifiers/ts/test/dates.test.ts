import { describe, it, expect } from 'vitest'
import { parseStrictUtc, parseIsoLenient } from '../src/dates.js'

describe('dates', () => {
  it('strict accepts the canonical form only', () => {
    expect(parseStrictUtc('2025-01-01T00:00:00Z')).toBe(Date.UTC(2025, 0, 1, 0, 0, 0))
    expect(parseStrictUtc('2025-01-01T00:00:00.000Z')).toBeNull() // fractional -> fail closed
    expect(parseStrictUtc('2025-01-01T00:00:00+00:00')).toBeNull() // offset -> fail closed
    expect(parseStrictUtc('not-a-date')).toBeNull()
    expect(parseStrictUtc(null)).toBeNull()
  })
  it('lenient parses ISO with offset/fraction', () => {
    expect(parseIsoLenient('2025-08-01T12:00:00Z')).toBe(Date.UTC(2025, 7, 1, 12, 0, 0))
    expect(parseIsoLenient('nope')).toBeNull()
  })
})
