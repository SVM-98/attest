import { describe, it, expect } from 'vitest'
import { explain, explainVerdict, COMPONENTS } from '../src/explain.js'

const KNOWN: Record<string, string[]> = {
  signature: ['valid', 'invalid'],
  schema: ['valid', 'invalid', 'not_checked'],
  revocation: ['unknown', 'revoked', 'invalid_revocation_ignored', 'not_revoked_as_of:2026-01-01T00:00:00Z'],
  binding: ['proven', 'not_proven', 'not_checked'],
  trust: ['verified', 'unauthenticated_tofu', 'unverified_rotation'],
}

describe('explain', () => {
  it('covers every known component value with real copy', () => {
    for (const component of COMPONENTS) {
      for (const value of KNOWN[component]) {
        const e = explain(component, value)
        expect(e.label.length, `${component}/${value}`).toBeGreaterThan(0)
        expect(e.text.length, `${component}/${value}`).toBeGreaterThan(40) // a real sentence, not a stub
      }
    }
  })

  it('assigns honest tones', () => {
    expect(explain('signature', 'valid').tone).toBe('good')
    expect(explain('signature', 'invalid').tone).toBe('bad')
    expect(explain('revocation', 'revoked').tone).toBe('bad')
    expect(explain('revocation', 'unknown').tone).toBe('neutral')
    expect(explain('trust', 'unauthenticated_tofu').tone).toBe('warn')
    expect(explain('trust', 'unverified_rotation').tone).toBe('warn')
    expect(explain('binding', 'proven').tone).toBe('good')
  })

  it('never throws on unknown values (future-proof fallback)', () => {
    const e = explain('revocation', 'something_new')
    expect(e.tone).toBe('neutral')
    expect(e.text.length).toBeGreaterThan(0)
  })

  it('explains the verdict', () => {
    expect(explainVerdict(true).tone).toBe('good')
    expect(explainVerdict(false).tone).toBe('bad')
  })
})
