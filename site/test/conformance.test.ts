import { describe, it, expect } from 'vitest'
import { runVerify } from '../src/run.js'
import * as V from './helpers/vectors.js'

const leaves = V.findLeafDirs()

describe('conformance corpus through the site adapter', () => {
  it('discovers the full vector suite (>= 51 leaves)', () => {
    expect(leaves.length).toBeGreaterThanOrEqual(51)
  })

  it.each(leaves.map((d) => [V.vectorId(d), d] as const))('%s', (_id, dir) => {
    const exp = V.expected(dir)
    const run = runVerify(V.envelopeBytes(dir), V.trustStore(dir), V.revocationView(dir), V.disclosure(dir))
    const r = run.result
    expect(r.signature).toBe(exp.signature)
    expect(r.schema).toBe(exp.schema)
    expect(r.trust).toBe(exp.trust)
    if ('revocation' in exp) expect(r.revocation).toBe(exp.revocation)
    if ('binding' in exp) expect(r.binding).toBe(exp.binding)
    if ('ok' in exp) expect(run.ok).toBe(exp.ok)
    if ('errors' in exp) expect([...r.errors]).toEqual(exp.errors)
    if ('warnings' in exp) expect([...r.warnings]).toEqual(exp.warnings)
    for (const s of exp.errors_contains ?? []) expect(r.errors.some((e: string) => e.includes(s))).toBe(true)
    for (const s of exp.warnings_contains ?? []) expect(r.warnings.some((w: string) => w.includes(s))).toBe(true)
  })
})
