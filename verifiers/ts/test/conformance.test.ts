// The 18-vector merge gate: this suite discovers every leaf under
// `docs/spec/vectors/` and asserts the produced VerificationResult matches
// its `expected.json`, using the exact same match rules as the Python
// reference's `tests/test_vectors.py`. Passing this suite in full IS the
// definition of attest v0.1 conformance for this implementation (see README).
import { describe, it, expect } from 'vitest'
import { verify, isOk } from '../src/index.js'
import * as V from './helpers/vectors.js'

const leaves = V.findLeafDirs()

describe('attest v0.1 conformance vectors', () => {
  it('discovers the full vector suite (>= 23 leaves)', () => {
    expect(leaves.length).toBeGreaterThanOrEqual(23)
  })

  it.each(leaves.map((d) => [V.vectorId(d), d] as const))('%s', (_id, dir) => {
    const exp = V.expected(dir)
    const r = verify(V.envelopeBytes(dir), V.trustStore(dir), V.revocationView(dir) as any, V.disclosure(dir))

    // always-exact
    expect(r.signature).toBe(exp.signature)
    expect(r.schema).toBe(exp.schema)
    expect(r.trust).toBe(exp.trust)
    // conditional-exact scalars
    if ('revocation' in exp) expect(r.revocation).toBe(exp.revocation)
    if ('binding' in exp) expect(r.binding).toBe(exp.binding)
    if ('ok' in exp) expect(isOk(r)).toBe(exp.ok)
    // exact-list
    if ('errors' in exp) expect([...r.errors]).toEqual(exp.errors)
    if ('warnings' in exp) expect([...r.warnings]).toEqual(exp.warnings)
    // substring-contains
    for (const s of exp.errors_contains ?? []) expect(r.errors.some((e) => e.includes(s)), `error containing ${s}; got ${JSON.stringify(r.errors)}`).toBe(true)
    for (const s of exp.warnings_contains ?? []) expect(r.warnings.some((w) => w.includes(s)), `warning containing ${s}; got ${JSON.stringify(r.warnings)}`).toBe(true)
  })
})
