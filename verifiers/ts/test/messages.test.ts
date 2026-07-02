import { describe, it, expect } from 'vitest'
import * as M from '../src/messages.js'

describe('message contract', () => {
  it('pyRepr mirrors Python !r for strings and None', () => {
    expect(M.pyRepr('store.example.com')).toBe("'store.example.com'")
    expect(M.pyRepr(null)).toBe('None')
    expect(M.pyRepr(undefined)).toBe('None')
    expect(M.pyRepr(42n)).toBe('42')
  })
  it('every vector-mandated substring is emitted by some constant/builder', () => {
    const corpus = [
      M.ERR.SIG_VERIFICATION_FAILED, M.ERR.ISSUER_MISMATCH, M.ERR.ENVELOPE_NOT_OBJECT,
      M.ERR.MISSING_PAYLOAD, M.ERR.MISSING_SIGNATURES, M.ERR.MALFORMED_SIG_BLOCK,
      M.ERR.MALFORMED_SIG_BLOCK_TYPES, M.ERR.MISSING_ISSUER_ID,
      M.noKeyInManifest('store.example.com/keys/2025-01#ed25519-9'),
      M.keyCompromised('kid'), M.keyRetired('kid'), M.duplicateKey('opr_version'),
      M.intOutOfRange(9007199254740992n), M.unknownField('promo_code'),
      M.WARN.DRM_BOUND, M.WARN.REVOCABILITY_NONE_IGNORED,
    ].join('')
    for (const needle of [
      'signature verification failed', 'no key', 'in issuer manifest', 'issuer_mismatch',
      'duplicate object key', 'integer out of I-JSON safe range', 'compromised',
      'drm-bound', 'unknown payload field', 'promo_code', 'retired', "revocability is 'none'",
    ]) expect(corpus.includes(needle), needle).toBe(true)
  })
})
