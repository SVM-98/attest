// test/smoke.test.ts
import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { scrypt } from '@noble/hashes/scrypt'
import { OPR_VERSION } from '../src/index.js'

const L = 2n ** 252n + 27742317777372353535851937790883648493n

describe('scaffold', () => {
  it('exposes OPR version', () => { expect(OPR_VERSION).toBe('0.1') })
  it('noble ed25519 verify exists and curve order equals L', () => {
    expect(typeof ed25519.verify).toBe('function')
    expect(ed25519.CURVE.n).toBe(L)
  })
  it('noble scrypt is importable', () => { expect(typeof scrypt).toBe('function') })
})
