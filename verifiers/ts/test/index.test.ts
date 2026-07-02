import { describe, it, expect } from 'vitest'
import * as api from '../src/index.js'

describe('public API', () => {
  it('exports verify, isOk, loadsStrict', () => {
    expect(typeof api.verify).toBe('function')
    expect(typeof api.isOk).toBe('function')
    expect(typeof api.loadsStrict).toBe('function')
  })
})
