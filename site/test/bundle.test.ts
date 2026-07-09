import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { zipSync } from 'fflate'
import { loadsStrict, canonicalBytes } from 'attest-verifier'
import type { JsonObject } from 'attest-verifier'
import { parseBundle, BundleError, PrivateBundleError, DEFAULT_CAPS } from '../src/bundle.js'
import { runVerify } from '../src/run.js'
import { VECTORS_ROOT } from './helpers/vectors.js'

const V01 = join(VECTORS_ROOT, '01-valid-minimal')

// Build a real .attest-shaped zip from the 01-valid-minimal vector: its
// envelope + its key manifest wrapped in the export format
// manifests/<issuer>.json = {issuer, key_manifests: [...], artifact_manifests: []}.
function sampleZip(): { zip: Uint8Array; issuer: string } {
  const envelope = new Uint8Array(readFileSync(join(V01, 'envelope.json')))
  const d = loadsStrict(new Uint8Array(readFileSync(join(V01, 'manifests.json')))) as JsonObject
  const manifests = d.manifests as JsonObject
  const issuer = Object.keys(manifests)[0]
  const blob: JsonObject = { issuer, key_manifests: [manifests[issuer]], artifact_manifests: [] }
  const zip = zipSync({
    ['receipts/01HZX0000000000000000000AA.attest.json']: envelope,
    [`manifests/${issuer}.json`]: canonicalBytes(blob),
    ['README.html']: new TextEncoder().encode('<p>bundle readme</p>'),
  })
  return { zip, issuer }
}

describe('parseBundle', () => {
  it('extracts receipts and builds a TOFU trust store that verifies', () => {
    const { zip, issuer } = sampleZip()
    const parsed = parseBundle(zip)
    expect(parsed.receipts).toHaveLength(1)
    expect(parsed.receipts[0].name).toBe('01HZX0000000000000000000AA')
    expect(parsed.trustStore.provenance[issuer]).toBe('bundle')
    const run = runVerify(parsed.receipts[0].bytes, parsed.trustStore)
    expect(run.result.signature).toBe('valid')
    expect(run.result.trust).toBe('unauthenticated_tofu') // never 'verified' from a bundle
  })

  it('keeps the latest key manifest and the full ordered chain', () => {
    const { zip: _zip, issuer } = sampleZip()
    const d = loadsStrict(new Uint8Array(readFileSync(join(V01, 'manifests.json')))) as JsonObject
    const km = (d.manifests as JsonObject)[issuer] as JsonObject
    const v2: JsonObject = { ...km, manifest_version: 2n }
    const blob: JsonObject = { issuer, key_manifests: [v2, km], artifact_manifests: [] }
    const zip = zipSync({
      ['receipts/X.attest.json']: new Uint8Array(readFileSync(join(V01, 'envelope.json'))),
      [`manifests/${issuer}.json`]: canonicalBytes(blob),
    })
    const parsed = parseBundle(zip)
    expect((parsed.trustStore.manifests[issuer] as JsonObject).manifest_version).toBe(2n)
    expect(parsed.trustStore.chains?.[issuer]).toHaveLength(2)
    expect((parsed.trustStore.chains?.[issuer][0] as JsonObject).manifest_version).toBe(1n)
  })

  it('rejects a bundle with zero receipts', () => {
    const zip = zipSync({ ['README.html']: new TextEncoder().encode('x') })
    expect(() => parseBundle(zip)).toThrow(BundleError)
  })

  it('rejects garbage bytes as not-a-zip', () => {
    expect(() => parseBundle(new TextEncoder().encode('not a zip'))).toThrow(BundleError)
  })

  it('refuses a private bundle (salts.json) without decompressing secrets', () => {
    const zip = zipSync({ ['salts.json']: new TextEncoder().encode('{"R":"c2FsdA"}') })
    expect(() => parseBundle(zip)).toThrow(PrivateBundleError)
  })

  it('refuses a private bundle (keys/)', () => {
    const zip = zipSync({ ['keys/R.seed']: new Uint8Array(32) })
    expect(() => parseBundle(zip)).toThrow(PrivateBundleError)
  })

  it('enforces the entry-count cap', () => {
    const entries: Record<string, Uint8Array> = {}
    for (let i = 0; i < 4; i++) entries[`receipts/${i}.attest.json`] = new TextEncoder().encode('{}')
    const zip = zipSync(entries)
    expect(() => parseBundle(zip, { ...DEFAULT_CAPS, maxEntries: 3 })).toThrow(/entries/)
  })

  it('enforces the per-member cap', () => {
    const zip = zipSync({ ['receipts/big.attest.json']: new Uint8Array(2048) })
    expect(() => parseBundle(zip, { ...DEFAULT_CAPS, maxMemberBytes: 1024 })).toThrow(/cap/)
  })

  it('enforces the aggregate cap', () => {
    const zip = zipSync({
      ['receipts/a.attest.json']: new Uint8Array(800),
      ['receipts/b.attest.json']: new Uint8Array(800),
    })
    expect(() => parseBundle(zip, { ...DEFAULT_CAPS, maxTotalBytes: 1000 })).toThrow(/cap/)
  })
})
