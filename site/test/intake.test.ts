import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { zipSync } from 'fflate'
import { loadsStrict, canonicalBytes } from 'attest-verifier'
import type { JsonObject } from 'attest-verifier'
import { intake, trustStoreFromManifestBytes } from '../src/intake.js'
import { runVerify } from '../src/run.js'
import { VECTORS_ROOT } from './helpers/vectors.js'

const V01 = join(VECTORS_ROOT, '01-valid-minimal')
const envelopeBytes = () => new Uint8Array(readFileSync(join(V01, 'envelope.json')))
const keyManifest = (): { issuer: string; manifest: JsonObject } => {
  const d = loadsStrict(new Uint8Array(readFileSync(join(V01, 'manifests.json')))) as JsonObject
  const manifests = d.manifests as JsonObject
  const issuer = Object.keys(manifests)[0]
  return { issuer, manifest: manifests[issuer] as JsonObject }
}

describe('intake', () => {
  it('rejects *.private.attest by name without reading it', () => {
    const r = intake('library.private.attest', new Uint8Array([0x50, 0x4b, 3, 4]))
    expect(r.kind).toBe('rejected')
  })

  it('routes a zip to parseBundle and yields one job per receipt', () => {
    const { issuer, manifest } = keyManifest()
    const blob: JsonObject = { issuer, key_manifests: [manifest], artifact_manifests: [] }
    const zip = zipSync({
      ['receipts/R1.attest.json']: envelopeBytes(),
      [`manifests/${issuer}.json`]: canonicalBytes(blob),
    })
    const r = intake('library.attest', zip)
    if (r.kind !== 'jobs') throw new Error(`expected jobs, got ${r.kind}`)
    expect(r.jobs).toHaveLength(1)
    expect(r.jobs[0].label).toBe('R1')
    expect(runVerify(r.jobs[0].envelopeBytes, r.jobs[0].trustStore).result.signature).toBe('valid')
  })

  it('rejects a private zip with the private message', () => {
    const zip = zipSync({ ['salts.json']: new TextEncoder().encode('{}') })
    const r = intake('oops.attest', zip)
    expect(r.kind).toBe('rejected')
    if (r.kind === 'rejected') expect(r.reason).toMatch(/private/i)
  })

  it('uses delivery.issuer_manifest when embedded in a bare envelope', () => {
    const { issuer, manifest } = keyManifest()
    const env = loadsStrict(envelopeBytes()) as JsonObject
    const withDelivery: JsonObject = { ...env, delivery: { issuer_manifest: manifest } }
    const r = intake('receipt.attest.json', canonicalBytes(withDelivery))
    if (r.kind !== 'jobs') throw new Error(`expected jobs, got ${r.kind}`)
    const run = runVerify(r.jobs[0].envelopeBytes, r.jobs[0].trustStore)
    expect(run.result.signature).toBe('valid')
    expect(run.result.trust).toBe('unauthenticated_tofu')
    expect(r.jobs[0].trustStore.provenance[issuer]).toBe('embedded')
  })

  it('asks for a manifest when a parseable envelope has none embedded', () => {
    const r = intake('receipt.attest.json', envelopeBytes())
    expect(r.kind).toBe('needs-manifest')
  })

  it('still yields a job (empty trust store) for unparseable JSON so verify() speaks', () => {
    const r = intake('garbage.attest.json', new TextEncoder().encode('{"n": 1.5}'))
    if (r.kind !== 'jobs') throw new Error(`expected jobs, got ${r.kind}`)
    const run = runVerify(r.jobs[0].envelopeBytes, r.jobs[0].trustStore)
    expect(run.result.signature).toBe('invalid')
    expect(run.ok).toBe(false)
  })
})

describe('trustStoreFromManifestBytes', () => {
  it('builds a user-supplied trust store from a key manifest', () => {
    const { issuer, manifest } = keyManifest()
    const ts = trustStoreFromManifestBytes(canonicalBytes(manifest))
    expect(ts).not.toBeNull()
    expect(ts!.provenance[issuer]).toBe('user-supplied')
    expect(runVerify(envelopeBytes(), ts!).result.signature).toBe('valid')
  })

  it('returns null for JSON that is not a key manifest', () => {
    expect(trustStoreFromManifestBytes(new TextEncoder().encode('{"a": 1}'))).toBeNull()
    expect(trustStoreFromManifestBytes(new TextEncoder().encode('not json'))).toBeNull()
  })
})
