// @vitest-environment jsdom
import { describe, it, expect, beforeEach } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { loadsStrict, canonicalBytes } from 'attest-verifier'
import type { JsonObject } from 'attest-verifier'
import { initApp, type AppHandle } from '../src/main.js'
import { VECTORS_ROOT } from './helpers/vectors.js'

const V01 = join(VECTORS_ROOT, '01-valid-minimal')
const envelope = () => new Uint8Array(readFileSync(join(V01, 'envelope.json')))
const manifest = (): JsonObject => {
  const d = loadsStrict(new Uint8Array(readFileSync(join(V01, 'manifests.json')))) as JsonObject
  const manifests = d.manifests as JsonObject
  return manifests[Object.keys(manifests)[0]] as JsonObject
}

const PAGE = `
  <div id="dropzone"></div><input id="file-input" type="file">
  <div id="manifest-zone" hidden></div><input id="manifest-input" type="file">
  <input id="binding-identifier"><select id="binding-type"><option value="email">email</option><option value="issuer-account">issuer-account</option></select>
  <input id="binding-salt"><button id="binding-apply"></button>
  <button id="load-sample"></button>
  <section id="results"></section>`

let app: AppHandle
beforeEach(() => {
  document.body.innerHTML = PAGE
  app = initApp(document)
})

describe('initApp wiring', () => {
  it('renders a verified result for an envelope with embedded manifest', () => {
    const env = loadsStrict(envelope()) as JsonObject
    const withDelivery: JsonObject = { ...env, delivery: { issuer_manifest: manifest() } }
    app.handleBytes('receipt.attest.json', canonicalBytes(withDelivery))
    const results = document.getElementById('results')!
    expect(results.querySelectorAll('article.result')).toHaveLength(1)
    expect(results.textContent).toContain('unauthenticated_tofu')
  })

  it('asks for a manifest, then verifies once one is supplied', () => {
    app.handleBytes('receipt.attest.json', envelope())
    expect(document.getElementById('manifest-zone')!.hidden).toBe(false)
    app.handleManifestBytes(canonicalBytes(manifest()))
    expect(document.getElementById('manifest-zone')!.hidden).toBe(true)
    expect(document.getElementById('results')!.textContent).toContain('Receipt verifies')
  })

  it('shows the private-file refusal', () => {
    app.handleBytes('lib.private.attest', new Uint8Array([0x50, 0x4b]))
    expect(document.getElementById('results')!.textContent).toMatch(/never share/i)
  })
})
