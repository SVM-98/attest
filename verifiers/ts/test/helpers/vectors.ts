// Vector loader for the OPR v0.1 conformance suite. Reads (never mutates)
// `docs/spec/vectors/` — the language-neutral vector set replayed identically
// by the Python reference's `tests/test_vectors.py`. See that file's module
// docstring for the vector-directory conventions this loader implements.
import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { b64uDecode } from '../../src/b64u.js'
import { loadsStrict } from '../../src/canon.js'
import type { JsonObject } from '../../src/canon.js'
import type { Disclosure } from '../../src/index.js'

const HERE = fileURLToPath(new URL('.', import.meta.url))
export const VECTORS_ROOT = join(HERE, '..', '..', '..', '..', 'docs', 'spec', 'vectors')

export function findLeafDirs(root = VECTORS_ROOT): string[] {
  const out: string[] = []
  const walk = (d: string) => {
    if (existsSync(join(d, 'expected.json'))) out.push(d)
    for (const name of readdirSync(d)) { const p = join(d, name); if (statSync(p).isDirectory()) walk(p) }
  }
  walk(root)
  return out.sort()
}
export const vectorId = (dir: string) => relative(VECTORS_ROOT, dir).split(sep).join('/')
const loadJson = (p: string) => JSON.parse(readFileSync(p, 'utf-8'))
// manifests.json / revocation.json feed straight into verify()'s canon-typed
// JsonObject (TrustStore.manifests, revocation records) — anywhere that data
// gets self-verified (manifest signature, revocation record signature) it is
// re-canonicalized via canonicalBytes(), which only accepts `bigint` for JSON
// integers (see canon.ts JsonValue). Plain JSON.parse yields `number` for
// fields like manifest_version, so canonicalBytes() throws TYPE_NOT_JSON and
// the self-verify is silently swallowed as `false`. Route these two files
// through the same strict parser loadsStrict() uses for envelope bytes so
// integers arrive as bigint, matching the runtime type the verifier expects.
const loadJsonStrict = (p: string): JsonObject => loadsStrict(new Uint8Array(readFileSync(p))) as JsonObject

export function envelopeBytes(dir: string): Uint8Array {
  const raw = join(dir, 'envelope.raw.json')
  if (existsSync(raw)) return new Uint8Array(readFileSync(raw)) // exact bytes; strict parser must reject dups
  return new Uint8Array(readFileSync(join(dir, 'envelope.json')))
}
export function trustStore(dir: string) {
  const d = loadJsonStrict(join(dir, 'manifests.json'))
  return {
    manifests: d.manifests as Record<string, JsonObject>,
    provenance: d.provenance as Record<string, string>,
    chains: (d.chains ?? {}) as Record<string, JsonObject[]>,
  }
}
export function revocationView(dir: string): unknown[] | null {
  const p = join(dir, 'revocation.json')
  return existsSync(p) ? [loadJsonStrict(p)] : null
}
export function disclosure(dir: string): Disclosure | null {
  const p = join(dir, 'disclosure.json')
  if (!existsSync(p)) return null
  const d = loadJson(p)
  if ('salt_b64u' in d) return { identifier: d.identifier, identifier_type: d.identifier_type, salt: b64uDecode(d.salt_b64u) }
  return { challenge: [b64uDecode(d.nonce_b64u), b64uDecode(d.sig_b64u)] }
}
export const expected = (dir: string) => loadJson(join(dir, 'expected.json'))
