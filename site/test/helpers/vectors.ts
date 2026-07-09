import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { loadsStrict } from 'attest-verifier'
import type { JsonObject, TrustStore, Disclosure, JsonValue } from 'attest-verifier'

const HERE = fileURLToPath(new URL('.', import.meta.url))
export const VECTORS_ROOT = join(HERE, '..', '..', '..', 'docs', 'spec', 'vectors')

export function findLeafDirs(root = VECTORS_ROOT): string[] {
  const out: string[] = []
  const walk = (d: string) => {
    if (existsSync(join(d, 'expected.json'))) out.push(d)
    for (const name of readdirSync(d)) {
      const p = join(d, name)
      if (statSync(p).isDirectory()) walk(p)
    }
  }
  walk(root)
  return out.sort()
}
export const vectorId = (dir: string) => relative(VECTORS_ROOT, dir).split(sep).join('/')

const loadJsonStrict = (p: string): JsonObject =>
  loadsStrict(new Uint8Array(readFileSync(p))) as JsonObject

export function envelopeBytes(dir: string): Uint8Array {
  const raw = join(dir, 'envelope.raw.json')
  if (existsSync(raw)) return new Uint8Array(readFileSync(raw))
  return new Uint8Array(readFileSync(join(dir, 'envelope.json')))
}
export function trustStore(dir: string): TrustStore {
  const d = loadJsonStrict(join(dir, 'manifests.json'))
  return {
    manifests: d.manifests as unknown as Record<string, JsonObject>,
    provenance: d.provenance as unknown as Record<string, string>,
    chains: (d.chains ?? {}) as unknown as Record<string, JsonObject[]>,
  }
}
export function revocationView(dir: string): JsonValue[] | null {
  const p = join(dir, 'revocation.json')
  return existsSync(p) ? [loadJsonStrict(p)] : null
}
export function disclosure(dir: string): Disclosure | null {
  const p = join(dir, 'disclosure.json')
  if (!existsSync(p)) return null
  const d = JSON.parse(readFileSync(p, 'utf-8'))
  const b64u = (s: string): Uint8Array => {
    const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'))
    return Uint8Array.from(bin, (c) => c.charCodeAt(0))
  }
  if ('salt_b64u' in d) return { identifier: d.identifier, identifier_type: d.identifier_type, salt: b64u(d.salt_b64u) }
  return { challenge: [b64u(d.nonce_b64u), b64u(d.sig_b64u)] }
}
export const expected = (dir: string) => JSON.parse(readFileSync(join(dir, 'expected.json'), 'utf-8'))
