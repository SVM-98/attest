import { loadsStrict } from 'attest-verifier'
import type { JsonObject, TrustStore } from 'attest-verifier'
import { parseBundle, BundleError } from './bundle.js'

export interface VerifyJob {
  label: string
  envelopeBytes: Uint8Array
  trustStore: TrustStore
}

export type IntakeResult =
  | { kind: 'jobs'; jobs: VerifyJob[] }
  | { kind: 'needs-manifest'; envelopeBytes: Uint8Array; fileName: string }
  | { kind: 'rejected'; reason: string }

export const EMPTY_TRUST: TrustStore = { manifests: {}, provenance: {} }

const PRIVATE_NAME_MSG =
  'That file is named .private.attest — it holds your binding salts and keys. ' +
  'Never share or upload it anywhere. Drop the shareable .attest instead.'

const asObject = (v: unknown): JsonObject | null =>
  v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as JsonObject) : null

export function intake(fileName: string, bytes: Uint8Array): IntakeResult {
  if (fileName.endsWith('.private.attest')) return { kind: 'rejected', reason: PRIVATE_NAME_MSG }

  const isZip = bytes.length >= 2 && bytes[0] === 0x50 && bytes[1] === 0x4b
  if (isZip) {
    try {
      const parsed = parseBundle(bytes)
      return {
        kind: 'jobs',
        jobs: parsed.receipts.map((r) => ({ label: r.name, envelopeBytes: r.bytes, trustStore: parsed.trustStore })),
      }
    } catch (e) {
      if (e instanceof BundleError) return { kind: 'rejected', reason: e.message } // includes PrivateBundleError
      throw e
    }
  }

  // Bare envelope. Peek for delivery.issuer_manifest; if the bytes don't even
  // strict-parse, hand them to verify() anyway — its error catalog speaks
  // better than we could, and a failing receipt rendering is demo gold.
  let parsed = false
  let embedded: JsonObject | null = null
  try {
    const env = asObject(loadsStrict(bytes))
    parsed = env !== null
    const delivery = env ? asObject(env['delivery']) : null
    embedded = delivery ? asObject(delivery['issuer_manifest']) : null
  } catch {
    parsed = false
  }

  if (embedded && typeof embedded['issuer'] === 'string') {
    const issuer = embedded['issuer']
    return {
      kind: 'jobs',
      jobs: [{
        label: fileName,
        envelopeBytes: bytes,
        trustStore: { manifests: { [issuer]: embedded }, provenance: { [issuer]: 'embedded' } },
      }],
    }
  }
  if (parsed) return { kind: 'needs-manifest', envelopeBytes: bytes, fileName }
  return { kind: 'jobs', jobs: [{ label: fileName, envelopeBytes: bytes, trustStore: EMPTY_TRUST }] }
}

export function trustStoreFromManifestBytes(bytes: Uint8Array): TrustStore | null {
  try {
    const m = asObject(loadsStrict(bytes))
    if (m && typeof m['issuer'] === 'string' && Array.isArray(m['keys'])) {
      const issuer = m['issuer']
      return { manifests: { [issuer]: m }, provenance: { [issuer]: 'user-supplied' } }
    }
  } catch {
    /* not canonical JSON → not a manifest */
  }
  return null
}
