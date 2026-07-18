import { JsonObject, JsonValue, canonicalBytes } from './canon.js'
import { verifyStrict } from './ed25519.js'
import { verifyStrict as verifyMldsaStrict } from './mldsa.js'
import { b64uDecode } from './b64u.js'
import { parseStrictUtc } from './dates.js'

export type KeyStatus = 'active' | 'retired' | 'compromised'
export interface KeyEntry {
  kid: string; pub: string; valid_from: string; valid_to: string | null; status: KeyStatus
  pub_ml_dsa_65?: string
}
export interface KeyManifest {
  issuer: string; manifest_version: number; issued_at: string
  keys: KeyEntry[]; manifest_signature: { kid: string; sig: string }
}
export interface TrustStore {
  manifests: Record<string, JsonObject>
  provenance: Record<string, string>
  chains?: Record<string, JsonObject[]>
}

function asObject(v: JsonValue | undefined): JsonObject | null {
  return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as JsonObject) : null
}

export function findKey(manifest: JsonObject, kid: string): JsonObject | null {
  const keys = manifest['keys']
  if (!Array.isArray(keys)) return null
  for (const e of keys) {
    const o = asObject(e)
    if (o && o['kid'] === kid) return o
  }
  return null
}

export function signableManifestBytes(manifest: JsonObject): Uint8Array {
  const body: JsonObject = Object.create(null)
  for (const k of Object.keys(manifest)) if (k !== 'manifest_signature') body[k] = manifest[k]!
  return canonicalBytes(body)
}

// AND rule: `entry` hybrid (carries `pub_ml_dsa_65`) requires BOTH legs present
// and valid; non-hybrid requires the Ed25519 leg valid and `sig_ml_dsa_65`
// ABSENT. Any other combination fails closed. Never throws — decode/type
// errors on untrusted input are treated as verification failure. Mirrors
// manifests.py's `verify_signature_block` — exported (not module-private, unlike
// the Python function's leading-underscore convention) because it is the
// single shared hybrid-verification primitive behind every v0.2 signed
// side-document: `revocation.ts`'s `verifyRecordSignature` calls this too.
export function verifySignatureBlock(payload: Uint8Array, sigBlock: JsonObject, entry: JsonObject): boolean {
  const isHybridEntry = 'pub_ml_dsa_65' in entry
  const hasMldsaLeg = 'sig_ml_dsa_65' in sigBlock
  if (isHybridEntry !== hasMldsaLeg) return false
  try {
    const sig = sigBlock['sig'], pub = entry['pub']
    if (typeof sig !== 'string' || typeof pub !== 'string') return false
    const edOk = verifyStrict(payload, b64uDecode(sig), b64uDecode(pub))
    if (!isHybridEntry) return edOk
    const mldsaSig = sigBlock['sig_ml_dsa_65'], mldsaPub = entry['pub_ml_dsa_65']
    if (typeof mldsaSig !== 'string' || typeof mldsaPub !== 'string') return false
    return edOk && verifyMldsaStrict(payload, b64uDecode(mldsaSig), b64uDecode(mldsaPub))
  } catch { return false }
}

export function verifyKeyManifest(manifest: JsonObject): boolean {
  try {
    const sigBlock = asObject(manifest['manifest_signature'])
    if (!sigBlock) return false
    const kid = sigBlock['kid']
    if (typeof kid !== 'string') return false
    const entry = findKey(manifest, kid)
    if (!entry) return false
    return verifySignatureBlock(signableManifestBytes(manifest), sigBlock, entry)
    // NOTE: deliberately does NOT check entry.status — a retired/compromised signer still self-verifies.
  } catch { return false }
}

export function withinValidity(issuedAt: unknown, entry: JsonObject): boolean {
  const issued = parseStrictUtc(issuedAt)
  const from = parseStrictUtc(entry['valid_from'])
  if (issued === null || from === null) return false
  if (issued < from) return false
  const to = entry['valid_to']
  if (to === null || to === undefined) return true
  const toMs = parseStrictUtc(to)
  if (toMs === null) return false
  return issued <= toMs
}

function withinReleaseWindow(at: unknown, entry: JsonObject): boolean {
  const t = parseStrictUtc(at)
  const from = parseStrictUtc(entry['valid_from'])
  if (t === null || from === null) return false
  if (t < from) return false
  const to = entry['valid_to']
  if (to === null || to === undefined) return true
  const toMs = parseStrictUtc(to)
  return toMs !== null && t <= toMs
}

export function checkContinuity(trusted: JsonObject, candidate: JsonObject): boolean {
  try {
    if (!verifyKeyManifest(trusted) || !verifyKeyManifest(candidate)) return false
    if (trusted['issuer'] !== candidate['issuer']) return false
    const tv = trusted['manifest_version'], cv = candidate['manifest_version']
    if (typeof tv !== 'bigint' || typeof cv !== 'bigint' || cv !== tv + 1n) return false
    const sigBlock = asObject(candidate['manifest_signature'])
    if (!sigBlock || typeof sigBlock['kid'] !== 'string') return false
    const signer = findKey(trusted, sigBlock['kid'])
    if (signer === null || signer['status'] !== 'active') return false
    // The signer key must also cover the candidate's issuance window, consistent
    // with verifyArtifactManifest (2026-07-13 review, finding 12).
    if (!withinValidity(candidate['issued_at'], signer)) return false
    // Bind continuity to the key TRUSTED vouches for: verify the candidate's
    // signature under trusted's pub for signer_kid, NOT the candidate's own
    // (attacker-substitutable) entry (2026-07-13 review, finding 1).
    return verifySignatureBlock(signableManifestBytes(candidate), sigBlock, signer)
  } catch { return false }
}

export function chainContinuous(chain: JsonObject[]): boolean {
  if (chain.length < 2) return true
  for (let i = 0; i < chain.length - 1; i++) if (!checkContinuity(chain[i]!, chain[i + 1]!)) return false
  return true
}

// AND rule (v0.2, mirrors verifyKeyManifest/manifests.py's
// verify_artifact_manifest): if the signer's keyManifest entry is hybrid
// (carries pub_ml_dsa_65), manifest_signature MUST also carry a valid
// sig_ml_dsa_65 leg over the same signed bytes, or verification fails closed;
// an Ed25519-only entry with a stray sig_ml_dsa_65 leg likewise fails closed
// (see verifySignatureBlock). Ed25519-only signers keep v0.1 behavior
// byte-for-byte (Stage 2 Task 6/8 sibling-patch parity).
export function verifyArtifactManifest(manifest: JsonObject, keyManifest: JsonObject): boolean {
  try {
    if (!verifyKeyManifest(keyManifest)) return false
    const sigBlock = asObject(manifest['manifest_signature'])
    if (!sigBlock || typeof sigBlock['kid'] !== 'string') return false
    if (manifest['issuer'] !== keyManifest['issuer']) return false
    const entry = findKey(keyManifest, sigBlock['kid'])
    if (!entry || entry['status'] !== 'active') return false
    if (!withinReleaseWindow(manifest['released_at'], entry)) return false
    return verifySignatureBlock(signableManifestBytes(manifest), sigBlock, entry)
  } catch { return false }
}
