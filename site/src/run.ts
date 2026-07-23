import { verify, isOk, auditChain } from 'attest-verifier'
import type {
  VerificationResult, Disclosure, TrustStore, JsonValue, JsonObject, VerifyTransparencyOptions,
  LogKey, AnchorPolicy, ChainAuditResult,
} from 'attest-verifier'

export interface VerifyRun {
  result: VerificationResult
  ok: boolean
}

// The single verify() call site in site/. Everything the page verifies —
// bundles, bare envelopes, the sample — funnels through here, so the
// conformance suite in test/conformance.test.ts pins the page's actual path.
// `options` (transparency/logKeys/anchorPolicy/transferView) is additive: the
// page itself never passes it today (defaults to `{}`, zero behavior
// change), only the group-28/35 conformance leaves in
// test/conformance.test.ts do.
export function runVerify(
  envelopeBytes: Uint8Array,
  trustStore: TrustStore,
  revocationView: JsonValue[] | null = null,
  disclosure: Disclosure | null = null,
  options: VerifyTransparencyOptions = {},
): VerifyRun {
  const result = verify(envelopeBytes, trustStore, revocationView, disclosure, undefined, options)
  return { result, ok: isOk(result) }
}

// The single auditChain() call site in site/ (v0.2 §17.5, group-36
// conformance leaves only today — the page itself does not yet expose a
// chain-of-title UI, but the production adapter carries the surface, not
// just the test, mirroring runVerify()'s own P1.4-established convention).
export function runChainAudit(
  payloads: JsonObject[],
  transferView: JsonValue[],
  revocationView: JsonValue[],
  keyManifest: JsonObject,
  logKeys: LogKey[],
  anchorPolicy: AnchorPolicy,
): ChainAuditResult {
  return auditChain(payloads, transferView, revocationView, keyManifest, logKeys, anchorPolicy)
}
