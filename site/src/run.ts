import { verify, isOk } from 'attest-verifier'
import type { VerificationResult, Disclosure, TrustStore, JsonValue } from 'attest-verifier'

export interface VerifyRun {
  result: VerificationResult
  ok: boolean
}

// The single verify() call site in site/. Everything the page verifies —
// bundles, bare envelopes, the sample — funnels through here, so the
// conformance suite in test/conformance.test.ts pins the page's actual path.
export function runVerify(
  envelopeBytes: Uint8Array,
  trustStore: TrustStore,
  revocationView: JsonValue[] | null = null,
  disclosure: Disclosure | null = null,
): VerifyRun {
  const result = verify(envelopeBytes, trustStore, revocationView, disclosure)
  return { result, ok: isOk(result) }
}
