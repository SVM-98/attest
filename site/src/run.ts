import { verify, isOk } from 'attest-verifier'
import type { VerificationResult, Disclosure, TrustStore, JsonValue, VerifyTransparencyOptions } from 'attest-verifier'

export interface VerifyRun {
  result: VerificationResult
  ok: boolean
}

// The single verify() call site in site/. Everything the page verifies —
// bundles, bare envelopes, the sample — funnels through here, so the
// conformance suite in test/conformance.test.ts pins the page's actual path.
// `options` (transparency/logKeys/anchorPolicy) is additive: the page itself
// never passes it today (defaults to `{}`, zero behavior change), only the
// group-28 conformance leaves in test/conformance.test.ts do.
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
