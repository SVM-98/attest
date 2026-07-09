export type Tone = 'good' | 'warn' | 'bad' | 'neutral'
export interface Explanation {
  label: string
  text: string
  tone: Tone
}
export type Component = 'signature' | 'schema' | 'revocation' | 'binding' | 'trust'

export const COMPONENTS: Component[] = ['signature', 'schema', 'revocation', 'binding', 'trust']

// One entry per (component, value). Register: honest, concrete, no hype —
// same voice as README.md and docs/faq.md. Spec section pointers included
// so a curious reader can go straight to the normative text.
const CATALOG: Record<Component, Record<string, Explanation>> = {
  signature: {
    valid: {
      label: 'Signature',
      tone: 'good',
      text: 'The issuer’s Ed25519 signature over the canonical payload checks out: these exact terms were signed by the key identified in the issuer’s manifest, and nothing in them has changed since (spec §10, §11 step 4).',
    },
    invalid: {
      label: 'Signature',
      tone: 'bad',
      text: 'This receipt does not carry a valid signature from the issuer’s published key material — it may be tampered with, corrupted, malformed, or signed by a key this verifier has no manifest for. The errors below say exactly which check failed.',
    },
  },
  schema: {
    valid: {
      label: 'Schema',
      tone: 'good',
      text: 'The signed payload matches the attest v0.1 receipt schema: every required field is present with the right shape, so other tools will read this receipt the same way this one does (spec §11 step 5).',
    },
    invalid: {
      label: 'Schema',
      tone: 'bad',
      text: 'The signature may check out, but the payload does not match the attest v0.1 receipt schema — a conforming issuer should never have produced it. Treat it with suspicion.',
    },
    not_checked: {
      label: 'Schema',
      tone: 'neutral',
      text: 'Schema validation never ran, because verification stopped at an earlier step — there is no valid signature to make the payload worth validating (spec §11: short-circuit order).',
    },
  },
  revocation: {
    unknown: {
      label: 'Revocation',
      tone: 'neutral',
      text: 'No revocation feed was consulted, so this verifier honestly reports “unknown” instead of guessing — like a paper receipt, the absence of a revocation check does not erase the signature (spec §11.2). The CLI can check a feed when one is available.',
    },
    revoked: {
      label: 'Revocation',
      tone: 'bad',
      text: 'The issuer has published a signed, authenticated revocation record for this receipt, and its license class allows revocation — this receipt is revoked (spec §12).',
    },
    invalid_revocation_ignored: {
      label: 'Revocation',
      tone: 'warn',
      text: 'A revocation record for this receipt exists but was IGNORED: either it is not properly authenticated, or it tries to revoke a receipt whose license class forbids it (revocability “none”, or outside the refund window). The receipt stands (spec §12.2).',
    },
  },
  binding: {
    proven: {
      label: 'Buyer binding',
      tone: 'good',
      text: 'The disclosed identifier and salt reproduce the buyer commitment sealed inside the signed payload — whoever supplied them is the buyer this receipt was issued to (spec §8.1).',
    },
    not_proven: {
      label: 'Buyer binding',
      tone: 'warn',
      text: 'A binding proof was attempted but did not reproduce the sealed buyer commitment — wrong identifier, wrong salt, or a receipt that simply is not theirs (spec §8).',
    },
    not_checked: {
      label: 'Buyer binding',
      tone: 'neutral',
      text: 'Nobody attempted to prove who this receipt belongs to — the receipt is genuine either way; binding only says whose it is. Use the panel above with the receipt’s salt to prove it (spec §8).',
    },
  },
  trust: {
    verified: {
      label: 'Key trust',
      tone: 'good',
      text: 'The issuer’s key manifest was fetched over TLS from the issuer’s own domain — the strongest provenance attest v0.1 defines (spec §7.4).',
    },
    unauthenticated_tofu: {
      label: 'Key trust',
      tone: 'warn',
      text: 'The issuer’s keys came from inside the file you dropped, not from the issuer’s website — the math checks out, but a browser cannot confirm who published these keys (and this page never phones home to try). That is trust-on-first-use, reported honestly; the attest CLI can fetch the manifest over TLS for the “verified” level (spec §7.4).',
    },
    unverified_rotation: {
      label: 'Key trust',
      tone: 'warn',
      text: 'The issuer’s key manifest history has a gap: a newer manifest is not signed by a key from the previous trusted one, so continuity cannot be proven (spec §7.3). The signature math still ran, but key provenance deserves suspicion.',
    },
  },
}

const FALLBACK: Record<Component, string> = {
  signature: 'Signature',
  schema: 'Schema',
  revocation: 'Revocation',
  binding: 'Buyer binding',
  trust: 'Key trust',
}

export function explain(component: Component, value: string): Explanation {
  const hit = CATALOG[component][value]
  if (hit) return hit
  if (component === 'revocation' && value.startsWith('not_revoked_as_of:')) {
    const t = value.slice('not_revoked_as_of:'.length)
    return {
      label: 'Revocation',
      tone: 'good',
      text: `An authenticated revocation feed was consulted and no valid revocation matches this receipt — current as of ${t}, the newest signed timestamp in that feed (spec §12.3). Freshness is only as good as the feed.`,
    }
  }
  return {
    label: FALLBACK[component],
    tone: 'neutral',
    text: `This verifier does not have dedicated wording for “${value}” — see the raw result below and spec §11.1 for the normative meaning.`,
  }
}

export function explainVerdict(ok: boolean): Explanation {
  return ok
    ? {
        label: 'Receipt verifies',
        tone: 'good',
        text: 'Signature valid, schema valid, not revoked as far as this check could see, and no errors — the four-gate “ok” of spec §11.1.',
      }
    : {
        label: 'Receipt does NOT verify',
        tone: 'bad',
        text: 'At least one of the four gates failed — the rows below show exactly which one and why (spec §11.1).',
      }
}
