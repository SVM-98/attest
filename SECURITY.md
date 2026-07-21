# Security Policy

attest is a cryptographic standard: a flaw in verification, canonicalization, or
key handling can let a forged or revoked receipt pass as valid. Please treat
security issues with care.

## Supported versions

Both published specification versions receive security fixes. This is not a
courtesy: a receipt is meant to outlive the store that issued it, so a signature
profile stops being supported only if it is broken, never because it is old.

| Version | Supported | Notes |
|---------|-----------|-------|
| 0.2     | ✅        | Hybrid Ed25519 + ML-DSA-65 signature profile; adds transparency/anchoring evidence |
| 0.1     | ✅        | Ed25519 profile; v0.1 receipts remain valid and verifiable indefinitely |

Report anything affecting either profile, including the post-quantum half of the
hybrid profile.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.** Report it privately
by email to `SVM-98@proton.me`.

Please include:

- the affected component (spec section, reference implementation, or the TypeScript verifier) and version/commit;
- a description of the issue and its security impact (e.g. signature bypass, fail-open, canonicalization mismatch, revocation bypass);
- a minimal reproduction — ideally a conformance-style vector (envelope + trust store + expected vs. actual `VerificationResult`).

## What to expect

- Acknowledgement of your report within 5 business days.
- A private assessment and, if confirmed, a coordinated fix before public disclosure.
- Credit for the discovery in the release notes, unless you ask to remain anonymous.

Please give us a reasonable window to ship a fix before any public disclosure.
No public zero-day disclosures.
