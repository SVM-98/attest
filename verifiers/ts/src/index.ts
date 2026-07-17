export const ATTEST_VERSION = '0.1'
export const SUPPORTED_ATTEST_VERSIONS = ['0.1', '0.2'] as const
export { MAX_REVOCATION_RECORDS } from './revocation.js'
export { verify, isOk } from './verify.js'
export type { VerificationResult, Disclosure } from './verify.js'
export { loadsStrict, canonicalBytes, CanonError } from './canon.js'
export type { JsonValue, JsonObject } from './canon.js'
export type { TrustStore, KeyManifest, KeyEntry } from './manifests.js'
