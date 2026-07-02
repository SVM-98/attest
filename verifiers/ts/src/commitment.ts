import { scrypt } from '@noble/hashes/scrypt'
import { verifyStrict } from './ed25519.js'

const LABEL_COMMITMENT = 'Attest-buyer-commitment-v1'
const LABEL_CHALLENGE = 'Attest-binding-challenge-v1'
const SCRYPT = { N: 32768, r: 8, p: 1, dkLen: 32 } as const // fixed, never configurable
const IDENTIFIER_TYPES = new Set(['issuer-account', 'email'])

function stripAsciiWs(s: string): string {
  return s.replace(/^[ \t\n\r]+/, '').replace(/[ \t\n\r]+$/, '')
}

export function normalizeIdentifier(identifier: string, identifierType: string): string {
  if (!IDENTIFIER_TYPES.has(identifierType))
    throw new Error(`unknown identifier_type: '${identifierType}'`)
  let norm: string
  if (identifierType === 'email') {
    norm = stripAsciiWs(identifier).normalize('NFC')
      .replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32))
  } else {
    norm = identifier.normalize('NFC') // issuer-account: NFC only, case preserved
  }
  if (norm.includes('\x00')) throw new Error('normalized identifier must not contain 0x00')
  return norm
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(total)
  let o = 0
  for (const p of parts) { out.set(p, o); o += p.length }
  return out
}

export function computeCommitment(identifier: string, identifierType: string, salt: Uint8Array): Uint8Array {
  if (salt.length !== 16) throw new Error('salt must be exactly 16 raw bytes')
  const norm = normalizeIdentifier(identifier, identifierType)
  const enc = new TextEncoder()
  const password = concatBytes(
    enc.encode(LABEL_COMMITMENT), Uint8Array.of(0),
    enc.encode(identifierType), Uint8Array.of(0),
    enc.encode(norm),
  )
  return scrypt(password, salt, SCRYPT)
}

export function verifyChallenge(receiptId: string, nonce: Uint8Array, sig: Uint8Array, pub: Uint8Array): boolean {
  if (nonce.length < 16) throw new Error('nonce must be at least 16 bytes')
  const enc = new TextEncoder()
  const msg = concatBytes(enc.encode(LABEL_CHALLENGE), Uint8Array.of(0), enc.encode(receiptId), Uint8Array.of(0), nonce)
  return verifyStrict(msg, sig, pub)
}
