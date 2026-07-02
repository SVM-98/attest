// Unpadded base64url <-> bytes, matching Python keys.b64u / b64u_decode.
// No deps: @noble/hashes ships no base64 and we refuse libsodium.

function bytesToBinary(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return s
}

export function b64uEncode(bytes: Uint8Array): string {
  const b64 = btoa(bytesToBinary(bytes))
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function b64uDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/')
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4) // matches '=' * (-len % 4)
  const binary = atob(padded)
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i)
  return out
}
