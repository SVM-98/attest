// base64url WITHOUT padding (spec §9.1) — '=' is rejected on purpose.
export function b64uDecode(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error('not base64url (unpadded) input')
  if (s.length % 4 === 1) throw new Error('not base64url (unpadded) input')
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4))
  return Uint8Array.from(bin, (c) => c.charCodeAt(0))
}
