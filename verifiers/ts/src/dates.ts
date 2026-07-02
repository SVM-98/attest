// Strict window dates mirror Python strptime '%Y-%m-%dT%H:%M:%SZ'. Revocation
// freshness uses a separate lenient ISO parse (Python fromisoformat). Both fail closed.
const STRICT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/

export function parseStrictUtc(s: unknown): number | null {
  if (typeof s !== 'string') return null
  const m = STRICT.exec(s)
  if (!m) return null
  const [, y, mo, d, h, mi, se] = m.map(Number) as unknown as number[]
  const t = Date.UTC(y!, mo! - 1, d!, h!, mi!, se!)
  // reject impossible dates that Date.UTC would roll over (e.g. month 13, day 32)
  const back = new Date(t)
  if (back.getUTCFullYear() !== y! || back.getUTCMonth() !== mo! - 1 || back.getUTCDate() !== d!)
    return null
  return t
}

export function parseIsoLenient(s: unknown): number | null {
  if (typeof s !== 'string') return null
  const t = Date.parse(s)
  return Number.isNaN(t) ? null : t
}
