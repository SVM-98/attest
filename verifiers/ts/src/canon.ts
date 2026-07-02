import { duplicateKey, notUtf8, invalidJson, ERR } from './messages.js'

export class CanonError extends Error {}

export type JsonValue = null | boolean | bigint | string | JsonValue[] | JsonObject
export interface JsonObject { [k: string]: JsonValue }

// ---- strict recursive-descent parser (replaces JSON.parse) ----
class Reader {
  i = 0
  constructor(readonly s: string) {}
  err(msg: string): never { throw new CanonError(invalidJson(`${msg} at ${this.i}`)) }
  ws() { while (this.i < this.s.length && ' \t\n\r'.includes(this.s[this.i]!)) this.i++ }
  end() { this.ws(); if (this.i !== this.s.length) this.err('trailing content') }
}

function parseValue(r: Reader): JsonValue {
  r.ws()
  const c = r.s[r.i]
  if (c === undefined) r.err('unexpected end')
  if (c === '{') return parseObject(r)
  if (c === '[') return parseArray(r)
  if (c === '"') return parseString(r)
  if (c === '-' || (c >= '0' && c <= '9')) return parseNumber(r)
  if (r.s.startsWith('true', r.i)) { r.i += 4; return true }
  if (r.s.startsWith('false', r.i)) { r.i += 5; return false }
  if (r.s.startsWith('null', r.i)) { r.i += 4; return null }
  // NaN / Infinity / -Infinity and anything else are invalid JSON
  r.err(`unexpected token '${c}'`)
}

function parseObject(r: Reader): JsonObject {
  r.i++ // {
  const obj: JsonObject = Object.create(null)
  const seen = new Set<string>()
  r.ws()
  if (r.s[r.i] === '}') { r.i++; return obj }
  for (;;) {
    r.ws()
    if (r.s[r.i] !== '"') r.err('expected object key')
    const key = parseString(r)
    if (seen.has(key)) throw new CanonError(duplicateKey(key))
    seen.add(key)
    r.ws()
    if (r.s[r.i] !== ':') r.err("expected ':'")
    r.i++
    obj[key] = parseValue(r)
    r.ws()
    const d = r.s[r.i]
    if (d === ',') { r.i++; continue }
    if (d === '}') { r.i++; return obj }
    r.err("expected ',' or '}'")
  }
}

function parseArray(r: Reader): JsonValue[] {
  r.i++ // [
  const arr: JsonValue[] = []
  r.ws()
  if (r.s[r.i] === ']') { r.i++; return arr }
  for (;;) {
    arr.push(parseValue(r))
    r.ws()
    const d = r.s[r.i]
    if (d === ',') { r.i++; continue }
    if (d === ']') { r.i++; return arr }
    r.err("expected ',' or ']'")
  }
}

function parseString(r: Reader): string {
  r.i++ // opening quote
  let out = ''
  for (;;) {
    const c = r.s[r.i]
    if (c === undefined) r.err('unterminated string')
    if (c === '"') { r.i++; return out }
    if (c === '\\') {
      const e = r.s[r.i + 1]
      switch (e) {
        case '"': out += '"'; r.i += 2; break
        case '\\': out += '\\'; r.i += 2; break
        case '/': out += '/'; r.i += 2; break
        case 'b': out += '\b'; r.i += 2; break
        case 'f': out += '\f'; r.i += 2; break
        case 'n': out += '\n'; r.i += 2; break
        case 'r': out += '\r'; r.i += 2; break
        case 't': out += '\t'; r.i += 2; break
        case 'u': {
          const hex = r.s.slice(r.i + 2, r.i + 6)
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) r.err('bad \\u escape')
          out += String.fromCharCode(parseInt(hex, 16))
          r.i += 6
          break
        }
        default: r.err('bad escape')
      }
    } else if (c.charCodeAt(0) < 0x20) {
      r.err('unescaped control character')
    } else {
      out += c; r.i++
    }
  }
}

const NUM_RE = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/
function parseNumber(r: Reader): bigint {
  const m = NUM_RE.exec(r.s.slice(r.i))
  if (!m) r.err('bad number')
  const tok = m[0]
  if (tok.includes('.') || tok.includes('e') || tok.includes('E'))
    throw new CanonError(ERR.FLOATS_NOT_ALLOWED)
  r.i += tok.length
  return BigInt(tok) // full precision; range check deferred to canonicalBytes
}

// ---- post-parse lone-surrogate rejection (catches \uXXXX-injected surrogates) ----
function hasLoneSurrogate(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const cp = s.charCodeAt(i)
    if (cp >= 0xd800 && cp <= 0xdbff) {
      const lo = s.charCodeAt(i + 1)
      if (lo >= 0xdc00 && lo <= 0xdfff) { i++; continue }
      return true
    }
    if (cp >= 0xdc00 && cp <= 0xdfff) return true
  }
  return false
}
function rejectSurrogates(v: JsonValue): void {
  if (typeof v === 'string') { if (hasLoneSurrogate(v)) throw new CanonError(ERR.LONE_SURROGATE) }
  else if (Array.isArray(v)) v.forEach(rejectSurrogates)
  else if (v !== null && typeof v === 'object') {
    for (const k of Object.keys(v)) {
      if (hasLoneSurrogate(k)) throw new CanonError(ERR.LONE_SURROGATE)
      rejectSurrogates(v[k]!)
    }
  }
}

export function loadsStrict(bytes: Uint8Array): JsonValue {
  let text: string
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch (e) {
    throw new CanonError(notUtf8(e instanceof Error ? e.message : String(e)))
  }
  const r = new Reader(text)
  const value = parseValue(r)
  r.end()
  rejectSurrogates(value)
  return value
}
