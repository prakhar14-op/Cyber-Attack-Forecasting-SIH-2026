/**
 * Browser-side re-implementation of the tamper-evident audit ledger, mirroring
 * `ledger/ledger.py` and `ledger/merkle.py` in the Python backend.
 *
 * Every hash, pseudonym and Merkle root produced here is REAL cryptography,
 * computed with the Web Crypto API (`crypto.subtle`). Nothing is simulated.
 *
 * Construction (kept in lock-step with the Python source):
 *  - canonical(obj) = JSON with keys sorted ascending, separators ',' and ':',
 *    no whitespace — the exact shape of Python
 *    `json.dumps(obj, sort_keys=True, separators=(',',':'), ensure_ascii=True)`.
 *  - record content = { host: pseudonym, window_start, probability, stage,
 *    technique } + seq (0-based) + prev (previous record hash; genesis = 64 zeros).
 *  - pseudonym = HMAC-SHA256(key, host)[:16 hex chars],
 *    key = 'sih26-ledger-dev' (ledger.py's documented fallback when
 *    SIH26_LEDGER_KEY is unset).
 *  - record hash = SHA-256( ascii(prev) || utf8(canonical(content)) ), hex.
 *  - Merkle: leaf = SHA-256(0x00 || utf8(line)); node = SHA-256(0x01 || left ||
 *    right) over decoded hex digests; odd level duplicates its last leaf; an
 *    empty list hashes to SHA-256(0x00). Leaves are the canonical JSON LINES of
 *    each full entry (content + hash), matching Ledger._current_merkle_root.
 *
 * IMPORTANT CAVEATS
 *  - Byte-for-byte parity with the Python writer additionally depends on Python
 *    float formatting (`json.dumps` of a float uses `repr`), which does not
 *    always match JavaScript's `Number.prototype.toString`. The chain built
 *    here is internally consistent and verifies correctly against itself; it is
 *    not guaranteed to reproduce the exact digests of a file written by Python
 *    when a probability's float repr differs between the two runtimes.
 *  - `python -m ledger.verify_cli run/audit_chain.jsonl` remains the AUTHORITY
 *    for verifying a real ledger file produced by the engine. This module is an
 *    interactive, offline demonstration of the same mechanism.
 */

export const GENESIS = '0'.repeat(64)
export const LEDGER_KEY = 'sih26-ledger-dev'

/** The plaintext forecast fields the engine appends (before pseudonymisation). */
export interface ForecastRecordInput {
  host: string
  window_start: number
  probability: number
  stage: string
  technique: string | null
}

/** A finished chain entry: pseudonymised content + chain links + its own hash. */
export interface ChainEntry {
  host: string
  window_start: number
  probability: number
  stage: string
  technique: string | null
  seq: number
  prev: string
  hash: string
}

/** Result of recomputing the hash chain from genesis (mirrors Ledger.verify). */
export interface VerifyResult {
  ok: boolean
  /** First inconsistent index, or null when the whole chain verifies. */
  firstBadIndex: number | null
}

/** Anchored commitment (mirrors Ledger.checkpoint). */
export interface Checkpoint {
  head: string
  count: number
  merkle_root: string
}

/** Result of the anchored check (mirrors Ledger.verify_against_checkpoints). */
export interface AnchorResult {
  ok: boolean
  /** Recomputed chain head. */
  head: string
  /** Recomputed Merkle root. */
  merkleRoot: string
  headMatches: boolean
  rootMatches: boolean
}

// --------------------------------------------------------------------------
// Low-level crypto helpers (Web Crypto)
// --------------------------------------------------------------------------

/** True when a real SubtleCrypto is available (needs a secure context). */
export function cryptoAvailable(): boolean {
  return typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined'
}

function requireSubtle(): SubtleCrypto {
  if (!cryptoAvailable()) {
    throw new Error(
      'Web Crypto (crypto.subtle) is unavailable. A secure context (https:// or ' +
        'localhost) is required to compute real hashes.',
    )
  }
  return crypto.subtle
}

const encoder = new TextEncoder()

function toHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let out = ''
  for (const byte of bytes) {
    out += byte.toString(16).padStart(2, '0')
  }
  return out
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await requireSubtle().digest('SHA-256', bytes as unknown as BufferSource)
  return toHex(digest)
}

// --------------------------------------------------------------------------
// Canonical JSON — mirrors Python json.dumps(sort_keys, separators, ensure_ascii)
// --------------------------------------------------------------------------

/**
 * Deterministic JSON for hashing: keys sorted ascending, ',' and ':' separators,
 * no whitespace, non-ASCII escaped (ensure_ascii=True). Handles the value shapes
 * the ledger uses (string, number, boolean, null, nested objects, arrays).
 */
export function canonical(value: unknown): string {
  return encodeValue(value)
}

function encodeValue(value: unknown): string {
  if (value === null) return 'null'
  const kind = typeof value
  if (kind === 'string') return encodeString(value as string)
  if (kind === 'boolean') return value ? 'true' : 'false'
  if (kind === 'number') return encodeNumber(value as number)
  if (Array.isArray(value)) {
    return `[${value.map((item) => encodeValue(item)).join(',')}]`
  }
  if (kind === 'object') {
    const obj = value as Record<string, unknown>
    const keys = Object.keys(obj).sort()
    const parts = keys.map((key) => `${encodeString(key)}:${encodeValue(obj[key])}`)
    return `{${parts.join(',')}}`
  }
  throw new Error(`canonical: unsupported value type ${kind}`)
}

function encodeNumber(value: number): string {
  if (!Number.isFinite(value)) {
    throw new Error('canonical: non-finite numbers are not representable in JSON')
  }
  // Integers serialise identically in Python and JS. Floats can differ (Python
  // uses repr); see the module header caveat. This is the closest JS equivalent.
  return String(value)
}

/**
 * String escaping matching Python's ensure_ascii=True: escapes control chars,
 * '"' and '\\', and any code point >= 0x80 as \\uXXXX (surrogate pairs kept as
 * two \\uXXXX escapes, which is what CPython emits).
 */
function encodeString(value: string): string {
  let out = '"'
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i)
    if (code === 0x22) {
      out += '\\"'
    } else if (code === 0x5c) {
      out += '\\\\'
    } else if (code === 0x08) {
      out += '\\b'
    } else if (code === 0x09) {
      out += '\\t'
    } else if (code === 0x0a) {
      out += '\\n'
    } else if (code === 0x0c) {
      out += '\\f'
    } else if (code === 0x0d) {
      out += '\\r'
    } else if (code < 0x20 || code >= 0x7f) {
      out += `\\u${code.toString(16).padStart(4, '0')}`
    } else {
      out += String.fromCharCode(code)
    }
  }
  return `${out}"`
}

// --------------------------------------------------------------------------
// Pseudonymisation — HMAC-SHA256(key, host)[:16] (mirrors Ledger._pseudonym)
// --------------------------------------------------------------------------

export async function pseudonym(host: string, key: string = LEDGER_KEY): Promise<string> {
  const subtle = requireSubtle()
  const cryptoKey = await subtle.importKey(
    'raw',
    encoder.encode(key) as unknown as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const mac = await subtle.sign(
    'HMAC',
    cryptoKey,
    encoder.encode(host) as unknown as BufferSource,
  )
  return toHex(mac).slice(0, 16)
}

// --------------------------------------------------------------------------
// Record hashing — SHA-256(ascii(prev) || utf8(canonical(content)))
// --------------------------------------------------------------------------

/** The content object that is hashed (everything except the `hash` field). */
type EntryContent = Omit<ChainEntry, 'hash'>

function contentOf(entry: ChainEntry): EntryContent {
  const { hash: _hash, ...content } = entry
  void _hash
  return content
}

export async function recordHash(prev: string, content: EntryContent): Promise<string> {
  // prev is a 64-char hex string (ASCII); canonical(content) is UTF-8.
  const prevBytes = encoder.encode(prev) // ASCII subset of UTF-8, identical bytes
  const contentBytes = encoder.encode(canonical(content))
  return sha256Hex(concatBytes(prevBytes, contentBytes))
}

// --------------------------------------------------------------------------
// Chain construction (mirrors Ledger.append across a batch)
// --------------------------------------------------------------------------

/**
 * Build the full hash-chained ledger from forecast records, in order — exactly
 * as `engine/predict.py` appends `{host, window_start, probability, stage,
 * technique}` through `Ledger.append`.
 */
export async function buildChain(
  records: ForecastRecordInput[],
  key: string = LEDGER_KEY,
): Promise<ChainEntry[]> {
  const entries: ChainEntry[] = []
  let prev = GENESIS
  let seq = 0
  for (const rec of records) {
    const content: EntryContent = {
      host: await pseudonym(rec.host, key),
      window_start: rec.window_start,
      probability: rec.probability,
      stage: rec.stage,
      technique: rec.technique,
      seq,
      prev,
    }
    const hash = await recordHash(prev, content)
    entries.push({ ...content, hash })
    prev = hash
    seq += 1
  }
  return entries
}

// --------------------------------------------------------------------------
// Verification (mirrors Ledger.verify)
// --------------------------------------------------------------------------

/**
 * Recompute the hash chain from genesis. Returns the FIRST index whose stored
 * hash or prev-link is inconsistent, or { ok:true, firstBadIndex:null }.
 */
export async function verify(entries: ChainEntry[]): Promise<VerifyResult> {
  let prev = GENESIS
  let i = 0
  for (const entry of entries) {
    if (entry.prev !== prev) {
      return { ok: false, firstBadIndex: i }
    }
    const recomputed = await recordHash(prev, contentOf(entry))
    if (entry.hash !== recomputed) {
      return { ok: false, firstBadIndex: i }
    }
    prev = entry.hash
    i += 1
  }
  return { ok: true, firstBadIndex: null }
}

// --------------------------------------------------------------------------
// Merkle root (mirrors ledger/merkle.py + Ledger._current_merkle_root)
// --------------------------------------------------------------------------

const LEAF_PREFIX = new Uint8Array([0x00])
const NODE_PREFIX = new Uint8Array([0x01])

export async function leafHash(payload: string): Promise<string> {
  return sha256Hex(concatBytes(LEAF_PREFIX, encoder.encode(payload)))
}

async function nodeHash(leftHex: string, rightHex: string): Promise<string> {
  return sha256Hex(concatBytes(NODE_PREFIX, hexToBytes(leftHex), hexToBytes(rightHex)))
}

/** Merkle root over pre-hashed leaf hex digests. Empty -> SHA-256(0x00). */
export async function merkleRootFromLeaves(leaves: string[]): Promise<string> {
  if (leaves.length === 0) {
    return sha256Hex(LEAF_PREFIX)
  }
  let level = [...leaves]
  while (level.length > 1) {
    if (level.length % 2 === 1) {
      const last = level[level.length - 1]
      if (last !== undefined) level.push(last) // duplicate the last leaf
    }
    const next: string[] = []
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i]
      const right = level[i + 1]
      if (left === undefined || right === undefined) break
      next.push(await nodeHash(left, right))
    }
    level = next
  }
  return level[0] ?? (await sha256Hex(LEAF_PREFIX))
}

/**
 * Merkle root over the current chain records — one leaf per canonical JSON LINE
 * (the full entry including its hash), matching Ledger._current_merkle_root.
 */
export async function merkleRoot(entries: ChainEntry[]): Promise<string> {
  const leaves: string[] = []
  for (const entry of entries) {
    leaves.push(await leafHash(canonical(entry)))
  }
  return merkleRootFromLeaves(leaves)
}

// --------------------------------------------------------------------------
// Checkpoint / anchoring (mirrors Ledger.checkpoint + verify_against_checkpoints)
// --------------------------------------------------------------------------

/** The chain head hash (last entry's hash, or genesis for an empty chain). */
export function chainHead(entries: ChainEntry[]): string {
  const last = entries[entries.length - 1]
  return last === undefined ? GENESIS : last.hash
}

/** Anchor the current head + count + Merkle root (mirrors Ledger.checkpoint). */
export async function checkpoint(entries: ChainEntry[]): Promise<Checkpoint> {
  return {
    head: chainHead(entries),
    count: entries.length,
    merkle_root: await merkleRoot(entries),
  }
}

/**
 * Compare the current chain against an anchored checkpoint at the same count —
 * BOTH the head hash AND the recomputed Merkle root must match. Catches a full
 * self-consistent rewrite (which re-passes verify() but produces a different
 * head) and, via the Merkle root, any single-record content edit.
 * Mirrors Ledger.verify_against_checkpoints.
 */
export async function verifyAgainstCheckpoint(
  entries: ChainEntry[],
  cp: Checkpoint,
): Promise<AnchorResult> {
  const head = chainHead(entries)
  const root = await merkleRoot(entries)
  // The Python check only compares when counts match; a differing count means
  // no anchored checkpoint applies, so it cannot be confirmed.
  const countMatches = entries.length === cp.count
  const headMatches = countMatches && head === cp.head
  const rootMatches = countMatches && root === cp.merkle_root
  return { ok: headMatches && rootMatches, head, merkleRoot: root, headMatches, rootMatches }
}

// --------------------------------------------------------------------------
// Tamper helpers (mirror ledger/panels.py tamper modes) — pure, non-mutating
// --------------------------------------------------------------------------

/** The probability value ledger/panels.py writes when tampering a record. */
export const TAMPER_PROBABILITY = 0.999999

/**
 * Tamper mode 1 — single-record edit. Set probability to 0.999999 on the chosen
 * record WITHOUT recomputing its hash. verify() then fails at exactly `index`.
 * Returns a new array (does not mutate the input).
 */
export function tamperRecord(
  entries: ChainEntry[],
  index: number,
  probability: number = TAMPER_PROBABILITY,
): ChainEntry[] {
  return entries.map((entry, i) =>
    i === index ? { ...entry, probability } : { ...entry },
  )
}

/**
 * Tamper mode 2 — full self-consistent rewrite. Apply the same edit, then
 * recompute EVERY hash and prev-link from genesis so verify() passes again.
 * The anchored checkpoint then fails on head + Merkle-root mismatch.
 * Returns a new, internally-consistent chain.
 */
export async function rewriteChain(
  entries: ChainEntry[],
  index: number,
  probability: number = TAMPER_PROBABILITY,
): Promise<ChainEntry[]> {
  const edited = tamperRecord(entries, index, probability)
  const rebuilt: ChainEntry[] = []
  let prev = GENESIS
  let i = 0
  for (const entry of edited) {
    const content: EntryContent = { ...contentOf(entry), prev, seq: i }
    const hash = await recordHash(prev, content)
    rebuilt.push({ ...content, hash })
    prev = hash
    i += 1
  }
  return rebuilt
}
