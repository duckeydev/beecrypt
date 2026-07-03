import { sha256, sha384, sha512 } from "./sha.ts";

const encoder = new TextEncoder();

type Digest = "SHA-256" | "SHA-384" | "SHA-512";

interface BeecryptOptions {
  iterations?: number;
  saltBytes?: number;
  keyBytes?: number;
  digest?: Digest;
}

const DEFAULTS = {
  iterations: 210_000,
  saltBytes: 32,
  keyBytes: 64,
  digest: "SHA-512" as Digest,
};

const BLOCK_SIZE: Record<Digest, number> = {
  "SHA-256": 64,
  "SHA-384": 128,
  "SHA-512": 128,
};

const HASH_SIZE: Record<Digest, number> = {
  "SHA-256": 32,
  "SHA-384": 48,
  "SHA-512": 64,
};

const SHA_FN: Record<Digest, (data: Uint8Array) => Uint8Array> = {
  "SHA-256": sha256,
  "SHA-384": sha384,
  "SHA-512": sha512,
};

// ── Universal random bytes ──
function randomBytes(n: number): Uint8Array {
  const buf = new Uint8Array(n);
  try {
    const c = (typeof globalThis !== "undefined" && globalThis.crypto) ||
              (typeof crypto !== "undefined" && crypto) ||
              (typeof window !== "undefined" && window.crypto);
    if (c && c.getRandomValues) {
      c.getRandomValues(buf);
      return buf;
    }
  } catch { /* fall through */ }

  try {
    const req = typeof require === "function" ? require : undefined;
    if (req) {
      const nc = req("crypto");
      if (nc.randomFillSync) {
        nc.randomFillSync(buf);
        return buf;
      }
    }
  } catch { /* fall through */ }

  throw new Error("No secure random number generator available");
}

// ── Base64url ──
function base64urlEncode(buf: Uint8Array): string {
  const codes = new Array(buf.length);
  for (let i = 0; i < buf.length; i++) codes[i] = String.fromCharCode(buf[i]);
  return btoa(codes.join("")).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlDecode(s: string): Uint8Array {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4;
  if (pad === 1) throw new Error("Invalid base64url string");
  if (pad === 2) s += "==";
  else if (pad === 3) s += "=";
  const binary = atob(s);
  const buf = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) buf[i] = binary.charCodeAt(i);
  return buf;
}

// ── Format ──
function encodeFormat(
  digest: Digest,
  keyBytes: number,
  iterations: number,
  salt: string,
  hash: string,
): string {
  return `$beecrypt$${digest}$k=${keyBytes}&i=${iterations}$${salt}$${hash}`;
}

interface Parsed {
  digest: Digest;
  keyBytes: number;
  iterations: number;
  salt: string;
  hash: string;
}

function tryParse(encoded: string): Parsed | null {
  const parts = encoded.split("$");
  if (parts.length !== 6 || parts[1] !== "beecrypt") return null;
  const digest = parts[2] as Digest;
  if (digest !== "SHA-256" && digest !== "SHA-384" && digest !== "SHA-512") return null;
  const params = parts[3]?.split("&");
  if (!params) return null;

  let keyBytes = 0, iterations = 0;
  for (const p of params) {
    if (p.startsWith("k=")) keyBytes = Number(p.slice(2));
    else if (p.startsWith("i=")) iterations = Number(p.slice(2));
  }
  if (!Number.isSafeInteger(keyBytes) || keyBytes <= 0) return null;
  if (!Number.isSafeInteger(iterations) || iterations <= 0) return null;

  return { digest, keyBytes, iterations, salt: parts[4], hash: parts[5] };
}

// ── Native PBKDF2 (Web Crypto) ──
function hasSubtle(): boolean {
  try {
    const c = (typeof globalThis !== "undefined" && globalThis.crypto) ||
              (typeof crypto !== "undefined" && crypto);
    return !!(c && c.subtle && c.subtle.importKey);
  } catch { return false; }
}

async function nativePbkdf2(
  password: string,
  salt: Uint8Array,
  iterations: number,
  digest: Digest,
  keyBytes: number,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: digest },
    key, keyBytes * 8,
  );
  return new Uint8Array(bits);
}

// ── Pure-JS PBKDF2 (zero concat, inlined HMAC, reusable buffers) ──
function fallbackPbkdf2(
  password: string,
  salt: Uint8Array,
  iterations: number,
  digest: Digest,
  keyBytes: number,
): Uint8Array {
  const hashLen = HASH_SIZE[digest];
  const blockSize = BLOCK_SIZE[digest];
  const blocks = ((keyBytes + hashLen - 1) / hashLen) | 0;
  const out = new Uint8Array(keyBytes);

  // Pre-process key
  let key = encoder.encode(password);
  if (key.length > blockSize) key = SHA_FN[digest](key);

  // Reusable HMAC buffers: inner = blockSize + max(salt+4, hashLen)
  const maxMsg = Math.max(salt.length + 4, hashLen);
  const inner = new Uint8Array(blockSize + maxMsg);
  const outer = new Uint8Array(blockSize + hashLen);

  for (let i = 0; i < blockSize; i++) {
    const k = i < key.length ? key[i] : 0;
    inner[i] = k ^ 0x36;
    outer[i] = k ^ 0x5c;
  }

  for (let b = 1; b <= blocks; b++) {
    // First HMAC: password || (salt || blockIndex)
    const innerLen = blockSize + salt.length + 4;
    inner.set(salt, blockSize);
    inner[blockSize + salt.length]     = (b >>> 24) & 0xff;
    inner[blockSize + salt.length + 1] = (b >>> 16) & 0xff;
    inner[blockSize + salt.length + 2] = (b >>> 8) & 0xff;
    inner[blockSize + salt.length + 3] = b & 0xff;

    let u = SHA_FN[digest](inner.subarray(0, innerLen));
    outer.set(u, blockSize);
    const t = SHA_FN[digest](outer.subarray(0, blockSize + hashLen));

    // Subsequent iterations: HMAC(password, u)
    for (let i = 1; i < iterations; i++) {
      inner.set(u, blockSize);
      u = SHA_FN[digest](inner.subarray(0, blockSize + hashLen));
      outer.set(u, blockSize);
      u = SHA_FN[digest](outer.subarray(0, blockSize + hashLen));
      for (let j = 0; j < hashLen; j++) t[j] ^= u[j];
    }

    const offset = (b - 1) * hashLen;
    const take = Math.min(hashLen, keyBytes - offset);
    out.set(t.subarray(0, take), offset);
  }

  return out;
}

// ── Derive (always returns a Promise) ──
async function pbkdf2Derive(
  password: string,
  salt: Uint8Array,
  iterations: number,
  digest: Digest,
  keyBytes: number,
): Promise<Uint8Array> {
  if (hasSubtle()) {
    try {
      return await nativePbkdf2(password, salt, iterations, digest, keyBytes);
    } catch {
      // Native failed — fall through to pure JS
    }
  }
  return fallbackPbkdf2(password, salt, iterations, digest, keyBytes);
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ── Public API ──
export class Beecrypt {
  private opts: Required<BeecryptOptions>;

  constructor(opts: BeecryptOptions = {}) {
    this.opts = { ...DEFAULTS, ...opts };
  }

  configure(opts: BeecryptOptions): void {
    Object.assign(this.opts, opts);
  }

  async hash(password: string): Promise<string> {
    const { digest, keyBytes, iterations, saltBytes } = this.opts;
    const salt = randomBytes(saltBytes);
    const derived = await pbkdf2Derive(password, salt, iterations, digest, keyBytes);
    return encodeFormat(digest, keyBytes, iterations, base64urlEncode(salt), base64urlEncode(derived));
  }

  async verify(password: string, encoded: string): Promise<boolean> {
    const parsed = tryParse(encoded);
    if (!parsed) return false;
    const salt = base64urlDecode(parsed.salt);
    const expected = base64urlDecode(parsed.hash);
    const derived = await pbkdf2Derive(password, salt, parsed.iterations, parsed.digest, parsed.keyBytes);
    return constantTimeEqual(derived, expected);
  }

  needsRehash(encoded: string): boolean {
    const parsed = tryParse(encoded);
    if (!parsed) return true;
    const { digest, keyBytes, iterations } = this.opts;
    return parsed.digest !== digest || parsed.keyBytes < keyBytes || parsed.iterations < iterations;
  }
}

const _default = new Beecrypt();

export const hash: typeof _default.hash = (pw) => _default.hash(pw);
export const verify: typeof _default.verify = (pw, enc) => _default.verify(pw, enc);
export const needsRehash: typeof _default.needsRehash = (enc) => _default.needsRehash(enc);