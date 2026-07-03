import { sha256, sha384, sha512 } from "./sha.ts";
import type { Digest } from "./types.ts";

const encoder = new TextEncoder();

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

export interface Pbkdf2Backend {
  name: "webcrypto" | "pure-js";
  reason?: string;
}

function getSubtle(): SubtleCrypto | null {
  try {
    const c = (typeof globalThis !== "undefined" && globalThis.crypto) ||
              (typeof crypto !== "undefined" && crypto);
    return c?.subtle && c.subtle.importKey && c.subtle.deriveBits ? c.subtle : null;
  } catch {
    return null;
  }
}

export async function nativePbkdf2(
  password: string,
  salt: Uint8Array,
  iterations: number,
  digest: Digest,
  keyBytes: number,
): Promise<Uint8Array> {
  const subtle = getSubtle();
  if (!subtle) throw new Error("WebCrypto PBKDF2 is unavailable");

  const key = await subtle.importKey(
    "raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"],
  );
  const bits = await subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: digest },
    key, keyBytes * 8,
  );
  return new Uint8Array(bits);
}

export async function detectPbkdf2Backend(): Promise<Pbkdf2Backend> {
  try {
    await nativePbkdf2("probe", new Uint8Array(8), 1, "SHA-256", 32);
    return { name: "webcrypto" };
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    return { name: "pure-js", reason };
  }
}

export function fallbackPbkdf2(
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

  let key = encoder.encode(password);
  if (key.length > blockSize) key = SHA_FN[digest](key);

  const maxMsg = Math.max(salt.length + 4, hashLen);
  const inner = new Uint8Array(blockSize + maxMsg);
  const outer = new Uint8Array(blockSize + hashLen);

  for (let i = 0; i < blockSize; i++) {
    const k = i < key.length ? key[i] : 0;
    inner[i] = k ^ 0x36;
    outer[i] = k ^ 0x5c;
  }

  for (let b = 1; b <= blocks; b++) {
    const innerLen = blockSize + salt.length + 4;
    inner.set(salt, blockSize);
    inner[blockSize + salt.length]     = (b >>> 24) & 0xff;
    inner[blockSize + salt.length + 1] = (b >>> 16) & 0xff;
    inner[blockSize + salt.length + 2] = (b >>> 8) & 0xff;
    inner[blockSize + salt.length + 3] = b & 0xff;

    let u = SHA_FN[digest](inner.subarray(0, innerLen));
    outer.set(u, blockSize);
    u = SHA_FN[digest](outer.subarray(0, blockSize + hashLen));
    const t = new Uint8Array(u);

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

export async function derivePbkdf2(
  password: string,
  salt: Uint8Array,
  iterations: number,
  digest: Digest,
  keyBytes: number,
): Promise<Uint8Array> {
  try {
    return await nativePbkdf2(password, salt, iterations, digest, keyBytes);
  } catch {
    return fallbackPbkdf2(password, salt, iterations, digest, keyBytes);
  }
}
