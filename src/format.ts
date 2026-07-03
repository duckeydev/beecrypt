import type { Digest } from "./types.ts";

export interface Parsed {
  digest: Digest;
  keyBytes: number;
  iterations: number;
  salt: string;
  hash: string;
}

export function encodeFormat(
  digest: Digest,
  keyBytes: number,
  iterations: number,
  salt: string,
  hash: string,
): string {
  return `$beecrypt$${digest}$k=${keyBytes}&i=${iterations}$${salt}$${hash}`;
}

export function tryParse(encoded: string): Parsed | null {
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
