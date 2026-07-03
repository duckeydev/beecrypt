export function randomBytes(n: number): Uint8Array {
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
