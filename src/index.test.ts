import { describe, it, expect } from "bun:test";
import { createHash, pbkdf2Sync } from "node:crypto";
import { Beecrypt, hash, verify, needsRehash } from "./index.ts";
import { sha256, sha384, sha512 } from "./sha.ts";

function hex(buf: Uint8Array): string {
  return Buffer.from(buf).toString("hex");
}

function decodeBase64url(s: string): Uint8Array {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4;
  if (pad === 2) s += "==";
  else if (pad === 3) s += "=";
  return Uint8Array.from(Buffer.from(s, "base64"));
}

describe("Beecrypt class", () => {
  it("hashes and verifies with defaults", async () => {
    const bc = new Beecrypt();
    const encoded = await bc.hash("hunter2");
    expect(encoded).toMatch(/^\$beecrypt\$SHA-512\$k=64&i=210000\$.+\$.+$/);
    expect(await bc.verify("hunter2", encoded)).toBe(true);
    expect(await bc.verify("wrong", encoded)).toBe(false);
  });

  it("accepts custom iterations", async () => {
    const bc = new Beecrypt({ iterations: 100 });
    const encoded = await bc.hash("pw");
    expect(encoded).toContain("i=100");
    expect(await bc.verify("pw", encoded)).toBe(true);
  });

  it("accepts custom salt length", async () => {
    const bc = new Beecrypt({ saltBytes: 8 });
    const encoded = await bc.hash("pw");
    expect(encoded).toMatch(/^\$beecrypt/);
    expect(await bc.verify("pw", encoded)).toBe(true);
  });

  it("accepts custom key length", async () => {
    const bc = new Beecrypt({ keyBytes: 16 });
    const encoded = await bc.hash("pw");
    expect(encoded).toContain("k=16");
    expect(await bc.verify("pw", encoded)).toBe(true);
  });

  it("works with SHA-256", async () => {
    const bc = new Beecrypt({ digest: "SHA-256", keyBytes: 32, iterations: 100 });
    const encoded = await bc.hash("pw");
    expect(encoded).toContain("SHA-256");
    expect(await bc.verify("pw", encoded)).toBe(true);
  });

  it("works with SHA-384", async () => {
    const bc = new Beecrypt({ digest: "SHA-384", keyBytes: 48, iterations: 100 });
    const encoded = await bc.hash("pw");
    expect(encoded).toContain("SHA-384");
    expect(await bc.verify("pw", encoded)).toBe(true);
  });

  it("configure() updates settings", async () => {
    const bc = new Beecrypt({ iterations: 100 });
    const e1 = await bc.hash("pw");
    bc.configure({ iterations: 200 });
    const e2 = await bc.hash("pw");
    expect(e1).toContain("i=100");
    expect(e2).toContain("i=200");
    expect(await bc.verify("pw", e1)).toBe(true);
    expect(await bc.verify("pw", e2)).toBe(true);
  });

  it("needsRehash detects weaker params", async () => {
    const bc = new Beecrypt({ iterations: 1000, keyBytes: 32 });
    const encoded = await bc.hash("pw");
    expect(bc.needsRehash(encoded)).toBe(false);

    bc.configure({ iterations: 2000 });
    expect(bc.needsRehash(encoded)).toBe(true);

    bc.configure({ iterations: 1000, keyBytes: 64 });
    expect(bc.needsRehash(encoded)).toBe(true);

    bc.configure({ digest: "SHA-256", iterations: 1000, keyBytes: 32 });
    expect(bc.needsRehash(encoded)).toBe(true);
  });

  it("needsRehash returns true for garbage", () => {
    const bc = new Beecrypt();
    expect(bc.needsRehash("garbage")).toBe(true);
    expect(bc.needsRehash("$beecrypt$bad")).toBe(true);
  });

  it("verify returns false for malformed input", async () => {
    const bc = new Beecrypt();
    expect(await bc.verify("x", "nope")).toBe(false);
    expect(await bc.verify("x", "$beecrypt$SHA-512$k=64&i=100$$$")).toBe(false);
  });

  it("multiple instances are independent", async () => {
    const a = new Beecrypt({ iterations: 100 });
    const b = new Beecrypt({ iterations: 200 });
    const ea = await a.hash("pw");
    const eb = await b.hash("pw");
    expect(ea).toContain("i=100");
    expect(eb).toContain("i=200");
    expect(await a.verify("pw", ea)).toBe(true);
    expect(await b.verify("pw", eb)).toBe(true);
    // each can verify the other's hash (params are encoded)
    expect(await a.verify("pw", eb)).toBe(true);
    expect(await b.verify("pw", ea)).toBe(true);
  });
});

describe("pure JS fallback", () => {
  it("SHA primitives match Node crypto", () => {
    const inputs = ["", "abc", "hello world"];
    const cases = [
      ["sha256", sha256],
      ["sha384", sha384],
      ["sha512", sha512],
    ] as const;

    for (const input of inputs) {
      const bytes = new TextEncoder().encode(input);
      for (const [algorithm, fn] of cases) {
        expect(hex(fn(bytes))).toBe(createHash(algorithm).update(input).digest("hex"));
      }
    }
  });

  it("PBKDF2 output matches Node crypto when native APIs are unavailable", async () => {
    const originalCrypto = Object.getOwnPropertyDescriptor(globalThis, "crypto");
    const originalProcess = Object.getOwnPropertyDescriptor(globalThis, "process");
    const salt = Uint8Array.from([1, 35, 69, 103, 137, 171, 205, 239]);

    Object.defineProperty(globalThis, "crypto", {
      configurable: true,
      value: {
        getRandomValues(buf: Uint8Array) {
          buf.set(salt.subarray(0, buf.length));
          return buf;
        },
      },
    });
    Object.defineProperty(globalThis, "process", { configurable: true, value: undefined });

    try {
      const cases = [
        ["SHA-256", "sha256", 32],
        ["SHA-384", "sha384", 48],
        ["SHA-512", "sha512", 64],
      ] as const;

      for (const [digest, nodeDigest, keyBytes] of cases) {
        const bc = new Beecrypt({ digest, keyBytes, iterations: 100, saltBytes: salt.length });
        const encoded = await bc.hash("password");
        const parts = encoded.split("$");
        const derived = decodeBase64url(parts[5]);
        const expected = pbkdf2Sync("password", salt, 100, keyBytes, nodeDigest);

        expect(hex(derived)).toBe(hex(expected));
        expect(await bc.verify("password", encoded)).toBe(true);
      }
    } finally {
      if (originalCrypto) Object.defineProperty(globalThis, "crypto", originalCrypto);
      if (originalProcess) Object.defineProperty(globalThis, "process", originalProcess);
    }
  });
});

describe("convenience exports (default instance)", () => {
  it("hash/verify work", async () => {
    const encoded = await hash("password123");
    expect(await verify("password123", encoded)).toBe(true);
    expect(await verify("wrong", encoded)).toBe(false);
  });

  it("needsRehash works", () => {
    expect(needsRehash("garbage")).toBe(true);
  });
});
