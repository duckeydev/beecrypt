import { base64urlDecode, base64urlEncode } from "./base64url.ts";
import { constantTimeEqual } from "./constant-time.ts";
import { encodeFormat, tryParse } from "./format.ts";
import { derivePbkdf2, fallbackPbkdf2 } from "./pbkdf2.ts";
import { randomBytes } from "./random.ts";
import { DEFAULTS, type BeecryptOptions } from "./types.ts";

export type { BeecryptOptions, Digest } from "./types.ts";

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
    const derived = await derivePbkdf2(
      password,
      salt,
      iterations,
      digest,
      keyBytes,
    );
    return encodeFormat(
      digest,
      keyBytes,
      iterations,
      base64urlEncode(salt),
      base64urlEncode(derived),
    );
  }

  async verify(password: string, encoded: string): Promise<boolean> {
    const parsed = tryParse(encoded);
    if (!parsed) return false;
    const salt = base64urlDecode(parsed.salt);
    const expected = base64urlDecode(parsed.hash);
    const derived = await derivePbkdf2(
      password,
      salt,
      parsed.iterations,
      parsed.digest,
      parsed.keyBytes,
    );
    return constantTimeEqual(derived, expected);
  }

  needsRehash(encoded: string): boolean {
    const parsed = tryParse(encoded);
    if (!parsed) return true;
    const { digest, keyBytes, iterations } = this.opts;
    return (
      parsed.digest !== digest ||
      parsed.keyBytes < keyBytes ||
      parsed.iterations < iterations
    );
  }
}

const _default = new Beecrypt();

// ── bcrypt-compatible API ──
// These allow beecrypt to be used as a drop-in replacement for the bcrypt npm package.

export async function hash(
  password: string,
  saltOrRounds?: string | number,
): Promise<string> {
  if (saltOrRounds === undefined) return _default.hash(password);
  if (typeof saltOrRounds === "number") return hash(password, genSaltSync(saltOrRounds));

  const parsed = tryParse(saltOrRounds);
  if (!parsed) return _default.hash(password);

  const salt = base64urlDecode(parsed.salt);
  const derived = await derivePbkdf2(
    password,
    salt,
    parsed.iterations,
    parsed.digest,
    parsed.keyBytes,
  );
  return encodeFormat(
    parsed.digest,
    parsed.keyBytes,
    parsed.iterations,
    parsed.salt,
    base64urlEncode(derived),
  );
}

export async function verify(password: string, encoded: string): Promise<boolean> {
  return _default.verify(password, encoded);
}

export function needsRehash(encoded: string): boolean {
  return _default.needsRehash(encoded);
}

export function genSaltSync(rounds: number = 10): string {
  const salt = randomBytes(16);
  return encodeFormat(DEFAULTS.digest, DEFAULTS.keyBytes, rounds, base64urlEncode(salt), "");
}

export async function genSalt(rounds: number = 10): Promise<string> {
  return genSaltSync(rounds);
}

export function hashSync(password: string, saltOrRounds?: string | number): string {
  if (saltOrRounds === undefined) {
    const { digest, keyBytes, iterations, saltBytes } = DEFAULTS;
    const salt = randomBytes(saltBytes);
    const derived = fallbackPbkdf2(password, salt, iterations, digest, keyBytes);
    return encodeFormat(digest, keyBytes, iterations, base64urlEncode(salt), base64urlEncode(derived));
  }
  if (typeof saltOrRounds === "number") return hashSync(password, genSaltSync(saltOrRounds));

  const parsed = tryParse(saltOrRounds);
  if (!parsed) return hashSync(password);

  const salt = base64urlDecode(parsed.salt);
  const derived = fallbackPbkdf2(
    password,
    salt,
    parsed.iterations,
    parsed.digest,
    parsed.keyBytes,
  );
  return encodeFormat(
    parsed.digest,
    parsed.keyBytes,
    parsed.iterations,
    parsed.salt,
    base64urlEncode(derived),
  );
}

export async function compare(password: string, encrypted: string): Promise<boolean> {
  return _default.verify(password, encrypted);
}

export function compareSync(password: string, encrypted: string): boolean {
  const parsed = tryParse(encrypted);
  if (!parsed) return false;
  const salt = base64urlDecode(parsed.salt);
  const expected = base64urlDecode(parsed.hash);
  const derived = fallbackPbkdf2(
    password,
    salt,
    parsed.iterations,
    parsed.digest,
    parsed.keyBytes,
  );
  return constantTimeEqual(derived, expected);
}

export function getRounds(encrypted: string): number {
  const parsed = tryParse(encrypted);
  if (!parsed) throw new Error("Invalid beecrypt hash");
  return parsed.iterations;
}

export function getSalt(encrypted: string): string {
  const parsed = tryParse(encrypted);
  if (!parsed) throw new Error("Invalid beecrypt hash");
  return encodeFormat(parsed.digest, parsed.keyBytes, parsed.iterations, parsed.salt, "");
}
