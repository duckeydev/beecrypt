import { base64urlDecode, base64urlEncode } from "./base64url.ts";
import { constantTimeEqual } from "./constant-time.ts";
import { encodeFormat, tryParse } from "./format.ts";
import { derivePbkdf2 } from "./pbkdf2.ts";
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
    const derived = await derivePbkdf2(password, salt, iterations, digest, keyBytes);
    return encodeFormat(digest, keyBytes, iterations, base64urlEncode(salt), base64urlEncode(derived));
  }

  async verify(password: string, encoded: string): Promise<boolean> {
    const parsed = tryParse(encoded);
    if (!parsed) return false;
    const salt = base64urlDecode(parsed.salt);
    const expected = base64urlDecode(parsed.hash);
    const derived = await derivePbkdf2(password, salt, parsed.iterations, parsed.digest, parsed.keyBytes);
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
