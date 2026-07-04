# beecrypt

**PBKDF2-SHA password hashing, zero dependencies, pure JavaScript — with a bcrypt-compatible API.**

beecrypt is a modern password hashing library that uses **PBKDF2** with the **SHA-2** family (SHA-256, SHA-384, SHA-512). It works everywhere — Bun, Node, Deno, and the browser — with no native bindings, no dependencies, and no build step.

The API mirrors the popular `bcrypt` npm package, making beecrypt a **drop-in replacement** for projects that want to move away from the Blowfish cipher without rewriting authentication code.

## Why beecrypt over bcrypt?

| | bcrypt | beecrypt |
|---|---|---|
| **Algorithm** | Blowfish cipher (obsolete) | PBKDF2 + SHA-2 (NIST standard) |
| **Hash format** | `$2b$...` | `$beecrypt$SHA-512$k=64&i=210000$...` |
| **Dependencies** | `node-gyp`, native C++ build | **Zero** — pure JS, no native code |
| **Platforms** | Node only (needs `node-gyp`) | Bun, Node, Deno, browser |
| **Sync support** | Blocking C++ call | Non-blocking async + true sync fallback |
| **Flexibility** | Fixed 184-bit output, cost only | Configurable digest, key length, salt length, iterations |
| **Auditability** | Complex Blowfish key schedule | Standard PBKDF2 — well-studied, FIPS-approved |

## Features

- **bcrypt-compatible API** — `hash`, `compare`, `hashSync`, `compareSync`, `genSalt`, `genSaltSync`, `getRounds`, `getSalt` — all with the same signatures.
- **Pure JavaScript** — zero dependencies, no `node-gyp`, no native compilation.
- **Universal** — runs in Bun, Node.js, Deno, and modern browsers.
- **Auto-backend** — uses Web Crypto `SubtleCrypto.deriveBits()` when available, falls back to a hand-optimized pure-JS PBKDF2 implementation.
- **Configurable** — choose digest (SHA-256/384/512), key length, salt length, and iteration count.
- **Constant-time verification** — timing-safe comparison prevents side-channel attacks.
- **Self-contained hash format** — every hash encodes its own parameters (digest, key length, iterations, salt), so upgrading settings doesn't break existing hashes.
- **`needsRehash()`** — detect when a hash uses weaker parameters than your current policy.
- **Synchronous API** — `hashSync` / `compareSync` use the pure-JS PBKDF2 backend with no event-loop blocking from native code.

## Install

```
bun add beecrypt
npm install beecrypt
pnpm add beecrypt
yarn add beecrypt
```

## Quick start

```ts
import { hash, compare, genSalt } from "beecrypt";

// Hash a password (bcrypt-compatible style)
const salt = await genSalt(12);
const hashed = await hash("hunter2", salt);
console.log(hashed);
// → $beecrypt$SHA-512$k=64&i=12$pX6c9dQ...$8f3a...

// Verify
const match = await compare("hunter2", hashed); // true
const wrong = await compare("wrong", hashed);    // false
```

### Defaults (convenience style)

```ts
import { hash, compare } from "beecrypt";

// Uses SHA-512, 210000 iterations, 64-byte key, 32-byte salt
const hashed = await hash("mypassword");
const ok = await compare("mypassword", hashed); // true
```

## API

### `hash(password, saltOrRounds?)`

- **password** `string` — the password to hash.
- **saltOrRounds** `string | number | undefined` — either a salt string from `genSalt`, a round count (passed to `genSalt` internally), or `undefined` to use default parameters.
- **returns** `Promise<string>` — the encoded hash.

```ts
await hash("pw");               // default params
await hash("pw", 12);           // 12 rounds → genSalt(12) → hash with that salt
await hash("pw", saltString);   // use a specific salt
```

### `compare(password, encrypted)`

- **password** `string`
- **encrypted** `string` — a hash previously produced by `hash`.
- **returns** `Promise<boolean>`

```ts
await compare("mypassword", hashed); // true or false
```

### `hashSync(password, saltOrRounds?)`

Synchronous version of `hash`. Uses the pure-JS PBKDF2 backend; does **not** block on native code.

```ts
const hashed = hashSync("pw");       // default params
const hashed = hashSync("pw", 12);   // 12 rounds
const hashed = hashSync("pw", salt); // explicit salt
```

### `compareSync(password, encrypted)`

Synchronous version of `compare`.

```ts
const ok = compareSync("pw", hashed);
```

### `genSalt(rounds?)`

- **rounds** `number` (default `10`) — iteration count stored in the salt string.
- **returns** `Promise<string>` — a salt string that can be passed to `hash`.

```ts
const salt = await genSalt(12);
// → $beecrypt$SHA-512$k=64&i=12$base64salt$
```

### `genSaltSync(rounds?)`

Synchronous version of `genSalt`.

```ts
const salt = genSaltSync(12);
```

### `getRounds(encrypted)`

Returns the iteration count stored in a hash.

```ts
getRounds(hashed); // → 210000
```

### `getSalt(encrypted)`

Returns the salt prefix of a hash (usable with `hash`).

```ts
const salt = getSalt(hashed);
const rehashed = await hash("pw", salt);
```

### `verify(password, encoded)`

Alias for `compare`. Exists for backward compatibility with the original beecrypt API.

```ts
await verify("pw", hashed);
```

### `needsRehash(encoded)`

Returns `true` if the hash uses weaker parameters than the current default settings.

```ts
needsRehash(hashed);
```

### `Beecrypt` class

For multiple configurations or instance-specific control.

```ts
import { Beecrypt } from "beecrypt";

const bc = new Beecrypt({
  digest: "SHA-256",
  iterations: 100_000,
  keyBytes: 32,
  saltBytes: 16,
});

const hashed = await bc.hash("pw");
const ok = await bc.verify("pw", hashed);
bc.needsRehash(hashed);   // false (matches instance config)
bc.configure({ iterations: 200_000 });
bc.needsRehash(hashed);   // true  (iterations increased)
```

## Hash format

```
$beecrypt$<digest>$k=<keyBytes>&i=<iterations>$<salt>$<hash>
```

Example:
```
$beecrypt$SHA-512$k=64&i=210000$pX6c9dQ3...$8f3aBc1...
```

| Part | Description |
|---|---|
| `beecrypt` | Format identifier |
| `SHA-512` | Digest algorithm (`SHA-256`, `SHA-384`, or `SHA-512`) |
| `k=64` | Derived key length in bytes |
| `i=210000` | PBKDF2 iteration count |
| `salt` | Base64url-encoded random salt |
| `hash` | Base64url-encoded derived key |

All parameters are embedded in the hash string, so **changing settings never breaks verification of existing hashes**.

## Configuration

### Default parameters

| Option | Default | Description |
|---|---|---|
| `iterations` | `210_000` | PBKDF2 iteration count |
| `saltBytes` | `32` | Random salt length (bytes) |
| `keyBytes` | `64` | Derived key length (bytes) |
| `digest` | `"SHA-512"` | Hash function |

### Choosing an iteration count

For PBKDF2-SHA-512, a good starting point in 2026 is **200,000–300,000 iterations** (the default of 210,000 targets ~1 second hash time on modern hardware). Adjust based on your performance requirements:

```ts
// Faster hashing, less security margin
const bc = new Beecrypt({ iterations: 100_000 });

// Slower hashing, more security margin
const bc = new Beecrypt({ iterations: 600_000 });
```

Use `needsRehash()` to enforce a minimum iteration count as hardware improves over time.

### Choosing a digest

- **SHA-512** (default) — best security margin. 64-byte internal state, 64-byte output.
- **SHA-384** — reduced output (48 bytes), useful when truncating to fit legacy fields.
- **SHA-256** — 32-byte output, matching e.g. HMAC-SHA-256 expectations.

SHA-512 is recommended for all new applications. It has a larger internal state than SHA-256, making it more resistant to length-extension and multi-target attacks.

### Using the class

```ts
const bc = new Beecrypt({
  digest: "SHA-512",
  iterations: 210_000,
  keyBytes: 64,
  saltBytes: 32,
});

await bc.hash("password");
await bc.verify("password", hash);
bc.needsRehash(hash);
bc.configure({ iterations: 300_000 });
```

## Migrating from bcrypt

**Step 1:** replace imports.

```diff
-import { hash, compare } from "bcrypt";
+import { hash, compare } from "beecrypt";
```

**Step 2:** existing bcrypt hashes (`$2b$...`) can be stored alongside beecrypt hashes. beecrypt **does not** verify bcrypt hashes — you'll need to rehash users on next login:

```ts
import { compare } from "bcrypt";
import { hash, compare as beecryptCompare } from "beecrypt";

async function login(password, storedHash) {
  if (storedHash.startsWith("$2b$")) {
    const ok = await compare(password, storedHash);
    if (ok) {
      const newHash = await hash(password);
      // save newHash to DB
    }
    return ok;
  }
  return beecryptCompare(password, storedHash);
}
```

## Platform support

| Runtime | Web Crypto | Pure JS fallback |
|---|---|---|
| **Bun** | Yes | Yes |
| **Node.js 18+** | Yes | Yes |
| **Deno** | Yes | Yes |
| **Browser** | Yes | Yes |

The library auto-detects the best available backend. Web Crypto provides native PBKDF2 (~10–50x faster). The pure-JS fallback is a fully self-contained PBKDF2-HMAC-SHA implementation.

## Benchmarks

```
bun run bnch
```

Runs hash/verify benchmarks across multiple configurations, including direct PBKDF2 derivation with both the Web Crypto and pure-JS backends.

## Development

```
bun test        # run tests
bun run bnch    # run benchmarks
```

## License

AGPL-3.0
