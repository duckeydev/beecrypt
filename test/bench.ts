import { Beecrypt } from "../src/index.ts";
import {
  detectPbkdf2Backend,
  fallbackPbkdf2,
  nativePbkdf2,
} from "../src/pbkdf2.ts";
import type { Digest } from "../src/types.ts";

const password = "benchmark-password-123!@#$";
const salt = new Uint8Array(32);
for (let i = 0; i < salt.length; i++) salt[i] = i + 1;

const warmupRuns = 1;
const hashRuns = 3;
const deriveRuns = 5;

interface BunPassword {
  hash(password: string): Promise<string>;
  verify(password: string, encoded: string): Promise<boolean>;
}

interface RuntimeGlobals {
  Bun?: {
    version?: string;
    password?: BunPassword;
  };
  Deno?: {
    version?: string | { deno?: string };
  };
  Ant?: {
    version?: string;
  };
  process?: {
    versions?: { node?: string };
  };
}

const runtimeGlobals = globalThis as unknown as RuntimeGlobals;

interface Config {
  label: string;
  iterations: number;
  digest: Digest;
  keyBytes: number;
  saltBytes: number;
}

const publicConfigs: Config[] = [
  {
    label: "SHA-512  64B key",
    iterations: 210_000,
    digest: "SHA-512",
    keyBytes: 64,
    saltBytes: 32,
  },
  {
    label: "SHA-512  64B key",
    iterations: 100_000,
    digest: "SHA-512",
    keyBytes: 64,
    saltBytes: 32,
  },
  {
    label: "SHA-512  64B key",
    iterations: 10_000,
    digest: "SHA-512",
    keyBytes: 64,
    saltBytes: 32,
  },
  {
    label: "SHA-256  32B key",
    iterations: 210_000,
    digest: "SHA-256",
    keyBytes: 32,
    saltBytes: 32,
  },
  {
    label: "SHA-256  32B key",
    iterations: 100_000,
    digest: "SHA-256",
    keyBytes: 32,
    saltBytes: 32,
  },
  {
    label: "SHA-256  32B key",
    iterations: 10_000,
    digest: "SHA-256",
    keyBytes: 32,
    saltBytes: 32,
  },
  {
    label: "SHA-512  16B key",
    iterations: 210_000,
    digest: "SHA-512",
    keyBytes: 16,
    saltBytes: 16,
  },
  {
    label: "SHA-512  16B key",
    iterations: 100_000,
    digest: "SHA-512",
    keyBytes: 16,
    saltBytes: 16,
  },
  {
    label: "SHA-512  16B key",
    iterations: 10_000,
    digest: "SHA-512",
    keyBytes: 16,
    saltBytes: 16,
  },
];

const deriveConfigs: Config[] = [
  {
    label: "SHA-512  64B key",
    iterations: 10_000,
    digest: "SHA-512",
    keyBytes: 64,
    saltBytes: 32,
  },
  {
    label: "SHA-256  32B key",
    iterations: 10_000,
    digest: "SHA-256",
    keyBytes: 32,
    saltBytes: 32,
  },
];

const pureConfigs: Config[] = [
  {
    label: "SHA-512  64B key",
    iterations: 250,
    digest: "SHA-512",
    keyBytes: 64,
    saltBytes: 32,
  },
  {
    label: "SHA-256  32B key",
    iterations: 250,
    digest: "SHA-256",
    keyBytes: 32,
    saltBytes: 32,
  },
];

function fmtMs(n: number): string {
  return n.toFixed(1).padStart(7);
}

function fmtUs(n: number): string {
  return n.toFixed(1).padStart(7);
}

function fmtNum(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(0)}k`;
  return String(n);
}

function runtimeName(): string {
  const bun = runtimeGlobals.Bun;
  if (bun) return `Bun ${bun.version ?? ""}`.trim();

  const deno = runtimeGlobals.Deno;
  if (deno) {
    const version =
      typeof deno.version === "string" ? deno.version : deno.version?.deno;
    return `Deno ${version ?? ""}`.trim();
  }

  const ant = runtimeGlobals.Ant;
  if (ant) return `Ant ${ant.version ?? ""}`.trim();

  const nodeVersion = runtimeGlobals.process?.versions?.node;
  if (nodeVersion) return `Node ${nodeVersion}`;

  return "unknown";
}

async function meanAsync(
  runs: number,
  fn: () => Promise<void>,
): Promise<number> {
  const start = performance.now();
  for (let i = 0; i < runs; i++) await fn();
  return (performance.now() - start) / runs;
}

function meanSync(runs: number, fn: () => void): number {
  const start = performance.now();
  for (let i = 0; i < runs; i++) fn();
  return (performance.now() - start) / runs;
}

async function benchPublicHashVerify(
  configs: Config[],
  activeBackend: string,
): Promise<void> {
  console.log(`\n  public API hash/verify (${activeBackend})`);
  console.log(`  ─────────────────────────────────────`);

  for (const cfg of configs) {
    const bc = new Beecrypt({
      iterations: cfg.iterations,
      digest: cfg.digest,
      keyBytes: cfg.keyBytes,
      saltBytes: cfg.saltBytes,
    });

    let encoded = "";
    for (let i = 0; i < warmupRuns; i++) encoded = await bc.hash(password);
    for (let i = 0; i < warmupRuns; i++) await bc.verify(password, encoded);

    const hashMs = await meanAsync(hashRuns, async () => {
      encoded = await bc.hash(password);
    });
    const verifyMs = await meanAsync(hashRuns, async () => {
      await bc.verify(password, encoded);
    });

    console.log(
      `  ${fmtMs(hashMs)} ms hash | ${fmtMs(verifyMs)} ms verify — ${cfg.label}  k=${fmtNum(cfg.iterations)}`,
    );
  }
}

async function benchNativeDerive(configs: Config[]): Promise<void> {
  console.log(`\n  direct derive only (WebCrypto PBKDF2)`);
  console.log(`  ─────────────────────────────────────`);

  for (const cfg of configs) {
    await nativePbkdf2(
      password,
      salt.subarray(0, cfg.saltBytes),
      cfg.iterations,
      cfg.digest,
      cfg.keyBytes,
    );
    const ms = await meanAsync(deriveRuns, async () => {
      await nativePbkdf2(
        password,
        salt.subarray(0, cfg.saltBytes),
        cfg.iterations,
        cfg.digest,
        cfg.keyBytes,
      );
    });
    console.log(
      `  ${fmtMs(ms)} ms derive — ${cfg.label}  k=${fmtNum(cfg.iterations)}  (${fmtUs((ms * 1000) / cfg.iterations)} µs/iter)`,
    );
  }
}

function benchPureDerive(configs: Config[]): void {
  console.log(`\n  direct derive only (pure JS fallback)`);
  console.log(`  ─────────────────────────────────────`);

  for (const cfg of configs) {
    fallbackPbkdf2(
      password,
      salt.subarray(0, cfg.saltBytes),
      cfg.iterations,
      cfg.digest,
      cfg.keyBytes,
    );
    const ms = meanSync(deriveRuns, () => {
      fallbackPbkdf2(
        password,
        salt.subarray(0, cfg.saltBytes),
        cfg.iterations,
        cfg.digest,
        cfg.keyBytes,
      );
    });
    const usPerIter = (ms * 1000) / cfg.iterations;
    console.log(
      `  ${fmtMs(ms)} ms derive — ${cfg.label}  k=${fmtNum(cfg.iterations)}  (${fmtUs(usPerIter)} µs/iter, ~${fmtMs((usPerIter * 210_000) / 1000)} ms @210k)`,
    );
  }
}

console.log(`\n  runtime:  ${runtimeName()}`);
console.log(`  password: ${password.length} chars`);
console.log(`  warmup:   ${warmupRuns} run(s)`);
console.log(`  samples:  ${hashRuns} hash/verify, ${deriveRuns} derive`);

const backend = await detectPbkdf2Backend();
console.log(
  `  backend:  ${backend.name}${backend.reason ? ` (${backend.reason})` : ""}`,
);

if (backend.name === "webcrypto") {
  await benchPublicHashVerify(publicConfigs, "WebCrypto PBKDF2");
  await benchNativeDerive(deriveConfigs);
} else {
  const scaled = publicConfigs.map((cfg) => ({
    ...cfg,
    iterations: Math.min(cfg.iterations, 1_000),
  }));
  await benchPublicHashVerify(
    scaled,
    "pure JS fallback, scaled to <=1k iterations",
  );
}

benchPureDerive(pureConfigs);

const bunPassword = runtimeGlobals.Bun?.password;
if (bunPassword) {
  console.log(`\n  Bun.password reference (argon2id)`);
  console.log(`  ─────────────────────────────────────`);
  let encoded = "";
  for (let i = 0; i < warmupRuns; i++)
    encoded = await bunPassword.hash(password);
  for (let i = 0; i < warmupRuns; i++)
    await bunPassword.verify(password, encoded);

  const hashMs = await meanAsync(hashRuns, async () => {
    encoded = await bunPassword.hash(password);
  });
  const verifyMs = await meanAsync(hashRuns, async () => {
    await bunPassword.verify(password, encoded);
  });
  console.log(
    `  ${fmtMs(hashMs)} ms hash | ${fmtMs(verifyMs)} ms verify — Bun.password`,
  );
}

console.log();
