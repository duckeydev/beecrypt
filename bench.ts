import { Beecrypt } from "./src/index.ts";

const password = "benchmark-password-123!@#$";
const warmupRuns = 1;
const benchRuns = 3;

function fmt(n: number): string {
  return n.toFixed(1).padStart(7);
}

function fmtNum(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
  if (n >= 1_000) return (n / 1_000).toFixed(0) + "k";
  return String(n);
}

const runtime = (() => {
  // @ts-ignore
  if (typeof Bun !== "undefined") return `Bun ${Bun.version}`;
  // @ts-ignore
  if (typeof Deno !== "undefined") return `Deno ${Deno.version}`;
  // @ts-ignore
  if (typeof process !== "undefined" && process.versions?.node && !process.versions?.ant) return `Node ${process.versions.node}`;
  const ua = typeof navigator !== "undefined" ? navigator.userAgent : "";
  if (ua.includes("Ant")) return ua.includes("/") ? `Ant ${ua.split("/")[1]}` : "Ant";
  // @ts-ignore
  if (typeof process !== "undefined" && process.versions?.node) return `Node ${process.versions.node}`;
  return "unknown";
})();

// Probe: how fast is 100 iterations?
const probe = new Beecrypt({ iterations: 100, digest: "SHA-256", keyBytes: 32 });
const t0 = performance.now();
await probe.hash(password);
const probeMs = performance.now() - t0;
const native = probeMs < 20; // native PBKDF2 does 100 iters in <1ms; pure-JS takes much longer
const speed = probeMs / 100; // ms per iteration

if (!native) {
  console.log(`\n  ⚠  Using pure-JS PBKDF2 fallback (~${(speed * 1000).toFixed(0)} µs/iter)`);
  console.log(`     Reducing iteration counts to avoid long waits.`);
}

const scaleFactor = native ? 1 : Math.min(1, 800 / speed / 210_000);

function scale(n: number): number {
  return Math.max(10, Math.round(n * scaleFactor));
}

function label(prefix: string, iterations: number): string {
  const scaled = scale(iterations);
  const itStr = fmtNum(scaled);
  return scaled === iterations ? `${prefix}  k=${itStr}` : `${prefix}  k=${itStr} (scaled)`;
}

const configs = [
  { label: label("SHA-512  64B key", 210_000), i: scale(210_000), d: "SHA-512" as const, k: 64, s: 32 },
  { label: label("SHA-512  64B key", 100_000), i: scale(100_000), d: "SHA-512" as const, k: 64, s: 32 },
  { label: label("SHA-512  64B key",  10_000), i: scale(10_000),  d: "SHA-512" as const, k: 64, s: 32 },
  { label: label("SHA-256  32B key", 210_000), i: scale(210_000), d: "SHA-256" as const, k: 32, s: 32 },
  { label: label("SHA-256  32B key", 100_000), i: scale(100_000), d: "SHA-256" as const, k: 32, s: 32 },
  { label: label("SHA-256  32B key",  10_000), i: scale(10_000),  d: "SHA-256" as const, k: 32, s: 32 },
  { label: label("SHA-512  16B key", 210_000), i: scale(210_000), d: "SHA-512" as const, k: 16, s: 16 },
  { label: label("SHA-512  16B key", 100_000), i: scale(100_000), d: "SHA-512" as const, k: 16, s: 16 },
  { label: label("SHA-512  16B key",  10_000), i: scale(10_000),  d: "SHA-512" as const, k: 16, s: 16 },
];

console.log(`\n  runtime:  ${runtime}`);
console.log(`  password: ${password.length} chars`);
console.log(`  warmup:   ${warmupRuns} run(s)`);
console.log(`  samples:  ${benchRuns} per config`);
console.log(`  ─────────────────────────────────────`);

const results: { label: string; hashMs: number; verifyMs: number }[] = [];

for (const cfg of configs) {
  const bc = new Beecrypt({ iterations: cfg.i, digest: cfg.d, keyBytes: cfg.k, saltBytes: cfg.s });

  let enc = "";
  for (let w = 0; w < warmupRuns; w++) enc = await bc.hash(password);
  for (let w = 0; w < warmupRuns; w++) await bc.verify(password, enc);

  const hStart = performance.now();
  for (let r = 0; r < benchRuns; r++) enc = await bc.hash(password);
  const hashMs = (performance.now() - hStart) / benchRuns;

  const vStart = performance.now();
  for (let r = 0; r < benchRuns; r++) await bc.verify(password, enc);
  const verifyMs = (performance.now() - vStart) / benchRuns;

  results.push({ label: cfg.label, hashMs, verifyMs });
}

console.log();
for (const r of results) {
  console.log(`  ${fmt(r.hashMs)} ms  hash  |  ${fmt(r.verifyMs)} ms  verify  —  ${r.label}`);
}

// vs Bun.password if available
// @ts-ignore
if (typeof Bun !== "undefined" && Bun.password) {
  console.log(`\n  ──────────  vs Bun.password (argon2id) ──────────`);
  let enc2 = "";
  for (let w = 0; w < warmupRuns; w++) enc2 = await Bun.password.hash(password);
  for (let w = 0; w < warmupRuns; w++) await Bun.password.verify(password, enc2);

  const h2 = performance.now();
  for (let r = 0; r < benchRuns; r++) enc2 = await Bun.password.hash(password);
  const bpHash = (performance.now() - h2) / benchRuns;

  const v2 = performance.now();
  for (let r = 0; r < benchRuns; r++) await Bun.password.verify(password, enc2);
  const bpVerify = (performance.now() - v2) / benchRuns;

  console.log(`  ${fmt(bpHash)} ms  hash  |  ${fmt(bpVerify)} ms  verify  —  Bun.password (argon2id)`);
}

// Print the non-scaled reference
if (!native) {
  console.log(`\n  ── unscaled estimates (SHA-512) ──`);
  const refIters = [210_000, 100_000, 10_000];
  for (const i of refIters) {
    const est = speed * i;
    console.log(`  ~${est.toFixed(1).padStart(8)} ms  per hash  @ ${fmtNum(i)} iterations`);
  }
}

console.log();
