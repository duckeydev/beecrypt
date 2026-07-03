import { Beecrypt } from './src/index'; // Adjust import path as needed

async function runBenchmark() {
  const hasher = new Beecrypt({ iterations: 210_000 });
  const password = "my-super-secure-password";

  console.log("--- Starting Performance Benchmark ---");
  console.log(`Settings: ${hasher['opts'].iterations} iterations, ${hasher['opts'].digest}`);

  // Measure Hashing
  const startHash = performance.now();
  const hash = await hasher.hash(password);
  const endHash = performance.now();
  
  console.log(`\nHash generated in: ${(endHash - startHash).toFixed(2)}ms`);
  console.log(`Result: ${hash.substring(0, 40)}...`);

  // Measure Verification
  const startVerify = performance.now();
  const isValid = await hasher.verify(password, hash);
  const endVerify = performance.now();

  console.log(`Verify time: ${(endVerify - startVerify).toFixed(2)}ms`);
  console.log(`Verification status: ${isValid ? "SUCCESS" : "FAILED"}`);

  // Measure NeedsRehash
  const needsRehash = hasher.needsRehash(hash);
  console.log(`Needs rehash: ${needsRehash}`);
}

runBenchmark().catch(console.error);