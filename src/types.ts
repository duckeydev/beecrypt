export type Digest = "SHA-256" | "SHA-384" | "SHA-512";

export interface BeecryptOptions {
  iterations?: number;
  saltBytes?: number;
  keyBytes?: number;
  digest?: Digest;
}

export const DEFAULTS = {
  iterations: 210_000,
  saltBytes: 32,
  keyBytes: 64,
  digest: "SHA-512" as Digest,
};
