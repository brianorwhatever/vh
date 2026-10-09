import { createHash } from "node:crypto";
import { base58btcDecode, base58btcEncode } from "./encoding.ts";

/** Multihash code and digest length for SHA-256, the only algorithm `vh-log:1.0` permits. */
const SHA256_CODE = 0x12;
const SHA256_LENGTH = 32;

export function sha256(data: Uint8Array | string): Uint8Array {
  return new Uint8Array(createHash("sha256").update(data).digest());
}

/** `base58btc(multihash(data, SHA-256))` — the encoding of SCIDs, entry hashes and key hashes. */
export function hashB58(data: Uint8Array | string): string {
  return base58btcEncode(Uint8Array.from([SHA256_CODE, SHA256_LENGTH, ...sha256(data)]));
}

export type MultihashCheck = "ok" | "not-base58" | "unsupported-algorithm";

/** Classifies a base58btc string as a SHA-256 multihash, some other multihash/bytes, or not base58. */
export function checkSha256Multihash(value: string): MultihashCheck {
  const bytes = base58btcDecode(value);
  if (!bytes || bytes.length === 0) return "not-base58";
  if (bytes.length !== 2 + SHA256_LENGTH || bytes[0] !== SHA256_CODE || bytes[1] !== SHA256_LENGTH) {
    return "unsupported-algorithm";
  }
  return "ok";
}

/** Pre-rotation key hash: the multikey string itself is hashed. */
export function keyHash(multikey: string): string {
  return hashB58(multikey);
}
