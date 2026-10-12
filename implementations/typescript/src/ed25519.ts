import { createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { hexToBytes, multikeyFromPublicKey } from "./encoding.ts";

// DER prefixes that wrap a raw 32-byte Ed25519 seed / public key for node:crypto.
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export interface Signer {
  multikey: string;
  sign(data: Uint8Array): Uint8Array;
}

export function signerFromSeed(seedHex: string): Signer {
  const seed = hexToBytes(seedHex);
  if (seed.length !== 32) throw new Error("Ed25519 seed must be 32 bytes");
  const privateKey: KeyObject = createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const publicKey = new Uint8Array(spki.subarray(spki.length - 32));
  return {
    multikey: multikeyFromPublicKey(publicKey),
    sign: (data) => new Uint8Array(nodeSign(null, data, privateKey)),
  };
}

// Profile §2. Masking the sign bit covers all eight small-order points.
// Curve membership and the uncofactored equation remain backend checks.
const P = 57896044618658097711785492504343953926634992332820282019728792003956564819949n;
const L = 7237005577332262213973186563042994240857116359379907606001950938285454250989n;
const SMALL_Y = new Set([0n, 1n, 2707385501144840649318225287225658788936804267575313519463743609750303402022n, 55188659117513257062467267217118295137698188065244968500265048394206261417927n, 57896044618658097711785492504343953926634992332820282019728792003956564819948n]);
function littleEndian(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
  return n;
}
function admissiblePoint(bytes: Uint8Array): boolean {
  const y = littleEndian(bytes) & ((1n << 255n) - 1n);
  return y < P && !SMALL_Y.has(y);
}

export function verifySignature(publicKey: Uint8Array, data: Uint8Array, signature: Uint8Array): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  if (!admissiblePoint(publicKey) || !admissiblePoint(signature.subarray(0, 32)) || littleEndian(signature.subarray(32)) >= L) return false;
  try {
    const key = createPublicKey({ key: Buffer.concat([SPKI_PREFIX, publicKey]), format: "der", type: "spki" });
    return nodeVerify(null, data, key, signature);
  } catch {
    return false;
  }
}
