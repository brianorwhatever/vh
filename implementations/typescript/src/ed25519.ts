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

export function verifySignature(publicKey: Uint8Array, data: Uint8Array, signature: Uint8Array): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  try {
    const key = createPublicKey({ key: Buffer.concat([SPKI_PREFIX, publicKey]), format: "der", type: "spki" });
    return nodeVerify(null, data, key, signature);
  } catch {
    return false;
  }
}
