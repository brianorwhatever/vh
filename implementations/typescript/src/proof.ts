import { base58btcDecode, base58btcEncode, publicKeyFromMultikey } from "./encoding.ts";
import { signerFromSeed, verifySignature } from "./ed25519.ts";
import { sha256 } from "./hash.ts";
import { canonicalize } from "./jcs.ts";

export const CRYPTOSUITE = "eddsa-jcs-2022";

export interface Proof {
  type: string;
  cryptosuite: string;
  verificationMethod: string;
  created?: string;
  proofPurpose: string;
  proofValue: string;
  [key: string]: unknown;
}

export function didKeyVerificationMethod(multikey: string): string {
  return `did:key:${multikey}#${multikey}`;
}

/**
 * Returns the multikey named by a `did:key:<mk>#<mk>` verification method, or
 * null if the value is not in that form.
 */
export function multikeyFromVerificationMethod(vm: unknown): string | null {
  if (typeof vm !== "string") return null;
  const match = /^did:key:([^#]+)#(.+)$/.exec(vm);
  if (!match || match[1] !== match[2] || !publicKeyFromMultikey(match[1])) return null;
  return match[1];
}

function signingInput(document: unknown, proofConfig: Record<string, unknown>): Uint8Array {
  return Uint8Array.from([...sha256(canonicalize(proofConfig)), ...sha256(canonicalize(document))]);
}

export interface ProofOptions {
  verificationMethod?: string;
  created?: string;
  proofPurpose?: string;
  cryptosuite?: string;
}

/** Creates an eddsa-jcs-2022 proof. `cryptosuite`/`proofPurpose` overrides exist only to build invalid test vectors. */
export function createProof(document: unknown, seedHex: string, options: ProofOptions = {}): Proof {
  const signer = signerFromSeed(seedHex);
  const config: Record<string, unknown> = {
    type: "DataIntegrityProof",
    cryptosuite: options.cryptosuite ?? CRYPTOSUITE,
    verificationMethod: options.verificationMethod ?? didKeyVerificationMethod(signer.multikey),
  };
  if (options.created !== undefined) config.created = options.created;
  config.proofPurpose = options.proofPurpose ?? "assertionMethod";
  const signature = signer.sign(signingInput(document, config));
  return { ...config, proofValue: "z" + base58btcEncode(signature) } as Proof;
}

/**
 * Checks a proof's structure and eddsa-jcs-2022 signature over `document`.
 * Does not check whether the key is authorised.
 */
export function verifyProof(document: unknown, proof: unknown): boolean {
  if (typeof proof !== "object" || proof === null || Array.isArray(proof)) return false;
  const p = proof as Record<string, unknown>;
  if (p.type !== "DataIntegrityProof" || p.cryptosuite !== CRYPTOSUITE || p.proofPurpose !== "assertionMethod") {
    return false;
  }
  const multikey = multikeyFromVerificationMethod(p.verificationMethod);
  if (!multikey || typeof p.proofValue !== "string" || !p.proofValue.startsWith("z")) return false;
  const signature = base58btcDecode(p.proofValue.slice(1));
  if (!signature) return false;
  const { proofValue: _, ...config } = p;
  return verifySignature(publicKeyFromMultikey(multikey)!, signingInput(document, config), signature);
}
