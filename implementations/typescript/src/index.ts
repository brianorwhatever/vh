export { base58btcDecode, base58btcEncode, multikeyFromPublicKey, publicKeyFromMultikey } from "./encoding.ts";
export { signerFromSeed, verifySignature, type Signer } from "./ed25519.ts";
export { VHLogError, type ErrorCode, type ErrorReport } from "./errors.ts";
export { checkSha256Multihash, hashB58, keyHash } from "./hash.ts";
export { canonicalize } from "./jcs.ts";
export {
  computeEntryHash,
  computeScid,
  createLog,
  LOG_VERSION,
  parseLogLines,
  SCID_PLACEHOLDER,
  sealEntry,
  sealGenesis,
  serializeEntry,
  updateLog,
  witnessProof,
  type CreateInput,
  type LogEntry,
  type UpdateInput,
} from "./log.ts";
export { createProof, didKeyVerificationMethod, verifyProof, type Proof } from "./proof.ts";
export { resolve, type ResolveInput, type ResolveResult } from "./resolve.ts";
export { verifyLog, type Parameters, type VerifiedLog } from "./verify.ts";
