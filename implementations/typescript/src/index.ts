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
export { verifyLog, VH_LOG, type Parameters, type Specialisation, type VerifiedLog } from "./verify.ts";
export {
  createDid,
  DID_VH,
  DID_VH_METHOD,
  DidVhError,
  didVhSpecialisation,
  checkRef,
  parseDid,
  parseDidUrl,
  resolveDid,
  srcReferences,
  updateDid,
  type CreateDidInput,
  type DidDocumentMetadata,
  type DidResolutionOptions,
  type DidResolutionResult,
  type DidUrl,
  type DidVhErrorCode,
  type ResolverContext,
  type RefKind,
  type UpdateDidInput,
} from "./didvh.ts";
