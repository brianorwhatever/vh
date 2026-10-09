const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const ALPHABET_MAP = new Map([...ALPHABET].map((c, i) => [c, i]));

/** Ed25519 public key multicodec prefix (0xed, varint-encoded). */
const ED25519_PUB = [0xed, 0x01];

export function base58btcEncode(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits: number[] = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = "1".repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) out += ALPHABET[digits[i]];
  return out;
}

/** Decodes base58btc; returns null if `s` contains a non-alphabet character. */
export function base58btcDecode(s: string): Uint8Array | null {
  let zeros = 0;
  while (zeros < s.length && s[zeros] === "1") zeros++;
  const bytes: number[] = [];
  for (let i = zeros; i < s.length; i++) {
    const value = ALPHABET_MAP.get(s[i]);
    if (value === undefined) return null;
    let carry = value;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  const out = new Uint8Array(zeros + bytes.length);
  for (let i = 0; i < bytes.length; i++) out[out.length - 1 - i] = bytes[i];
  return out;
}

export function multikeyFromPublicKey(publicKey: Uint8Array): string {
  return "z" + base58btcEncode(Uint8Array.from([...ED25519_PUB, ...publicKey]));
}

/** Returns the raw Ed25519 public key, or null if `multikey` is not an Ed25519 multikey. */
export function publicKeyFromMultikey(multikey: string): Uint8Array | null {
  if (typeof multikey !== "string" || !multikey.startsWith("z")) return null;
  const bytes = base58btcDecode(multikey.slice(1));
  if (!bytes || bytes.length !== 34 || bytes[0] !== ED25519_PUB[0] || bytes[1] !== ED25519_PUB[1]) {
    return null;
  }
  return bytes.slice(2);
}

export function hexToBytes(hex: string): Uint8Array {
  if (!/^([0-9a-fA-F]{2})*$/.test(hex)) throw new Error(`invalid hex: ${hex}`);
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

export function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}
