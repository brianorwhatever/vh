package vhlog

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var base58Index = func() (t [256]int8) {
	for i := range t {
		t[i] = -1
	}
	for i := 0; i < len(base58Alphabet); i++ {
		t[base58Alphabet[i]] = int8(i)
	}
	return t
}()

// ed25519PubPrefix is the multicodec prefix for an Ed25519 public key (0xed, varint-encoded).
var ed25519PubPrefix = [2]byte{0xed, 0x01}

// Base58btcEncode encodes bytes with the Bitcoin base58 alphabet, without a
// multibase prefix.
func Base58btcEncode(data []byte) string {
	zeros := 0
	for zeros < len(data) && data[zeros] == 0 {
		zeros++
	}
	var digits []byte // little-endian base-58 digits
	for _, b := range data[zeros:] {
		carry := int(b)
		for j := range digits {
			carry += int(digits[j]) << 8
			digits[j] = byte(carry % 58)
			carry /= 58
		}
		for carry > 0 {
			digits = append(digits, byte(carry%58))
			carry /= 58
		}
	}
	var sb strings.Builder
	sb.Grow(zeros + len(digits))
	for i := 0; i < zeros; i++ {
		sb.WriteByte('1')
	}
	for i := len(digits) - 1; i >= 0; i-- {
		sb.WriteByte(base58Alphabet[digits[i]])
	}
	return sb.String()
}

// Base58btcDecode decodes a base58btc string (no multibase prefix). It
// reports false if s contains a character outside the alphabet.
func Base58btcDecode(s string) ([]byte, bool) {
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}
	var bytes []byte // little-endian
	for i := zeros; i < len(s); i++ {
		v := base58Index[s[i]]
		if v < 0 {
			return nil, false
		}
		carry := int(v)
		for j := range bytes {
			carry += int(bytes[j]) * 58
			bytes[j] = byte(carry)
			carry >>= 8
		}
		for carry > 0 {
			bytes = append(bytes, byte(carry))
			carry >>= 8
		}
	}
	out := make([]byte, zeros+len(bytes))
	for i, b := range bytes {
		out[len(out)-1-i] = b
	}
	return out, true
}

// MultikeyFromPublicKey returns the Ed25519 multikey "z" + base58btc(0xed 0x01 ‖ key).
func MultikeyFromPublicKey(pub ed25519.PublicKey) string {
	return "z" + Base58btcEncode(append(ed25519PubPrefix[:], pub...))
}

// PublicKeyFromMultikey returns the raw Ed25519 public key in an Ed25519
// multikey, or false if multikey is not one.
func PublicKeyFromMultikey(multikey string) (ed25519.PublicKey, bool) {
	rest, ok := strings.CutPrefix(multikey, "z")
	if !ok {
		return nil, false
	}
	b, ok := Base58btcDecode(rest)
	if !ok || len(b) != 2+ed25519.PublicKeySize || b[0] != ed25519PubPrefix[0] || b[1] != ed25519PubPrefix[1] {
		return nil, false
	}
	return ed25519.PublicKey(b[2:]), true
}

// KeyFromSeedHex returns the Ed25519 private key for a hex-encoded 32-byte
// seed (RFC 8032 §5.1.5), the form test keys take in the interop profile.
func KeyFromSeedHex(seedHex string) (ed25519.PrivateKey, error) {
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex seed: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("Ed25519 seed must be 32 bytes")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Multikey returns the Ed25519 multikey of a private key's public half.
func Multikey(key ed25519.PrivateKey) string {
	return MultikeyFromPublicKey(key.Public().(ed25519.PublicKey))
}

// Multihash code and digest length for SHA-256, the only algorithm vh-log:1.0 permits.
const (
	sha256Code   = 0x12
	sha256Length = 32
)

// HashB58 returns base58btc(multihash(SHA-256(data))): the encoding of SCIDs,
// entry hashes and key hashes. A SHA-256 multihash always starts with "Qm".
func HashB58(data []byte) string {
	sum := sha256.Sum256(data)
	return Base58btcEncode(append([]byte{sha256Code, sha256Length}, sum[:]...))
}

// HashString is HashB58 over the UTF-8 encoding of s.
func HashString(s string) string {
	return HashB58(toUTF8(s))
}

// KeyHash returns the pre-rotation hash of a multikey: the multikey string
// itself is hashed.
func KeyHash(multikey string) string {
	return HashString(multikey)
}

// MultihashCheck classifies a string as a SHA-256 multihash.
type MultihashCheck int

const (
	// MultihashOK means the value is a base58btc SHA-256 multihash.
	MultihashOK MultihashCheck = iota
	// MultihashNotBase58 means the value is empty or not base58btc.
	MultihashNotBase58
	// MultihashUnsupported means the value decodes but is not a SHA-256 multihash.
	MultihashUnsupported
)

// CheckSHA256Multihash classifies a base58btc string as a SHA-256 multihash,
// some other multihash or bytes, or not base58btc at all.
func CheckSHA256Multihash(value string) MultihashCheck {
	b, ok := Base58btcDecode(value)
	if !ok || len(b) == 0 {
		return MultihashNotBase58
	}
	if len(b) != 2+sha256Length || b[0] != sha256Code || b[1] != sha256Length {
		return MultihashUnsupported
	}
	return MultihashOK
}
