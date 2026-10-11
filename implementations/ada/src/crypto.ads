package Crypto is
   subtype Digest_256 is String (1 .. 32);
   subtype Digest_512 is String (1 .. 64);
   subtype Ed25519_Public_Key is String (1 .. 32);
   subtype Ed25519_Signature is String (1 .. 64);
   subtype Hex_Seed is String (1 .. 64)
   with
     Dynamic_Predicate =>
       (for all C of Hex_Seed => C in '0' .. '9' | 'a' .. 'f' | 'A' .. 'F');
   function Base58_Encode (Bytes : String) return String;
   function Base58_Decode (Text : String) return String;
   function SHA256 (Bytes : String) return Digest_256;
   function SHA512 (Bytes : String) return Digest_512;
   function Hash (Text : String) return String;
   function Hex_Decode (Text : String) return String;
   function Multikey (Seed : Hex_Seed) return String;
   function Public_Key (MK : String) return Ed25519_Public_Key;
   function Sign (Message : String; Seed : Hex_Seed) return Ed25519_Signature;
   function Verify (Message, Signature, Public_Key : String) return Boolean;
   function Valid_Hash (Text : String) return Boolean;
   Encoding_Error : exception;
end Crypto;
