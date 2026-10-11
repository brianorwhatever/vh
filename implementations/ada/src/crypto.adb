with Interfaces.C;
with System;
with Ada.Strings.Unbounded;

package body Crypto is
   use Ada.Strings.Unbounded;
   use Interfaces.C;
   function Init return int
   with Import, Convention => C, External_Name => "sodium_init";
   function H256 (O, I : System.Address; N : unsigned_long_long) return int
   with Import, Convention => C, External_Name => "crypto_hash_sha256";
   function H512 (O, I : System.Address; N : unsigned_long_long) return int
   with Import, Convention => C, External_Name => "crypto_hash_sha512";
   function Keypair (P, K, S : System.Address) return int
   with Import, Convention => C, External_Name => "crypto_sign_seed_keypair";
   function Detached
     (S, L, M : System.Address; N : unsigned_long_long; K : System.Address)
      return int
   with Import, Convention => C, External_Name => "crypto_sign_detached";
   function Check
     (S, M : System.Address; N : unsigned_long_long; P : System.Address)
      return int
   with
     Import,
     Convention    => C,
     External_Name => "crypto_sign_verify_detached";
   Alphabet : constant String :=
     "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
   function Base58_Encode (Bytes : String) return String is
      D     : array (1 .. Bytes'Length * 2 + 1) of Natural := (others => 0);
      Used  : Natural := 1;
      Carry : Natural;
      Z     : Natural := 0;
      R     : Unbounded_String;
   begin
      for C of Bytes loop
         Carry := Character'Pos (C);
         for I in 1 .. Used loop
            Carry := Carry + D (I) * 256;
            D (I) := Carry mod 58;
            Carry := Carry / 58;
         end loop;
         while Carry > 0 loop
            Used := Used + 1;
            D (Used) := Carry mod 58;
            Carry := Carry / 58;
         end loop;
      end loop;
      for C of Bytes loop
         exit when C /= ASCII.NUL;
         Z := Z + 1;
      end loop;
      for I in 1 .. Z loop
         Append (R, '1');
      end loop;
      if Z < Bytes'Length then
         for I in reverse 1 .. Used loop
            Append (R, Alphabet (D (I) + 1));
         end loop;
      end if;
      return To_String (R);
   end;
   function Base58_Decode (Text : String) return String is
      D     : array (1 .. Text'Length + 1) of Natural := (others => 0);
      Used  : Natural := 1;
      Carry : Natural;
      Z     : Natural := 0;
      R     : Unbounded_String;
      Found : Boolean;
   begin
      if Text'Length = 0 then
         raise Encoding_Error;
      end if;
      for C of Text loop
         Found := False;
         Carry := 0;
         for I in Alphabet'Range loop
            if C = Alphabet (I) then
               Carry := I - 1;
               Found := True;
               exit;
            end if;
         end loop;
         if not Found then
            raise Encoding_Error;
         end if;
         for I in 1 .. Used loop
            Carry := Carry + D (I) * 58;
            D (I) := Carry mod 256;
            Carry := Carry / 256;
         end loop;
         while Carry > 0 loop
            Used := Used + 1;
            D (Used) := Carry mod 256;
            Carry := Carry / 256;
         end loop;
      end loop;
      for C of Text loop
         exit when C /= '1';
         Z := Z + 1;
      end loop;
      for I in 1 .. Z loop
         Append (R, ASCII.NUL);
      end loop;
      if Z < Text'Length then
         for I in reverse 1 .. Used loop
            Append (R, Character'Val (D (I)));
         end loop;
      end if;
      return To_String (R);
   end;
   function SHA256 (Bytes : String) return Digest_256 is
      R : aliased String (1 .. 32);
      Q : int;
   begin
      Q := H256 (R'Address, Bytes'Address, unsigned_long_long (Bytes'Length));
      if Q /= 0 then
         raise Encoding_Error;
      end if;
      return R;
   end;
   function SHA512 (Bytes : String) return Digest_512 is
      R : aliased String (1 .. 64);
      Q : int;
   begin
      Q := H512 (R'Address, Bytes'Address, unsigned_long_long (Bytes'Length));
      if Q /= 0 then
         raise Encoding_Error;
      end if;
      return R;
   end;
   function Hash (Text : String) return String
   is (Base58_Encode
         (Character'Val (16#12#) & Character'Val (32) & SHA256 (Text)));
   function Hex_Decode (Text : String) return String is
      R : String (1 .. Text'Length / 2);
      function D (C : Character) return Natural is
      begin
         case C is
            when '0' .. '9' =>
               return Character'Pos (C) - 48;

            when 'a' .. 'f' =>
               return Character'Pos (C) - 87;

            when 'A' .. 'F' =>
               return Character'Pos (C) - 55;

            when others     =>
               raise Encoding_Error;
         end case;
      end;
   begin
      if Text'Length mod 2 /= 0 then
         raise Encoding_Error;
      end if;
      for I in R'Range loop
         R (I) :=
           Character'Val
             (D (Text (Text'First + (I - 1) * 2))
              * 16
              + D (Text (Text'First + (I - 1) * 2 + 1)));
      end loop;
      return R;
   end;
   procedure Keys (Seed : String; P, K : out String) is
      B : constant String := Hex_Decode (Seed);
      Q : int;
   begin
      if B'Length /= 32 or else P'Length /= 32 or else K'Length /= 64 then
         raise Encoding_Error;
      end if;
      Q := Keypair (P'Address, K'Address, B'Address);
      if Q /= 0 then
         raise Encoding_Error;
      end if;
   end;
   function Multikey (Seed : Hex_Seed) return String is
      P : String (1 .. 32);
      K : String (1 .. 64);
   begin
      Keys (Seed, P, K);
      return
        "z" & Base58_Encode (Character'Val (16#ED#) & Character'Val (1) & P);
   end;
   function Public_Key (MK : String) return Ed25519_Public_Key is
   begin
      if MK'Length < 2 or else MK (MK'First) /= 'z' then
         raise Encoding_Error;
      end if;
      declare
         B : constant String := Base58_Decode (MK (MK'First + 1 .. MK'Last));
      begin
         if B'Length /= 34
           or else B (1) /= Character'Val (16#ED#)
           or else B (2) /= Character'Val (1)
         then
            raise Encoding_Error;
         end if;
         return B (3 .. 34);
      end;
   end;
   function Sign (Message : String; Seed : Hex_Seed) return Ed25519_Signature
   is
      P : String (1 .. 32);
      K : String (1 .. 64);
      R : String (1 .. 64);
      Q : int;
      L : aliased unsigned_long_long;
   begin
      Keys (Seed, P, K);
      Q :=
        Detached
          (R'Address,
           L'Address,
           Message'Address,
           unsigned_long_long (Message'Length),
           K'Address);
      if Q /= 0 then
         raise Encoding_Error;
      end if;
      return R;
   end;
   function Verify (Message, Signature, Public_Key : String) return Boolean is
   begin
      return
        Signature'Length = 64
        and then Public_Key'Length = 32
        and then Check
                   (Signature'Address,
                    Message'Address,
                    unsigned_long_long (Message'Length),
                    Public_Key'Address)
                 = 0;
   end;
   function Valid_Hash (Text : String) return Boolean is
   begin
      declare
         B : constant String := Base58_Decode (Text);
      begin
         return
           B'Length = 34
           and then B (1) = Character'Val (16#12#)
           and then B (2) = Character'Val (32);
      end;
   exception
      when others =>
         return False;
   end;
   Q        : int;
begin
   Q := Init;
   if Q < 0 then
      raise Encoding_Error;
   end if;
end Crypto;
