with Crypto;
with Ada.Strings.Unbounded;
with Ada.Strings.Fixed;
with Ada.Containers.Vectors;

package body VH_Log is
   use JSON;
   use Ada.Strings.Unbounded;
   function Image (N : Natural) return String
   is (Ada.Strings.Fixed.Trim (Natural'Image (N), Ada.Strings.Both));
   function Replace_All (T, Old, New_Text : String) return String is
      R : Unbounded_String;
      P : Integer := T'First;
      K : Natural;
   begin
      if Old'Length = 0 then
         return T;
      end if;
      while P <= T'Last loop
         K := Ada.Strings.Fixed.Index (T (P .. T'Last), Old);
         if K = 0 then
            Append (R, T (P .. T'Last));
            exit;
         end if;
         Append (R, T (P .. K - 1));
         Append (R, New_Text);
         P := K + Old'Length;
      end loop;
      return To_String (R);
   end;
   function SCID (Log_Entry : Value_Access) return String
   is (Crypto.Hash (Canonical (Log_Entry)));
   function Entry_Hash
     (Log_Entry : Value_Access; Previous_Version_Id : String) return String
   is
      D : Value_Access := Copy (Log_Entry);
   begin
      Remove (D, "proof");
      Put (D, "versionId", Str (Previous_Version_Id));
      return Crypto.Hash (Canonical (D));
   end;
   function Method_Key (P : Value_Access) return String is
      T : constant String := S (Get (P, "verificationMethod"));
      K : Natural;
   begin
      if Get (P, "verificationMethod").Tag /= String_Value
        or else T'Length < 9
        or else T (1 .. 8) /= "did:key:"
      then
         return "";
      end if;
      K := Ada.Strings.Fixed.Index (T, "#");
      if K < 10 or else T (9 .. K - 1) /= T (K + 1 .. T'Last) then
         return "";
      end if;
      return T (9 .. K - 1);
   end;
   function Signing_Input (D, P : Value_Access) return String is
      C        : Value_Access := Copy (P);
      Document : Value_Access := Copy (D);
   begin
      Remove (C, "proofValue");
      Remove (Document, "proof");
      return
        Crypto.SHA256 (Canonical (C)) & Crypto.SHA256 (Canonical (Document));
   end;
   function Sign
     (Document            : Value_Access;
      Seed                : String;
      Verification_Method : String := "";
      Created             : String := "";
      Include_Created     : Boolean := False) return Value_Access
   is
      P  : Value_Access := Obj;
      MK : constant String := Crypto.Multikey (Seed);
   begin
      Put (P, "type", Str ("DataIntegrityProof"));
      Put (P, "cryptosuite", Str ("eddsa-jcs-2022"));
      Put
        (P,
         "verificationMethod",
         Str
           ((if Verification_Method = ""
             then "did:key:" & MK & "#" & MK
             else Verification_Method)));
      if Created /= "" or else Include_Created then
         Put (P, "created", Str (Created));
      end if;
      Put (P, "proofPurpose", Str ("assertionMethod"));
      Put
        (P,
         "proofValue",
         Str
           ("z"
            & Crypto.Base58_Encode
                (Crypto.Sign (Signing_Input (Document, P), Seed))));
      return P;
   end;
   function Verify (Document, Proof : Value_Access) return Boolean is
      MK : constant String := Method_Key (Proof);
      T  : constant String := S (Get (Proof, "proofValue"));
   begin
      if Proof.Tag /= Object_Value
        or else MK = ""
        or else S (Get (Proof, "type")) /= "DataIntegrityProof"
        or else S (Get (Proof, "cryptosuite")) /= "eddsa-jcs-2022"
        or else S (Get (Proof, "proofPurpose")) /= "assertionMethod"
        or else Get (Proof, "proofValue").Tag /= String_Value
        or else T'Length < 2
        or else T (1) /= 'z'
      then
         return False;
      end if;
      return
        Crypto.Verify
          (Signing_Input (Document, Proof),
           Crypto.Base58_Decode (T (2 .. T'Last)),
           Crypto.Public_Key (MK));
   exception
      when others =>
         return False;
   end;
   function Parse_Log (Text : String) return Value_Access is
      R : Value_Access := Arr;
      P : Integer := Text'First;
      K : Natural;
      V : Value_Access;
   begin
      while P <= Text'Last loop
         K :=
           Ada.Strings.Fixed.Index
             (Text (P .. Text'Last), String'(1 => ASCII.LF));
         if K = 0 then
            K := Text'Last + 1;
         end if;
         begin
            V := Parse (Text (P .. K - 1));
            if V.Tag /= Object_Value then
               V := Nil;
            end if;
         exception
            when others =>
               V := Nil;
         end;
         Add (R, V);
         P := K + 1;
      end loop;
      return R;
   end;
   procedure Add_Proofs (E, Input : Value_Access) is
      P : Value_Access := Arr;
   begin
      for M of Get (Input, "signers").Children loop
         Add
           (P,
            Sign
              (E,
               S (M.Item),
               Created         => S (Get (Input, "versionTime")),
               Include_Created => True));
      end loop;
      Put (E, "proof", P);
   end;
   function Create (Input : Value_Access) return Value_Access is
      P : Value_Access :=
        (if Has (Input, "parameters")
         then Copy (Get (Input, "parameters"))
         else Obj);
      E : Value_Access := Obj;
      R : Value_Access := Obj;
      H : Unbounded_String;
   begin
      if not Has (P, "scid") then
         Put (P, "scid", Str ("{SCID}"));
      end if;
      if not Has (P, "logVersion") then
         Put (P, "logVersion", Str ("vh-log:1.0"));
      end if;
      Put (E, "versionId", Str ("{SCID}"));
      Put (E, "versionTime", Get (Input, "versionTime"));
      Put (E, "parameters", P);
      Put (E, "state", Get (Input, "state"));
      H := To_Unbounded_String (SCID (E));
      E := Parse (Replace_All (Canonical (E), "{SCID}", To_String (H)));
      Put (E, "versionId", Str ("1-" & Entry_Hash (E, To_String (H))));
      Add_Proofs (E, Input);
      Put (R, "log", Str (Canonical (E) & ASCII.LF));
      Put (R, "scid", Str (To_String (H)));
      Put (R, "versionId", Get (E, "versionId"));
      return R;
   end;
   function Update (Input : Value_Access) return Value_Access is
      L        : constant String := S (Get (Input, "log"));
      Entries  : Value_Access := Parse_Log (L);
      Previous : Value_Access := At_Index (Entries, Len (Entries));
      T        : constant String := S (Get (Previous, "versionId"));
      K        : Natural := Ada.Strings.Fixed.Index (T, "-");
      N        : Natural := Natural'Value (T (1 .. K - 1)) + 1;
      E        : Value_Access := Obj;
      R        : Value_Access := Obj;
   begin
      Put (E, "versionId", Str (T));
      Put (E, "versionTime", Get (Input, "versionTime"));
      Put
        (E,
         "parameters",
         (if Has (Input, "parameters")
          then Get (Input, "parameters")
          else Obj));
      Put (E, "state", Get (Input, "state"));
      Put (E, "versionId", Str (Image (N) & "-" & Entry_Hash (E, T)));
      Add_Proofs (E, Input);
      Put
        (R,
         "log",
         Str
           (L
            & (if L'Length > 0 and then L (L'Last) = ASCII.LF
               then ""
               else String'(1 => ASCII.LF))
            & Canonical (E)
            & ASCII.LF));
      Put (R, "versionId", Get (E, "versionId"));
      return R;
   end;
   function Witness (Input : Value_Access) return Value_Access is
      D : Value_Access := Obj;
      R : Value_Access := Obj;
   begin
      Put (D, "versionId", Get (Input, "versionId"));
      Put
        (R,
         "proof",
         Sign
           (D,
            S (Get (Input, "seed")),
            Created         => S (Get (Input, "created")),
            Include_Created => Has (Input, "created")));
      return R;
   end;
   function Contains (A : Value_Access; T : String) return Boolean is
   begin
      for M of A.Children loop
         if M.Item.Tag = String_Value and then S (M.Item) = T then
            return True;
         end if;
      end loop;
      return False;
   end;
   function Timestamp (Text : String) return Long_Long_Integer is
      T                    : constant String (1 .. Text'Length) := Text;
      Y, M, D, H, Min, Sec : Integer;
      Days                 : Long_Long_Integer;
      Months               : constant array (1 .. 12) of Integer :=
        (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31);
      Max_D                : Integer;
      function Dig (A, B : Positive) return Integer is
      begin
         for C of T (A .. B) loop
            if C not in '0' .. '9' then
               raise Constraint_Error;
            end if;
         end loop;
         return Integer'Value (T (A .. B));
      end;
   begin
      if T'Length /= 20 and then T'Length /= 25 then
         raise Constraint_Error;
      end if;
      if T (5) /= '-'
        or else T (8) /= '-'
        or else T (11) /= 'T'
        or else T (14) /= ':'
        or else T (17) /= ':'
        or else (T'Length = 20 and then T (20) /= 'Z')
        or else (T'Length = 25 and then T (20 .. 25) /= "+00:00")
      then
         raise Constraint_Error;
      end if;
      Y := Dig (1, 4);
      M := Dig (6, 7);
      D := Dig (9, 10);
      H := Dig (12, 13);
      Min := Dig (15, 16);
      Sec := Dig (18, 19);
      if M not in 1 .. 12 or else H > 23 or else Min > 59 or else Sec > 59 then
         raise Constraint_Error;
      end if;
      Max_D := Months (M);
      if M = 2
        and then Y mod 4 = 0
        and then (Y mod 100 /= 0 or else Y mod 400 = 0)
      then
         Max_D := 29;
      end if;
      if D not in 1 .. Max_D then
         raise Constraint_Error;
      end if;
      Days :=
        365
        * Long_Long_Integer (Y)
        + Long_Long_Integer ((Y + 3) / 4 - (Y + 99) / 100 + (Y + 399) / 400);
      for I in 1 .. M - 1 loop
         Days := Days + Long_Long_Integer (Months (I));
      end loop;
      if M > 2
        and then Y mod 4 = 0
        and then (Y mod 100 /= 0 or else Y mod 400 = 0)
      then
         Days := Days + 1;
      end if;
      Days := Days + Long_Long_Integer (D - 1);
      return Days * 86400 + Long_Long_Integer (H * 3600 + Min * 60 + Sec);
   end;
   function Integer_In
     (V : Value_Access; Low, High : Long_Float) return Boolean is
   begin
      return
        V.Tag = Number_Value
        and then V.Number >= Low
        and then V.Number <= High
        and then Long_Float'Floor (V.Number) = V.Number;
   end;
   function Valid_MK (T : String) return Boolean is
   begin
      declare
         B : constant String := Crypto.Public_Key (T);
      begin
         return B'Length = 32;
      end;
   exception
      when others =>
         return False;
   end;
   function Valid_Watcher (Text : String) return Boolean is
      T : constant String (1 .. Text'Length) := Text;
      P : Natural;
   begin
      for C of T loop
         if Character'Pos (C) not in 33 .. 126 then
            return False;
         end if;
      end loop;
      if T'Length > 8 and then T (1 .. 8) = "https://" then
         P := 9;
      elsif T'Length > 7 and then T (1 .. 7) = "http://" then
         P := 8;
      else
         return False;
      end if;
      return T (P) not in '/' | '?' | '#';
   end;
   function Valid_Witness (W : Value_Access) return Boolean is
      A, T : Value_Access;
   begin
      if W.Tag /= Object_Value then
         return False;
      end if;
      if Len (W) = 0 then
         return True;
      end if;
      A := Get (W, "witnesses");
      T := Get (W, "threshold");
      if A.Tag /= Array_Value
        or else Len (A) = 0
        or else not Integer_In (T, 1.0, Long_Float (Len (A)))
      then
         return False;
      end if;
      for I in 1 .. Len (A) loop
         declare
            E  : Value_Access := At_Index (A, I);
            ID : constant String := S (Get (E, "id"));
         begin
            if E.Tag /= Object_Value
              or else Get (E, "id").Tag /= String_Value
              or else ID'Length < 9
              or else ID (1 .. 8) /= "did:key:"
              or else not Valid_MK (ID (9 .. ID'Last))
            then
               return False;
            end if;
            for J in 1 .. I - 1 loop
               if S (Get (At_Index (A, J), "id")) = ID then
                  return False;
               end if;
            end loop;
         end;
      end loop;
      return True;
   end;
   function Parameter_Error (P : Value_Access; First : Boolean) return String
   is
      V : Value_Access;
   begin
      if First and then not Has (P, "logVersion") then
         return "unsupported-log-version";
      end if;
      for M of P.Children loop
         declare
            K : constant String := To_String (M.Key);
         begin
            V := M.Item;
            if K = "logVersion" then
               if V.Tag /= String_Value then
                  return "invalid-parameter";
               elsif S (V) /= "vh-log:1.0" then
                  return "unsupported-log-version";
               end if;
            elsif K = "scid" then
               if not First or else V.Tag /= String_Value then
                  return "invalid-parameter";
               end if;
            elsif K = "updateKeys" or else K = "nextKeyHashes" then
               if V.Tag /= Array_Value then
                  return "invalid-parameter";
               end if;
               for E of V.Children loop
                  if E.Item.Tag /= String_Value
                    or else (K = "updateKeys"
                             and then not Valid_MK (S (E.Item)))
                    or else (K = "nextKeyHashes"
                             and then not Crypto.Valid_Hash (S (E.Item)))
                  then
                     return "invalid-parameter";
                  end if;
               end loop;
            elsif K = "witness" then
               if not Valid_Witness (V) then
                  return "invalid-parameter";
               end if;
            elsif K = "watchers" then
               if V.Tag /= Array_Value then
                  return "invalid-parameter";
               end if;
               for E of V.Children loop
                  if E.Item.Tag /= String_Value
                    or else not Valid_Watcher (S (E.Item))
                  then
                     return "invalid-parameter";
                  end if;
               end loop;
            elsif K = "deactivated" then
               if V.Tag /= Boolean_Value then
                  return "invalid-parameter";
               end if;
            elsif K = "ttl" then
               if not Integer_In (V, 0.0, 2147483648.0) then
                  return "invalid-parameter";
               end if;
            end if;
         end;
      end loop;
      if First and then (not Has (P, "scid") or else not Has (P, "updateKeys"))
      then
         return "invalid-parameter";
      end if;
      return "";
   end;
   function Error_Object
     (Code : String; Version : Natural := 0) return Value_Access
   is
      R : Value_Access := Obj;
   begin
      Put (R, "code", Str (Code));
      Put
        (R,
         "version",
         (if Version = 0 then Nil else Num (Long_Float (Version))));
      Put (R, "message", Str (Code));
      return R;
   end;
   function Failed (Code : String; Version : Natural := 0) return Value_Access
   is
      R : Value_Access := Obj;
   begin
      Put (R, "valid", Bool (False));
      Put (R, "error", Error_Object (Code, Version));
      return R;
   end;
   type Verified_Log is record
      Entries       : Value_Access := Arr;
      Configs       : Value_Access := Arr;
      Witness_Lists : Value_Access := Arr;
      Valid_Count   : Natural := 0;
      First_Invalid : Natural := 0;
      Error         : Value_Access := Nil;
   end record;
   function Defaults return Value_Access is
      P : Value_Access := Obj;
   begin
      Put (P, "nextKeyHashes", Arr);
      Put (P, "witness", Obj);
      Put (P, "watchers", Arr);
      Put (P, "ttl", Num (3600.0));
      Put (P, "deactivated", Bool (False));
      return P;
   end;
   function Entry_Error
     (E, P     : Value_Access;
      N        : Positive;
      Previous : Value_Access;
      Now      : Long_Long_Integer) return String
   is
      Changes : Value_Access := Get (E, "parameters");
      Keys    : Value_Access;
      C       : Unbounded_String;
      Pre     : Boolean := Len (Get (P, "nextKeyHashes")) > 0;
      V       : Value_Access;
      Tm      : Long_Long_Integer;
      K       : Natural;
   begin
      if Get (P, "deactivated").Flag then
         return "entry-after-deactivation";
      end if;
      if E.Tag /= Object_Value then
         return "invalid-log";
      end if;
      if Len (E) /= 5
        or else Get (E, "versionId").Tag /= String_Value
        or else Get (E, "versionTime").Tag /= String_Value
        or else Changes.Tag /= Object_Value
        or else Get (E, "state").Tag /= Object_Value
        or else Get (E, "proof").Tag /= Array_Value
      then
         return "invalid-entry";
      end if;
      C := To_Unbounded_String (Parameter_Error (Changes, N = 1));
      if Length (C) > 0 then
         return To_String (C);
      end if;
      if N > 1 and then Pre then
         if not Has (Changes, "updateKeys")
           or else not Has (Changes, "nextKeyHashes")
           or else Len (Get (Changes, "updateKeys")) = 0
         then
            return "prerotation-violation";
         end if;
         for M of Get (Changes, "updateKeys").Children loop
            if not Contains
                     (Get (P, "nextKeyHashes"), Crypto.Hash (S (M.Item)))
            then
               return "prerotation-violation";
            end if;
         end loop;
      end if;
      Keys :=
        (if N = 1 or else Pre
         then Get (Changes, "updateKeys")
         else Get (P, "updateKeys"));
      if Len (Get (E, "proof")) = 0 then
         return "invalid-proof";
      end if;
      for M of Get (E, "proof").Children loop
         declare
            MK : constant String := Method_Key (M.Item);
         begin
            if MK = "" then
               return "invalid-proof";
            end if;
            if not Contains (Keys, MK) then
               return "unauthorized-key";
            end if;
            if not Verify (E, M.Item) then
               return "invalid-proof";
            end if;
         end;
      end loop;
      declare
         ID : constant String := S (Get (E, "versionId"));
      begin
         K := Ada.Strings.Fixed.Index (ID, "-");
         if K < 2 or else K = ID'Last then
            return "invalid-version-id";
         end if;
         if ID (1 .. K - 1) /= Image (N)
           or else Ada.Strings.Fixed.Index (ID (K + 1 .. ID'Last), "-") /= 0
         then
            return "invalid-version-id";
         end if;
         begin
            declare
               Decoded : constant String :=
                 Crypto.Base58_Decode (ID (K + 1 .. ID'Last));
            begin
               null;
            end;
         exception
            when Crypto.Encoding_Error =>
               return "invalid-version-id";
         end;
         if not Crypto.Valid_Hash (ID (K + 1 .. ID'Last)) then
            return "invalid-hash-algorithm";
         end if;
         if Entry_Hash
              (E,
               (if N = 1
                then S (Get (Changes, "scid"))
                else S (Get (Previous, "versionId"))))
           /= ID (K + 1 .. ID'Last)
         then
            return "entry-hash-mismatch";
         end if;
      end;
      begin
         Tm := Timestamp (S (Get (E, "versionTime")));
         if N > 1 and then Tm <= Timestamp (S (Get (Previous, "versionTime")))
         then
            return "invalid-version-time";
         end if;
      exception
         when others =>
            return "invalid-version-time";
      end;
      if Tm > Now + 300 then
         return "future-version-time";
      end if;
      if N = 1 then
         declare
            ID : constant String := S (Get (Changes, "scid"));
            D  : Value_Access := Copy (E);
         begin
            if not Crypto.Valid_Hash (ID) then
               return "invalid-hash-algorithm";
            end if;
            Remove (D, "proof");
            Put (D, "versionId", Str ("{SCID}"));
            V := Parse (Replace_All (Canonical (D), ID, "{SCID}"));
            if SCID (V) /= ID then
               return "scid-mismatch";
            end if;
         end;
      end if;
      return "";
   end;
   function Witness_File_Valid (W : Value_Access) return Boolean is
   begin
      if W.Tag /= Array_Value then
         return False;
      end if;
      for M of W.Children loop
         if M.Item.Tag /= Object_Value
           or else Get (M.Item, "versionId").Tag /= String_Value
           or else Get (M.Item, "proof").Tag /= Array_Value
         then
            return False;
         end if;
      end loop;
      return True;
   end;
   function Is_Witnessed
     (Config, W, Entries : Value_Access; N : Positive) return Boolean
   is
      A        : Value_Access := Get (Config, "witnesses");
      Count    : Natural := 0;
      Approved : Boolean;
      D        : Value_Access;
   begin
      for M of A.Children loop
         Approved := False;
         for R of W.Children loop
            declare
               ID    : constant String := S (Get (R.Item, "versionId"));
               Found : Boolean := False;
            begin
               for I in N .. Len (Entries) loop
                  if S (Get (At_Index (Entries, I), "versionId")) = ID then
                     Found := True;
                     exit;
                  end if;
               end loop;
               if Found then
                  D := Obj;
                  Put (D, "versionId", Str (ID));
                  for P of Get (R.Item, "proof").Children loop
                     declare
                        MK : constant String := Method_Key (P.Item);
                     begin
                        if MK /= ""
                          and then "did:key:" & MK = S (Get (M.Item, "id"))
                          and then Verify (D, P.Item)
                        then
                           Approved := True;
                           exit;
                        end if;
                     end;
                  end loop;
               end if;
            end;
            exit when Approved;
         end loop;
         if Approved then
            Count := Count + 1;
         end if;
      end loop;
      return Long_Float (Count) >= Get (Config, "threshold").Number;
   end;
   function Verify_Log
     (Input                 : Value_Access;
      Now                   : Long_Long_Integer;
      Trusted_Entries       : Value_Access := null;
      Trusted_Configs       : Value_Access := null;
      Trusted_Witness_Lists : Value_Access := null) return Verified_Log
   is
      R          : Verified_Log;
      P          : Value_Access := Defaults;
      Prev       : Value_Access := Nil;
      W          : Value_Access := Get (Input, "witness");
      Applicable : Value_Access;
      E, C       : Value_Access;
      Code       : Unbounded_String;
   begin
      R.Entries := Parse_Log (S (Get (Input, "log")));
      if Len (R.Entries) = 0 then
         R.Error := Error_Object ("invalid-log");
         return R;
      end if;
      for N in 1 .. Len (R.Entries) loop
         if Trusted_Entries /= null and then N <= Len (Trusted_Entries) then
            E := At_Index (Trusted_Entries, N);
            R.Entries.Children.Replace_Element (N, (Null_Unbounded_String, E));
            C := At_Index (Trusted_Configs, N);
            Add (R.Configs, C);
            Add (R.Witness_Lists, At_Index (Trusted_Witness_Lists, N));
            P := C;
            Prev := E;
            R.Valid_Count := N;
         else
            E := At_Index (R.Entries, N);
            Code := To_Unbounded_String (Entry_Error (E, P, N, Prev, Now));
            if Length (Code) > 0 then
               R.First_Invalid := N;
               R.Error := Error_Object (To_String (Code), N);
               exit;
            end if;
            C := Copy (P);
            for M of Get (E, "parameters").Children loop
               Put (C, To_String (M.Key), M.Item);
            end loop;
            Applicable :=
              (if Len (Get (P, "witness")) = 0
               then Get (C, "witness")
               else Get (P, "witness"));
            Add (R.Witness_Lists, Applicable);
            Add (R.Configs, C);
            P := C;
            Prev := E;
            R.Valid_Count := N;
         end if;
      end loop;
      -- A failed non-witness pass is returned before witness processing, as pinned by profile vectors.
      if R.First_Invalid = 0 then
         for N in 1 .. R.Valid_Count loop
            Applicable := At_Index (R.Witness_Lists, N);
            if Len (Applicable) > 0
              and then (Trusted_Entries = null
                        or else N > Len (Trusted_Entries))
            then
               if Has (Input, "witness") and then not Witness_File_Valid (W)
               then
                  R.First_Invalid := N;
                  R.Error := Error_Object ("invalid-witness-file", N);
                  exit;
               elsif not Has (Input, "witness")
                 or else not Is_Witnessed (Applicable, W, R.Entries, N)
               then
                  R.First_Invalid := N;
                  R.Error := Error_Object ("witness-threshold-not-met", N);
                  exit;
               end if;
            end if;
         end loop;
         if R.First_Invalid > 0 then
            R.Valid_Count := R.First_Invalid - 1;
         end if;
      end if;
      return R;
   end;
   procedure Warn (W : Value_Access; Code, Source : String := "") is
      O : Value_Access := Obj;
   begin
      Put (O, "code", Str (Code));
      Put (O, "message", Str (Code));
      if Source /= "" then
         Put (O, "source", Str (Source));
      end if;
      Add (W, O);
   end;
   type Copy_Info is record
      Source       : Unbounded_String;
      Input        : Value_Access;
      Verification : Verified_Log;
      Accepted     : Boolean := False;
      Unavailable  : Boolean := False;
   end record;
   package Copy_List is new Ada.Containers.Vectors (Positive, Copy_Info);
   function Last_ID (L : Verified_Log) return String is
   begin
      if Len (L.Entries) = 0 then
         return "";
      end if;
      return S (Get (At_Index (L.Entries, Len (L.Entries)), "versionId"));
   end;
   function Full (L : Verified_Log) return Boolean
   is (L.Valid_Count > 0
       and then L.First_Invalid = 0
       and then L.Error.Tag = Null_Value);
   function Fork_Result
     (N : Positive; Source_A, ID_A, Source_B, ID_B : String)
      return Value_Access
   is
      R : Value_Access := Failed ("fork-detected", N);
      F : Value_Access := Obj;
      A : Value_Access := Arr;
      C : Value_Access;
   begin
      Put (F, "version", Num (Long_Float (N)));
      C := Obj;
      Put (C, "source", Str (Source_A));
      Put (C, "versionId", Str (ID_A));
      Add (A, C);
      C := Obj;
      Put (C, "source", Str (Source_B));
      Put (C, "versionId", Str (ID_B));
      Add (A, C);
      Put (F, "copies", A);
      Put (Get (R, "error"), "fork", F);
      return R;
   end;
   function Resolve (Input : Value_Access) return Value_Access is
      Now                        : Long_Long_Integer;
      Options                    : Value_Access := Get (Input, "options");
      Selectors                  : Natural := 0;
      Minimum                    : Natural := 1;
      Logs                       : Copy_List.Vector;
      Info, Ref_Info             : Copy_Info;
      Reference                  : Positive := 1;
      L                          : Verified_Log;
      Warnings                   : Value_Access := Arr;
      Copy_Status                : Value_Access := Arr;
      Target                     : Natural := 0;
      Count                      : Natural := 0;
      E, P, Last_Config, M, R, C : Value_Access;
      Time                       : Long_Long_Integer;
      Have_Full                  : Boolean := False;
   begin
      if not Has (Input, "options") then
         Options := Obj;
      end if;
      if Options.Tag /= Object_Value then
         return Failed ("invalid-option");
      end if;
      for O of Options.Children loop
         declare
            K : constant String := To_String (O.Key);
         begin
            if K = "versionNumber" then
               Selectors := Selectors + 1;
               if not Integer_In (O.Item, 1.0, 2147483648.0) then
                  return Failed ("invalid-option");
               end if;
            elsif K = "versionId" then
               Selectors := Selectors + 1;
               if O.Item.Tag /= String_Value then
                  return Failed ("invalid-option");
               end if;
            elsif K = "versionTime" then
               Selectors := Selectors + 1;
               if O.Item.Tag /= String_Value then
                  return Failed ("invalid-option");
               end if;
               begin
                  Time := Timestamp (S (O.Item));
               exception
                  when others =>
                     return Failed ("invalid-option");
               end;
            elsif K = "minCopies" then
               if not Integer_In (O.Item, 1.0, 2147483647.0) then
                  return Failed ("invalid-option");
               end if;
               Minimum := Natural (O.Item.Number);
            else
               return Failed ("invalid-option");
            end if;
         end;
      end loop;
      if Selectors > 1 then
         return Failed ("invalid-option");
      end if;
      begin
         Now := Timestamp (S (Get (Input, "now")));
      exception
         when others =>
            return Failed ("invalid-option");
      end;
      Info.Source := To_Unbounded_String ("primary");
      Info.Input := Input;
      Info.Verification := Verify_Log (Input, Now);
      Info.Accepted := Full (Info.Verification);
      Have_Full := Info.Accepted;
      Logs.Append (Info);
      for O of Get (Input, "copies").Children loop
         Info :=
           (Source => To_Unbounded_String (S (Get (O.Item, "source"))),
            Input  => O.Item,
            others => <>);
         Info.Unavailable := Has (O.Item, "unavailable");
         if not Info.Unavailable then
            Info.Verification := Verify_Log (O.Item, Now);
         end if;
         Logs.Append (Info);
      end loop;
      if not Have_Full then
         for I in 2 .. Natural (Logs.Length) loop
            if Full (Logs (I).Verification) then
               Reference := I;
               Info := Logs (I);
               Info.Accepted := True;
               Logs.Replace_Element (I, Info);
               Have_Full := True;
               exit;
            end if;
         end loop;
      end if;
      if Have_Full then
         for I in 1 .. Natural (Logs.Length) loop
            if I /= Reference and then not Logs (I).Unavailable then
               Info := Logs (I);
               Ref_Info := Logs (Reference);
               declare
                  A        : Natural := Len (Info.Verification.Entries);
                  B        : Natural := Len (Ref_Info.Verification.Entries);
                  K        : Natural := Natural'Min (A, B);
                  Matching : Boolean := False;
               begin
                  if K > 0 then
                     Matching :=
                       S
                         (Get
                            (At_Index (Info.Verification.Entries, K),
                             "versionId"))
                       = S
                           (Get
                              (At_Index (Ref_Info.Verification.Entries, K),
                               "versionId"));
                  end if;
                  if Matching and then A > B then
                     Info.Verification :=
                       Verify_Log
                         (Info.Input,
                          Now,
                          Ref_Info.Verification.Entries,
                          Ref_Info.Verification.Configs,
                          Ref_Info.Verification.Witness_Lists);
                  end if;
                  if Matching
                    and then A <= B
                    and then not (I = 1 and then not Full (Info.Verification))
                  then
                     Info.Accepted := True;
                  elsif Full (Info.Verification) then
                     Info.Accepted := True;
                     if Matching then
                        Reference := I;
                     else
                        for N in 1 .. K loop
                           declare
                              IA : constant String :=
                                S
                                  (Get
                                     (At_Index
                                        (Ref_Info.Verification.Entries, N),
                                      "versionId"));
                              IB : constant String :=
                                S
                                  (Get
                                     (At_Index (Info.Verification.Entries, N),
                                      "versionId"));
                           begin
                              if IA /= IB then
                                 return
                                   Fork_Result
                                     (N,
                                      To_String (Ref_Info.Source),
                                      IA,
                                      To_String (Info.Source),
                                      IB);
                              end if;
                           end;
                        end loop;
                     end if;
                  end if;
               end;
               Logs.Replace_Element (I, Info);
            end if;
         end loop;
      end if;
      L := Logs (Reference).Verification;
      if L.Valid_Count = 0 then
         R := Obj;
         Put (R, "valid", Bool (False));
         Put (R, "error", L.Error);
         return R;
      end if;
      if Has (Input, "copies") or else Minimum > 1 then
         for I in 1 .. Natural (Logs.Length) loop
            Info := Logs (I);
            C := Obj;
            Put (C, "source", Str (To_String (Info.Source)));
            if Info.Unavailable then
               Put (C, "status", Str ("unavailable"));
               Warn (Warnings, "copy-unavailable", To_String (Info.Source));
            else
               Put (C, "versionId", Str (Last_ID (Info.Verification)));
               if Info.Accepted then
                  Count := Count + 1;
                  if Len (Info.Verification.Entries) < Len (L.Entries) then
                     Put (C, "status", Str ("behind"));
                     Warn (Warnings, "copy-behind", To_String (Info.Source));
                  else
                     Put (C, "status", Str ("current"));
                  end if;
               else
                  Put (C, "status", Str ("invalid"));
                  Warn (Warnings, "copy-invalid", To_String (Info.Source));
               end if;
            end if;
            Add (Copy_Status, C);
         end loop;
      else
         Count := 1;
      end if;
      if Count < Minimum then
         return Failed ("min-copies-not-met");
      end if;
      if Has (Input, "retainedVersionId") then
         declare
            ID : constant String := S (Get (Input, "retainedVersionId"));
            K  : Natural := Ada.Strings.Fixed.Index (ID, "-");
            N  : Natural := 0;
         begin
            begin
               N := Natural'Value (ID (1 .. K - 1));
            exception
               when others =>
                  return Failed ("invalid-option");
            end;
            if N > L.Valid_Count then
               Warn (Warnings, "retained-version-not-found");
            elsif N > 0
              and then S (Get (At_Index (L.Entries, N), "versionId")) /= ID
            then
               return
                 Fork_Result
                   (N,
                    To_String (Logs (Reference).Source),
                    S (Get (At_Index (L.Entries, N), "versionId")),
                    "retained",
                    ID);
            end if;
         end;
      end if;
      if Selectors = 0 then
         Target := L.Valid_Count;
      elsif Has (Options, "versionNumber") then
         declare
            N : constant Natural :=
              Natural (Get (Options, "versionNumber").Number);
         begin
            if N <= Len (L.Entries) then
               Target := N;
            end if;
         end;
      elsif Has (Options, "versionId") then
         for I in 1 .. Len (L.Entries) loop
            if S (Get (At_Index (L.Entries, I), "versionId"))
              = S (Get (Options, "versionId"))
            then
               Target := I;
               exit;
            end if;
         end loop;
      else
         Time := Timestamp (S (Get (Options, "versionTime")));
         for I in 1 .. Len (L.Entries) loop
            begin
               if Timestamp (S (Get (At_Index (L.Entries, I), "versionTime")))
                 <= Time
               then
                  Target := I;
               end if;
            exception
               when others =>
                  null;
            end;
         end loop;
      end if;
      if Target = 0 then
         return Failed ("not-found");
      elsif Target > L.Valid_Count then
         R := Obj;
         Put (R, "valid", Bool (False));
         Put (R, "error", L.Error);
         return R;
      end if;
      E := At_Index (L.Entries, Target);
      P := At_Index (L.Configs, Target);
      Last_Config := At_Index (L.Configs, L.Valid_Count);
      M := Obj;
      for K of E.Children loop
         if To_String (K.Key) = "versionId"
           or else To_String (K.Key) = "versionTime"
         then
            Put (M, To_String (K.Key), K.Item);
         end if;
      end loop;
      Put (M, "versionNumber", Num (Long_Float (Target)));
      Put (M, "created", Get (At_Index (L.Entries, 1), "versionTime"));
      Put
        (M,
         "updated",
         Get (At_Index (L.Entries, L.Valid_Count), "versionTime"));
      Put (M, "scid", Get (At_Index (L.Configs, 1), "scid"));
      Put (M, "deactivated", Get (Last_Config, "deactivated"));
      Put (M, "ttl", Get (Last_Config, "ttl"));
      Put
        (M,
         "witness",
         (if Len (Get (Last_Config, "witness")) = 0
          then Nil
          else Get (Last_Config, "witness")));
      Put (M, "watchers", Get (Last_Config, "watchers"));
      Put (M, "updateKeys", Get (P, "updateKeys"));
      Put (M, "nextKeyHashes", Get (P, "nextKeyHashes"));
      if Has (Input, "copies") or else Minimum > 1 then
         Put (M, "copies", Copy_Status);
      end if;
      if L.First_Invalid > 0 then
         Warn (Warnings, "invalid-entries");
      end if;
      Put (M, "warnings", Warnings);
      R := Obj;
      Put (R, "valid", Bool (True));
      Put (R, "state", Get (E, "state"));
      Put (R, "metadata", M);
      Put
        (R,
         "firstInvalidVersion",
         (if L.First_Invalid = 0
          then Nil
          else Num (Long_Float (L.First_Invalid))));
      Put (R, "error", L.Error);
      return R;
   end;
   function Controller_Input
     (Request : VH_Types.Controller_Request) return Value_Access
   is
      Input   : Value_Access := Obj;
      Signers : Value_Access := Arr;
   begin
      Put (Input, "state", Request.State);
      Put (Input, "parameters", Request.Parameters);
      Put (Input, "versionTime", Str (To_String (Request.Version_Time)));
      for Seed of Request.Signers loop
         Add (Signers, Str (Seed));
      end loop;
      Put (Input, "signers", Signers);
      return Input;
   end Controller_Input;
   function Generated (Result : Value_Access) return VH_Types.Generated_Log is
   begin
      return
        (Content    => To_Unbounded_String (S (Get (Result, "log"))),
         Version_Id => To_Unbounded_String (S (Get (Result, "versionId"))),
         SCID       => To_Unbounded_String (S (Get (Result, "scid"))));
   end Generated;
   function Create
     (Request : VH_Types.Controller_Request) return VH_Types.Generated_Log is
   begin
      return Generated (Create (Controller_Input (Request)));
   end Create;
   function Update
     (Log : String; Request : VH_Types.Controller_Request)
      return VH_Types.Generated_Log
   is
      Input : Value_Access := Controller_Input (Request);
   begin
      Put (Input, "log", Str (Log));
      return Generated (Update (Input));
   end Update;
   function Resolve
     (Log, Now            : String;
      Options             : VH_Types.Resolution_Options := (others => <>);
      Witness_File        : Value_Access := null;
      Copies              : Value_Access := null;
      Retained_Version_Id : String := "") return VH_Types.Resolution_Result
   is
      use VH_Types;
      Input        : Value_Access := Obj;
      JSON_Options : Value_Access := Obj;
      Result       : Value_Access;
   begin
      Put (Input, "log", Str (Log));
      Put (Input, "now", Str (Now));
      case Options.Selector.Kind is
         when Latest            =>
            null;

         when By_Version_Id     =>
            Put
              (JSON_Options,
               "versionId",
               Str (To_String (Options.Selector.Value)));

         when By_Version_Time   =>
            Put
              (JSON_Options,
               "versionTime",
               Str (To_String (Options.Selector.Value)));

         when By_Version_Number =>
            Put
              (JSON_Options,
               "versionNumber",
               Num (Long_Float (Options.Selector.Number)));
      end case;
      Put (JSON_Options, "minCopies", Num (Long_Float (Options.Min_Copies)));
      Put (Input, "options", JSON_Options);
      if Witness_File /= null then
         Put (Input, "witness", Witness_File);
      end if;
      if Copies /= null then
         Put (Input, "copies", Copies);
      end if;
      if Retained_Version_Id /= "" then
         Put (Input, "retainedVersionId", Str (Retained_Version_Id));
      end if;
      Result := Resolve (Input);
      return
        (Valid                 => Get (Result, "valid").Flag,
         State                 => Get (Result, "state"),
         Metadata              => Get (Result, "metadata"),
         First_Invalid_Version =>
           Natural (Get (Result, "firstInvalidVersion").Number),
         Error                 => Get (Result, "error"));
   end Resolve;
   function Dispatch
     (Operation : String; Input : Value_Access) return Value_Access
   is
      R : Value_Access := Obj;
   begin
      if Operation = "jcs" then
         Put (R, "output", Str (Canonical (Parse (S (Get (Input, "text"))))));
      elsif Operation = "hash" then
         Put (R, "output", Str (Crypto.Hash (S (Get (Input, "data")))));
      elsif Operation = "multikey" then
         Put (R, "multikey", Str (Crypto.Multikey (S (Get (Input, "seed")))));
      elsif Operation = "key-hash" then
         Put (R, "output", Str (Crypto.Hash (S (Get (Input, "multikey")))));
      elsif Operation = "scid" then
         Put (R, "scid", Str (SCID (Get (Input, "entry"))));
      elsif Operation = "entry-hash" then
         Put
           (R,
            "hash",
            Str
              (Entry_Hash
                 (Get (Input, "entry"),
                  S (Get (Input, "previousVersionId")))));
      elsif Operation = "sign" then
         Put
           (R,
            "proof",
            Sign
              (Get (Input, "document"),
               S (Get (Input, "seed")),
               S (Get (Input, "verificationMethod")),
               S (Get (Input, "created")),
               Has (Input, "created")));
      elsif Operation = "verify" then
         Put
           (R,
            "valid",
            Bool (Verify (Get (Input, "document"), Get (Input, "proof"))));
      elsif Operation = "create" then
         return Create (Input);
      elsif Operation = "update" then
         return Update (Input);
      elsif Operation = "witness" then
         return Witness (Input);
      elsif Operation = "resolve" then
         return Resolve (Input);
      else
         raise Constraint_Error with "unknown operation";
      end if;
      return R;
   end;
end VH_Log;
