with Ada.Characters.Handling;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded;

package body Did_VH is
   use JSON;
   use Ada.Strings.Unbounded;

   Bad : exception;

   Base58 : constant String :=
     "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

   function Lower (T : String) return String
   renames Ada.Characters.Handling.To_Lower;

   function U (T : String) return Unbounded_String
   renames To_Unbounded_String;

   type Name_List is array (Positive range <>) of Unbounded_String;

   -- Index of the first C in T (From ..), or 0.
   function Find (T : String; C : Character; From : Integer) return Natural is
   begin
      for I in From .. T'Last loop
         if T (I) = C then
            return I;
         end if;
      end loop;
      return 0;
   end Find;

   function Is_Digits (T : String) return Boolean is
   begin
      for C of T loop
         if C not in '0' .. '9' then
            return False;
         end if;
      end loop;
      return True;
   end Is_Digits;

   -- ------------------------------------------------------------ DIDs

   function DID_SCID (Text : String) return String is
      T : constant String (1 .. Text'Length) := Text;
   begin
      if T'Length /= 53 or else T (1 .. 7) /= "did:vh:" then
         return "";
      end if;
      for C of T (8 .. 53) loop
         if Ada.Strings.Fixed.Index (Base58, String'(1 => C)) = 0 then
            return "";
         end if;
      end loop;
      return T (8 .. 53);
   end DID_SCID;

   -- did:vh:<major>.<minor>, each a non-negative integer without leading zeros.
   function Method_Syntax (Value : String) return Boolean is
      T   : constant String (1 .. Value'Length) := Value;
      Dot : Natural;
      function Number (X : String) return Boolean
      is (X'Length > 0
          and then Is_Digits (X)
          and then (X'Length = 1 or else X (X'First) /= '0'));
   begin
      if T'Length < 8 or else T (1 .. 7) /= "did:vh:" then
         return False;
      end if;
      Dot := Find (T, '.', 8);
      return
        Dot > 0
        and then Number (T (8 .. Dot - 1))
        and then Number (T (Dot + 1 .. T'Last));
   end Method_Syntax;

   function Specialisation (SCID : String) return VH_Log.Specialisation is
      Names : constant Value_Access := Arr;
   begin
      for N of
        Name_List'(U ("method"), U ("scid"), U ("updateKeys"), U ("nextKeyHashes"),
         U ("witness"), U ("watchers"), U ("deactivated"), U ("ttl"))
      loop
         Add (Names, Str (To_String (N)));
      end loop;
      return
        (Version_Param   => U ("method"),
         Accepted        => U ("did:vh:1.0"),
         Version_Syntax  => Method_Syntax'Access,
         Closed          => Names,
         Check_State     => True,
         State_Id_Prefix => U ("did:vh:"),
         Expected_SCID   => U (SCID));
   end Specialisation;

   -- ------------------------------------------------------------ text helpers

   function Printable (T : String) return Boolean is
   begin
      if T'Length = 0 then
         return False;
      end if;
      for C of T loop
         if Character'Pos (C) not in 33 .. 126 then
            return False;
         end if;
      end loop;
      return True;
   end Printable;

   function Valid_UTF8 (T : String) return Boolean is
      I     : Integer := T'First;
      B, N  : Natural;
      Point : Natural;
   begin
      while I <= T'Last loop
         B := Character'Pos (T (I));
         if B < 16#80# then
            N := 0;
            Point := B;
         elsif B in 16#C2# .. 16#DF# then
            N := 1;
            Point := B - 16#C0#;
         elsif B in 16#E0# .. 16#EF# then
            N := 2;
            Point := B - 16#E0#;
         elsif B in 16#F0# .. 16#F4# then
            N := 3;
            Point := B - 16#F0#;
         else
            return False;
         end if;
         if I + N > T'Last then
            return False;
         end if;
         for K in 1 .. N loop
            B := Character'Pos (T (I + K));
            if B not in 16#80# .. 16#BF# then
               return False;
            end if;
            Point := Point * 64 + (B - 16#80#);
         end loop;
         if (N = 2
             and then (Point < 16#800# or else Point in 16#D800# .. 16#DFFF#))
           or else (N = 3
                    and then (Point < 16#1_0000# or else Point > 16#10_FFFF#))
         then
            return False;
         end if;
         I := I + N + 1;
      end loop;
      return True;
   end Valid_UTF8;

   -- The code point starting at T (I), in valid UTF-8.
   function Code_Point (T : String; I : Integer) return Natural is
      B     : constant Natural := Character'Pos (T (I));
      N     : Natural;
      Point : Natural;
   begin
      if B < 16#80# then
         return B;
      elsif B < 16#E0# then
         N := 1;
         Point := B - 16#C0#;
      elsif B < 16#F0# then
         N := 2;
         Point := B - 16#E0#;
      else
         N := 3;
         Point := B - 16#F0#;
      end if;
      for K in 1 .. N loop
         Point := Point * 64 + (Character'Pos (T (I + K)) - 16#80#);
      end loop;
      return Point;
   end Code_Point;

   function Last_Code_Point (T : String) return Natural is
      J : Integer := T'Last;
   begin
      while J > T'First and then Character'Pos (T (J)) in 16#80# .. 16#BF# loop
         J := J - 1;
      end loop;
      return Code_Point (T, J);
   end Last_Code_Point;

   function White_Space (Point : Natural) return Boolean
   is (Point in 16#09# .. 16#0D# | 16#20# | 16#85# | 16#A0# | 16#1680#
              | 16#2000# .. 16#200A# | 16#2028# | 16#2029# | 16#202F#
              | 16#205F# | 16#3000#);

   function Hex (C : Character) return Natural is
   begin
      case C is
         when '0' .. '9' =>
            return Character'Pos (C) - 48;

         when 'a' .. 'f' =>
            return Character'Pos (C) - 87;

         when 'A' .. 'F' =>
            return Character'Pos (C) - 55;

         when others =>
            raise Bad;
      end case;
   end Hex;

   -- Percent-decodes once; the result must be UTF-8. Other bytes are kept,
   -- so an unescaped non-ASCII character stays whole.
   function Percent_Decode (T : String) return String is
      R : Unbounded_String;
      I : Integer := T'First;
   begin
      while I <= T'Last loop
         if T (I) = '%' then
            if I + 2 > T'Last then
               raise Bad;
            end if;
            Append (R, Character'Val (Hex (T (I + 1)) * 16 + Hex (T (I + 2))));
            I := I + 3;
         else
            Append (R, T (I));
            I := I + 1;
         end if;
      end loop;
      if not Valid_UTF8 (To_String (R)) then
         raise Bad;
      end if;
      return To_String (R);
   end Percent_Decode;

   -- A path segment of a reference; Strict adds the src rules.
   procedure Segment (Seg : String; Strict : Boolean) is
      D : constant String := Percent_Decode (Seg);
   begin
      if D = "." or else D = ".." then
         raise Bad;
      end if;
      for C of D loop
         if C = '/' or else C = '\' or else C = ASCII.NUL then
            raise Bad;
         end if;
      end loop;
      if Strict
        and then (D'Length = 0
                  or else White_Space (Code_Point (D, D'First))
                  or else White_Space (Last_Code_Point (D)))
      then
         raise Bad;
      end if;
   end Segment;

   -- The segments after the leading '/' of Path.
   procedure Path_Segments (Path : String; Strict : Boolean := False) is
      P : Integer := Path'First + 1;
      K : Natural;
   begin
      loop
         K := Find (Path, '/', P);
         if K = 0 then
            Segment (Path (P .. Path'Last), Strict);
            exit;
         end if;
         Segment (Path (P .. K - 1), Strict);
         P := K + 1;
      end loop;
   end Path_Segments;

   -- The index of the ':' ending a valid scheme.
   function Scheme_End (T : String) return Positive is
      K : constant Natural := Find (T, ':', T'First);
   begin
      if K <= T'First or else T (T'First) not in 'a' .. 'z' | 'A' .. 'Z' then
         raise Bad;
      end if;
      for C of T (T'First + 1 .. K - 1) loop
         if C not in 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '+' | '.' | '-' then
            raise Bad;
         end if;
      end loop;
      return K;
   end Scheme_End;

   -- Splits an authority into a lowercase host, checking any port.
   procedure Host_Port
     (Authority : String; Host : out Unbounded_String; Literal : out Boolean)
   is
      A        : constant String (1 .. Authority'Length) := Authority;
      J        : Natural;
      Port     : Unbounded_String;
      Has_Port : Boolean := False;
   begin
      if Find (A, '@', 1) /= 0 then
         raise Bad;
      end if;
      if A'Length > 0 and then A (1) = '[' then
         J := Find (A, ']', 1);
         if J = 0 then
            raise Bad;
         end if;
         Host := U (A (1 .. J));
         if J < A'Last then
            if A (J + 1) /= ':' then
               raise Bad;
            end if;
            Has_Port := True;
            Port := U (A (J + 2 .. A'Last));
         end if;
      else
         J := Find (A, ':', 1);
         if J = 0 then
            Host := U (A);
         else
            Host := U (A (1 .. J - 1));
            Has_Port := True;
            Port := U (A (J + 1 .. A'Last));
         end if;
      end if;
      if Has_Port
        and then (Length (Port) not in 1 .. 5
                  or else not Is_Digits (To_String (Port))
                  or else Natural'Value (To_String (Port)) > 65535)
      then
         raise Bad;
      end if;
      Literal := Length (Host) > 0 and then Element (Host, 1) = '[';
      Host := U (Lower (To_String (Host)));
   end Host_Port;

   function Domain (Host : String) return Boolean is
      H : constant String :=
        (if Host'Length > 0 and then Host (Host'Last) = '.'
         then Host (Host'First .. Host'Last - 1)
         else Host);
      P : Integer := H'First;
      K : Natural;
   begin
      if H'Length not in 1 .. 253 then
         return False;
      end if;
      loop
         K := Find (H, '.', P);
         declare
            L : constant String := H (P .. (if K = 0 then H'Last else K - 1));
         begin
            if L'Length not in 1 .. 63
              or else L (L'First) = '-'
              or else L (L'Last) = '-'
            then
               return False;
            end if;
            for C of L loop
               if C not in 'a' .. 'z' | '0' .. '9' | '-' then
                  return False;
               end if;
            end loop;
            if K = 0 then
               return not Is_Digits (L);
            end if;
         end;
         P := K + 1;
      end loop;
   end Domain;

   function Loopback (Host : String) return Boolean is
      P     : Integer := Host'First;
      K     : Natural;
      Count : Natural := 0;
   begin
      if Host = "localhost" or else Host = "[::1]" then
         return True;
      end if;
      loop
         K := Find (Host, '.', P);
         declare
            O : constant String := Host (P .. (if K = 0 then Host'Last else K - 1));
         begin
            Count := Count + 1;
            if O'Length not in 1 .. 3
              or else not Is_Digits (O)
              or else (O'Length > 1 and then O (O'First) = '0')
              or else Natural'Value (O) > 255
              or else (Count = 1 and then O /= "127")
            then
               return False;
            end if;
         end;
         exit when K = 0;
         P := K + 1;
      end loop;
      return Count = 4;
   end Loopback;

   -- ------------------------------------------------------------ references

   function Kind_Of (R : String) return String is
      T      : constant String (1 .. R'Length) := R;
      K      : constant Positive := Scheme_End (T);
      Scheme : constant String := Lower (T (1 .. K - 1));
      Rest   : constant String := T (K + 1 .. T'Last);
      Host   : Unbounded_String;
      Lit    : Boolean;
   begin
      if Scheme = "https" or else Scheme = "http" then
         if Rest'Length < 2 or else Rest (Rest'First .. Rest'First + 1) /= "//"
         then
            raise Bad;
         end if;
         declare
            X     : constant String := Rest (Rest'First + 2 .. Rest'Last);
            Slash : constant Natural := Find (X, '/', X'First);
            Query : constant Natural := Find (X, '?', X'First);
            A     : Integer := X'Last + 1;
         begin
            if Slash /= 0 then
               A := Slash;
            end if;
            if Query /= 0 and then Query < A then
               A := Query;
            end if;
            declare
               After : constant String := X (A .. X'Last);
               Q     : constant Natural := Find (After, '?', After'First);
               Path  : constant String :=
                 After (After'First .. (if Q = 0 then After'Last else Q - 1));
            begin
               Host_Port (X (X'First .. A - 1), Host, Lit);
               if Scheme = "https" then
                  if Lit or else not Domain (To_String (Host)) then
                     raise Bad;
                  end if;
               elsif not Loopback (To_String (Host)) then
                  raise Bad;
               end if;
               if Path'Length = 0 then
                  raise Bad;
               end if;
               Path_Segments (Path);
            end;
         end;
         return (if Scheme = "https" then "web" else "loopback");
      elsif Scheme = "file" then
         if Find (Rest, '?', Rest'First) /= 0 then
            raise Bad;
         end if;
         if Rest'Length >= 2 and then Rest (Rest'First .. Rest'First + 1) = "//"
         then
            declare
               X : constant String := Rest (Rest'First + 2 .. Rest'Last);
               J : constant Natural := Find (X, '/', X'First);
            begin
               if J = 0 then
                  raise Bad;
               end if;
               if J > X'First and then Lower (X (X'First .. J - 1)) /= "localhost"
               then
                  raise Bad;
               end if;
               Path_Segments (X (J .. X'Last));
            end;
         else
            if Rest'Length = 0 or else Rest (Rest'First) /= '/' then
               raise Bad;
            end if;
            Path_Segments (Rest);
         end if;
         return "file";
      else
         if Rest'Length = 0 then
            raise Bad;
         end if;
         return "other";
      end if;
   end Kind_Of;

   function Reference_Kind (Reference : Value_Access) return String is
   begin
      if Reference.Tag /= String_Value
        or else not Printable (S (Reference))
        or else Find (S (Reference), '#', 1) /= 0
      then
         return "";
      end if;
      return Kind_Of (S (Reference));
   exception
      when Bad | Constraint_Error =>
         return "";
   end Reference_Kind;

   function Src_Locations (Src : String) return Value_Access is
      T : constant String (1 .. Src'Length) := Src;
   begin
      if not Printable (T) or else Find (T, '?', 1) /= 0 or else Find (T, '#', 1) /= 0
      then
         return null;
      end if;
      declare
         K      : constant Positive := Scheme_End (T);
         Scheme : constant String := Lower (T (1 .. K - 1));
         Full   : constant String := T (K + 1 .. T'Last);
         Rest   : constant String :=
           (if Full'Length > 0 and then Full (Full'Last) = '/'
            then Full (Full'First .. Full'Last - 1)
            else Full);
         Host   : Unbounded_String;
         Lit    : Boolean;
         R      : Value_Access;
      begin
         if Scheme = "http"
           or else Scheme = "file"
           or else Full'Length < 2
           or else Full (Full'First .. Full'First + 1) /= "//"
           or else Rest'Length < 2
         then
            return null;
         end if;
         declare
            X         : constant String := Rest (Rest'First + 2 .. Rest'Last);
            J         : constant Natural := Find (X, '/', X'First);
            Authority : constant String :=
              X (X'First .. (if J = 0 then X'Last else J - 1));
         begin
            if Authority'Length = 0 then
               return null;
            end if;
            if Scheme = "https" then
               Host_Port (Authority, Host, Lit);
               if Lit or else not Domain (To_String (Host)) then
                  return null;
               end if;
               if J /= 0 then
                  Path_Segments (X (J .. X'Last), Strict => True);
               end if;
            end if;
         end;
         R := Obj;
         Put (R, "srcLog", Str (Scheme & ":" & Rest & "/did.jsonl"));
         Put (R, "srcWitness", Str (Scheme & ":" & Rest & "/did-witness.json"));
         return R;
      end;
   exception
      when Bad | Constraint_Error =>
         return null;
   end Src_Locations;

   -- ------------------------------------------------------------ DID URLs

   function Is_Resolution_Option (Name : String) return Boolean
   is (Name = "didLog"
       or else Name = "didWitness"
       or else Name = "srcLog"
       or else Name = "srcWitness"
       or else Name = "checkWatchers"
       or else Name = "extraWatchers"
       or else Name = "minCopies"
       or else Name = "includeDidLog");

   -- Splits on ASCII delimiter bytes, which never occur inside a multi-byte
   -- UTF-8 sequence, so raw non-ASCII characters stay whole.
   function Parse_DID_URL (URL : Value_Access) return Value_Access is
      Seen : constant Value_Access := Obj;
   begin
      if URL.Tag /= String_Value then
         return null;
      end if;
      declare
         Raw     : constant String := S (URL);
         T       : constant String (1 .. Raw'Length) := Raw;
         H       : constant Natural := Find (T, '#', 1);
         Before  : constant String := (if H = 0 then T else T (1 .. H - 1));
         Q       : constant Natural := Find (Before, '?', 1);
         DID     : constant String :=
           (if Q = 0 then Before else Before (1 .. Q - 1));
         Options : constant Value_Access := Obj;
         R       : constant Value_Access := Obj;
         P       : Integer;
         K       : Natural;
         procedure Part (X : String) is
            E : constant Natural := Find (X, '=', X'First);
         begin
            if E = 0 then
               raise Bad;
            end if;
            declare
               Name      : constant String := Percent_Decode (X (X'First .. E - 1));
               Value     : constant String := Percent_Decode (X (E + 1 .. X'Last));
               Locations : Value_Access;
            begin
               if Is_Resolution_Option (Name) then
                  raise Bad;
               end if;
               if Name /= "src"
                 and then Name /= "versionId"
                 and then Name /= "versionTime"
                 and then Name /= "versionNumber"
               then
                  return;
               end if;
               if Has (Seen, Name) then
                  raise Bad;
               end if;
               Put (Seen, Name, Bool (True));
               if Name = "src" then
                  Locations := Src_Locations (Value);
                  if Locations = null then
                     raise Bad;
                  end if;
                  Put (Options, "srcLog", Get (Locations, "srcLog"));
                  Put (Options, "srcWitness", Get (Locations, "srcWitness"));
               elsif Name = "versionNumber" then
                  if Value'Length not in 1 .. 16
                    or else not Is_Digits (Value)
                    or else Value (Value'First) = '0'
                  then
                     raise Bad;
                  end if;
                  Put
                    (Options,
                     "versionNumber",
                     Num (Long_Float (Long_Long_Integer'Value (Value))));
               else
                  Put (Options, Name, Str (Value));
               end if;
            end;
         end Part;
      begin
         if DID_SCID (DID) = "" then
            return null;
         end if;
         if Q /= 0 then
            P := Q + 1;
            loop
               K := Find (Before, '&', P);
               if K = 0 then
                  Part (Before (P .. Before'Last));
                  exit;
               end if;
               Part (Before (P .. K - 1));
               P := K + 1;
            end loop;
         end if;
         Put (R, "did", Str (DID));
         Put (R, "options", Options);
         if H /= 0 then
            Put (R, "fragment", Str (T (H + 1 .. T'Last)));
         end if;
         return R;
      end;
   exception
      when Bad | Constraint_Error =>
         return null;
   end Parse_DID_URL;

   -- ------------------------------------------------------------ generation

   function Controller (Input : Value_Access) return Value_Access is
      R : constant Value_Access := Obj;
   begin
      Put (R, "state", Get (Input, "document"));
      Put
        (R,
         "parameters",
         (if Has (Input, "parameters") then Get (Input, "parameters") else Obj));
      Put (R, "versionTime", Get (Input, "versionTime"));
      Put (R, "signers", Get (Input, "signers"));
      return R;
   end Controller;

   function Create (Input : Value_Access) return Value_Access is
      R : constant Value_Access :=
        VH_Log.Create (Controller (Input), "method", "did:vh:1.0", True);
   begin
      Put (R, "did", Str ("did:vh:" & S (Get (R, "scid"))));
      return R;
   end Create;

   function Update (Input : Value_Access) return Value_Access is
      C : constant Value_Access := Controller (Input);
   begin
      Put (C, "log", Get (Input, "log"));
      return VH_Log.Update (C);
   end Update;

   -- ------------------------------------------------------------ resolution

   function Error_Code (VH_Code : String) return String
   is (if VH_Code = "not-found" then "notFound"
       elsif VH_Code = "invalid-option" then "invalidOptions"
       elsif VH_Code = "unsupported-log-version" then "featureNotSupported"
       elsif VH_Code = "fork-detected" then "logForked"
       elsif VH_Code = "min-copies-not-met" then "insufficientCopies"
       else "invalidDid");

   function Failure
     (Code, Detail : String; VH : Value_Access := null) return Value_Access
   is
      R : constant Value_Access := Obj;
      M : constant Value_Access := Obj;
      P : constant Value_Access := Obj;
   begin
      Put (P, "title", Str (Code));
      Put (P, "detail", Str (Detail));
      if VH /= null then
         Put (P, "vhLog", VH);
      end if;
      Put (M, "error", Str (Code));
      Put (M, "problemDetails", P);
      Put (R, "didResolutionMetadata", M);
      Put (R, "didDocument", Nil);
      Put (R, "didDocumentMetadata", Obj);
      return R;
   end Failure;

   function Integer_At_Least (V : Value_Access; Min : Long_Float) return Boolean
   is (V.Tag = Number_Value
       and then V.Number >= Min
       and then Long_Float'Floor (V.Number) = V.Number);

   -- The lines the VH-Log verifier reads: split on LF, final LF dropped.
   function Log_Lines (Text : String) return Value_Access is
      R : constant Value_Access := Arr;
      P : Integer := Text'First;
      K : Natural;
   begin
      while P <= Text'Last loop
         K := Find (Text, ASCII.LF, P);
         if K = 0 then
            K := Text'Last + 1;
         end if;
         Add (R, Str (Text (P .. K - 1)));
         P := K + 1;
      end loop;
      return R;
   end Log_Lines;

   function Resolve
     (DID, Options, Now : Value_Access; Remote : Boolean := False)
      return Value_Access
   is
      O         : Value_Access renames Options;
      Selectors : Natural := 0;
      function Has (K : String) return Boolean
      is (JSON.Has (O, K));
      function Invalid (Detail : String) return Value_Access
      is (Failure ("invalidOptions", Detail));
      function Unsupported (Detail : String) return Value_Access
      is (Failure ("featureNotSupported", Detail));
   begin
      if DID.Tag /= String_Value or else DID_SCID (S (DID)) = "" then
         return Failure ("invalidDid", "not a did:vh DID");
      end if;
      if O.Tag /= Object_Value then
         return Invalid ("options must be an object");
      end if;
      if Has ("didLog") = Has ("srcLog") then
         return Invalid ("exactly one of didLog and srcLog is required");
      elsif Has ("didWitness") and then Has ("srcWitness") then
         return Invalid ("didWitness and srcWitness are exclusive");
      elsif Has ("didLog") and then Get (O, "didLog").Tag /= String_Value then
         return Invalid ("didLog must be a string");
      elsif Has ("didWitness") and then Get (O, "didWitness").Tag /= Array_Value
      then
         return Invalid ("didWitness must be an array");
      end if;
      for Name of Name_List'(U ("srcLog"), U ("srcWitness")) loop
         if Has (To_String (Name)) then
            declare
               Kind : constant String :=
                 Reference_Kind (Get (O, To_String (Name)));
            begin
               if Kind = "" then
                  return Invalid (To_String (Name) & " is not a valid reference");
               elsif Remote and then (Kind = "file" or else Kind = "loopback")
               then
                  return Invalid (To_String (Name) & " is local");
               end if;
            end;
         end if;
      end loop;
      for Name of Name_List'(U ("versionId"), U ("versionTime"), U ("versionNumber")) loop
         if Has (To_String (Name)) then
            Selectors := Selectors + 1;
         end if;
      end loop;
      if Selectors > 1 then
         return Invalid ("more than one version selector");
      elsif Has ("versionId") and then Get (O, "versionId").Tag /= String_Value
      then
         return Invalid ("versionId");
      elsif Has ("versionTime")
        and then (Get (O, "versionTime").Tag /= String_Value
                  or else not VH_Log.Timestamp_Valid
                                (S (Get (O, "versionTime"))))
      then
         return Invalid ("versionTime");
      elsif Has ("versionNumber")
        and then not Integer_At_Least (Get (O, "versionNumber"), 1.0)
      then
         return Invalid ("versionNumber");
      elsif Has ("checkWatchers")
        and then not Integer_At_Least (Get (O, "checkWatchers"), 0.0)
        and then not (Get (O, "checkWatchers").Tag = String_Value
                      and then S (Get (O, "checkWatchers")) = "all")
      then
         return Invalid ("checkWatchers");
      elsif Has ("minCopies")
        and then not Integer_At_Least (Get (O, "minCopies"), 1.0)
      then
         return Invalid ("minCopies");
      elsif Has ("includeDidLog")
        and then Get (O, "includeDidLog").Tag /= Boolean_Value
      then
         return Invalid ("includeDidLog");
      end if;
      if Has ("extraWatchers") then
         if Get (O, "extraWatchers").Tag /= Array_Value then
            return Invalid ("extraWatchers");
         end if;
         for M of Get (O, "extraWatchers").Children loop
            if M.Item.Tag /= String_Value
              or else Length (M.Item.Text) < 8
              or else Slice (M.Item.Text, 1, 8) /= "https://"
              or else not VH_Log.Watcher_URL_Valid (S (M.Item))
            then
               return Invalid ("extraWatchers");
            end if;
         end loop;
      end if;
      if Has ("srcLog") then
         return Unsupported ("retrieving srcLog is not supported");
      elsif Has ("checkWatchers")
        and then not (Get (O, "checkWatchers").Tag = Number_Value
                      and then Get (O, "checkWatchers").Number = 0.0)
      then
         return Unsupported ("checkWatchers");
      elsif Has ("extraWatchers") and then Len (Get (O, "extraWatchers")) > 0
      then
         return Unsupported ("extraWatchers");
      end if;
      declare
         Log    : constant String := S (Get (O, "didLog"));
         Lines  : constant Value_Access := Log_Lines (Log);
         function Needs_Witnessing return Boolean
         is (VH_Log.Needs_Witnessing
               (Log,
                (if Now.Tag = String_Value then S (Now) else ""),
                Specialisation (DID_SCID (S (DID)))));
         Input  : constant Value_Access := Obj;
         VH_Opt : constant Value_Access := Obj;
         DDM    : constant Value_Access := Obj;
         DRM    : constant Value_Access := Obj;
         R      : constant Value_Access := Obj;
         Result : Value_Access;
         Error  : Value_Access;
         MD     : Value_Access;
         Valid  : Natural;
         Latest : Boolean;
         Text   : Unbounded_String;
      begin
         -- The log needs witnessing if a witness list applies to an entry
         -- that passes the per-entry checks (section 5 step 4).
         if Has ("srcWitness") and then Needs_Witnessing
         then
            return Unsupported ("retrieving srcWitness is not supported");
         end if;
         Put (Input, "log", Str (Log));
         Put (Input, "now", Now);
         if Has ("didWitness") then
            Put (Input, "witness", Get (O, "didWitness"));
         end if;
         for Name of
           Name_List'(U ("versionId"), U ("versionTime"), U ("versionNumber"), U ("minCopies"))
         loop
            if Has (To_String (Name)) then
               Put (VH_Opt, To_String (Name), Get (O, To_String (Name)));
            end if;
         end loop;
         Put (Input, "options", VH_Opt);
         Result := VH_Log.Resolve (Input, Specialisation (DID_SCID (S (DID))));
         Error := Get (Result, "error");
         if not Get (Result, "valid").Flag
           or else (Selectors = 0
                    and then Error.Tag = Object_Value
                    and then S (Get (Error, "code")) = "unsupported-log-version")
         then
            return
              Failure
                (Error_Code (S (Get (Error, "code"))),
                 S (Get (Error, "message")),
                 Error);
         end if;
         MD := Get (Result, "metadata");
         Valid :=
           (if Get (Result, "firstInvalidVersion").Tag = Number_Value
            then Natural (Get (Result, "firstInvalidVersion").Number) - 1
            else Len (Lines));
         Latest := Get (MD, "versionNumber").Number = Long_Float (Valid);
         for Name of
           Name_List'(U ("versionId"), U ("versionTime"), U ("created"), U ("updated"),
            U ("scid"), U ("deactivated"), U ("ttl"))
         loop
            Put (DDM, To_String (Name), Get (MD, To_String (Name)));
         end loop;
         if Get (MD, "witness").Tag /= Null_Value then
            Put (DDM, "witness", Get (MD, "witness"));
         end if;
         Put (DDM, "watchers", Get (MD, "watchers"));
         Put (DRM, "contentType", Str ("application/did+json"));
         if Len (Get (MD, "warnings")) > 0 then
            Put (DRM, "warnings", Get (MD, "warnings"));
         end if;
         if Has ("includeDidLog") and then Get (O, "includeDidLog").Flag then
            for I in 1 .. Valid loop
               Append (Text, S (At_Index (Lines, I)) & ASCII.LF);
            end loop;
            Put (DRM, "didLog", Str (To_String (Text)));
            if Needs_Witnessing then
               Put
                 (DRM,
                  "didWitness",
                  (if Has ("didWitness") then Get (O, "didWitness") else Arr));
            end if;
         end if;
         Put (R, "didResolutionMetadata", DRM);
         Put
           (R,
            "didDocument",
            (if Get (MD, "deactivated").Flag and then Latest
             then Nil
             else Get (Result, "state")));
         Put (R, "didDocumentMetadata", DDM);
         return R;
      end;
   end Resolve;

   -- ------------------------------------------------------------ driver ops

   function Invalid_Result (Code : String) return Value_Access is
      R : constant Value_Access := Obj;
   begin
      Put (R, "valid", Bool (False));
      Put (R, "error", Str (Code));
      return R;
   end Invalid_Result;

   function Dispatch
     (Operation : String; Input : Value_Access) return Value_Access
   is
      R : Value_Access := null;
   begin
      if Operation = "didvh-create" then
         return Create (Input);
      elsif Operation = "didvh-update" then
         return Update (Input);
      elsif Operation = "didvh-resolve" then
         return
           Resolve
             (Get (Input, "did"),
              (if Has (Input, "options") then Get (Input, "options") else Obj),
              Get (Input, "now"),
              Get (Input, "remote").Tag = Boolean_Value
              and then Get (Input, "remote").Flag);
      elsif Operation = "didvh-ref" then
         declare
            Kind : constant String := Reference_Kind (Get (Input, "ref"));
         begin
            if Kind = "" then
               return Invalid_Result ("invalidOptions");
            end if;
            R := Obj;
            Put (R, "valid", Bool (True));
            Put (R, "kind", Str (Kind));
            return R;
         end;
      elsif Operation = "didvh-src" then
         if Get (Input, "src").Tag = String_Value then
            R := Src_Locations (S (Get (Input, "src")));
         end if;
         if R = null then
            return Invalid_Result ("invalidDidUrl");
         end if;
         Put (R, "valid", Bool (True));
         return R;
      elsif Operation = "didvh-did-url" then
         R := Parse_DID_URL (Get (Input, "didUrl"));
         if R = null then
            return Invalid_Result ("invalidDidUrl");
         end if;
         Put (R, "valid", Bool (True));
         return R;
      else
         return VH_Log.Dispatch (Operation, Input);
      end if;
   end Dispatch;
end Did_VH;
