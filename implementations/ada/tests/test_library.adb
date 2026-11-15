with Ada.Text_IO;
with Ada.Directories;
with Ada.Streams.Stream_IO;
with Did_VH;
with Ada.Strings.Unbounded;
with JSON;
with Crypto;
with VH_Log;
with VH_Types;

procedure Test_Library is
   use JSON;
   use Ada.Strings.Unbounded;
   use VH_Types;
   Scope                                               : JSON.Storage_Scope;
   Checks                                              : Natural := 0;
   Seed                                                :
     constant Crypto.Hex_Seed := (others => '0');
   Next_Seed                                           :
     constant Crypto.Hex_Seed := (others => '1');
   Request                                             : Controller_Request;
   Genesis, Second, Third                              : Generated_Log;
   Result                                              : Resolution_Result;
   Proof, Document, Entries, Input, Copies, Copy_Input : Value_Access;
   procedure Check (Condition : Boolean; Label_Text : String) is
   begin
      if not Condition then
         raise Program_Error with Label_Text;
      end if;
      Checks := Checks + 1;
   end Check;
   procedure Reject_JSON (Text : String) is
      V        : Value_Access;
      Rejected : Boolean := False;
   begin
      begin
         V := Parse (Text);
      exception
         when JSON.Invalid_JSON =>
            Rejected := True;
      end;
      Check (Rejected, "invalid JSON accepted");
   end Reject_JSON;
   function Lines (Log : String) return Value_Access is
      A : Value_Access := Arr;
      P : Positive := 1;
   begin
      for I in Log'Range loop
         if Log (I) = ASCII.LF then
            Add (A, Parse (Log (P .. I - 1)));
            P := I + 1;
         end if;
      end loop;
      return A;
   end Lines;
   function Log_Text (A : Value_Access) return String is
      R : Unbounded_String;
   begin
      for M of A.Children loop
         Append (R, Canonical (M.Item) & ASCII.LF);
      end loop;
      return To_String (R);
   end Log_Text;
begin
   Check
     (Crypto.Hash ("abc") = "QmatYkNGZnELf8cAGdyJpUca2PyY4szai3RHyyWofNY1pY",
      "SHA-256 multihash");
   Check
     (Crypto.SHA512 ("abc")
      = Crypto.Hex_Decode
          ("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2"
           & "192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
      "SHA-512 standard known answer");
   Check
     (Crypto.Base58_Decode
        (Crypto.Base58_Encode (ASCII.NUL & ASCII.NUL & "abc"))
      = ASCII.NUL & ASCII.NUL & "abc",
      "base58 leading zero preservation");
   Check
     (Crypto.Multikey (Seed)
      = "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
      "Ed25519 seed derivation");
   Check
     (Canonical (Parse ("{""a"":0,""a"":1}")) = "{""a"":1}",
      "duplicate last value");
   Check
     (Canonical (Parse ("[123456789012345678,-0,1e-6,1e21]"))
      = "[123456789012345680,0,0.000001,1e+21]",
      "binary64 canonical formatting");
   Check
     (Canonical (Parse ("{""\ufeff"":1,""x"":2}"))
      = "{""x"":2,"""
        & Character'Val (16#EF#)
        & Character'Val (16#BB#)
        & Character'Val (16#BF#)
        & """:1}",
      "BOM codepoint key preservation");
   Reject_JSON ("""\ud800""");
   Reject_JSON ("1e400");
   Reject_JSON ("01");
   Reject_JSON
     (""""
      & Character'Val (16#ED#)
      & Character'Val (16#A0#)
      & Character'Val (16#80#)
      & """");
   Document := Parse ("{""hello"":""world""}");
   Proof := VH_Log.Sign (Document, Seed);
   Check (VH_Log.Verify (Document, Proof), "proof verification");
   Put (Document, "extra", Bool (True));
   Check (not VH_Log.Verify (Document, Proof), "proof tampering");
   Request.State := Parse ("{""id"":""example:{SCID}"",""value"":1}");
   Request.Version_Time := To_Unbounded_String ("2026-01-01T00:00:00Z");
   Request.Signers.Append (Seed);
   Put (Request.Parameters, "updateKeys", Arr);
   Add (Get (Request.Parameters, "updateKeys"), Str (Crypto.Multikey (Seed)));
   Genesis := VH_Log.Create (Request);
   Result :=
     VH_Log.Resolve (To_String (Genesis.Content), "2026-01-02T00:00:00Z");
   Check
     (Result.Valid
      and then Get (Result.Metadata, "versionNumber").Number = 1.0,
      "typed create and resolve");
   Request.Parameters := Obj;
   Request.State := Parse ("{""value"":2}");
   Request.Version_Time := To_Unbounded_String ("2026-01-02T00:00:00Z");
   Second := VH_Log.Update (To_String (Genesis.Content), Request);
   Request.State := Parse ("{""value"":3}");
   Request.Version_Time := To_Unbounded_String ("2026-01-03T00:00:00Z");
   Third := VH_Log.Update (To_String (Second.Content), Request);
   Result :=
     VH_Log.Resolve
       (To_String (Third.Content),
        "2026-01-04T00:00:00Z",
        Options => (Selector => (By_Version_Number, 1), Min_Copies => 1));
   Check
     (Result.Valid and then Get (Result.State, "value").Number = 1.0,
      "historical selection");
   Entries := Lines (To_String (Third.Content));
   Remove (At_Index (Entries, 3), "proof");
   Result := VH_Log.Resolve (Log_Text (Entries), "2026-01-04T00:00:00Z");
   Check
     (Result.Valid
      and then Result.First_Invalid_Version = 3
      and then Get (Result.State, "value").Number = 2.0,
      "partial prefix validity");
   Request.Parameters := Obj;
   Put (Request.Parameters, "deactivated", Bool (True));
   Request.Version_Time := To_Unbounded_String ("2026-01-03T00:00:00Z");
   Third := VH_Log.Update (To_String (Second.Content), Request);
   Result :=
     VH_Log.Resolve
       (To_String (Third.Content),
        "2026-01-04T00:00:00Z",
        Options => (Selector => (By_Version_Number, 1), Min_Copies => 1));
   Check
     (Result.Valid and then Get (Result.Metadata, "deactivated").Flag,
      "historical deactivation metadata");
   Request.Parameters := Obj;
   Request.Version_Time := To_Unbounded_String ("2026-01-04T00:00:00Z");
   Third := VH_Log.Update (To_String (Third.Content), Request);
   Result :=
     VH_Log.Resolve (To_String (Third.Content), "2026-01-05T00:00:00Z");
   Check
     (Result.Valid
      and then Result.First_Invalid_Version = 4
      and then S (Get (Result.Error, "code")) = "entry-after-deactivation",
      "entry after deactivation");
   -- Copy comparison must verify only an extending suffix and retain trusted prefix state.
   Request.Parameters := Obj;
   Request.State := Parse ("{""value"":3}");
   Request.Version_Time := To_Unbounded_String ("2026-01-03T00:00:00Z");
   Third := VH_Log.Update (To_String (Second.Content), Request);
   Entries := Lines (To_String (Third.Content));
   Put (At_Index (Entries, 1), "state", Parse ("{""tampered"":true}"));
   Copies := Arr;
   Copy_Input := Obj;
   Put (Copy_Input, "source", Str ("watcher"));
   Put (Copy_Input, "log", Str (Log_Text (Entries)));
   Add (Copies, Copy_Input);
   Result :=
     VH_Log.Resolve
       (To_String (Second.Content),
        "2026-01-04T00:00:00Z",
        Options => (Selector => (By_Version_Number, 1), Min_Copies => 2),
        Copies  => Copies);
   Check
     (Result.Valid
      and then Get (Result.State, "value").Number = 1.0
      and then S (Get (Result.Metadata, "updated")) = "2026-01-03T00:00:00Z",
      "copy extension trusts cached prefix state");
   -- Nested storage scopes free temporary values without invalidating an outer document.
   declare
      Inner     : JSON.Storage_Scope;
      Temporary : Value_Access := Copy (Document);
   begin
      Check (Has (Temporary, "extra"), "nested scope document");
   end;
   Check (Has (Document, "extra"), "outer scope remains alive");
   -- did:vh: the shared vectors through the library API.
   declare
      Dir : constant String := "../../vectors/didvh/";
      function Read (Path : String) return Value_Access is
         use Ada.Streams.Stream_IO;
         F    : File_Type;
         Text : String (1 .. Natural (Ada.Directories.Size (Path)));
      begin
         Open (F, In_File, Path);
         String'Read (Stream (F), Text);
         Close (F);
         return Parse (Text);
      end Read;
      function Opt (V : Value_Access; K : String) return Value_Access
      is (if Has (V, K) then Get (V, K) else Nil);
      procedure Simple (File, Op, Field : String) is
         Cases : constant Value_Access := Get (Read (Dir & File), "cases");
      begin
         for M of Cases.Children loop
            declare
               In_Value : constant Value_Access := Obj;
            begin
               Put (In_Value, Field, Get (M.Item, Field));
               Check
                 (Canonical (Did_VH.Dispatch (Op, In_Value))
                  = Canonical (Get (M.Item, "expect")),
                  File & "/" & S (Get (M.Item, "name")));
            end;
         end loop;
      end Simple;
      procedure Resolution (File : String) is
         Cases : constant Value_Access :=
           Get (Read (Dir & "resolution/" & File), "cases");
      begin
         for M of Cases.Children loop
            declare
               I     : constant Value_Access := Get (M.Item, "input");
               E     : constant Value_Access := Get (M.Item, "expect");
               Got   : constant Value_Access :=
                 Did_VH.Resolve
                   (Get (I, "did"),
                    Get (I, "options"),
                    Get (I, "now"),
                    Get (I, "remote").Flag);
               Meta  : constant Value_Access := Get (Got, "didResolutionMetadata");
               Codes : constant Value_Access := Arr;
               Name  : constant String := File & "/" & S (Get (M.Item, "name"));
            begin
               if Has (E, "error") then
                  Check
                    (S (Get (Meta, "error")) = S (Get (E, "error"))
                     and then Get (Got, "didDocument").Tag = Null_Value
                     and then (not Has (E, "vhLogError")
                               or else S (Get (Get (Get (Meta, "problemDetails"), "vhLog"), "code"))
                                       = S (Get (E, "vhLogError"))),
                     Name);
               else
                  -- The vectors list at most one warning code, so order is moot.
                  for W of Get (Meta, "warnings").Children loop
                     Add (Codes, Get (W.Item, "code"));
                  end loop;
                  Check
                    (Canonical (Get (Got, "didDocument")) = Canonical (Get (E, "didDocument"))
                     and then Canonical (Get (Got, "didDocumentMetadata"))
                              = Canonical (Get (E, "didDocumentMetadata"))
                     and then Canonical (Codes)
                              = Canonical ((if Has (E, "warnings") then Get (E, "warnings") else Arr))
                     and then Canonical (Opt (Meta, "didLog")) = Canonical (Opt (E, "didLog"))
                     and then Canonical (Opt (Meta, "didWitness")) = Canonical (Opt (E, "didWitness")),
                     Name);
               end if;
            end;
         end loop;
      end Resolution;
      Search : Ada.Directories.Search_Type;
      Item   : Ada.Directories.Directory_Entry_Type;
      Made   : Value_Access;
      Did_In : constant Value_Access := Obj;
   begin
      Simple ("ref.json", "didvh-ref", "ref");
      Simple ("src.json", "didvh-src", "src");
      Simple ("did-url.json", "didvh-did-url", "didUrl");
      Ada.Directories.Start_Search (Search, Dir & "resolution", "*.json");
      while Ada.Directories.More_Entries (Search) loop
         Ada.Directories.Get_Next_Entry (Search, Item);
         Resolution (Ada.Directories.Simple_Name (Item));
      end loop;
      Ada.Directories.End_Search (Search);
      Put (Did_In, "document", Parse ("{""id"":""did:vh:{SCID}""}"));
      Put
        (Did_In,
         "parameters",
         Parse ("{""updateKeys"":[""" & Crypto.Multikey (Seed) & """]}"));
      Put (Did_In, "versionTime", Str ("2026-01-01T00:00:00Z"));
      Put (Did_In, "signers", Parse ("[""" & Seed & """]"));
      Made := Did_VH.Create (Did_In);
      Check
        (S (Get (Get (Did_VH.Resolve
                        (Get (Made, "did"),
                         Parse ("{""didLog"":" & Canonical (Get (Made, "log")) & "}"),
                         Str ("2026-01-02T00:00:00Z")),
                      "didDocument"),
                 "id"))
         = S (Get (Made, "did")),
         "a created did:vh DID resolves");
   end;
   Ada.Text_IO.Put_Line
     (Natural'Image (Checks) & " native Ada library checks passed");
end Test_Library;
