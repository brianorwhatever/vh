with Ada.Text_IO;
with Ada.Exceptions;
with Ada.Strings.Unbounded;
with Interfaces.C;
with System;
with JSON;
with VH_Log;

procedure Driver is
   use JSON;
   use Ada.Strings.Unbounded;
   use type Interfaces.C.long;
   function Read
     (Descriptor : Interfaces.C.int;
      Buffer     : System.Address;
      Count      : Interfaces.C.size_t) return Interfaces.C.long
   with Import, Convention => C, External_Name => "read";
   Buffer  : aliased String (1 .. 8192);
   Pending : Unbounded_String;
   Count   : Interfaces.C.long;
   procedure Respond (Line : String) is
      Scope             : JSON.Storage_Scope;
      Request, Response : Value_Access;
   begin
      Response := Obj;
      begin
         Request := Parse (Line);
         Put (Response, "id", Get (Request, "id"));
         Put (Response, "ok", Bool (True));
         Put
           (Response,
            "result",
            VH_Log.Dispatch (S (Get (Request, "op")), Get (Request, "input")));
      exception
         when E : others =>
            Put (Response, "ok", Bool (False));
            Put
              (Response,
               "error",
               Str
                 (Ada.Exceptions.Exception_Name (E)
                  & ": "
                  & Ada.Exceptions.Exception_Message (E)));
      end;
      Ada.Text_IO.Put_Line (Canonical (Response));
      Ada.Text_IO.Flush;
   end Respond;
begin
   loop
      Count := Read (0, Buffer'Address, Buffer'Length);
      exit when Count = 0;
      if Count < 0 then
         raise Ada.Text_IO.Device_Error with "stdin read failed";
      end if;
      for I in 1 .. Integer (Count) loop
         if Buffer (I) = ASCII.LF then
            Respond (To_String (Pending));
            Pending := Null_Unbounded_String;
         else
            Append (Pending, Buffer (I));
         end if;
      end loop;
   end loop;
   if Length (Pending) > 0 then
      Respond (To_String (Pending));
   end if;
end Driver;
