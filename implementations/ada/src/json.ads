with Ada.Strings.Unbounded;
with Ada.Containers.Vectors;
with Ada.Finalization;

package JSON is
   pragma
     Compile_Time_Error
       (Long_Float'Size /= 64, "JCS requires IEEE binary64 Long_Float");
   use Ada.Strings.Unbounded;
   type Kind is
     (Null_Value,
      Boolean_Value,
      Number_Value,
      String_Value,
      Array_Value,
      Object_Value);
   type Value;
   type Value_Access is access all Value;
   type Member is record
      Key  : Unbounded_String;
      Item : Value_Access;
   end record;
   package Members is new Ada.Containers.Vectors (Positive, Member);
   type Value is record
      Tag             : Kind := Null_Value;
      Text            : Unbounded_String;
      Number          : Long_Float := 0.0;
      Flag            : Boolean := False;
      Children        : Members.Vector;
      Next_Allocation : Value_Access := null;
   end record;
   function Parse (Text : String) return Value_Access;
   function Canonical (V : Value_Access) return String;
   function Obj return Value_Access;
   function Arr return Value_Access;
   function Str (S : String) return Value_Access;
   function Num (N : Long_Float) return Value_Access;
   function Bool (B : Boolean) return Value_Access;
   function Nil return Value_Access;
   function Get (V : Value_Access; Key : String) return Value_Access;
   function Has (V : Value_Access; Key : String) return Boolean;
   procedure Put (V : Value_Access; Key : String; Item : Value_Access);
   procedure Add (V : Value_Access; Item : Value_Access);
   function S (V : Value_Access) return String;
   function Len (V : Value_Access) return Natural;
   function At_Index (V : Value_Access; I : Positive) return Value_Access;
   function Copy (V : Value_Access) return Value_Access;
   procedure Remove (V : Value_Access; Key : String);
   -- Values allocated while a scope is alive belong to that scope. Nested
   -- scopes are supported; values must not escape their allocating scope.
   -- JSON allocation is single-task; use external synchronisation across tasks.
   type Storage_Scope is new Ada.Finalization.Limited_Controlled with private;
   Invalid_JSON : exception;
private
   type Storage_Scope is new Ada.Finalization.Limited_Controlled with record
      Mark : Value_Access := null;
   end record;
   overriding
   procedure Initialize (Scope : in out Storage_Scope);
   overriding
   procedure Finalize (Scope : in out Storage_Scope);
end JSON;
