with Ada.Strings.Unbounded;
with Ada.Containers.Vectors;
with Crypto;
with JSON;

package VH_Types is
   use Ada.Strings.Unbounded;
   subtype Cache_Seconds is Long_Long_Integer range 0 .. 2**31;
   package Seed_Lists is new
     Ada.Containers.Vectors
       (Index_Type   => Positive,
        Element_Type => Crypto.Hex_Seed);
   type Controller_Request is record
      State        : JSON.Value_Access := JSON.Obj;
      Parameters   : JSON.Value_Access := JSON.Obj;
      Version_Time : Unbounded_String;
      Signers      : Seed_Lists.Vector;
   end record;
   type Generated_Log is record
      Content    : Unbounded_String;
      Version_Id : Unbounded_String;
      SCID       : Unbounded_String;
   end record;
   type Selector_Kind is
     (Latest, By_Version_Id, By_Version_Time, By_Version_Number);
   type Version_Selector (Kind : Selector_Kind := Latest) is record
      case Kind is
         when Latest =>
            null;

         when By_Version_Id | By_Version_Time =>
            Value : Unbounded_String;

         when By_Version_Number =>
            Number : Positive;
      end case;
   end record;
   type Resolution_Options is record
      Selector   : Version_Selector;
      Min_Copies : Positive := 1;
   end record;
   type Resolution_Result is record
      Valid                 : Boolean := False;
      State                 : JSON.Value_Access := null;
      Metadata              : JSON.Value_Access := null;
      First_Invalid_Version : Natural := 0;
      Error                 : JSON.Value_Access := null;
   end record;
end VH_Types;
