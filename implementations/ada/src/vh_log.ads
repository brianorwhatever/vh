with JSON;
with VH_Types;

package VH_Log is
   function SCID (Log_Entry : JSON.Value_Access) return String;
   function Entry_Hash
     (Log_Entry : JSON.Value_Access; Previous_Version_Id : String)
      return String;
   function Sign
     (Document            : JSON.Value_Access;
      Seed                : String;
      Verification_Method : String := "";
      Created             : String := "";
      Include_Created     : Boolean := False) return JSON.Value_Access;
   function Verify (Document, Proof : JSON.Value_Access) return Boolean;
   function Create (Input : JSON.Value_Access) return JSON.Value_Access;
   function Update (Input : JSON.Value_Access) return JSON.Value_Access;
   function Witness (Input : JSON.Value_Access) return JSON.Value_Access;
   function Resolve (Input : JSON.Value_Access) return JSON.Value_Access;
   function Dispatch
     (Operation : String; Input : JSON.Value_Access) return JSON.Value_Access;
   function Create
     (Request : VH_Types.Controller_Request) return VH_Types.Generated_Log;
   function Update
     (Log : String; Request : VH_Types.Controller_Request)
      return VH_Types.Generated_Log;
   function Resolve
     (Log, Now            : String;
      Options             : VH_Types.Resolution_Options := (others => <>);
      Witness_File        : JSON.Value_Access := null;
      Copies              : JSON.Value_Access := null;
      Retained_Version_Id : String := "") return VH_Types.Resolution_Result;
end VH_Log;
