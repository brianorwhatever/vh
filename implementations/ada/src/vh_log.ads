with Ada.Strings.Unbounded;
with JSON;
with VH_Types;

package VH_Log is
   use Ada.Strings.Unbounded;
   type Syntax_Check is access function (Value : String) return Boolean;
   -- A specialisation of the VH-Log verifier. With a Version_Syntax, a
   -- missing (entry 1) or malformed version parameter is invalid-parameter;
   -- a well-formed value other than Accepted is unsupported-log-version.
   -- Closed (an array of names) rejects any other parameter. With
   -- Check_State, every entry's state.id must equal State_Id_Prefix & the
   -- log's SCID, and that SCID must equal Expected_SCID when it is set;
   -- otherwise the entry fails with invalid-state (after the SCID check).
   type Specialisation is record
      Version_Param   : Unbounded_String := To_Unbounded_String ("logVersion");
      Accepted        : Unbounded_String := To_Unbounded_String ("vh-log:1.0");
      Version_Syntax  : Syntax_Check := null;
      Closed          : JSON.Value_Access := null;
      Check_State     : Boolean := False;
      State_Id_Prefix : Unbounded_String;
      Expected_SCID   : Unbounded_String;
   end record;
   function Timestamp_Valid (Text : String) return Boolean;
   function Watcher_URL_Valid (Text : String) return Boolean;
   -- Protocol create with the version parameter added (before scid when
   -- Version_First) when absent.
   function Create
     (Input                        : JSON.Value_Access;
      Version_Param, Version_Value : String;
      Version_First                : Boolean) return JSON.Value_Access;
   function Resolve
     (Input : JSON.Value_Access; Spec : Specialisation) return JSON.Value_Access;
   -- Whether a log needs witnessing (did:vh profile section 5 step 4): the
   -- witness list that applies (profile section 3) to some entry before the
   -- first one failing a per-entry check is not {}. No witness file is used.
   function Needs_Witnessing
     (Log, Now : String; Spec : Specialisation) return Boolean;
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
