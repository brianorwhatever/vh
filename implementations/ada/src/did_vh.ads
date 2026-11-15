with JSON;
with VH_Log;

-- did:vh (didvh-interop-0, docs/didvh-profile.md) on the VH-Log verifier.
package Did_VH is
   -- The SCID of a did:vh DID, or "" when Text is not one.
   function DID_SCID (Text : String) return String;
   -- The specialisation for resolving did:vh:<SCID>.
   function Specialisation (SCID : String) return VH_Log.Specialisation;
   -- A srcLog/srcWitness reference's kind (web, loopback, file or other),
   -- or "" (invalidOptions).
   function Reference_Kind (Reference : JSON.Value_Access) return String;
   -- {srcLog, srcWitness} for a percent-decoded src value, or null
   -- (invalidDidUrl).
   function Src_Locations (Src : String) return JSON.Value_Access;
   -- {did, options, fragment?} for a DID URL, or null (invalidDidUrl).
   function Parse_DID_URL (URL : JSON.Value_Access) return JSON.Value_Access;
   -- {document, parameters, versionTime, signers} -> {log, did, scid, versionId}
   function Create (Input : JSON.Value_Access) return JSON.Value_Access;
   -- {log, document, parameters, versionTime, signers} -> {log, versionId}
   function Update (Input : JSON.Value_Access) return JSON.Value_Access;
   -- Offline resolution: {didResolutionMetadata, didDocument, didDocumentMetadata}.
   function Resolve
     (DID, Options, Now : JSON.Value_Access; Remote : Boolean := False)
      return JSON.Value_Access;
   -- Every protocol operation: the did:vh ones and VH_Log.Dispatch's.
   function Dispatch
     (Operation : String; Input : JSON.Value_Access) return JSON.Value_Access;
end Did_VH;
