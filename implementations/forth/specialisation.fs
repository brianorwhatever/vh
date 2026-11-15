\ How a method specialises VH-Log (docs/didvh-profile.md section 1).
\ The default is plain VH-Log; didvh.fs installs did:vh for one resolution.
require json.fs
2variable spec-parameter  \ the version parameter's name
2variable spec-version    \ its accepted value
variable spec-syntax      \ 0, or xt ( value -- flag ). With a syntax, a missing
                          \ or malformed value is invalid-parameter.
variable spec-closed      \ unknown parameters are invalid-parameter
variable spec-state       \ 0, or xt ( state scid -- flag ), run on every entry
                          \ after the SCID check; failing is invalid-state.
: vh-log-specialisation ( -- )
  s" logVersion" spec-parameter 2! s" vh-log:1.0" spec-version 2!
  0 spec-syntax ! false spec-closed ! 0 spec-state ! ;
vh-log-specialisation
: version-name ( -- addr len ) spec-parameter 2@ ;
: version-value ( -- string ) spec-version 2@ str ;
