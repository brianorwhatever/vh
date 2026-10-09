;;;; package.lisp

(defpackage #:vh-log
  (:use #:cl)
  (:export
   ;; JSON values: objects are JSON-OBJECTs, arrays are vectors, numbers are
   ;; double-floats, strings are strings, and true/false/null are :TRUE,
   ;; :FALSE and :NULL.
   #:json-object #:json-object-p #:make-json #:jget #:jhas #:jkeys #:jpairs
   #:jwith #:jwithout #:json-true-p
   #:parse-json #:json-parse-error #:json-parse-error-reason
   #:to-json #:canonicalize
   ;; Encodings
   #:base58-encode #:base58-decode #:hex-decode #:hex-encode #:utf8
   #:sha256 #:sha512 #:multihash #:decode-multihash #:hash-string
   #:ed25519-multikey #:decode-ed25519-multikey #:key-hash
   ;; Time
   #:parse-version-time
   ;; Proofs
   #:signer #:make-signer #:signer-multikey #:signer-verification-method
   #:sign-document #:verify-proof #:did-key-multikey
   ;; Log Controller
   #:+log-version+ #:compute-scid #:entry-hash #:create-log #:update-log
   #:witness-proof #:split-log-lines
   ;; Resolver
   #:resolve #:resolution #:resolution-valid-p #:resolution-state
   #:resolution-metadata #:resolution-first-invalid-version
   #:resolution-error #:resolution-to-json
   #:log-error #:log-error-code #:log-error-version #:log-error-message
   #:log-error-fork))
