;;;; unit.lisp — unit tests for each layer, plus end-to-end generate → resolve.

(in-package #:vh-log/tests)

(defparameter *seed-1* "90930409d492fb6cd7b50542c97fc6003fcedd59012b47ac114417373796eaaa")
(defparameter *seed-2* "e0203d7f35f898d2c66bbc45b1d5ed23410af56e775d3601a1f4ee3f22987ea6")
(defparameter *seed-3* "b2f56f12a0b0513455e61f01bb11b5af580fdf1bd4ea1b560bc4bf96ee1e0162")
(defparameter *now* "2026-06-01T00:00:00Z")

(defun jcs-of (text) (canonicalize (parse-json text)))

;;; ------------------------------------------------------------ JSON

(deftest json-round-trip
  (is-equal "{\"a\":[1,true,false,null],\"b\":{\"c\":\"d\"}}"
            (to-json (parse-json " { \"a\" : [ 1 , true , false , null ] , \"b\" : { \"c\" : \"d\" } } ")))
  (is-equal "{\"b\":2,\"a\":1}" (to-json (parse-json "{\"b\":2,\"a\":1}")))
  (is-equal "{\"a\":1,\"b\":2}" (jcs-of "{\"b\":2,\"a\":1}")))

(deftest json-duplicate-keys-last-wins
  (is-equal "{\"a\":2}" (jcs-of "{\"a\":1,\"a\":2}")))

(deftest json-rejects-malformed
  (dolist (text '("" "{" "[1,]" "{\"a\":1,}" "01" "1." ".5" "+1" "-" "1e" "tru" "\"\\x\"" "\"a" "[1] 2"
                  "{\"a\" 1}" "nul" "\"\\u12\"" "{1:2}"))
    (is (handler-case (progn (parse-json text) nil) (json-parse-error () t))
        "~s should not parse" text)))

(deftest json-rejects-control-characters-in-strings
  (is (handler-case (progn (parse-json (format nil "\"a~cb\"" (code-char 10))) nil)
        (json-parse-error () t))))

(deftest json-i-json-rules
  (is (handler-case (progn (parse-json "1e400") nil) (json-parse-error () t)) "1e400 overflows")
  (is (handler-case (progn (parse-json "[-1e400]") nil) (json-parse-error () t)) "-1e400 overflows")
  (is (handler-case (progn (parse-json "\"\\ud800\"") nil) (json-parse-error () t)) "lone high surrogate")
  (is (handler-case (progn (parse-json "\"\\udc00x\"") nil) (json-parse-error () t)) "lone low surrogate")
  (is (handler-case (progn (parse-json "{\"\\ud800\":1}") nil) (json-parse-error () t)) "lone surrogate key")
  (is-equal 0d0 (parse-json "1e-400"))
  (is-equal "😀" (parse-json "\"\\ud83d\\ude00\""))
  ;; The non-strict mode (used for driver requests) is lenient.
  (is (stringp (parse-json "\"\\ud800\"" :strict nil))))

(deftest json-numbers-are-doubles
  (is-equal "123456789012345680" (jcs-of "123456789012345678"))
  (is-equal "9007199254740992" (jcs-of "9007199254740993"))
  (is-equal "1" (jcs-of "1.0"))
  (is-equal "0" (jcs-of "-0"))
  (is-equal "1.7976931348623157e+308" (jcs-of "1.7976931348623157e308"))
  (is-equal "1.7976931348623157e+308" (jcs-of "1.7976931348623158e308")) ; rounds down to max
  (is (handler-case (progn (parse-json "1.7976931348623159e308") nil) (json-parse-error () t))
      "a value past max + half an ulp overflows")
  (is-equal "5e-324" (jcs-of "5e-324"))
  (is-equal "5e-324" (jcs-of "3e-324"))       ; rounds up to the smallest subnormal
  (is-equal "0" (jcs-of "2e-324")))           ; rounds down to zero

(deftest json-number-formatting
  (loop for (text expected) in '(("1e21" "1e+21") ("1e20" "100000000000000000000") ("1e-6" "0.000001")
                                 ("1e-7" "1e-7") ("123e-20" "1.23e-18") ("0.1" "0.1") ("-1.5" "-1.5")
                                 ("896365914996807.2" "896365914996807.2") ("4.35" "4.35")
                                 ("0.30000000000000004" "0.30000000000000004") ("9.999999999999999e22" "1e+23")
                                 ("2.2250738585072014e-308" "2.2250738585072014e-308"))
        do (is-equal expected (jcs-of text))))

(defun random-double (state)
  (loop (let ((bits (random (ash 1 64) state)))
          (unless (= (ldb (byte 11 52) bits) #x7ff) ; skip NaN and infinity
            (return (sb-kernel:make-double-float (let ((hi (ldb (byte 32 32) bits)))
                                                   (if (logbitp 31 hi) (- hi (ash 1 32)) hi))
                                                 (ldb (byte 32 0) bits)))))))

(deftest json-number-formatting-round-trips
  ;; Every formatted double parses back to itself, and uses at most 17 digits.
  (let ((state (sb-ext:seed-random-state 8785)))
    (dotimes (i 20000)
      (let* ((x (random-double state))
             (text (canonicalize x)))
        (unless (is (eql (parse-json text) (if (zerop x) 0d0 x)) "~s formatted as ~a" x text)
          (return))
        (is (<= (significant-digits text) 17) "~a has more than 17 significant digits" text)))))

(defun significant-digits (text)
  (let ((mantissa (remove-if-not #'digit-char-p (subseq text 0 (or (position #\e text) (length text))))))
    (length (string-trim "0" mantissa))))

(deftest jcs-sorts-keys-by-utf-16
  ;; U+1F600 (surrogates D83D DE00) sorts before U+FB33 in UTF-16 order,
  ;; though it is after it by code point.
  (is-equal (format nil "{\"~c\":1,\"~c\":2}" (code-char #x1f600) (code-char #xfb33))
            (jcs-of "{\"\\ufb33\":2,\"\\ud83d\\ude00\":1}")))

(deftest jcs-string-escaping
  (is-equal "\"\\u000f\\n\\\"\\\\/\"" (canonicalize (format nil "~c~c\"\\/" (code-char 15) (code-char 10))))
  (is-equal (format nil "\"~c~c\"" (code-char #x7f) (code-char #x2028))
            (canonicalize (format nil "~c~c" (code-char #x7f) (code-char #x2028)))))

;;; ------------------------------------------------------------ encodings

(deftest base58
  (is-equal "" (base58-encode (coerce #() '(vector (unsigned-byte 8)))))
  (is-equal "11" (base58-encode (coerce #(0 0) '(vector (unsigned-byte 8)))))
  (is-equal "Cn8eVZg" (base58-encode (utf8 "hello")))
  (is-equal "hello" (sb-ext:octets-to-string (base58-decode "Cn8eVZg") :external-format :utf-8))
  (is (null (base58-decode "0OIl")) "0, O, I and l are not base58")
  (let ((bytes (coerce #(0 0 1 2 255) '(vector (unsigned-byte 8)))))
    (is (equalp bytes (base58-decode (base58-encode bytes))))))

(deftest hex
  (is (equalp #(0 171 255) (hex-decode "00abFF")))
  (is (null (hex-decode "abc")))
  (is (null (hex-decode "zz")))
  (is-equal "00abff" (hex-encode (hex-decode "00ABFF"))))

(deftest multihash-and-hashes
  (is-equal "1220ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            (hex-encode (multihash (utf8 "abc"))))
  (is-equal (base58-encode (multihash (utf8 "abc"))) (hash-string "abc"))
  (is (eq :sha-256 (decode-multihash (hash-string "x"))))
  (is (eq :sha-512 (decode-multihash (hash-string "x" :sha-512))))
  (is (eq :unknown (decode-multihash "abc")))
  (is (null (decode-multihash "0abc"))))

(deftest multikeys
  (let ((mk (signer-multikey (make-signer *seed-1*))))
    (is-equal "z6MkwTAY3aCT7UL96ddvxWr1upj2VFQDMPFFRYxM1fRneSrv" mk)
    (is (= 32 (length (decode-ed25519-multikey mk))))
    (is-equal "QmchKW5rynK1kqB1CAUt9B7NEP7TYnnMKRrGQDMXpRV4QG" (key-hash mk))
    (is (null (decode-ed25519-multikey "not-a-key")))
    (is (null (decode-ed25519-multikey (subseq mk 1))) "needs the z prefix")
    (is (null (decode-ed25519-multikey (concatenate 'string "z1" (subseq mk 1)))) "non-canonical")))

;;; ------------------------------------------------------------ time

(deftest version-times
  (is-equal 0 (parse-version-time "1970-01-01T00:00:00Z"))
  (is-equal 0 (parse-version-time "1970-01-01T00:00:00+00:00"))
  (is-equal 951782400 (parse-version-time "2000-02-29T00:00:00Z"))
  (is (integerp (parse-version-time "0000-01-01T00:00:00Z")))
  (is (< (parse-version-time "0099-12-31T23:59:59Z") (parse-version-time "0100-01-01T00:00:00Z")))
  (dolist (bad '("2026-01-01T00:00:00" "2026-01-01T00:00:00.5Z" "2026-01-01T00:00:00z" "2026-01-01T00:00:00+01:00"
                 "2026-02-29T00:00:00Z" "1900-02-29T00:00:00Z" "2026-13-01T00:00:00Z" "2026-04-31T00:00:00Z"
                 "2026-01-01T24:00:00Z" "2026-01-01T23:59:60Z" "2026-01-01 00:00:00Z" "26-01-01T00:00:00Z"
                 "２026-01-01T00:00:00Z"))
    (is (null (parse-version-time bad)) "~s should be rejected" bad)))

;;; ------------------------------------------------------------ proofs

(deftest sign-and-verify
  (let* ((signer (make-signer *seed-1*))
         (doc (make-json "a" 1))
         (proof (sign-document doc signer :created "2026-01-01T00:00:00Z")))
    (is (verify-proof doc proof))
    (is (not (verify-proof (make-json "a" 2) proof)) "tampered document")
    (is (not (verify-proof doc (jwith proof "cryptosuite" "eddsa-rdfc-2022"))) "wrong cryptosuite")
    (is (not (verify-proof doc (jwith proof "created" "2027-01-01T00:00:00Z"))) "the proof options are signed")
    (is (not (verify-proof doc (jwith proof "proofValue" "zz"))) "malformed proofValue")
    (is (not (verify-proof doc (jwith proof "verificationMethod" (signer-multikey signer)))) "not did:key")
    (is (not (jhas (sign-document doc signer) "created")) "created is optional")))

(deftest did-key-verification-methods
  (is-equal "z6Mk" (did-key-multikey "did:key:z6Mk#z6Mk"))
  (is (null (did-key-multikey "did:key:z6Mk#z6Mx")))
  (is (null (did-key-multikey "did:key:#")))
  (is (null (did-key-multikey "did:web:z6Mk#z6Mk"))))

;;; ------------------------------------------------------------ end to end

(defun resolve* (log &rest args)
  (apply #'resolve log :now *now* args))

(defun new-log (&key (parameters (make-json "updateKeys" (vector (signer-multikey (make-signer *seed-1*)))))
                     (signers (list (make-signer *seed-1*))))
  (create-log :state (make-json "id" "example:{SCID}") :parameters parameters
              :version-time "2026-01-01T00:00:00Z" :signers signers))

(deftest create-and-resolve
  (multiple-value-bind (log scid version-id) (new-log)
    (is-equal "QmfZEwVdGDqkzNvbRjUnX3EHQwT569yChMNNN4mBYE6Fg7" scid)
    (is-equal "1-Qmc3wTfUMTgQ8Swi1npEst5ko4cHT4KiZyhRmg8HMrPpnM" version-id)
    (let ((r (resolve* log)))
      (is (resolution-valid-p r))
      (is-equal (format nil "example:~a" scid) (jget (resolution-state r) "id"))
      (is-equal 3600 (jget (resolution-metadata r) "ttl")))))

(deftest update-rotate-and-deactivate
  (let* ((k1 (make-signer *seed-1*)) (k2 (make-signer *seed-2*))
         (log (new-log)))
    (setf log (update-log log :state (make-json "v" 2) :parameters (make-json "updateKeys" (vector (signer-multikey k2)))
                              :version-time "2026-01-02T00:00:00Z" :signers (list k1)))
    (setf log (update-log log :state (make-json "v" 3) :parameters (make-json "deactivated" :true)
                              :version-time "2026-01-03T00:00:00Z" :signers (list k2)))
    (let ((r (resolve* log)))
      (is (resolution-valid-p r))
      (is (null (resolution-error r)))
      (is-equal 3 (jget (resolution-metadata r) "versionNumber"))
      (is (eq :true (jget (resolution-metadata r) "deactivated"))))
    (let ((r (resolve* log :options (make-json "versionNumber" 1d0))))
      (is (eq :true (jget (resolution-metadata r) "deactivated")) "deactivation is reported for every version"))
    ;; Old key after rotation: entry 4 is invalid (and follows deactivation).
    (let ((r (resolve* (update-log log :state (make-json) :version-time "2026-01-04T00:00:00Z" :signers (list k2)))))
      (is-equal "entry-after-deactivation" (log-error-code (resolution-error r)))
      (is-equal 4 (resolution-first-invalid-version r)))))

(deftest unauthorized-and-pre-rotation
  (let* ((k1 (make-signer *seed-1*)) (k2 (make-signer *seed-2*)) (k3 (make-signer *seed-3*))
         (log (new-log :parameters (make-json "updateKeys" (vector (signer-multikey k1))
                                              "nextKeyHashes" (vector (key-hash (signer-multikey k2)))))))
    (let ((r (resolve* (update-log log :state (make-json) :parameters (make-json)
                                       :version-time "2026-01-02T00:00:00Z" :signers (list k1)))))
      (is-equal "prerotation-violation" (log-error-code (resolution-error r))))
    (let ((r (resolve* (update-log log :state (make-json)
                                       :parameters (make-json "updateKeys" (vector (signer-multikey k3)) "nextKeyHashes" #())
                                       :version-time "2026-01-02T00:00:00Z" :signers (list k3)))))
      (is-equal "prerotation-violation" (log-error-code (resolution-error r))))
    (let ((r (resolve* (update-log log :state (make-json)
                                       :parameters (make-json "updateKeys" (vector (signer-multikey k2)) "nextKeyHashes" #())
                                       :version-time "2026-01-02T00:00:00Z" :signers (list k2)))))
      (is (null (resolution-error r)) "a committed key signs the rotation"))
    (let ((r (resolve* (update-log (new-log) :state (make-json) :version-time "2026-01-02T00:00:00Z" :signers (list k3)))))
      (is-equal "unauthorized-key" (log-error-code (resolution-error r))))))

(deftest witnessing
  (let* ((k1 (make-signer *seed-1*)) (w1 (make-signer *seed-2*)) (w2 (make-signer *seed-3*))
         (id1 (format nil "did:key:~a" (signer-multikey w1)))
         (id2 (format nil "did:key:~a" (signer-multikey w2))))
    (multiple-value-bind (log scid version-id)
        (new-log :parameters (make-json "updateKeys" (vector (signer-multikey k1))
                                        "witness" (make-json "threshold" 2 "witnesses" (vector (make-json "id" id1) (make-json "id" id2)))))
      (declare (ignore scid))
      (flet ((proofs (&rest signers) (map 'vector (lambda (s) (witness-proof version-id s)) signers)))
        (is (resolution-valid-p (resolve* log :witness (vector (make-json "versionId" version-id "proof" (proofs w1 w2))))))
        (is-equal "witness-threshold-not-met"
                  (log-error-code (resolution-error (resolve* log :witness (vector (make-json "versionId" version-id "proof" (proofs w1 w1)))))))
        (is-equal "witness-threshold-not-met" (log-error-code (resolution-error (resolve* log))))
        (is-equal "invalid-witness-file" (log-error-code (resolution-error (resolve* log :witness :null))))))))

(deftest copies-and-forks
  (let* ((k1 (make-signer *seed-1*))
         (log1 (new-log))
         (log2 (update-log log1 :state (make-json "v" 2) :version-time "2026-01-02T00:00:00Z" :signers (list k1)))
         (fork (update-log log1 :state (make-json "v" "fork") :version-time "2026-01-02T00:00:00Z" :signers (list k1))))
    (let ((r (resolve* log1 :copies (list (list :source "w" :log log2)))))
      (is (resolution-valid-p r))
      (is-equal 2 (jget (resolution-metadata r) "versionNumber")))
    (let ((r (resolve* log2 :copies (list (list :source "w" :log fork)))))
      (is (not (resolution-valid-p r)))
      (is-equal "fork-detected" (log-error-code (resolution-error r)))
      (is-equal 2 (log-error-version (resolution-error r))))
    (let ((r (resolve* log2 :copies (list (list :source "w" :unavailable "timeout")) :options (make-json "minCopies" 2d0))))
      (is-equal "min-copies-not-met" (log-error-code (resolution-error r))))))

(deftest options
  (let ((log (new-log)))
    (dolist (options (list (make-json "checkWatchers" 1d0) (make-json "versionNumber" 0d0)
                           (make-json "versionNumber" 1d0 "versionId" "x") (make-json "versionTime" "yesterday")))
      (is-equal "invalid-option" (log-error-code (resolution-error (resolve* log :options options)))))
    (is-equal "not-found" (log-error-code (resolution-error (resolve* log :options (make-json "versionNumber" 2d0)))))))
