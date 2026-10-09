;;;; resolve.lisp — verifying and resolving a log (spec: Read), with witnesses,
;;;; multiple copies and retained versionIds. Check order and error codes follow
;;;; the interop profile (docs/profile.md §4 and §6).

(in-package #:vh-log)

(defparameter +future-tolerance+ 300 "Seconds a versionTime may be ahead of now.")
(defparameter +max-ttl+ (expt 2 31))
(defparameter +supported-log-versions+ (list +log-version+))
(defparameter +known-parameters+
  '("logVersion" "scid" "updateKeys" "nextKeyHashes" "witness" "watchers" "deactivated" "ttl"))
(defparameter +entry-keys+ '("versionId" "versionTime" "parameters" "state" "proof"))

;;; ------------------------------------------------------------ errors

(define-condition log-error (error)
  ((code :initarg :code :reader log-error-code)
   (version :initarg :version :initform nil :reader log-error-version)
   (message :initarg :message :initform "" :reader log-error-message)
   (fork :initarg :fork :initform nil :reader log-error-fork
         :documentation "For fork-detected: a JSON object {version, copies}."))
  (:report (lambda (c s)
             (format s "~a~@[ at version ~d~]: ~a"
                     (log-error-code c) (log-error-version c) (log-error-message c)))))

(defun log-error (code version control &rest arguments)
  (error 'log-error :code code :version version :message (apply #'format nil control arguments)))

(defun log-error-json (e)
  (let ((json (make-json "code" (log-error-code e)
                         "version" (or (log-error-version e) :null)
                         "message" (log-error-message e))))
    (if (log-error-fork e) (jwith json "fork" (log-error-fork e)) json)))

;;; ------------------------------------------------------------ state

(defstruct (params (:copier copy-params))
  "Parameters accumulated up to and including an entry."
  (log-version nil)
  (scid nil)
  (update-keys #())
  (next-key-hashes #())
  (witness (make-json))
  (watchers #())
  (deactivated nil)
  (ttl 3600))

(defstruct log-entry
  "An entry that passed every non-witness check."
  number version-id version-time seconds state params
  ;; The witness config that applies to this entry (profile §3), or NIL if none.
  (witness-applies nil))

(defstruct (chain (:copier nil))
  "A verified copy of a log: LINES are the parsed lines, ENTRIES the valid
prefix, FAILURE the LOG-ERROR that invalidated the entry after it (if anything)."
  (lines #()) (entries #()) (failure nil) (witness-records '()))

(defun chain-passes-p (chain)
  "A copy passes verification only if every entry is valid and witnessed."
  (and (null (chain-failure chain)) (plusp (length (chain-entries chain)))))

;;; ------------------------------------------------------------ parameters

(defun empty-object-p (value)
  (and (json-object-p value) (null (jpairs value))))

(defun integral-double-p (value)
  (and (typep value 'double-float) (= value (ffloor value))))

(defun nfc (string) (sb-unicode:normalize-string string :nfc))

(defun string-vector-p (value predicate)
  (and (vectorp value) (not (stringp value))
       (every (lambda (item) (and (stringp item) (funcall predicate item))) value)))

(defun watcher-url-p (url)
  "Profile §4: printable ASCII, http(s) scheme, non-empty authority."
  (and (every (lambda (c) (char<= (code-char #x21) c (code-char #x7e))) url)
       (let ((rest (cond ((and (>= (length url) 8) (string= "https://" url :end2 8)) (subseq url 8))
                         ((and (>= (length url) 7) (string= "http://" url :end2 7)) (subseq url 7)))))
         (and rest (plusp (length rest)) (not (find (char rest 0) "/?#"))))))

(defun witness-id-multikey (id)
  (and (stringp id) (> (length id) 8) (string= "did:key:" id :end2 8)
       (decode-ed25519-multikey (subseq id 8))
       (subseq id 8)))

(defun witness-ids (config)
  "Distinct NFC-normalised ids of a (valid, non-empty) witness config."
  (remove-duplicates (map 'list (lambda (w) (nfc (jget w "id"))) (jget config "witnesses"))
                     :test #'string=))

(defun valid-witness-config-p (value)
  (or (empty-object-p value)
      (and (json-object-p value)
           (let ((threshold (jget value "threshold"))
                 (witnesses (jget value "witnesses")))
             (and (integral-double-p threshold) (>= threshold 1)
                  (vectorp witnesses) (not (stringp witnesses)) (plusp (length witnesses))
                  (every (lambda (w) (and (json-object-p w) (witness-id-multikey (jget w "id")))) witnesses)
                  (let ((ids (witness-ids value)))
                    (and (= (length ids) (length witnesses)) ; ids must be unique
                         (<= threshold (length ids)))))))))

(defun apply-parameters (raw prior number)
  "Validates the PARAMETERS of entry NUMBER against the PRIOR accumulated
parameters (NIL for the first entry) and returns the new accumulated ones."
  (flet ((bad (control &rest args) (apply #'log-error "invalid-parameter" number control args)))
    (let ((p (if prior (copy-params prior) (make-params))))
      (dolist (key +known-parameters+)
        (when (eq (jget raw key) :null) (bad "~a must not be null" key)))
      (multiple-value-bind (v present) (jget raw "logVersion")
        (cond (present
               (unless (stringp v) (bad "logVersion must be a string"))
               (unless (member v +supported-log-versions+ :test #'string=)
                 (log-error "unsupported-log-version" number "unsupported logVersion ~s" v))
               (setf (params-log-version p) v))
              ((= number 1)
               (log-error "unsupported-log-version" number "the first entry must set logVersion"))))
      (multiple-value-bind (v present) (jget raw "scid")
        (cond ((and present (> number 1)) (bad "scid may only appear in the first entry"))
              (present (unless (stringp v) (bad "scid must be a string"))
                       (setf (params-scid p) v))
              (t (when (= number 1) (bad "the first entry must set scid")))))
      (multiple-value-bind (v present) (jget raw "updateKeys")
        (cond (present (unless (string-vector-p v #'decode-ed25519-multikey)
                         (bad "updateKeys must be an array of Ed25519 multikeys"))
                       (setf (params-update-keys p) v))
              ((= number 1) (bad "the first entry must set updateKeys"))))
      (multiple-value-bind (v present) (jget raw "nextKeyHashes")
        (when present
          (unless (string-vector-p v (lambda (h) (eq (decode-multihash h) :sha-256)))
            (bad "nextKeyHashes must be an array of SHA-256 multihashes"))
          (setf (params-next-key-hashes p) v)))
      (multiple-value-bind (v present) (jget raw "witness")
        (when present
          (unless (valid-witness-config-p v)
            (bad "witness must be {} or {threshold, witnesses: [{id: did:key}]} with unique ids and 1 <= threshold <= ids"))
          (setf (params-witness p) v)))
      (multiple-value-bind (v present) (jget raw "watchers")
        (when present
          (unless (string-vector-p v #'watcher-url-p)
            (bad "watchers must be an array of http(s) URLs"))
          (setf (params-watchers p) v)))
      (multiple-value-bind (v present) (jget raw "deactivated")
        (when present
          (unless (member v '(:true :false)) (bad "deactivated must be a boolean"))
          (setf (params-deactivated p) (eq v :true))))
      (multiple-value-bind (v present) (jget raw "ttl")
        (when present
          (unless (and (integral-double-p v) (<= 0 v +max-ttl+))
            (bad "ttl must be an integer from 0 to 2^31"))
          (setf (params-ttl p) (round v))))
      ;; Pre-rotation (Read step 7), checked with the parameters (profile §4).
      (when (and prior (plusp (length (params-next-key-hashes prior))))
        (unless (and (jhas raw "updateKeys") (jhas raw "nextKeyHashes"))
          (log-error "prerotation-violation" number
                     "pre-rotation is active: updateKeys and nextKeyHashes must both be set"))
        (loop for key across (params-update-keys p)
              unless (find (key-hash key) (params-next-key-hashes prior) :test #'string=)
                do (log-error "prerotation-violation" number "~a was not committed in nextKeyHashes" key)))
      p)))

;;; ------------------------------------------------------------ entry checks

(defun check-structure (json number)
  (unless (and (json-object-p json)
               (= (length (jkeys json)) (length +entry-keys+))
               (every (lambda (k) (jhas json k)) +entry-keys+))
    (log-error "invalid-entry" number "an entry has exactly versionId, versionTime, parameters, state and proof"))
  (unless (and (stringp (jget json "versionId")) (stringp (jget json "versionTime"))
               (json-object-p (jget json "parameters")) (json-object-p (jget json "state"))
               (let ((proof (jget json "proof"))) (and (vectorp proof) (not (stringp proof)))))
    (log-error "invalid-entry" number "an entry property has the wrong type")))

(defun check-proofs (json number keys)
  (let ((proofs (jget json "proof"))
        (document (jwithout json "proof")))
    (when (zerop (length proofs))
      (log-error "invalid-proof" number "proof must not be empty"))
    (loop for proof across proofs
          for i from 1
          do (unless (json-object-p proof)
               (log-error "invalid-proof" number "proof ~d is not an object" i))
             (let ((mk (did-key-multikey (jget proof "verificationMethod"))))
               (unless mk
                 (log-error "invalid-proof" number "proof ~d: verificationMethod is not did:key:<mk>#<mk>" i))
               (unless (find mk keys :test #'string=)
                 (log-error "unauthorized-key" number "proof ~d: ~a is not an active update key" i mk))
               (unless (equal (jget proof "proofPurpose") +proof-purpose+)
                 (log-error "invalid-proof" number "proof ~d: proofPurpose must be assertionMethod" i))
               (unless (proof-signature-valid-p document proof (decode-ed25519-multikey mk))
                 (log-error "invalid-proof" number "proof ~d does not verify" i))))))

(defun check-version-id (json number predecessor)
  (let* ((version-id (jget json "versionId"))
         (dash (position #\- version-id))
         (prefix (and dash (subseq version-id 0 dash)))
         (hash (and dash (subseq version-id (1+ dash)))))
    (unless (and dash (= 1 (count #\- version-id))
                 (plusp (length prefix)) (every #'digit-p prefix) (char/= (char prefix 0) #\0)
                 (plusp (length hash)))
      (log-error "invalid-version-id" number "versionId must be <number>-<entry hash>"))
    (unless (= (parse-integer prefix) number)
      (log-error "invalid-version-id" number "expected version number ~d, got ~a" number prefix))
    (let ((algorithm (decode-multihash hash)))
      (cond ((null algorithm) (log-error "invalid-version-id" number "entry hash is not base58btc"))
            ((not (eq algorithm :sha-256))
             (log-error "invalid-hash-algorithm" number "entry hash is not a SHA-256 multihash"))))
    (unless (string= hash (entry-hash json predecessor))
      (log-error "entry-hash-mismatch" number "entry hash does not match the entry"))))

(defun check-version-time (json number previous now)
  (let ((time (parse-version-time (jget json "versionTime"))))
    (unless time
      (log-error "invalid-version-time" number "versionTime must be YYYY-MM-DDTHH:MM:SSZ in UTC"))
    (when (and previous (<= time (log-entry-seconds previous)))
      (log-error "invalid-version-time" number "versionTime must be later than the previous entry's"))
    (when (> time (+ now +future-tolerance+))
      (log-error "future-version-time" number "versionTime is in the future"))
    time))

(defun check-scid (json scid)
  (unless (eq (decode-multihash scid) :sha-256)
    (log-error "invalid-hash-algorithm" 1 "scid is not a SHA-256 multihash"))
  (let* ((preliminary (jwith (jwithout json "proof") "versionId" +scid-placeholder+))
         (text (replace-all (to-json preliminary) scid +scid-placeholder+))
         (restored (handler-case (parse-json text) (json-parse-error () nil))))
    (unless (and restored (string= scid (compute-scid restored)))
      (log-error "scid-mismatch" 1 "scid does not match the first entry"))))

(defun check-entry (json number previous now)
  "Runs every non-witness check on entry NUMBER in profile order and returns a
LOG-ENTRY, or signals LOG-ERROR. JSON is the parsed line, or a keyword naming
why the line isn't a JSON object."
  (when (and previous (params-deactivated (log-entry-params previous)))
    (log-error "entry-after-deactivation" number "the log was deactivated by entry ~d" (1- number)))
  (case json
    (:not-json (log-error "invalid-log" number "line ~d is not JSON (or not I-JSON)" number))
    (:not-object (log-error "invalid-log" number "line ~d is not a JSON object" number)))
  (check-structure json number)
  (let* ((prior (and previous (log-entry-params previous)))
         (raw (jget json "parameters"))
         (params (apply-parameters raw prior number))
         (prerotation (and prior (plusp (length (params-next-key-hashes prior)))))
         (prior-witness (if prior (params-witness prior) (make-json)))
         (applies (if (and (jhas raw "witness") (empty-object-p prior-witness))
                      (params-witness params)
                      prior-witness)))
    (check-proofs json number (if (or (null prior) prerotation)
                                  (params-update-keys params)
                                  (params-update-keys prior)))
    (check-version-id json number (if previous (log-entry-version-id previous) (params-scid params)))
    (let ((time (check-version-time json number previous now)))
      (when (= number 1) (check-scid json (params-scid params)))
      (make-log-entry :number number
                      :version-id (jget json "versionId")
                      :version-time (jget json "versionTime")
                      :seconds time
                      :state (jget json "state")
                      :params params
                      :witness-applies (if (empty-object-p applies) nil applies)))))

(defun verify-entries (lines now &key (start 0) previous)
  "Checks LINES from index START, following PREVIOUS. Returns (values ENTRIES
ERROR): the entries that passed, and the error that stopped processing."
  (let ((entries '()))
    (loop for i from start below (length lines)
          do (handler-case
                 (let ((entry (check-entry (aref lines i) (1+ i) previous now)))
                   (push entry entries)
                   (setf previous entry))
               (log-error (e) (return-from verify-entries (values (coerce (nreverse entries) 'vector) e)))))
    (values (coerce (nreverse entries) 'vector) nil)))

;;; ------------------------------------------------------------ witnesses

(defun witness-records (witness supplied-p)
  "The witness file as a list of (versionId . proofs), or :MALFORMED."
  (cond ((not supplied-p) '())
        ((and (vectorp witness) (not (stringp witness))
              (every (lambda (r)
                       (and (json-object-p r)
                            (stringp (jget r "versionId"))
                            (let ((p (jget r "proof"))) (and (vectorp p) (not (stringp p))))))
                     witness))
         (map 'list (lambda (r) (cons (jget r "versionId") (jget r "proof"))) witness))
        (t :malformed)))

(defun check-witnesses (entries records &key (from 1))
  "Returns NIL if every entry numbered FROM or later that needs witnessing is
witnessed (profile §3), else the LOG-ERROR for the first one that isn't.
Runs only after every entry has passed the other checks."
  (let ((needing (remove-if (lambda (e) (or (< (log-entry-number e) from) (null (log-entry-witness-applies e))))
                            (coerce entries 'list))))
    (when needing
      (when (eq records :malformed)
        (return-from check-witnesses
          (make-condition 'log-error :code "invalid-witness-file" :version (log-entry-number (first needing))
                                     :message "the witness file must be an array of {versionId, proof[]}")))
      (let ((positions (make-hash-table :test 'equal))
            (wanted (make-hash-table :test 'equal))
            (approved-up-to (make-hash-table :test 'equal)))
        (loop for e across entries do (setf (gethash (log-entry-version-id e) positions) (log-entry-number e)))
        (dolist (e needing)
          (dolist (id (witness-ids (log-entry-witness-applies e))) (setf (gethash id wanted) t)))
        ;; A valid proof over entry p's versionId approves entries 1..p.
        (loop for (version-id . proofs) in records
              for p = (gethash version-id positions)
              when p
                do (loop for proof across proofs
                         for mk = (and (json-object-p proof) (did-key-multikey (jget proof "verificationMethod")))
                         for id = (and mk (nfc (concatenate 'string "did:key:" mk)))
                         when (and id (gethash id wanted) (> p (gethash id approved-up-to 0))
                                   (verify-proof (make-json "versionId" version-id) proof :purpose +proof-purpose+))
                           do (setf (gethash id approved-up-to) p)))
        (dolist (e needing)
          (let* ((config (log-entry-witness-applies e))
                 (threshold (round (jget config "threshold")))
                 (approvals (count-if (lambda (id) (>= (gethash id approved-up-to 0) (log-entry-number e)))
                                      (witness-ids config))))
            (when (< approvals threshold)
              (return-from check-witnesses
                (make-condition 'log-error :code "witness-threshold-not-met" :version (log-entry-number e)
                                           :message (format nil "~d of ~d required witness approvals" approvals threshold))))))
        nil))))

;;; ------------------------------------------------------------ whole logs

(defun parse-log-lines (text)
  "Each line of TEXT parsed: a JSON-OBJECT, or :NOT-JSON / :NOT-OBJECT."
  (map 'vector (lambda (line)
                 (handler-case (let ((v (parse-json line)))
                                 (if (json-object-p v) v :not-object))
                   (json-parse-error () :not-json)))
       (split-log-lines text)))

(defun verify-log (text witness witness-supplied-p now)
  "Fully verifies one copy of a log and returns its CHAIN."
  (let* ((lines (parse-log-lines text))
         (records (witness-records witness witness-supplied-p)))
    (if (zerop (length lines))
        (make-chain :failure (make-condition 'log-error :code "invalid-log" :message "the log is empty"))
        (multiple-value-bind (entries error) (verify-entries lines now)
          (let ((witness-error (check-witnesses entries records)))
            (when witness-error
              (setf entries (subseq entries 0 (1- (log-error-version witness-error)))
                    error witness-error)))
          (make-chain :lines lines :entries entries :failure error
                      :witness-records (if (eq records :malformed) '() records))))))

(defun line-version-id (line)
  (and (json-object-p line) (let ((v (jget line "versionId"))) (and (stringp v) v))))

;;; ------------------------------------------------------------ copies

(defstruct (copy (:copier nil))
  source (available-p t) reason text witness witness-p
  (lines #()) chain
  ;; :current, :behind, :invalid or :unavailable; :match while comparing.
  (status nil)
  (invalid-at nil))

(defun copy-length (copy) (length (copy-lines copy)))

(defun copy-version-id (copy &optional (number (copy-length copy)))
  (and (<= 1 number (copy-length copy)) (line-version-id (aref (copy-lines copy) (1- number)))))

(defun reference-version-id (reference number)
  (log-entry-version-id (aref (chain-entries (copy-chain reference)) (1- number))))

(defun fully-verify (copy now)
  (or (copy-chain copy)
      (setf (copy-chain copy) (verify-log (copy-text copy) (copy-witness copy) (copy-witness-p copy) now))))

(defun mark-invalid (copy)
  (let ((error (chain-failure (copy-chain copy))))
    (setf (copy-status copy) :invalid
          (copy-invalid-at copy) (or (and error (log-error-version error)) 1))))

(defun fork-error (version a a-id b b-id)
  (error 'log-error
         :code "fork-detected" :version version
         :message (format nil "~a and ~a diverge at version ~d" a b version)
         :fork (make-json "version" version
                          "copies" (vector (make-json "source" a "versionId" a-id)
                                           (make-json "source" b "versionId" b-id)))))

(defun check-fork (reference copy now)
  "COPY diverges from REFERENCE: discard it if it fails verification, else fail
resolution with fork-detected."
  (if (chain-passes-p (fully-verify copy now))
      (let ((at (loop for n from 1 to (min (copy-length copy) (copy-length reference))
                      unless (equal (copy-version-id copy n) (reference-version-id reference n))
                        return n)))
        (fork-error at (copy-source reference) (reference-version-id reference at)
                    (copy-source copy) (copy-version-id copy at)))
      (mark-invalid copy)))

(defun compare-copy (reference copy now)
  "Compares COPY with REFERENCE (spec: Comparing Copies of a Log) and returns
the reference to use from now on."
  (let ((n-ref (copy-length reference))
        (n (copy-length copy)))
    (cond
      ((zerop n) (fully-verify copy now) (mark-invalid copy) reference)
      ((<= n n-ref)
       (if (equal (copy-version-id copy) (reference-version-id reference n))
           (setf (copy-status copy) :match)
           (check-fork reference copy now))
       reference)
      ((equal (copy-version-id copy n-ref) (reference-version-id reference n-ref))
       ;; The copy extends the reference: verify only its additional entries.
       (let* ((ref-chain (copy-chain reference))
              (old (chain-entries ref-chain))
              (records (witness-records (copy-witness copy) (copy-witness-p copy))))
         (multiple-value-bind (new error)
             (verify-entries (copy-lines copy) now :start n-ref :previous (aref old (1- n-ref)))
           (let* ((entries (concatenate 'vector old new))
                  (merged (if (eq records :malformed) :malformed (append (chain-witness-records ref-chain) records)))
                  (error (or error (check-witnesses entries merged :from (1+ n-ref)))))
             (cond (error
                    (setf (copy-chain copy) (make-chain :lines (copy-lines copy) :entries entries :failure error))
                    (mark-invalid copy)
                    reference)
                   (t
                    (setf (copy-chain copy) (make-chain :lines (copy-lines copy) :entries entries
                                                        :witness-records merged)
                          (copy-status reference) :match)
                    copy))))))
      (t (check-fork reference copy now) reference))))

(defun choose-reference (copies now)
  "Picks and compares copies; returns the reference copy. Copies that fail
are marked invalid; a fork signals fork-detected."
  (let ((reference nil))
    (dolist (copy copies)
      (cond ((not (copy-available-p copy)) (setf (copy-status copy) :unavailable))
            (reference (setf reference (compare-copy reference copy now)))
            ((chain-passes-p (fully-verify copy now)) (setf reference copy))
            (t (mark-invalid copy))))
    (or reference
        ;; No copy passes in full: resolve the first one with a valid prefix,
        ;; under the partial-validity rule (profile §4).
        (let ((fallback (find-if (lambda (c) (and (copy-chain c) (plusp (length (chain-entries (copy-chain c))))))
                                 copies)))
          (unless fallback
            (error (chain-failure (copy-chain (first copies)))))
          (setf (copy-status fallback) nil)
          fallback))))

;;; ------------------------------------------------------------ options

(defun parse-options (options)
  "Returns (values SELECTOR MIN-COPIES). SELECTOR is NIL or (KIND VALUE)."
  (let ((selectors '()) (min-copies 1))
    (flet ((bad (control &rest args) (apply #'log-error "invalid-option" nil control args))
           (positive-integer-p (v) (and (integral-double-p v) (>= v 1))))
      (when (and options (not (eq options :null)))
        (unless (json-object-p options) (bad "options must be an object"))
        (loop for (key . value) in (jpairs options)
              do (cond
                   ((string= key "versionId")
                    (unless (stringp value) (bad "versionId must be a string"))
                    (push (list :version-id value) selectors))
                   ((string= key "versionTime")
                    (let ((time (parse-version-time value)))
                      (unless time (bad "versionTime must be an ISO 8601 UTC time"))
                      (push (list :version-time time) selectors)))
                   ((string= key "versionNumber")
                    (unless (positive-integer-p value) (bad "versionNumber must be a positive integer"))
                    (push (list :version-number (round value)) selectors))
                   ((string= key "minCopies")
                    (unless (positive-integer-p value) (bad "minCopies must be a positive integer"))
                    (setf min-copies (round value)))
                   (t (bad "unsupported option ~s" key))))
        (when (> (length selectors) 1) (bad "at most one of versionId, versionTime and versionNumber"))))
    (values (first selectors) min-copies)))

;;; ------------------------------------------------------------ resolution

(defstruct resolution
  "The outcome of RESOLVE. When VALID-P, STATE and METADATA describe the
resolved version, and FIRST-INVALID-VERSION / ERROR any invalid tail."
  valid-p state metadata first-invalid-version error)

(defun select-target (chain selector)
  (let* ((entries (chain-entries chain))
         (error (chain-failure chain))
         (lines (chain-lines chain))
         (invalid-line (and error (< (length entries) (length lines)) (aref lines (length entries)))))
    (flet ((not-found () (log-error "not-found" nil "no entry matches the requested version"))
           (invalid () (error error)))
      (destructuring-bind (&optional kind value) selector
        (ecase kind
          ((nil) (aref entries (1- (length entries))))
          (:version-id
           (or (find value entries :key #'log-entry-version-id :test #'string=)
               (and error (find value (subseq lines (length entries)) :key #'line-version-id :test #'equal)
                    (invalid))
               (not-found)))
          (:version-number
           (cond ((<= value (length entries)) (aref entries (1- value)))
                 ((and error (<= value (length lines))) (invalid))
                 (t (not-found))))
          (:version-time
           (let ((match (find-if (lambda (e) (<= (log-entry-seconds e) value)) entries :from-end t)))
             (unless match (not-found))
             (when error
               (let ((time (and (json-object-p invalid-line) (parse-version-time (jget invalid-line "versionTime")))))
                 (when (if time
                           (<= time value)
                           (eq match (aref entries (1- (length entries)))))
                   (invalid))))
             match)))))))

(defun copy-status-name (status)
  (string-downcase (symbol-name status)))

(defun resolve (log-text &key (witness nil witness-p) now options
                              (copies nil copies-p) retained-version-id)
  "Resolves LOG-TEXT (spec: Read), returning a RESOLUTION.
WITNESS is the parsed witness file (omit it if there is none). NOW is an ISO
8601 UTC time. OPTIONS is a JSON object of resolution options (versionId,
versionTime, versionNumber, minCopies). COPIES are other copies, each a plist
(:source S :log TEXT [:witness W]) or (:source S :unavailable REASON).
RETAINED-VERSION-ID is a versionId kept from an earlier resolution."
  (let ((now (or (parse-version-time now) (error "now must be an ISO 8601 UTC time"))))
    (handler-case
        (multiple-value-bind (selector min-copies) (parse-options options)
          (let* ((candidates
                   (cons (make-copy :source "primary" :text log-text :witness witness :witness-p witness-p
                                    :lines (parse-log-lines log-text))
                         (loop for c in copies
                               collect (if (getf c :unavailable)
                                           (make-copy :source (getf c :source) :available-p nil
                                                      :reason (getf c :unavailable))
                                           (let ((text (getf c :log "")))
                                             (make-copy :source (getf c :source) :text text
                                                        :witness (getf c :witness)
                                                        :witness-p (not (eq (getf c :witness :absent) :absent))
                                                        :lines (parse-log-lines text)))))))
                 (reference (choose-reference candidates now))
                 (chain (copy-chain reference))
                 (entries (chain-entries chain))
                 (warnings '()))
            (flet ((warn* (code message &optional source)
                     (push (apply #'make-json "code" code
                                  (append (when source (list "source" source)) (list "message" message)))
                           warnings)))
              ;; A retained versionId is compared with the reference copy.
              (when retained-version-id
                (let ((number (version-number retained-version-id)))
                  (unless number (log-error "invalid-option" nil "retainedVersionId is not a versionId"))
                  (cond ((> number (length entries))
                         (warn* "retained-version-not-found"
                                (format nil "the log has ~d entries; version ~d was seen before" (length entries) number)))
                        ((string/= retained-version-id (reference-version-id reference number))
                         (fork-error number "retained" retained-version-id
                                     (copy-source reference) (reference-version-id reference number))))))
              (dolist (c candidates)
                (cond ((eq c reference) (setf (copy-status c) :current))
                      ((eq (copy-status c) :match)
                       (setf (copy-status c) (if (= (copy-length c) (length entries)) :current :behind)))))
              (when (< (count-if (lambda (c) (member (copy-status c) '(:current :behind))) candidates) min-copies)
                (log-error "min-copies-not-met" nil "fewer than ~d matching copies" min-copies))
              (dolist (c candidates)
                (case (copy-status c)
                  (:behind (warn* "copy-behind" (format nil "~d entries behind" (- (length entries) (copy-length c)))
                                  (copy-source c)))
                  (:invalid (warn* "copy-invalid" (format nil "failed verification at version ~d" (copy-invalid-at c))
                                   (copy-source c)))
                  (:unavailable (warn* "copy-unavailable" (princ-to-string (copy-reason c)) (copy-source c)))))
              (when (chain-failure chain)
                (warn* "invalid-entries"
                       (format nil "entries from version ~d are invalid; resolved from the last valid entry"
                               (log-error-version (chain-failure chain)))))
              (let* ((target (select-target chain selector))
                     (last (aref entries (1- (length entries))))
                     (latest (log-entry-params last))
                     (at-target (log-entry-params target))
                     (metadata
                       (make-json "versionId" (log-entry-version-id target)
                                  "versionTime" (log-entry-version-time target)
                                  "versionNumber" (log-entry-number target)
                                  "created" (log-entry-version-time (aref entries 0))
                                  "updated" (log-entry-version-time last)
                                  "scid" (params-scid latest)
                                  "deactivated" (if (params-deactivated latest) :true :false)
                                  "ttl" (params-ttl latest)
                                  "witness" (if (empty-object-p (params-witness latest)) :null (params-witness latest))
                                  "watchers" (params-watchers latest)
                                  "updateKeys" (params-update-keys at-target)
                                  "nextKeyHashes" (params-next-key-hashes at-target))))
                (when copies-p
                  (setf metadata
                        (jwith metadata "copies"
                               (map 'vector (lambda (c)
                                              (apply #'make-json "source" (copy-source c)
                                                     (append (let ((id (and (copy-available-p c) (copy-version-id c))))
                                                               (when id (list "versionId" id)))
                                                             (list "status" (copy-status-name (copy-status c))))))
                                    candidates))))
                (make-resolution :valid-p t
                                 :state (log-entry-state target)
                                 :metadata (jwith metadata "warnings" (coerce (nreverse warnings) 'vector))
                                 :first-invalid-version (and (chain-failure chain) (log-error-version (chain-failure chain)))
                                 :error (chain-failure chain))))))
      (log-error (e) (make-resolution :valid-p nil :error e)))))

(defun resolution-to-json (resolution)
  "The interop protocol's JSON form of RESOLUTION."
  (if (resolution-valid-p resolution)
      (make-json "valid" :true
                 "state" (resolution-state resolution)
                 "metadata" (resolution-metadata resolution)
                 "firstInvalidVersion" (or (resolution-first-invalid-version resolution) :null)
                 "error" (if (resolution-error resolution) (log-error-json (resolution-error resolution)) :null))
      (make-json "valid" :false
                 "error" (log-error-json (resolution-error resolution)))))
