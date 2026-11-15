;;;; didvh.lisp — did:vh on top of the VH-Log code (docs/didvh-profile.md):
;;;; DIDs, create/update, srcLog/srcWitness references, the src DID URL
;;;; parameter, DID URLs, and offline resolution.

(in-package #:vh-log)

(defparameter +did-vh-prefix+ "did:vh:")
(defparameter +did-vh-method-version+ "did:vh:1.0")
(defparameter +base58-alphabet-chars+ "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

;;; ------------------------------------------------------------ small helpers

(defun starts-with-p (prefix string)
  (and (>= (length string) (length prefix)) (string= prefix string :end2 (length prefix))))

(defun ascii-digits-p (string)
  (and (plusp (length string)) (every #'digit-p string)))

(defun printable-ascii-p (string)
  (every (lambda (c) (char<= (code-char #x21) c (code-char #x7e))) string))

(defun split-string (string char)
  (loop with start = 0
        for pos = (position char string :start start)
        collect (subseq string start pos)
        while pos
        do (setf start (1+ pos))))

(defun non-negative-integer-p (value)
  (and (integral-double-p value) (>= value 0)))

(defun positive-integer-p (value)
  (and (integral-double-p value) (>= value 1)))

;;; ------------------------------------------------------------ the DID (§2)

(defun parse-did-vh (did)
  "The SCID of a did:vh DID (\"did:vh:\" and 46 base58btc characters), or NIL."
  (and (stringp did)
       (= (length did) (+ 7 46))
       (starts-with-p +did-vh-prefix+ did)
       (every (lambda (c) (find c +base58-alphabet-chars+)) (subseq did 7))
       (subseq did 7)))

(defun method-version-p (value)
  "did:vh:<major>.<minor>, each a non-negative integer without leading zeros."
  (flet ((number-p (s) (and (ascii-digits-p s) (or (= (length s) 1) (char/= (char s 0) #\0)))))
    (and (starts-with-p +did-vh-prefix+ value)
         (let ((parts (split-string (subseq value 7) #\.)))
           (and (= (length parts) 2) (every #'number-p parts))))))

(defun did-vh-specialisation (&optional scid)
  "The did:vh specialisation of VH-Log. With SCID (the DID's), the log's SCID
must also equal it."
  (make-specialisation
   :version-parameter "method"
   :versions (list +did-vh-method-version+)
   :version-syntax #'method-version-p
   :closed t
   :check-state (lambda (state log-scid)
                  (let ((want (concatenate 'string +did-vh-prefix+ log-scid)))
                    (cond ((and scid (string/= scid log-scid))
                           (format nil "the log's SCID ~a is not the DID's ~a" log-scid scid))
                          ((not (equal (jget state "id") want))
                           (format nil "state.id must be ~a" want)))))))

;;; ------------------------------------------------------------ create / update

(defun create-did-vh (&key document parameters version-time signers)
  "Creates a did:vh DID. DOCUMENT uses \"did:vh:{SCID}\" for the DID; \"method\"
and \"scid\" are added to PARAMETERS when absent. Returns (values LOG-TEXT DID
SCID VERSION-ID)."
  (multiple-value-bind (log scid version-id)
      (create-log :state document :parameters parameters :version-time version-time :signers signers
                  :version (cons "method" +did-vh-method-version+))
    (values log (concatenate 'string +did-vh-prefix+ scid) scid version-id)))

(defun update-did-vh (log-text &key document parameters version-time signers)
  "Appends a did:vh entry (update, or deactivate with {\"deactivated\": true}).
Returns (values NEW-LOG-TEXT VERSION-ID)."
  (update-log log-text :state document :parameters parameters :version-time version-time :signers signers))

;;; ------------------------------------------------------------ percent-decoding

(defun utf8-decode-strict (bytes)
  "Decodes BYTES as UTF-8, or returns NIL if they are not well-formed UTF-8."
  (let ((out (make-string-output-stream)) (i 0) (n (length bytes)))
    (loop while (< i n)
          do (let* ((b (aref bytes i))
                    (len (cond ((< b #x80) 1) ((<= #xc2 b #xdf) 2) ((<= #xe0 b #xef) 3) ((<= #xf0 b #xf4) 4) (t nil))))
               (unless (and len (<= (+ i len) n)) (return-from utf8-decode-strict nil))
               (let ((code (if (= len 1) b (logand b (ash #xff (- (1+ len)))))))
                 (loop for j from 1 below len
                       for c = (aref bytes (+ i j))
                       do (unless (= (logand c #xc0) #x80) (return-from utf8-decode-strict nil))
                          (setf code (logior (ash code 6) (logand c #x3f))))
                 (when (or (and (= len 3) (< code #x800)) (and (= len 4) (< code #x10000))
                           (<= #xd800 code #xdfff) (> code #x10ffff))
                   (return-from utf8-decode-strict nil))
                 (write-char (code-char code) out)
                 (incf i len))))
    (get-output-stream-string out)))

(defun percent-decode (string)
  "Percent-decodes STRING once as UTF-8 (\"+\" stays \"+\"), or returns NIL for a
malformed escape or invalid UTF-8."
  (let ((bytes (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
        (i 0))
    (loop while (< i (length string))
          do (let ((c (char string i)))
               (if (char= c #\%)
                   (let ((hex (and (<= (+ i 3) (length string)) (subseq string (1+ i) (+ i 3)))))
                     (unless (and hex (every (lambda (h) (digit-char-p h 16)) hex))
                       (return-from percent-decode nil))
                     (vector-push-extend (parse-integer hex :radix 16) bytes)
                     (incf i 3))
                   (progn (loop for b across (utf8 (string c)) do (vector-push-extend b bytes))
                          (incf i)))))
    (utf8-decode-strict bytes)))

;;; ------------------------------------------------------------ references (§3)

(defun split-scheme (string)
  "Returns (values SCHEME-IN-LOWERCASE REST) for [A-Za-z][A-Za-z0-9+.-]*:REST, or NIL."
  (let ((colon (position #\: string)))
    (when (and colon (plusp colon)
               (alpha-char-p (char string 0)) (< (char-code (char string 0)) 128)
               (every (lambda (c) (or (and (< (char-code c) 128) (alphanumericp c)) (find c "+.-")))
                      (subseq string 0 colon)))
      (values (string-downcase (subseq string 0 colon)) (subseq string (1+ colon))))))

(defun domain-name-p (host)
  "An optional trailing dot, then 1-253 characters of LDH labels; the last
label is not all digits."
  (let ((name (if (and (plusp (length host)) (char= (char host (1- (length host))) #\.))
                  (subseq host 0 (1- (length host)))
                  host)))
    (and (<= 1 (length name) 253)
         (let ((labels (split-string name #\.)))
           (and (every (lambda (label)
                         (and (<= 1 (length label) 63)
                              (every (lambda (c) (or (char<= #\a c #\z) (char<= #\0 c #\9) (char= c #\-))) label)
                              (char/= (char label 0) #\-)
                              (char/= (char label (1- (length label))) #\-)))
                       labels)
                (not (every #'digit-p (car (last labels)))))))))

(defun loopback-host-p (host)
  (or (string= host "localhost")
      (string= host "[::1]")
      (let ((octets (split-string host #\.)))
        (and (= (length octets) 4)
             (every (lambda (o) (and (<= 1 (length o) 3) (every #'digit-p o)
                                     (or (= (length o) 1) (char/= (char o 0) #\0))
                                     (<= (parse-integer o) 255)))
                    octets)
             (string= (first octets) "127")))))

(defun split-authority (authority)
  "Returns the lowercase host of AUTHORITY (host[:port], or [literal][:port]),
or NIL if it has userinfo or a bad port."
  (unless (find #\@ authority)
    (multiple-value-bind (host port)
        (if (starts-with-p "[" authority)
            (let ((close (position #\] authority)))
              (when close
                (let ((after (subseq authority (1+ close))))
                  (cond ((zerop (length after)) (values (subseq authority 0 (1+ close)) nil))
                        ((char= (char after 0) #\:) (values (subseq authority 0 (1+ close)) (subseq after 1)))
                        (t (values nil nil))))))
            (let ((colon (position #\: authority)))
              (if colon
                  (values (subseq authority 0 colon) (subseq authority (1+ colon)))
                  (values authority nil))))
      (when (and host (or (null port)
                          (and (<= 1 (length port) 5) (every #'digit-p port) (<= (parse-integer port) 65535))))
        (string-downcase host)))))

(defun reference-segment-p (segment)
  "§3.1 step 4: a decoded path segment is not . or .. and has no / \\ or NUL."
  (let ((decoded (percent-decode segment)))
    (and decoded
         (not (member decoded '("." "..") :test #'string=))
         (not (find-if (lambda (c) (find c (list #\/ #\\ (code-char 0)))) decoded)))))

(defun path-segments-ok-p (path)
  "PATH starts with /; checks each segment between /s."
  (every #'reference-segment-p (rest (split-string path #\/))))

(defun reference-kind (ref)
  "Checks a srcLog or srcWitness reference (§3.1). Returns its kind, \"web\",
\"loopback\", \"file\" or \"other\", or NIL if it is invalid."
  (when (and (stringp ref) (printable-ascii-p ref) (not (find #\# ref)))
    (multiple-value-bind (scheme rest) (split-scheme ref)
      (cond
        ((null scheme) nil)
        ((member scheme '("https" "http") :test #'string=)
         (when (starts-with-p "//" rest)
           (let* ((rest (subseq rest 2))
                  (end (or (position-if (lambda (c) (find c "/?")) rest) (length rest)))
                  (host (split-authority (subseq rest 0 end)))
                  (path (subseq rest end (or (position #\? rest) (length rest)))))
             (and host
                  (if (string= scheme "https") (domain-name-p host) (loopback-host-p host))
                  (plusp (length path))
                  (path-segments-ok-p path)
                  (if (string= scheme "https") "web" "loopback")))))
        ((string= scheme "file")
         (unless (find #\? rest)
           (let ((path (cond ((starts-with-p "//" rest)
                              (let* ((slash (position #\/ rest :start 2))
                                     (host (subseq rest 2 (or slash (length rest)))))
                                (and slash (member host '("" "localhost") :test #'string-equal)
                                     (subseq rest slash))))
                             ((starts-with-p "/" rest) rest))))
             (and path (path-segments-ok-p path) "file"))))
        ((plusp (length rest)) "other")))))

(defparameter +white-space+
  (append (loop for c from #x09 to #x0d collect c) '(#x20 #x85 #xa0 #x1680)
          (loop for c from #x2000 to #x200a collect c) '(#x2028 #x2029 #x202f #x205f #x3000)))

(defun white-space-p (char) (member (char-code char) +white-space+))

(defun src-segment-p (segment)
  "§3.2 step 5: non-empty, not . or .., no / \\ or NUL once decoded, and no
leading or trailing White_Space."
  (let ((decoded (percent-decode segment)))
    (and decoded (plusp (length decoded))
         (reference-segment-p segment)
         (not (white-space-p (char decoded 0)))
         (not (white-space-p (char decoded (1- (length decoded))))))))

(defun src-references (src)
  "Derives (values SRC-LOG SRC-WITNESS) from a percent-decoded src DID URL
parameter (§3.2), or returns NIL if it is invalid."
  (when (and (stringp src) (printable-ascii-p src) (not (find #\# src)) (not (find #\? src)))
    (multiple-value-bind (scheme rest) (split-scheme src)
      (when (and scheme (not (member scheme '("http" "file") :test #'string=))
                 (starts-with-p "//" rest))
        (let* ((rest (if (char= (char rest (1- (length rest))) #\/) (subseq rest 0 (1- (length rest))) rest))
               (end (or (position #\/ rest :start 2) (length rest)))
               (authority (subseq rest 2 end))
               (path (subseq rest end)))
          (when (and (plusp (length authority))
                     (or (string/= scheme "https")
                         (let ((host (split-authority authority)))
                           (and host (domain-name-p host)
                                (every #'src-segment-p (rest (split-string path #\/)))))))
            (values (format nil "~a:~a/did.jsonl" scheme rest)
                    (format nil "~a:~a/did-witness.json" scheme rest))))))))

;;; ------------------------------------------------------------ DID URLs (§4)

(defparameter +did-url-option-names+
  '("didLog" "didWitness" "srcLog" "srcWitness" "checkWatchers" "extraWatchers" "minCopies" "includeDidLog"))

(defun parse-did-vh-url (url)
  "Dereferences a did:vh DID URL into (values DID OPTIONS FRAGMENT), where
OPTIONS is a JSON object and FRAGMENT is NIL without a #. Returns NIL if the
DID URL is invalid (invalidDidUrl)."
  (block parse
    (unless (stringp url) (return-from parse nil))
    (let* ((hash (position #\# url))
           (fragment (and hash (subseq url (1+ hash))))
           (before (subseq url 0 (or hash (length url))))
           (question (position #\? before))
           (did (subseq before 0 (or question (length before))))
           (options (make-json))
           (seen '()))
      (unless (parse-did-vh did) (return-from parse nil))
      (when question
        (dolist (part (split-string (subseq before (1+ question)) #\&))
          (let* ((eq (or (position #\= part) (return-from parse nil)))
                 (name (or (percent-decode (subseq part 0 eq)) (return-from parse nil)))
                 (value (or (percent-decode (subseq part (1+ eq))) (return-from parse nil))))
            (when (member name +did-url-option-names+ :test #'string=) (return-from parse nil))
            (when (member name '("src" "versionId" "versionTime" "versionNumber") :test #'string=)
              (when (member name seen :test #'string=) (return-from parse nil))
              (push name seen)
              (cond ((string= name "src")
                     (multiple-value-bind (src-log src-witness) (src-references value)
                       (unless src-log (return-from parse nil))
                       (setf options (jwith (jwith options "srcLog" src-log) "srcWitness" src-witness))))
                    ((string= name "versionNumber")
                     (unless (and (<= 1 (length value) 16) (ascii-digits-p value) (char/= (char value 0) #\0))
                       (return-from parse nil))
                     (setf options (jwith options name (coerce (parse-integer value) 'double-float))))
                    (t (setf options (jwith options name value))))))))
      (values did options fragment))))

;;; ------------------------------------------------------------ resolution (§5)

(defun did-vh-error-code (vh-log-code)
  (cond ((string= vh-log-code "not-found") "notFound")
        ((string= vh-log-code "invalid-option") "invalidOptions")
        ((string= vh-log-code "unsupported-log-version") "featureNotSupported")
        ((string= vh-log-code "fork-detected") "logForked")
        ((string= vh-log-code "min-copies-not-met") "insufficientCopies")
        (t "invalidDid")))

(defun did-resolution-error (code detail &optional log-error)
  (make-json "didResolutionMetadata"
             (make-json "error" code
                        "problemDetails" (apply #'make-json "title" code "detail" detail
                                                (when log-error (list "vhLog" (log-error-json log-error)))))
             "didDocument" :null
             "didDocumentMetadata" (make-json)))

(defun log-needs-witnessing-p (lines scid now)
  "True if the log needs witnessing (§5 step 4): the witness list that applies
(profile.md §3) to some entry before the first one failing a per-entry check,
with the did:vh specialisation, is not {}. No witness file is involved."
  (let ((*specialisation* (did-vh-specialisation scid))
        (seconds (parse-version-time now)))
    (and seconds (some #'log-entry-witness-applies (verify-entries lines seconds)))))

(defun extra-watcher-p (url)
  (and (stringp url) (starts-with-p "https://" url) (watcher-url-p url)))

(defun resolve-did-vh (did options &key now remote)
  "Resolves a did:vh DID offline (§5). OPTIONS is the JSON object of
resolution options, with the log in didLog. REMOTE is true when the resolver
serves other systems. Returns a JSON object with didResolutionMetadata,
didDocument and didDocumentMetadata."
  (block resolve
    (flet ((fail (code control &rest args)
             (return-from resolve (did-resolution-error code (apply #'format nil control args)))))
      ;; 1. The DID.
      (let ((scid (parse-did-vh did)))
        (unless scid (fail "invalidDid" "not a did:vh DID"))
        ;; 2. The options.
        (unless (json-object-p options) (fail "invalidOptions" "the resolution options must be an object"))
        (flet ((opt (key) (jget options key)) (has (key) (jhas options key)))
          (unless (= 1 (count-if #'has '("didLog" "srcLog")))
            (fail "invalidOptions" "exactly one of didLog and srcLog is required"))
          (when (and (has "didWitness") (has "srcWitness"))
            (fail "invalidOptions" "at most one of didWitness and srcWitness"))
          (when (and (has "didLog") (not (stringp (opt "didLog"))))
            (fail "invalidOptions" "didLog must be a string"))
          (when (and (has "didWitness") (let ((w (opt "didWitness"))) (or (not (vectorp w)) (stringp w))))
            (fail "invalidOptions" "didWitness must be an array"))
          (dolist (key '("srcLog" "srcWitness"))
            (when (has key)
              (let ((kind (reference-kind (opt key))))
                (unless kind (fail "invalidOptions" "~a is not a valid reference" key))
                (when (and remote (member kind '("file" "loopback") :test #'string=))
                  (fail "invalidOptions" "~a may not be a ~a reference for a remote resolver" key kind)))))
          (when (> (count-if #'has '("versionId" "versionTime" "versionNumber")) 1)
            (fail "invalidOptions" "at most one of versionId, versionTime and versionNumber"))
          (when (and (has "versionId") (not (stringp (opt "versionId"))))
            (fail "invalidOptions" "versionId must be a string"))
          (when (and (has "versionTime") (not (parse-version-time (opt "versionTime"))))
            (fail "invalidOptions" "versionTime must be YYYY-MM-DDTHH:MM:SSZ"))
          (when (and (has "versionNumber") (not (positive-integer-p (opt "versionNumber"))))
            (fail "invalidOptions" "versionNumber must be a positive integer"))
          (when (and (has "checkWatchers")
                     (not (or (equal (opt "checkWatchers") "all") (non-negative-integer-p (opt "checkWatchers")))))
            (fail "invalidOptions" "checkWatchers must be a non-negative integer or \"all\""))
          (when (and (has "extraWatchers")
                     (let ((w (opt "extraWatchers")))
                       (or (not (vectorp w)) (stringp w) (notevery #'extra-watcher-p w))))
            (fail "invalidOptions" "extraWatchers must be an array of https URLs"))
          (when (and (has "minCopies") (not (positive-integer-p (opt "minCopies"))))
            (fail "invalidOptions" "minCopies must be a positive integer"))
          (when (and (has "includeDidLog") (not (member (opt "includeDidLog") '(:true :false))))
            (fail "invalidOptions" "includeDidLog must be a boolean"))
          ;; 3. What an offline resolver can't do.
          (when (has "srcLog") (fail "featureNotSupported" "this resolver does not retrieve srcLog"))
          (when (and (has "checkWatchers") (not (eql (opt "checkWatchers") 0d0)))
            (fail "featureNotSupported" "this resolver does not query watchers"))
          (when (and (has "extraWatchers") (plusp (length (opt "extraWatchers"))))
            (fail "featureNotSupported" "this resolver does not query watchers"))
          (let* ((text (opt "didLog"))
                 (lines (parse-log-lines text)))
            ;; 4. A srcWitness matters only if the log needs witnessing: some
            ;; entry that passes the per-entry checks has a witness list.
            (when (and (has "srcWitness") (log-needs-witnessing-p lines scid now))
              (fail "featureNotSupported" "this resolver does not retrieve srcWitness"))
            ;; 5. VH-Log resolution with the did:vh specialisation.
            (let* ((selected (some #'has '("versionId" "versionTime" "versionNumber")))
                   (vh-options (apply #'make-json
                                      (loop for key in '("versionId" "versionTime" "versionNumber" "minCopies")
                                            when (has key) append (list key (opt key)))))
                   (result (apply #'resolve text :now now :options vh-options
                                  :specialisation (did-vh-specialisation scid)
                                  (when (has "didWitness") (list :witness (opt "didWitness")))))
                   (error (resolution-error result)))
              (unless (resolution-valid-p result)
                (return-from resolve (did-resolution-error (did-vh-error-code (log-error-code error))
                                              (log-error-message error) error)))
              ;; 6. An unsupported entry may change the document or its keys.
              (when (and (not selected) error (string= (log-error-code error) "unsupported-log-version"))
                (return-from resolve (did-resolution-error "featureNotSupported" (log-error-message error) error)))
              (let* ((metadata (resolution-metadata result))
                     (valid (if error (1- (log-error-version error)) (length lines)))
                     (deactivated (eq (jget metadata "deactivated") :true))
                     (latest-p (= (jget metadata "versionNumber") valid))
                     (witness (jget metadata "witness"))
                     (warnings (jget metadata "warnings"))
                     (resolution-metadata
                       (apply #'make-json "contentType" "application/did+json"
                              (append
                               (when (plusp (length warnings)) (list "warnings" warnings))
                               (when (eq (opt "includeDidLog") :true)
                                 (append
                                  (list "didLog" (format nil "~{~a~%~}" (subseq (split-log-lines text) 0 valid)))
                                  (when (log-needs-witnessing-p lines scid now)
                                    (list "didWitness" (if (has "didWitness") (opt "didWitness") #()))))))))
                     (document-metadata
                       (apply #'make-json
                              "versionId" (jget metadata "versionId")
                              "versionTime" (jget metadata "versionTime")
                              "created" (jget metadata "created")
                              "updated" (jget metadata "updated")
                              "scid" (jget metadata "scid")
                              "deactivated" (jget metadata "deactivated")
                              "ttl" (jget metadata "ttl")
                              (append (when (json-object-p witness) (list "witness" witness))
                                      (list "watchers" (jget metadata "watchers"))))))
                (make-json "didResolutionMetadata" resolution-metadata
                           "didDocument" (if (and deactivated latest-p) :null (resolution-state result))
                           "didDocumentMetadata" document-metadata)))))))))
