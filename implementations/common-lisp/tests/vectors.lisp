;;;; vectors.lisp — runs the shared vectors (../../vectors) through the library
;;;; directly, with the same comparison rules as harness/run.ts.

(in-package #:vh-log/tests)

(defparameter *vectors*
  (merge-pathnames "../../vectors/" (asdf:system-source-directory "vh-log")))

(defun read-text (path)
  (with-open-file (in path :external-format :utf-8)
    (let ((s (make-string (file-length in))))
      (subseq s 0 (read-sequence s in)))))

(defun load-vector (name) (parse-json (read-text (merge-pathnames name *vectors*))))

(defun same (a b)
  (string= (canonicalize a) (canonicalize b)))

(deftest primitive-vectors
  (let ((v (load-vector "primitives.json")))
    (loop for c across (jget v "jcs")
          do (is-equal (jget c "output") (canonicalize (parse-json (jget c "text")))))
    (loop for c across (jget v "hash")
          do (is-equal (jget c "output") (hash-string (jget c "data"))))
    (loop for c across (jget v "multikey")
          do (is-equal (jget c "multikey") (signer-multikey (make-signer (jget c "seed")))))
    (loop for c across (jget v "keyHash")
          do (is-equal (jget c "output") (key-hash (jget c "multikey"))))
    (loop for c across (jget v "scid")
          do (is-equal (jget c "scid") (compute-scid (jget c "entry"))))
    (loop for c across (jget v "entryHash")
          do (is-equal (jget c "hash") (entry-hash (jget c "entry") (jget c "previousVersionId"))))
    (loop for c across (jget v "sign")
          do (let ((proof (sign-document (jget c "document") (make-signer (jget c "seed"))
                                         :created (jget c "created"))))
               (is (same (jget c "proof") proof) "sign: ~a" (to-json proof))
               (is (verify-proof (jget c "document") (jget c "proof")))
               (is (not (verify-proof (jwith (jget c "document") "extra" 1d0) (jget c "proof"))))))))

(defun resolution-problems (expect got)
  "Mirrors compareResolution in harness/run.ts."
  (let ((problems '())
        (code (and (resolution-error got) (log-error-code (resolution-error got)))))
    (flet ((problem (control &rest args) (push (apply #'format nil control args) problems)))
      (unless (eq (json-true-p (jget expect "valid")) (resolution-valid-p got))
        (problem "valid: expected ~a" (jget expect "valid")))
      (let ((err (jget expect "error")))
        (cond ((json-object-p err)
               (let ((codes (coerce (or (jget err "oneOf") (vector (jget err "code"))) 'list)))
                 (unless (member code codes :test #'equal)
                   (problem "error: expected ~{~a~^|~}, got ~a" codes code)))
               (multiple-value-bind (version present) (jget err "version")
                 (when (and present (resolution-error got)
                            (not (equal (if (eq version :null) nil (round version))
                                        (log-error-version (resolution-error got)))))
                   (problem "error.version: expected ~a, got ~a" version (log-error-version (resolution-error got))))))
              (code (problem "unexpected error ~a" code))))
      (when (and (json-true-p (jget expect "valid")) (resolution-valid-p got))
        (let ((metadata (resolution-metadata got)))
          (unless (same (jget expect "state") (resolution-state got)) (problem "state differs"))
          (unless (eql (let ((f (jget expect "firstInvalidVersion" :null))) (if (eq f :null) nil (round f)))
                       (resolution-first-invalid-version got))
            (problem "firstInvalidVersion: got ~a" (resolution-first-invalid-version got)))
          (let ((want (sort (coerce (jget expect "warnings" #()) 'list) #'string<))
                (have (sort (map 'list (lambda (w) (jget w "code")) (jget metadata "warnings")) #'string<)))
            (unless (equal want have) (problem "warnings: expected ~a, got ~a" want have)))
          (loop for (key . value) in (jpairs (jget expect "metadata" (make-json)))
                unless (same value (jget metadata key :null))
                  do (problem "metadata.~a: expected ~a, got ~a" key (to-json value) (to-json (jget metadata key :null)))))))
    (nreverse problems)))

(defun resolve-case (input)
  (multiple-value-bind (witness witness-p) (jget input "witness")
    (multiple-value-bind (copies copies-p) (jget input "copies")
      (apply #'resolve (jget input "log")
             :now (jget input "now")
             :options (jget input "options")
             :retained-version-id (jget input "retainedVersionId")
             (append (when witness-p (list :witness witness))
                     (when copies-p
                       (list :copies (map 'list (lambda (c)
                                                  (if (jhas c "unavailable")
                                                      (list :source (jget c "source") :unavailable (jget c "unavailable"))
                                                      (append (list :source (jget c "source") :log (jget c "log"))
                                                              (when (jhas c "witness") (list :witness (jget c "witness"))))))
                                          copies))))))))

(deftest resolution-vectors
  (dolist (file (directory (merge-pathnames "resolution/*.json" *vectors*)))
    (loop for c across (jget (parse-json (read-text file)) "cases")
          for problems = (resolution-problems (jget c "expect") (resolve-case (jget c "input")))
          do (is (null problems) "~a/~a: ~{~a~^; ~}" (pathname-name file) (jget c "name") problems))))

(defun replace-scid (value scid)
  (parse-json (vh-log::replace-all (to-json value) "{SCID}" scid)))

(deftest generation-vectors
  (loop for scenario across (jget (load-vector "generation.json") "scenarios")
        do (let ((log "") (scid "") (version-ids '()))
             (loop for step across (jget scenario "steps")
                   for i from 1
                   for op = (jget step "op")
                   for in = (if (string= op "create") (jget step "input") (replace-scid (jget step "input") scid))
                   for expect = (jget step "expect")
                   for signers = (map 'list #'make-signer (jget in "signers"))
                   do (multiple-value-bind (new-log id-or-scid version-id)
                          (if (string= op "create")
                              (create-log :state (jget in "state") :parameters (jget in "parameters")
                                          :version-time (jget in "versionTime") :signers signers)
                              (update-log log :state (jget in "state") :parameters (jget in "parameters")
                                              :version-time (jget in "versionTime") :signers signers))
                        (unless version-id (setf version-id id-or-scid))
                        (when (string= op "create") (setf scid id-or-scid))
                        (setf log new-log)
                        (push version-id version-ids)
                        (is-equal (jget expect "versionId") version-id)
                        (is (same (jget expect "line") (parse-json (car (last (split-log-lines log)))))
                            "~a step ~d line" (jget scenario "name") i)))
             (setf version-ids (reverse version-ids))
             (multiple-value-bind (witness-spec present) (jget scenario "witness")
               (let ((witness (and present
                                   (map 'vector (lambda (w)
                                                  (let ((id (nth (1- (round (jget w "step"))) version-ids)))
                                                    (make-json "versionId" id
                                                               "proof" (map 'vector (lambda (seed) (witness-proof id (make-signer seed)))
                                                                            (jget w "seeds")))))
                                        witness-spec))))
                 (when present
                   (is (same (jget scenario "witnessFile") witness) "~a witness file" (jget scenario "name")))
                 (let* ((expected (jget scenario "resolve"))
                        (r (apply #'resolve log :now (jget expected "now") (when present (list :witness witness)))))
                   (is (and (resolution-valid-p r) (null (resolution-error r))) "~a resolves" (jget scenario "name"))
                   (when (resolution-valid-p r)
                     (is (same (jget expected "state") (resolution-state r)))
                     (is-equal (jget expected "versionId") (jget (resolution-metadata r) "versionId")))))))))

;;; ------------------------------------------------------------ did:vh

(defun didvh-vector (name) (load-vector (concatenate 'string "didvh/" name)))

(deftest didvh-reference-vectors
  (loop for c across (jget (didvh-vector "ref.json") "cases")
        for kind = (reference-kind (jget c "ref"))
        do (is (same (jget c "expect")
                     (if kind (make-json "valid" :true "kind" kind) (make-json "valid" :false "error" "invalidOptions")))
               "ref/~a: got ~a" (jget c "name") kind)))

(deftest didvh-src-vectors
  (loop for c across (jget (didvh-vector "src.json") "cases")
        do (multiple-value-bind (src-log src-witness) (src-references (jget c "src"))
             (is (same (jget c "expect")
                       (if src-log
                           (make-json "valid" :true "srcLog" src-log "srcWitness" src-witness)
                           (make-json "valid" :false "error" "invalidDidUrl")))
                 "src/~a: got ~a" (jget c "name") src-log))))

(deftest didvh-did-url-vectors
  (loop for c across (jget (didvh-vector "did-url.json") "cases")
        do (multiple-value-bind (did options fragment) (parse-did-vh-url (jget c "didUrl"))
             (let ((got (if did
                            (apply #'make-json "valid" :true "did" did "options" options
                                   (when fragment (list "fragment" fragment)))
                            (make-json "valid" :false "error" "invalidDidUrl"))))
               (is (same (jget c "expect") got) "did-url/~a: got ~a" (jget c "name") (to-json got))))))

(defun did-resolution-problems (expect got)
  "Mirrors compareDidResolution in harness/run.ts."
  (let ((problems '())
        (meta (jget got "didResolutionMetadata")))
    (flet ((problem (control &rest args) (push (apply #'format nil control args) problems)))
      (cond ((jhas expect "error")
             (unless (equal (jget expect "error") (jget meta "error"))
               (problem "error: expected ~a, got ~a" (jget expect "error") (jget meta "error")))
             (when (and (jhas expect "vhLogError")
                        (not (equal (jget expect "vhLogError") (jget (jget (jget meta "problemDetails") "vhLog") "code"))))
               (problem "vhLog code: expected ~a" (jget expect "vhLogError")))
             (unless (eq (jget got "didDocument") :null) (problem "didDocument must be null")))
            (t
             (when (jhas meta "error") (problem "unexpected error ~a" (to-json meta)))
             (unless (equal (jget meta "contentType") "application/did+json") (problem "contentType"))
             (unless (same (jget expect "didDocument") (jget got "didDocument")) (problem "didDocument differs"))
             (unless (same (jget expect "didDocumentMetadata") (jget got "didDocumentMetadata"))
               (problem "didDocumentMetadata: got ~a" (to-json (jget got "didDocumentMetadata"))))
             (let ((want (sort (coerce (jget expect "warnings" #()) 'list) #'string<))
                   (have (sort (map 'list (lambda (w) (jget w "code")) (jget meta "warnings" #())) #'string<)))
               (unless (equal want have) (problem "warnings: got ~a" have)))
             (dolist (key '("didLog" "didWitness"))
               (unless (same (jget expect key :null) (jget meta key :null))
                 (problem "didResolutionMetadata.~a differs" key))))))
    (nreverse problems)))

(defun resolve-did-case (input)
  (resolve-did-vh (jget input "did") (jget input "options")
                  :now (jget input "now") :remote (eq (jget input "remote") :true)))

(deftest didvh-resolution-vectors
  (dolist (file (directory (merge-pathnames "didvh/resolution/*.json" *vectors*)))
    (loop for c across (jget (parse-json (read-text file)) "cases")
          for problems = (did-resolution-problems (jget c "expect") (resolve-did-case (jget c "input")))
          do (is (null problems) "didvh ~a/~a: ~{~a~^; ~}" (pathname-name file) (jget c "name") problems))))

(deftest didvh-generation-vectors
  (loop for scenario across (jget (didvh-vector "generation.json") "scenarios")
        do (let ((log "") (scid "") (version-ids '()))
             (loop for step across (jget scenario "steps")
                   for i from 1
                   for create-p = (string= (jget step "op") "didvh-create")
                   for in = (if create-p (jget step "input") (replace-scid (jget step "input") scid))
                   for expect = (jget step "expect")
                   for signers = (map 'list #'make-signer (jget in "signers"))
                   do (if create-p
                          (multiple-value-bind (new-log did new-scid version-id)
                              (create-did-vh :document (jget in "document") :parameters (jget in "parameters")
                                             :version-time (jget in "versionTime") :signers signers)
                            (setf log new-log scid new-scid)
                            (push version-id version-ids)
                            (is-equal (jget expect "did") did)
                            (is-equal (jget expect "scid") new-scid))
                          (multiple-value-bind (new-log version-id)
                              (update-did-vh log :document (jget in "document") :parameters (jget in "parameters")
                                                 :version-time (jget in "versionTime") :signers signers)
                            (setf log new-log)
                            (push version-id version-ids)))
                      (is-equal (jget expect "versionId") (first version-ids))
                      (is (same (jget expect "line") (parse-json (car (last (split-log-lines log)))))
                          "~a step ~d line" (jget scenario "name") i))
             (setf version-ids (reverse version-ids))
             (let* ((witness (multiple-value-bind (spec present) (jget scenario "witness")
                               (and present
                                    (map 'vector (lambda (w)
                                                   (let ((id (nth (1- (round (jget w "step"))) version-ids)))
                                                     (make-json "versionId" id
                                                                "proof" (map 'vector (lambda (seed) (witness-proof id (make-signer seed)))
                                                                             (jget w "seeds")))))
                                         spec))))
                    (expected (jget scenario "resolve"))
                    (options (if witness (make-json "didLog" log "didWitness" witness) (make-json "didLog" log)))
                    (got (resolve-did-vh (jget expected "did") options :now (jget expected "now")))
                    (problems (did-resolution-problems
                               (make-json "didDocument" (jget expected "didDocument")
                                          "didDocumentMetadata" (jget expected "didDocumentMetadata"))
                               got)))
               (is (null problems) "didvh generation ~a resolves: ~{~a~^; ~}" (jget scenario "name") problems)))))

(deftest vh-log-ignores-did-vh-rules
  ;; Plain VH-Log keeps open parameters and no state check.
  (let* ((key (make-signer *seed-1*))
         (log (create-log :state (make-json "anything" "{SCID}")
                          :parameters (make-json "updateKeys" (vector (signer-multikey key)) "custom" 1d0)
                          :version-time "2026-01-01T00:00:00Z" :signers (list key))))
    (is (resolution-valid-p (resolve log :now *now*)))
    (let ((r (resolve log :now *now* :specialisation (did-vh-specialisation))))
      (is (not (resolution-valid-p r)))
      (is-equal "invalid-parameter" (log-error-code (resolution-error r))))))
