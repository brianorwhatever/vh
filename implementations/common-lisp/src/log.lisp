;;;; log.lisp — SCID and entry hashes, and the Log Controller operations.

(in-package #:vh-log)

(defparameter +log-version+ "vh-log:1.0")
(defparameter +scid-placeholder+ "{SCID}")

(defun split-log-lines (text)
  "Splits JSON Lines TEXT on #\\Newline only (never U+2028/U+2029 or CR). A
final newline does not start another line."
  (let ((lines '()) (start 0))
    (loop for nl = (position #\Newline text :start start)
          while nl
          do (push (subseq text start nl) lines)
             (setf start (1+ nl)))
    (when (< start (length text))
      (push (subseq text start) lines))
    (nreverse lines)))

(defun replace-all (string old new)
  (with-output-to-string (out)
    (loop with start = 0
          for hit = (search old string :start2 start)
          do (write-string string out :start start :end (or hit (length string)))
             (if hit
                 (progn (write-string new out) (setf start (+ hit (length old))))
                 (return)))))

(defun compute-scid (preliminary-entry)
  "SCID of a preliminary first entry (versionId \"{SCID}\", no proof)."
  (hash-string (canonicalize preliminary-entry)))

(defun entry-hash (entry previous-version-id)
  "Entry hash: the entry without its proof, with versionId set to the
predecessor's versionId (the SCID for the first entry)."
  (hash-string (canonicalize (jwith (jwithout entry "proof") "versionId" previous-version-id))))

(defun ordered-entry (version-id version-time parameters state &optional proof)
  "An entry with fields in the profile's order (profile §5)."
  (apply #'make-json "versionId" version-id "versionTime" version-time
         "parameters" parameters "state" state
         (when proof (list "proof" proof))))

(defun sign-entry (entry signers created)
  (coerce (loop for signer in signers
                collect (sign-document entry signer :created created))
          'simple-vector))

(defun create-log (&key state parameters version-time signers)
  "Creates a log (spec: Create). STATE and PARAMETERS may contain the
\"{SCID}\" placeholder; \"scid\" and \"logVersion\" are added when absent.
SIGNERS each add one proof. Generators don't check semantics (profile §5).
Returns (values LOG-TEXT SCID VERSION-ID)."
  (let* ((parameters (or parameters (make-json)))
         (parameters (if (jhas parameters "logVersion") parameters (jwith parameters "logVersion" +log-version+)))
         (parameters (if (jhas parameters "scid") parameters (jwith parameters "scid" +scid-placeholder+)))
         (preliminary (ordered-entry +scid-placeholder+ version-time parameters (or state (make-json))))
         (scid (compute-scid preliminary))
         ;; A literal text replacement on the serialised entry, as the spec says.
         (entry (parse-json (replace-all (to-json preliminary) +scid-placeholder+ scid)))
         (version-id (format nil "1-~a" (entry-hash entry scid)))
         (entry (jwith entry "versionId" version-id))
         (line (to-json (jwith entry "proof" (sign-entry entry signers version-time)))))
    (values (format nil "~a~%" line) scid version-id)))

(defun last-entry (log-text)
  (let ((lines (remove "" (split-log-lines log-text) :test #'string=)))
    (when (null lines) (error "the log is empty"))
    (parse-json (car (last lines)))))

(defun version-number (version-id)
  "The integer before the dash of VERSION-ID, or NIL."
  (let ((dash (and (stringp version-id) (position #\- version-id))))
    (when (and dash (plusp dash) (every #'digit-p (subseq version-id 0 dash)))
      (parse-integer version-id :end dash))))

(defun update-log (log-text &key state parameters version-time signers)
  "Appends an entry to LOG-TEXT (spec: Update), chained to its last line.
Returns (values NEW-LOG-TEXT VERSION-ID)."
  (let* ((previous (jget (last-entry log-text) "versionId"))
         (number (1+ (or (version-number previous) (error "the last entry has no valid versionId"))))
         (entry (ordered-entry previous version-time (or parameters (make-json)) (or state (make-json))))
         (version-id (format nil "~d-~a" number (entry-hash entry previous)))
         (entry (jwith entry "versionId" version-id))
         (line (to-json (jwith entry "proof" (sign-entry entry signers version-time))))
         (base (if (or (zerop (length log-text))
                       (char= (char log-text (1- (length log-text))) #\Newline))
                   log-text
                   (format nil "~a~%" log-text))))
    (values (format nil "~a~a~%" base line) version-id)))

(defun witness-proof (version-id signer &key created)
  "A witness's approval of VERSION-ID: a proof over {\"versionId\": …} (profile §3)."
  (sign-document (make-json "versionId" version-id) signer :created created))
