;;;; proof.lisp — eddsa-jcs-2022 Data Integrity proofs with did:key methods.

(in-package #:vh-log)

(defparameter +cryptosuite+ "eddsa-jcs-2022")
(defparameter +proof-type+ "DataIntegrityProof")
(defparameter +proof-purpose+ "assertionMethod")

(defclass signer ()
  ((private-key :initarg :private-key :reader signer-private-key)
   (multikey :initarg :multikey :reader signer-multikey))
  (:documentation "An Ed25519 key that can sign log entries or witness proofs."))

(defun make-signer (seed)
  "A signer from a 32-byte Ed25519 seed (RFC 8032 §5.1.5), as octets or hex."
  (let ((seed (if (stringp seed) (hex-decode seed) seed)))
    (unless (and seed (= (length seed) 32))
      (error "an Ed25519 seed must be 32 bytes"))
    (let* ((private (ironclad:make-private-key :ed25519 :x (coerce seed 'octets)))
           (public (getf (ironclad:destructure-private-key private) :y)))
      (make-instance 'signer :private-key private :multikey (ed25519-multikey public)))))

(defmethod print-object ((signer signer) stream)
  (print-unreadable-object (signer stream :type t)
    (write-string (signer-multikey signer) stream)))

(defun signer-verification-method (signer)
  "did:key:<mk>#<mk> (profile §2)."
  (let ((mk (signer-multikey signer)))
    (format nil "did:key:~a#~a" mk mk)))

(defun did-key-multikey (verification-method)
  "If VERIFICATION-METHOD is did:key:<mk>#<mk> with both halves equal, returns <mk>."
  (when (and (stringp verification-method)
             (> (length verification-method) 8)
             (string= "did:key:" verification-method :end2 8))
    (let ((hash (position #\# verification-method)))
      (when hash
        (let ((did-part (subseq verification-method 8 hash))
              (fragment (subseq verification-method (1+ hash))))
          (when (and (plusp (length did-part)) (string= did-part fragment))
            fragment))))))

(defun signing-input (document proof-config)
  "SHA-256(JCS(proofConfig)) ‖ SHA-256(JCS(document))."
  (concat-octets (sha256 (utf8 (canonicalize proof-config)))
                 (sha256 (utf8 (canonicalize document)))))

(defun sign-document (document signer &key verification-method created)
  "Returns an eddsa-jcs-2022 proof over DOCUMENT (a JSON-OBJECT). CREATED is
included only when given."
  (let* ((config (apply #'make-json
                        "type" +proof-type+
                        "cryptosuite" +cryptosuite+
                        "verificationMethod" (or verification-method (signer-verification-method signer))
                        (append (when created (list "created" created))
                                (list "proofPurpose" +proof-purpose+))))
         (signature (ironclad:sign-message (signer-private-key signer) (signing-input document config))))
    (jwith config "proofValue" (concatenate 'string "z" (base58-encode signature)))))

(defun admissible-ed25519-point-p (encoded)
  "Profile §2: canonical y and no point of order dividing 8."
  (let ((y (logand (loop for b across encoded for i from 0 sum (ash b (* 8 i)))
                   57896044618658097711785492504343953926634992332820282019728792003956564819967)))
    (and (< y 57896044618658097711785492504343953926634992332820282019728792003956564819949)
         (not (member y '(0 1 2707385501144840649318225287225658788936804267575313519463743609750303402022 55188659117513257062467267217118295137698188065244968500265048394206261417927 57896044618658097711785492504343953926634992332820282019728792003956564819948))))))

(defun proof-signature-valid-p (document proof public-key)
  "Checks the eddsa-jcs-2022 signature of PROOF over DOCUMENT for PUBLIC-KEY,
including its type, cryptosuite and proofValue form, but not proofPurpose."
  (let ((value (jget proof "proofValue")))
    (and (equal (jget proof "type") +proof-type+)
         (equal (jget proof "cryptosuite") +cryptosuite+)
         (stringp value)
         (> (length value) 1)
         (char= (char value 0) #\z)
         (let ((signature (base58-decode (subseq value 1))))
           (and signature
                (= (length signature) 64)
                (admissible-ed25519-point-p public-key)
                (admissible-ed25519-point-p (subseq signature 0 32))
                (ignore-errors
                 (ironclad:verify-signature (ironclad:make-public-key :ed25519 :y public-key)
                                            (signing-input document (jwithout proof "proofValue"))
                                            signature)))))))

(defun verify-proof (document proof &key (purpose nil))
  "True if PROOF is a valid eddsa-jcs-2022 proof over DOCUMENT by the key its
did:key verificationMethod names. With PURPOSE, proofPurpose must equal it.
No authorisation check is made."
  (when (json-object-p proof)
    (let* ((mk (did-key-multikey (jget proof "verificationMethod")))
           (public-key (and mk (decode-ed25519-multikey mk))))
      (and public-key
           (or (null purpose) (equal (jget proof "proofPurpose") purpose))
           (proof-signature-valid-p document proof public-key)
           t))))
