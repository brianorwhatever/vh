;;;; encoding.lisp — hex, base58btc, multihash and Ed25519 multikeys.

(in-package #:vh-log)

(deftype octets (&optional (n '*)) `(simple-array (unsigned-byte 8) (,n)))

(defun octets (&rest bytes)
  (coerce bytes 'octets))

(defun concat-octets (&rest vectors)
  (apply #'concatenate 'octets vectors))

(defun utf8 (string)
  "UTF-8 bytes of STRING."
  (coerce (sb-ext:string-to-octets string :external-format :utf-8) 'octets))

;;; ------------------------------------------------------------ hex

(defun hex-decode (string)
  "Decodes an even-length hex string; returns NIL if it isn't one."
  (when (and (stringp string) (evenp (length string)))
    (let ((out (make-array (/ (length string) 2) :element-type '(unsigned-byte 8))))
      (dotimes (i (length out) out)
        (let ((hi (position (char string (* 2 i)) "0123456789abcdef" :test #'char-equal))
              (lo (position (char string (1+ (* 2 i))) "0123456789abcdef" :test #'char-equal)))
          (unless (and hi lo) (return nil))
          (setf (aref out i) (+ (* 16 hi) lo)))))))

(defun hex-encode (octets)
  (with-output-to-string (s)
    (loop for b across octets do (format s "~(~2,'0x~)" b))))

;;; ------------------------------------------------------------ base58btc

(defparameter +base58-alphabet+ "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

(defun base58-encode (octets)
  "Bitcoin-alphabet base58 of OCTETS, without a multibase prefix."
  (let* ((zeros (or (position-if #'plusp octets) (length octets)))
         (n (loop with n = 0 for b across octets do (setf n (+ (* n 256) b)) finally (return n)))
         (digits '()))
    (loop while (plusp n)
          do (multiple-value-bind (q r) (floor n 58)
               (push (char +base58-alphabet+ r) digits)
               (setf n q)))
    (concatenate 'string (make-string zeros :initial-element #\1) (coerce digits 'string))))

(defun base58-decode (string)
  "Decodes base58btc; returns NIL if STRING has a character outside the alphabet."
  (when (stringp string)
    (let ((n 0) (zeros 0) (leading t))
      (loop for c across string
            for d = (position c +base58-alphabet+)
            do (unless d (return-from base58-decode nil))
               (if (and leading (zerop d))
                   (incf zeros)
                   (setf leading nil))
               (setf n (+ (* n 58) d)))
      (let ((bytes '()))
        (loop while (plusp n)
              do (push (ldb (byte 8 0) n) bytes)
                 (setf n (ash n -8)))
        (concat-octets (make-array zeros :element-type '(unsigned-byte 8) :initial-element 0)
                       (coerce bytes 'octets))))))

;;; ------------------------------------------------------------ hashes

(defun sha256 (octets) (ironclad:digest-sequence :sha256 octets))
(defun sha512 (octets) (ironclad:digest-sequence :sha512 octets))

(defparameter +multihash-codes+ '((:sha-256 #x12 32) (:sha-512 #x13 64))
  "Multihash codes this library can produce or recognise. Only SHA-256 is
permitted by vh-log:1.0.")

(defun multihash (octets &optional (algorithm :sha-256))
  "The multihash (code ‖ length ‖ digest) of OCTETS. Both codes fit in one varint byte."
  (destructuring-bind (code length) (rest (assoc algorithm +multihash-codes+))
    (let ((digest (ecase algorithm (:sha-256 (sha256 octets)) (:sha-512 (sha512 octets)))))
      (assert (= length (length digest)))
      (concat-octets (octets code length) digest))))

(defun decode-multihash (string)
  "Decodes a base58btc multihash string. Returns (values ALGORITHM DIGEST),
ALGORITHM being :SHA-256, :SHA-512 or :UNKNOWN; or NIL if STRING is not base58."
  (let ((bytes (base58-decode string)))
    (when bytes
      (let ((known (and (>= (length bytes) 2)
                        (find-if (lambda (spec)
                                   (and (= (aref bytes 0) (second spec))
                                        (= (aref bytes 1) (third spec))
                                        (= (length bytes) (+ 2 (third spec)))))
                                 +multihash-codes+))))
        (if known
            (values (first known) (subseq bytes 2))
            (values :unknown bytes))))))

(defun hash-string (string &optional (algorithm :sha-256))
  "base58btc(multihash(utf8(STRING))). Entry hashes, SCIDs and key hashes are all this."
  (base58-encode (multihash (utf8 string) algorithm)))

;;; ------------------------------------------------------------ multikeys

(defun ed25519-multikey (public-key)
  "Multikey for a 32-byte Ed25519 public key: \"z\" + base58btc(0xed 0x01 ‖ key)."
  (concatenate 'string "z" (base58-encode (concat-octets (octets #xed #x01) public-key))))

(defun decode-ed25519-multikey (multikey)
  "Returns the 32-byte public key of an Ed25519 multikey, or NIL if MULTIKEY isn't one."
  (when (and (stringp multikey) (> (length multikey) 1) (char= (char multikey 0) #\z))
    (let ((bytes (base58-decode (subseq multikey 1))))
      (when (and bytes (= (length bytes) 34) (= (aref bytes 0) #xed) (= (aref bytes 1) #x01)
                 ;; Reject non-canonical encodings (e.g. extra leading '1's).
                 (string= multikey (ed25519-multikey (subseq bytes 2))))
        (subseq bytes 2)))))

(defun key-hash (multikey)
  "Pre-rotation hash of a multikey: the multikey *string* is hashed (profile §1)."
  (hash-string multikey))
