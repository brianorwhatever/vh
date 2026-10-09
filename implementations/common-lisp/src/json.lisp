;;;; json.lisp — JSON values, an I-JSON parser, and RFC 8785 (JCS) output.
;;;;
;;;; Representation:
;;;;   object  -> JSON-OBJECT (ordered pairs, keys unique)
;;;;   array   -> simple-vector
;;;;   number  -> double-float (RFC 8785 treats every number as an IEEE-754
;;;;              double; integers are accepted on output for convenience)
;;;;   string  -> string
;;;;   true / false / null -> :TRUE / :FALSE / :NULL

(in-package #:vh-log)

;;; ------------------------------------------------------------ objects

(defstruct (json-object (:constructor %make-json-object (pairs)))
  "A JSON object. PAIRS is a list of (key . value) in insertion order."
  (pairs '() :type list))

(defun make-json (&rest keys-and-values)
  "Builds a JSON object from alternating keys and values."
  (%make-json-object (loop for (k v) on keys-and-values by #'cddr collect (cons k v))))

(defun jpairs (object) (json-object-pairs object))

(defun jkeys (object) (mapcar #'car (json-object-pairs object)))

(defun jget (object key &optional default)
  "Returns the value of KEY in OBJECT and whether it was present."
  (let ((pair (and (json-object-p object)
                   (assoc key (json-object-pairs object) :test #'string=))))
    (if pair (values (cdr pair) t) (values default nil))))

(defun jhas (object key)
  (nth-value 1 (jget object key)))

(defun jwith (object key value)
  "Returns a copy of OBJECT with KEY set to VALUE (in place if present, else appended)."
  (let ((found nil))
    (let ((pairs (loop for (k . v) in (json-object-pairs object)
                       collect (if (string= k key) (progn (setf found t) (cons k value)) (cons k v)))))
      (%make-json-object (if found pairs (append pairs (list (cons key value))))))))

(defun jwithout (object &rest keys)
  "Returns a copy of OBJECT without KEYS."
  (%make-json-object (remove-if (lambda (pair) (member (car pair) keys :test #'string=))
                                (json-object-pairs object))))

(defun json-true-p (value) (eq value :true))

;;; ------------------------------------------------------------ parsing

(define-condition json-parse-error (error)
  ((reason :initarg :reason :reader json-parse-error-reason)
   (position :initarg :position :initform nil :reader json-parse-error-position))
  (:report (lambda (c s)
             (format s "invalid JSON~@[ at ~a~]: ~a"
                     (json-parse-error-position c) (json-parse-error-reason c)))))

(defparameter *max-depth* 512
  "Nesting limit, so hostile input can't exhaust the stack.")

(defun parse-json (text &key (strict t))
  "Parses one JSON value from TEXT (RFC 8259, whitespace allowed around it).
Numbers become double-floats. Duplicate keys: the last value wins. With STRICT
(the default) the I-JSON rules of the interop profile apply: a number that is
not a finite double, or a string with a lone surrogate, is an error."
  (let ((pos 0) (end (length text)) (depth 0))
    (declare (type fixnum pos end depth) (type string text))
    (labels ((fail (reason) (error 'json-parse-error :reason reason :position pos))
             (peek () (if (< pos end) (char text pos) nil))
             (skip-ws ()
               (loop while (and (< pos end) (member (char text pos) '(#\Space #\Tab #\Newline #\Return)))
                     do (incf pos)))
             (expect (c)
               (unless (eql (peek) c) (fail (format nil "expected ~s" c)))
               (incf pos))
             (literal (word value)
               (if (and (<= (+ pos (length word)) end) (string= word text :start2 pos :end2 (+ pos (length word))))
                   (progn (incf pos (length word)) value)
                   (fail "invalid literal")))
             (value ()
               (skip-ws)
               (let ((c (peek)))
                 (case c
                   ((nil) (fail "unexpected end of input"))
                   (#\{ (nested #'object))
                   (#\[ (nested #'array))
                   (#\" (str))
                   (#\t (literal "true" :true))
                   (#\f (literal "false" :false))
                   (#\n (literal "null" :null))
                   (t (if (or (char= c #\-) (digit-p c)) (num) (fail "unexpected character"))))))
             (nested (fn)
               (when (> (incf depth) *max-depth*) (fail "nesting too deep"))
               (prog1 (funcall fn) (decf depth)))
             (object ()
               (incf pos)
               (skip-ws)
               (let ((pairs '()))
                 (if (eql (peek) #\})
                     (incf pos)
                     (loop
                       (skip-ws)
                       (unless (eql (peek) #\") (fail "expected a string key"))
                       (let ((key (str)))
                         (skip-ws)
                         (expect #\:)
                         (let* ((v (value))
                                (existing (assoc key pairs :test #'string=)))
                           (if existing
                               (setf (cdr existing) v) ; last value wins
                               (push (cons key v) pairs))))
                       (skip-ws)
                       (case (peek)
                         (#\, (incf pos))
                         (#\} (incf pos) (return))
                         (t (fail "expected , or }")))))
                 (%make-json-object (nreverse pairs))))
             (array ()
               (incf pos)
               (skip-ws)
               (let ((items '()))
                 (if (eql (peek) #\])
                     (incf pos)
                     (loop
                       (push (value) items)
                       (skip-ws)
                       (case (peek)
                         (#\, (incf pos))
                         (#\] (incf pos) (return))
                         (t (fail "expected , or ]")))))
                 (coerce (nreverse items) 'simple-vector)))
             (hex4 ()
               (when (> (+ pos 4) end) (fail "truncated \\u escape"))
               (let ((n 0))
                 (dotimes (i 4 n)
                   (let ((d (position (char text (+ pos i)) "0123456789abcdef" :test #'char-equal)))
                     (unless d (fail "bad \\u escape"))
                     (setf n (+ (* n 16) d))))))
             (lone-surrogate ()
               (if strict (fail "lone surrogate") nil))
             (str ()
               (incf pos)
               (let ((out (make-string-output-stream)))
                 (loop
                   (when (>= pos end) (fail "unterminated string"))
                   (let ((c (char text pos)))
                     (incf pos)
                     (cond
                       ((char= c #\") (return (get-output-stream-string out)))
                       ((char< c #\Space) (fail "control character in string"))
                       ((char= c #\\)
                        (when (>= pos end) (fail "unterminated escape"))
                        (let ((e (char text pos)))
                          (incf pos)
                          (case e
                            (#\" (write-char #\" out))
                            (#\\ (write-char #\\ out))
                            (#\/ (write-char #\/ out))
                            (#\b (write-char (code-char 8) out))
                            (#\f (write-char (code-char 12) out))
                            (#\n (write-char (code-char 10) out))
                            (#\r (write-char (code-char 13) out))
                            (#\t (write-char (code-char 9) out))
                            (#\u
                             (let ((u (hex4)))
                               (incf pos 4)
                               (cond
                                 ((<= #xD800 u #xDBFF)
                                  (let ((lo (and (<= (+ pos 6) end)
                                                 (char= (char text pos) #\\)
                                                 (char= (char text (1+ pos)) #\u)
                                                 (let ((saved pos))
                                                   (setf pos (+ pos 2))
                                                   (prog1 (hex4) (setf pos saved))))))
                                    (if (and lo (<= #xDC00 lo #xDFFF))
                                        (progn
                                          (incf pos 6)
                                          (write-char (code-char (+ #x10000 (ash (- u #xD800) 10) (- lo #xDC00))) out))
                                        (progn (lone-surrogate) (write-char (code-char u) out)))))
                                 ((<= #xDC00 u #xDFFF)
                                  (lone-surrogate)
                                  (write-char (code-char u) out))
                                 (t (write-char (code-char u) out)))))
                            (t (fail "bad escape")))))
                       ((and strict (<= #xD800 (char-code c) #xDFFF)) (fail "lone surrogate"))
                       (t (write-char c out)))))))
             (digits ()
               (let ((start pos))
                 (loop while (and (< pos end) (digit-p (char text pos))) do (incf pos))
                 (when (= start pos) (fail "expected a digit"))
                 (subseq text start pos)))
             (num ()
               (let ((negative nil) int frac (exponent 0))
                 (when (eql (peek) #\-) (setf negative t) (incf pos))
                 (setf int (digits))
                 (when (and (> (length int) 1) (char= (char int 0) #\0)) (fail "leading zero"))
                 (when (eql (peek) #\.)
                   (incf pos)
                   (setf frac (digits)))
                 (when (member (peek) '(#\e #\E))
                   (incf pos)
                   (let ((sign 1))
                     (case (peek) (#\+ (incf pos)) (#\- (setf sign -1) (incf pos)))
                     (setf exponent (* sign (parse-integer (digits))))))
                 (let ((d (decimal-to-double (concatenate 'string int (or frac ""))
                                             (- exponent (length (or frac ""))))))
                   (cond ((null d) (if strict (fail "number is not a finite double")
                                       (setf d most-positive-double-float)))
                         (negative (setf d (- d))))
                   d))))
      (let ((v (value)))
        (skip-ws)
        (when (< pos end) (fail "trailing characters"))
        v))))

(declaim (inline digit-p))
(defun digit-p (c) (char<= #\0 c #\9))

;;; ------------------------------------------------------------ numbers

(defun decimal-to-double (digits exponent)
  "Returns the double nearest to DIGITS × 10^EXPONENT (DIGITS a string of
decimal digits), or NIL if it overflows."
  (let* ((trimmed (string-left-trim "0" digits))
         (magnitude (+ (length trimmed) exponent)))
    (cond ((zerop (length trimmed)) 0d0)
          ((> magnitude 310) nil)
          ((< magnitude -330) 0d0)
          (t (rational-to-double (* (parse-integer trimmed) (expt 10 exponent)))))))

(defun rational-to-double (r)
  "Correctly rounded (round-half-even) conversion of a non-negative rational to
a double-float, done in exact integer arithmetic. Returns NIL on overflow."
  (if (zerop r)
      0d0
      (let* ((n (numerator r)) (d (denominator r))
             ;; Choose E so that Q = R / 2^E has 53 significant bits.
             (e (- (integer-length n) (integer-length d) 53)))
        (flet ((scaled (e) (if (minusp e) (/ (* n (ash 1 (- e))) d) (/ n (* d (ash 1 e))))))
          (loop for s = (scaled e)
                do (cond ((< s (ash 1 52)) (decf e))
                         ((>= s (ash 1 53)) (incf e))
                         (t (return))))
          (when (< e -1074) (setf e -1074)) ; subnormal: fewer significant bits
          (let ((q (round (scaled e))))     ; CL ROUND rounds ties to even
            (when (= q (ash 1 53)) (setf q (ash 1 52)) (incf e))
            (if (> (+ e 52) 1023)
                nil
                (scale-float (coerce q 'double-float) e)))))))

(defun shortest-digits (x)
  "For a positive double X, returns (values DIGITS N): the shortest digit
string that round-trips to X (closest to X when several are that short, ties
to even), and N such that X ≈ 0.DIGITS × 10^N. This is the digit choice of
ECMAScript Number::toString."
  (let* ((r (rational x))
         (n (let ((guess (floor (log x 10d0))))
              ;; Exact correction of the floating-point estimate: 10^(n-1) <= r < 10^n.
              (loop while (>= r (expt 10 (1+ guess))) do (incf guess))
              (loop while (< r (expt 10 guess)) do (decf guess))
              (1+ guess))))
    (loop for p from 1 to 17
          do (let ((s (round (* r (expt 10 (- p n)))))
                   (nn n))
               (when (= s (expt 10 p)) (setf s (expt 10 (1- p))) (incf nn))
               (when (eql (rational-to-double (* s (expt 10 (- nn p)))) x)
                 (let ((digits (string-right-trim "0" (princ-to-string s))))
                   (return-from shortest-digits (values digits nn))))))
    (error "no round-trip representation for ~a" x)))

(defun format-number (number)
  "Formats NUMBER as ECMAScript's Number::toString does (RFC 8785 §3.2.2.3)."
  (let ((x (if (typep number 'double-float) number (coerce number 'double-float))))
    (cond
      ((zerop x) "0")
      ((minusp x) (concatenate 'string "-" (format-number (- x))))
      (t
       (multiple-value-bind (digits n) (shortest-digits x)
         (let ((k (length digits)))
           (cond
             ((<= k n 21)
              (concatenate 'string digits (make-string (- n k) :initial-element #\0)))
             ((< 0 n 22)
              (concatenate 'string (subseq digits 0 n) "." (subseq digits n)))
             ((< -6 n 1)
              (concatenate 'string "0." (make-string (- n) :initial-element #\0) digits))
             (t
              (let ((e (1- n)))
                (format nil "~a~@[.~a~]e~a~d"
                        (char digits 0) (and (> k 1) (subseq digits 1)) (if (minusp e) "-" "+") (abs e)))))))))))

;;; ------------------------------------------------------------ output

(defun write-json-string (string stream)
  (write-char #\" stream)
  (loop for c across string
        for code = (char-code c)
        do (case c
             (#\" (write-string "\\\"" stream))
             (#\\ (write-string "\\\\" stream))
             (t (cond ((= code 8) (write-string "\\b" stream))
                      ((= code 9) (write-string "\\t" stream))
                      ((= code 10) (write-string "\\n" stream))
                      ((= code 12) (write-string "\\f" stream))
                      ((= code 13) (write-string "\\r" stream))
                      ((< code 32) (format stream "\\u~(~4,'0x~)" code))
                      (t (write-char c stream))))))
  (write-char #\" stream))

(defun utf16-units (string)
  "The UTF-16 code units of STRING, for RFC 8785 key ordering."
  (let ((units (make-array (length string) :adjustable t :fill-pointer 0)))
    (loop for c across string
          for code = (char-code c)
          do (if (> code #xFFFF)
                 (let ((v (- code #x10000)))
                   (vector-push-extend (+ #xD800 (ash v -10)) units)
                   (vector-push-extend (+ #xDC00 (logand v #x3FF)) units))
                 (vector-push-extend code units)))
    units))

(defun utf16< (a b)
  (let ((ua (utf16-units a)) (ub (utf16-units b)))
    (let ((m (mismatch ua ub)))
      (cond ((null m) nil)
            ((>= m (length ua)) t)
            ((>= m (length ub)) nil)
            (t (< (aref ua m) (aref ub m)))))))

(defun write-json (value stream canonical)
  (etypecase value
    (json-object
     (write-char #\{ stream)
     (let ((pairs (json-object-pairs value)))
       (when canonical
         (setf pairs (sort (copy-list pairs) #'utf16< :key #'car)))
       (loop for (pair . more) on pairs
             do (write-json-string (car pair) stream)
                (write-char #\: stream)
                (write-json (cdr pair) stream canonical)
                (when more (write-char #\, stream))))
     (write-char #\} stream))
    (string (write-json-string value stream))
    (vector
     (write-char #\[ stream)
     (loop for i from 0 below (length value)
           do (when (plusp i) (write-char #\, stream))
              (write-json (aref value i) stream canonical))
     (write-char #\] stream))
    (real (write-string (format-number value) stream))
    (symbol
     (write-string (ecase value (:true "true") (:false "false") (:null "null")) stream))))

(defun to-json (value)
  "Compact JSON text for VALUE, keeping object key order."
  (with-output-to-string (s) (write-json value s nil)))

(defun canonicalize (value)
  "RFC 8785 JSON Canonicalization Scheme text for VALUE."
  (with-output-to-string (s) (write-json value s t)))
