;;;; framework.lisp — a deliberately tiny test harness (no extra dependencies).

(defpackage #:vh-log/tests
  (:use #:cl #:vh-log)
  (:export #:run-all))

(in-package #:vh-log/tests)

(defvar *tests* '() "Registered tests, as (name . function), newest first.")
(defvar *failures*)
(defvar *checks*)

(defmacro deftest (name &body body)
  `(progn
     (setf *tests* (cons (cons ',name (lambda () ,@body)) (remove ',name *tests* :key #'car)))
     ',name))

(defun check (ok description &rest args)
  (incf *checks*)
  (unless ok
    (push (apply #'format nil description args) *failures*))
  ok)

(defmacro is (form &optional description &rest args)
  `(check ,form ,(or description (format nil "~s" form)) ,@args))

(defmacro is-equal (expected form)
  (let ((e (gensym)) (g (gensym)))
    `(let ((,e ,expected) (,g ,form))
       (check (equal ,e ,g) "~s~%      expected ~s~%      got      ~s" ',form ,e ,g))))

(defun run-all ()
  "Runs every test; prints a summary and returns true if all passed."
  (let ((passed 0) (failed 0) (checks 0))
    (dolist (test (reverse *tests*))
      (let ((*failures* '()) (*checks* 0))
        (handler-case (funcall (cdr test))
          (error (e) (push (format nil "signalled: ~a" e) *failures*)))
        (incf checks *checks*)
        (if *failures*
            (progn (incf failed)
                   (format t "~&✗ ~(~a~)~%" (car test))
                   (dolist (f (reverse *failures*)) (format t "    ~a~%" f)))
            (incf passed))))
    (format t "~&~d tests (~d checks): ~d passed, ~d failed~%" (+ passed failed) checks passed failed)
    (zerop failed)))
