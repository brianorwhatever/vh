;;;; vh-log.asd — VH-Log (Verifiable History Log) for Common Lisp.

(defsystem "vh-log"
  :description "VH-Log: create, update, witness, verify and resolve Verifiable History Logs."
  :version "0.1.0"
  :license "MIT"
  :depends-on ("ironclad/digest/sha256"
               "ironclad/digest/sha512"
               "ironclad/public-key/ed25519")
  :pathname "src/"
  :serial t
  :components ((:file "package")
               (:file "json")
               (:file "encoding")
               (:file "time")
               (:file "proof")
               (:file "log")
               (:file "resolve"))
  :in-order-to ((test-op (test-op "vh-log/tests"))))

(defsystem "vh-log/driver"
  :description "JSON Lines driver for the vh interop harness."
  :depends-on ("vh-log")
  :pathname "src/"
  :components ((:file "driver")))

(defsystem "vh-log/tests"
  :description "Unit tests and shared-vector tests for vh-log."
  :depends-on ("vh-log")
  :pathname "tests/"
  :serial t
  :components ((:file "framework")
               (:file "unit")
               (:file "vectors"))
  :perform (test-op (o c)
             (unless (uiop:symbol-call :vh-log/tests :run-all)
               (error "vh-log tests failed"))))
