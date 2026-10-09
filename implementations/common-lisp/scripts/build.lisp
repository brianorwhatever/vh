;;;; build.lisp — compiles vh-log and saves the driver executable bin/vh-log-driver.
;;;; Run from the implementation directory: sbcl --non-interactive --load scripts/build.lisp
(load "scripts/env.lisp")
(asdf:load-system "vh-log/driver")
(ensure-directories-exist "bin/")
(sb-ext:save-lisp-and-die "bin/vh-log-driver"
                          :executable t
                          :toplevel (lambda () (uiop:symbol-call :vh-log/driver :main))
                          :save-runtime-options nil)
