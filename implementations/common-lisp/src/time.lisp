;;;; time.lisp — versionTime parsing (profile §4).

(in-package #:vh-log)

(defun days-from-civil (year month day)
  "Days since 1970-01-01 in the proleptic Gregorian calendar (any year)."
  (let* ((y (if (<= month 2) (1- year) year))
         (era (floor y 400))
         (yoe (- y (* era 400)))
         (doy (+ (floor (+ (* 153 (+ month (if (> month 2) -3 9))) 2) 5) (1- day)))
         (doe (+ (* yoe 365) (floor yoe 4) (- (floor yoe 100)) doy)))
    (+ (* era 146097) doe -719468)))

(defun leap-year-p (year)
  (and (zerop (mod year 4)) (or (plusp (mod year 100)) (zerop (mod year 400)))))

(defun days-in-month (year month)
  (case month
    (2 (if (leap-year-p year) 29 28))
    ((4 6 9 11) 30)
    (t 31)))

(defun parse-version-time (string)
  "Parses YYYY-MM-DDTHH:MM:SSZ or YYYY-MM-DDTHH:MM:SS+00:00 (whole seconds,
UTC, a real calendar date, no leap second) and returns seconds since the Unix
epoch, or NIL if STRING is not in that form."
  (when (stringp string)
    (let ((len (length string)))
      (flet ((num (start end)
               (loop with n = 0
                     for i from start below end
                     for c = (char string i)
                     do (if (digit-p c) (setf n (+ (* n 10) (- (char-code c) 48))) (return nil))
                     finally (return n)))
             (at (i c) (char= (char string i) c)))
        (when (and (or (and (= len 20) (at 19 #\Z))
                       (and (= len 25) (string= "+00:00" string :start2 19)))
                   (at 4 #\-) (at 7 #\-) (at 10 #\T) (at 13 #\:) (at 16 #\:))
          (let ((year (num 0 4)) (month (num 5 7)) (day (num 8 10))
                (hour (num 11 13)) (minute (num 14 16)) (second (num 17 19)))
            (when (and year month day hour minute second
                       (<= 1 month 12) (<= 1 day (days-in-month year month))
                       (<= hour 23) (<= minute 59) (<= second 59))
              (+ (* 86400 (days-from-civil year month day)) (* 3600 hour) (* 60 minute) second))))))))
