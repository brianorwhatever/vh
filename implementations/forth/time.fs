require json.fs
: digits { text -- n|-1 }
  text str? text j-size 0> and 0= if -1 exit then
  0 { value }
  text j-size 0 ?do
    text j-data i + c@ [char] 0 - { digit }
    digit 0 10 within 0= if -1 unloop exit then
    value 900719925474099 > if -1 unloop exit then
    value 10 * digit + to value
  loop value ;
: leap? ( year -- flag ) dup 400 mod 0= swap dup 4 mod 0= swap 100 mod 0<> and or ;
: month-days { year month -- n }
  month 2 = if year leap? if 29 else 28 then exit then
  month 4 = month 6 = or month 9 = or month 11 = or if 30 else 31 then ;
: timestamp { text -- seconds|-1 }
  text str? 0= if -1 exit then
  text j-size 20 = if
    text 19 1 j-slice s" Z" text= 0= if -1 exit then
  else text j-size 25 <> if -1 exit then
    text 19 6 j-slice s" +00:00" text= 0= if -1 exit then
  then
  text 4 1 j-slice s" -" text= text 7 1 j-slice s" -" text= and
  text 10 1 j-slice s" T" text= and text 13 1 j-slice s" :" text= and
  text 16 1 j-slice s" :" text= and 0= if -1 exit then
  text 0 4 j-slice digits { y } text 5 2 j-slice digits { m }
  text 8 2 j-slice digits { d } text 11 2 j-slice digits { h }
  text 14 2 j-slice digits { minute } text 17 2 j-slice digits { second }
  y 0< m 1 13 within 0= or if -1 exit then
  d 1 y m month-days 1+ within h 0 24 within and
  minute 0 60 within and second 0 60 within and 0= if -1 exit then
  y 365 * y 3 + 4 / + y 99 + 100 / - y 399 + 400 / + { days }
  m 1 ?do days y i month-days + to days loop
  days d 1- + 86400 * h 3600 * + minute 60 * + second + ;
