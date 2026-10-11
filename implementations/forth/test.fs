require resolver.fs
: assert ( flag -- ) 0= if -600 throw then ;
: check-empty-stack ( -- ) depth 0= assert ;
: test-encoding ( -- )
  0 char$ 0 char$ j-cat 1 char$ j-cat dup base58 dup s" 112" text= assert unbase58 j-equal assert
  s" 0OIl" str unbase58 0= assert
  s" z" str decode-key 0= assert
  s" abc" str multihash s" QmatYkNGZnELf8cAGdyJpUca2PyY4szai3RHyyWofNY1pY" text= assert
  \ RFC 8032 section 7.1: complete public key and empty-message signature.
  s" 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60" str j-public
  base58 s" FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z" text= assert
  empty$ s" 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60" str j-sign
  base58 s" 5awYiUvGiDFA33EJjj4TXJG44a5afJc8QjWRpGgQiu6b23jCr7yndW2fmp9ujwqJVe32J456wV3VF78Asb1obnTc" text= assert ;
: test-time ( -- )
  s" 0000-01-01T00:00:00Z" str timestamp 0= assert
  s" 0000-03-01T00:00:00Z" str timestamp 60 86400 * = assert
  s" 1900-02-29T00:00:00Z" str timestamp -1 = assert
  s" 2000-02-29T00:00:00Z" str timestamp 0>= assert
  s" 2026-01-01T00:00:00Z" str timestamp
  s" 2026-01-01T00:00:00+00:00" str timestamp = assert
  s" 2026-01-01T00:00:60Z" str timestamp -1 = assert
  s" 2026-01-01T24:00:00Z" str timestamp -1 = assert ;
: test-json ( -- )
  s\" {\"b\":1,\"a\":2,\"a\":3}" str json-parse jcs s\" {\"a\":3,\"b\":1}" text= assert
  s\" {\"n\":1e400}" str json-parse 0= assert
  s\" {\"s\":\"\\ud800\"}" str json-parse 0= assert
  s\" {\"\\ud800\":0}" str json-parse 0= assert
  s\" \"\\u0000\"" str json-parse j-size 1 = assert
  s\" {\"n\":-0}" str json-parse jcs s\" {\"n\":0}" text= assert ;
: tests ( -- )
  test-encoding check-empty-stack j-reset
  test-time check-empty-stack j-reset
  test-json check-empty-stack j-reset
  ." Forth library checks passed" cr ;
tests bye
