require validation.fs
: witness-file? { file -- flag }
  file arr? 0= if false exit then
  file j-size 0 ?do
    file i j-at { record }
    record obj? record s" versionId" j-get str? and
    record s" proof" j-get arr? and 0= if false unloop exit then
  loop true ;
: entry-index { entries id -- index|-1 }
  entries j-size 0 ?do entries i j-at s" versionId" j-get id j-equal if i unloop exit then loop -1 ;
: approved? { config file entries index -- flag }
  j-array { approvals } config s" witnesses" j-get { witnesses }
  file j-size 0 ?do
    file i j-at { record } record s" versionId" j-get { id }
    entries id entry-index index >= if
      j-object { doc } id doc s" versionId" put
      record s" proof" j-get { proofs }
      proofs j-size 0 ?do
        proofs i j-at { proof } proof proof-key { key }
        key if
          s" did:key:" str key j-cat j-nfc { witness-id }
          false { listed }
          witnesses j-size 0 ?do
            witnesses i j-at s" id" j-get j-nfc witness-id j-equal if true to listed then
          loop
          listed approvals witness-id contains? 0= and if
            doc proof verify-proof if approvals witness-id j-push then
          then
        then
      loop
    then
  loop approvals j-size config s" threshold" j-get j-integer >= ;
: witness-tail { scan input start -- scan }
  \ The witness pass runs only if the entire entry pass succeeded.
  scan s" error" j-get j-type 0<> if scan exit then
  scan s" history" j-get { history } scan s" entries" j-get { entries }
  input s" witness" j-get { file }
  history j-size start ?do
    history i j-at s" witness" j-get { config }
    config j-size if
      0 { code }
      input s" witness" j-has if
        file witness-file? 0= if s" invalid-witness-file" str to code then
      then
      code 0= if config file entries i approved? 0= if s" witness-threshold-not-met" str to code then then
      code if
        code i 1+ error-object scan s" error" put
        j-array { prefix } i 0 ?do prefix history i j-at j-push loop
        prefix scan s" history" put leave
      then
    then
  loop scan ;
: verify-log ( input -- scan ) dup scan-log swap 0 witness-tail ;
