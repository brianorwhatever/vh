require selection.fs
: scan-count ( scan -- n ) s" history" j-get j-size ;
: fully-valid? ( scan -- flag ) dup scan-count 0> swap s" error" j-get j-type 0= and ;
: scan-id { scan index -- id } scan s" entries" j-get index j-at s" versionId" j-get ;
: last-id ( scan -- id ) dup s" entries" j-get j-size 1- scan-id ;
: extend-log { input reference -- scan }
  input s" log" j-get entries-from-log { entries }
  reference s" history" j-get j-clone { history } history j-size { start }
  j-array { trusted }
  start 0 ?do trusted reference s" entries" j-get i j-at j-push loop
  entries j-size start ?do trusted entries i j-at j-push loop
  trusted to entries
  history start 1- j-at { last }
  last s" params" j-get scan-active !
  last s" entry" j-get s" versionTime" j-get timestamp scan-time !
  last s" entry" j-get s" versionId" j-get scan-previous !
  input s" now" j-get timestamp scan-now ! 0 { error }
  entries j-size start ?do
    entries i j-at scan-entry ! i 1+ scan-number !
    ['] validate-entry catch dup if
      dup -500 <> if throw then drop
      error-code @ i 1+ error-object to error leave
    then drop
    j-object { snapshot } scan-entry @ snapshot s" entry" put
    scan-active @ snapshot s" params" put scan-witness @ snapshot s" witness" put
    history snapshot j-push
  loop
  j-object { scan } entries scan s" entries" put history scan s" history" put
  error scan s" error" put scan input start witness-tail ;
: fork-copy { source id -- copy }
  j-object { copy } source copy s" source" put id copy s" versionId" put copy ;
: fork-error { version source-a id-a source-b id-b -- error }
  s" fork-detected" str version error-object { error }
  j-object { fork } version j-number fork s" version" put
  j-array { copies } copies source-a id-a fork-copy j-push copies source-b id-b fork-copy j-push
  copies fork s" copies" put fork error s" fork" put error ;
: divergence { a b -- index|-1 }
  a scan-count b scan-count min 0 ?do
    a i scan-id b i scan-id j-equal 0= if i unloop exit then
  loop -1 ;
: initial-copy { source scan status -- record }
  j-object { record } source record s" source" put scan record s" scan" put
  status record s" status" put record ;
: compare-copies { input primary -- bundle }
  j-array { records } 0 { reference } s" primary" str { reference-source }
  primary fully-valid? if primary to reference s" matching" else s" invalid" then str { status }
  records reference-source primary status initial-copy j-push
  input s" copies" j-get { copies }
  copies j-size 0 ?do
    copies i j-at { copy } copy s" source" j-get { source }
    0 { scan } s" invalid" str to status
    copy s" unavailable" j-has if s" unavailable" str to status else
      copy j-clone { request } input s" now" j-get request s" now" put
      request s" log" j-get entries-from-log { entries }
      entries j-size { count }
      false { matches }
      reference if
        count reference scan-count min 1- { at }
        at 0>= if entries at j-at s" versionId" j-get reference at scan-id j-equal to matches then
      then
      matches count reference scan-count <= and if
        \ The spec trusts the matching versionId without re-verifying this copy.
        j-object to scan entries scan s" entries" put s" matching" str to status
      else
        matches if request reference extend-log else request verify-log then to scan
        scan fully-valid? if
          reference if
            scan reference divergence { at }
            at 0>= if
              j-object { bundle }
              at 1+ reference-source reference at scan-id source scan at scan-id fork-error
              bundle s" error" put bundle unloop exit
            then
          then
          reference 0= count reference scan-count > or if scan to reference source to reference-source then
          s" matching" str to status
        then
      then
    then
    records source scan status initial-copy j-push
  loop
  reference 0= if primary to reference then
  j-object { bundle } reference bundle s" reference" put reference-source bundle s" source" put
  records bundle s" records" put bundle ;
: copy-metadata { bundle warnings -- copies count }
  bundle s" reference" j-get scan-count { length }
  bundle s" records" j-get { records } j-array { copies } 0 { count }
  records j-size 0 ?do
    records i j-at { record } record s" source" j-get { source }
    record s" scan" j-get { scan } record s" status" j-get { status }
    status s" matching" text= if
      count 1+ to count
      scan s" entries" j-get j-size length < if
        s" behind" str to status warnings s" copy-behind" str source add-warning
      else s" current" str to status then
    else
      status s" unavailable" text= if s" copy-unavailable" else s" copy-invalid" then
      str { code } warnings code source add-warning
    then
    j-object { meta } source meta s" source" put status meta s" status" put
    scan if scan last-id dup str? if meta s" versionId" put else drop then then
    copies meta j-push
  loop copies count ;
