require crypto.fs
: placeholder ( -- string ) s" {SCID}" str ;
: signed-entry { entry signers -- entry }
  j-array { proofs }
  signers j-size 0 ?do
    proofs entry signers i j-at 0 entry s" versionTime" j-get sign-proof j-push
  loop proofs entry s" proof" put entry ;
: new-entry { input -- entry }
  j-object { entry }
  input s" versionTime" j-get entry s" versionTime" put
  input s" state" j-get entry s" state" put
  input s" parameters" j-get dup 0= if drop j-object then entry s" parameters" put entry ;
: version-id { n hash -- string } n integer$ s" -" str j-cat hash j-cat ;
: log-lines { text -- array|0 }
  text str? 0= if 0 exit then
  text 10 char$ j-split { lines } j-array { entries }
  lines j-size 0 ?do
    lines i j-at { line }
    line j-size 0<> if
      line json-parse { entry } entry obj? 0= if 0 unloop exit then
      entries entry j-push
    then
  loop entries j-size 0= if 0 else entries then ;
: create-log { input -- result }
  input new-entry { entry } entry s" parameters" j-get { params }
  params obj? 0= if -400 throw then
  params s" scid" j-has 0= if placeholder params s" scid" put then
  params s" logVersion" j-has 0= if s" vh-log:1.0" str params s" logVersion" put then
  params entry s" parameters" put placeholder entry s" versionId" put
  entry scid { id }
  entry j-dump placeholder id j-replace json-parse to entry
  1 entry id entry-hash version-id { version }
  version entry s" versionId" put
  entry input s" signers" j-get signed-entry j-dump 10 char$ j-cat { log }
  j-object { result } log result s" log" put id result s" scid" put
  version result s" versionId" put result ;
: update-log { input -- result }
  input s" log" j-get { log } log log-lines { entries }
  entries 0= if -400 throw then
  entries entries j-size 1- j-at s" versionId" j-get { previous }
  input new-entry { entry }
  entries j-size 1+ entry previous entry-hash version-id { version }
  version entry s" versionId" put
  log log j-size 1- 1 j-slice 10 char$ j-equal 0= if log 10 char$ j-cat to log then
  log entry input s" signers" j-get signed-entry j-dump j-cat 10 char$ j-cat to log
  j-object { result } log result s" log" put version result s" versionId" put result ;
: witness-proof { input -- proof }
  j-object { doc } input s" versionId" j-get doc s" versionId" put
  doc input s" seed" j-get 0 input s" created" j-get sign-proof ;
