require resolver.fs
: wrapped { value addr len -- result } j-object { result } value result addr len put result ;
: dispatch { input op -- result }
  op s" jcs" text= if input s" text" j-get json-parse dup 0= if -400 throw then jcs s" output" wrapped exit then
  op s" hash" text= if input s" data" j-get multihash s" output" wrapped exit then
  op s" multikey" text= if input s" seed" j-get multikey s" multikey" wrapped exit then
  op s" key-hash" text= if input s" multikey" j-get multihash s" output" wrapped exit then
  op s" scid" text= if input s" entry" j-get scid s" scid" wrapped exit then
  op s" entry-hash" text= if input s" entry" j-get input s" previousVersionId" j-get entry-hash s" hash" wrapped exit then
  op s" sign" text= if input s" document" j-get input s" seed" j-get input s" verificationMethod" j-get input s" created" j-get sign-proof s" proof" wrapped exit then
  op s" verify" text= if input s" document" j-get input s" proof" j-get verify-proof j-bool s" valid" wrapped exit then
  op s" create" text= if input create-log exit then
  op s" update" text= if input update-log exit then
  op s" witness" text= if input witness-proof s" proof" wrapped exit then
  op s" resolve" text= if input resolve-log exit then
  -400 throw ;
variable request
: handle ( -- result )
  request @ obj? 0= if -400 throw then
  request @ s" input" j-get obj? 0= if -400 throw then
  request @ s" input" j-get request @ s" op" j-get dispatch ;
: respond ( -- )
  j-object { response } request @ s" id" j-get response s" id" put
  ['] handle catch dup if
    drop s" Invalid request or operation failed" str response s" error" put false j-bool response s" ok" put
  else drop response s" result" put true j-bool response s" ok" put then
  response j-write ;
: main ( -- )
  begin j-reset j-read dup while
    json-parse request ! respond
    depth if -402 throw then
  repeat drop ;
main bye
