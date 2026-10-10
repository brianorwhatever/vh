require witness.fs
: add-warning { warnings code source -- }
  j-object { warning } code warning s" code" put code warning s" message" put
  source if source warning s" source" put then warnings warning j-push ;
: options? { options -- flag }
  options 0= if true exit then options obj? 0= if false exit then
  options j-keys { keys } 0 { selectors }
  keys j-size 0 ?do
    keys i j-at { key }
    key s" versionId" text= key s" versionTime" text= or key s" versionNumber" text= or if
      selectors 1+ to selectors
    else key s" minCopies" text= 0= if false unloop exit then then
  loop selectors 1 > if false exit then
  options s" versionId" j-has if options s" versionId" j-get str? 0= if false exit then then
  options s" versionTime" j-has if options s" versionTime" j-get timestamp 0< if false exit then then
  options s" versionNumber" j-has if
    options s" versionNumber" j-get dup j-integral swap j-integer 0> and 0= if false exit then
  then
  options s" minCopies" j-has if
    options s" minCopies" j-get dup j-integral swap j-integer 0> and 0= if false exit then
  then true ;
: select-index { scan options -- index|-1 }
  scan s" entries" j-get { entries }
  options s" versionNumber" j-has if options s" versionNumber" j-get j-integer 1- exit then
  options s" versionId" j-has if entries options s" versionId" j-get entry-index exit then
  options s" versionTime" j-has if
    options s" versionTime" j-get timestamp { target } -1 { selected }
    entries j-size 0 ?do
      entries i j-at s" versionTime" j-get timestamp { instant }
      instant 0>= instant target <= and if i to selected then
    loop selected exit
  then scan s" history" j-get j-size 1- ;
: copy-field { source dest addr len -- } source addr len j-get dest addr len put ;
: resolve-scan { scan options warnings -- result }
  scan s" history" j-get { history } scan s" error" j-get { error }
  history j-size 0= if error failure exit then
  scan options select-index { index }
  index history j-size >= error j-type 0<> and if error failure exit then
  index 0< index history j-size >= or if s" not-found" fail-code exit then
  history index j-at { chosen } chosen s" entry" j-get { entry }
  chosen s" params" j-get { params }
  history history j-size 1- j-at { last }
  last s" entry" j-get { last-entry } last s" params" j-get { latest }
  j-object { meta }
  entry meta s" versionId" copy-field entry meta s" versionTime" copy-field
  index 1+ j-number meta s" versionNumber" put
  history 0 j-at s" entry" j-get s" versionTime" j-get meta s" created" put
  last-entry s" versionTime" j-get meta s" updated" put
  latest meta s" scid" copy-field latest meta s" deactivated" copy-field
  latest meta s" ttl" copy-field latest meta s" watchers" copy-field
  latest s" witness" j-get dup j-size 0= if drop 0 then meta s" witness" put
  params meta s" updateKeys" copy-field params meta s" nextKeyHashes" copy-field
  error j-type 0<> if warnings s" invalid-entries" str 0 add-warning then
  warnings meta s" warnings" put
  j-object { result } true j-bool result s" valid" put
  entry s" state" j-get result s" state" put meta result s" metadata" put
  error result s" error" put error s" version" j-get result s" firstInvalidVersion" put result ;
