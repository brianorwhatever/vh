require copies.fs
: resolve-log { input -- result }
  input s" options" j-get { options } options options? 0= if s" invalid-option" fail-code exit then
  input verify-log { primary } input primary compare-copies { bundle }
  bundle s" error" j-get dup if failure exit then drop
  bundle s" reference" j-get { reference } j-array { warnings }
  bundle warnings copy-metadata { copies count }
  \ Ordinary single-copy partial validity uses invalid-entries, not copy-invalid.
  input s" copies" j-get j-size 0= if j-array to warnings then
  options s" minCopies" j-get dup if j-integer else drop 1 then { minimum }
  count minimum < minimum 1 > and if s" min-copies-not-met" fail-code exit then
  input s" retainedVersionId" j-get { retained }
  retained if
    retained version-parts drop { number }
    number reference scan-count > if
      warnings s" retained-version-not-found" str 0 add-warning
    else number 0> if
      reference number 1- scan-id { id }
      id retained j-equal 0= if
        number bundle s" source" j-get id s" retained" str retained fork-error failure exit
      then
    then then
  then
  reference options warnings resolve-scan { result }
  result s" valid" j-get j-truth input s" copies" j-get j-size 0> and if
    result s" metadata" j-get { meta } copies meta s" copies" put meta result s" metadata" put
  then result ;
