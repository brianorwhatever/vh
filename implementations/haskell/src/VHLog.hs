module VHLog (dispatch, resolve, create, update, sign, verify, scid, entryHash, signingInput) where

import Control.Monad (foldM, unless, when)
import qualified Crypto as C
import qualified Data.ByteString as B
import Data.List (find, findIndex, intercalate, isPrefixOf)
import qualified Data.Map.Strict as M
import Data.Maybe (fromMaybe, isJust, listToMaybe, mapMaybe)
import qualified Data.Set as S
import Data.Time.Calendar (fromGregorianValid, toModifiedJulianDay)
import Json
import Text.Read (readMaybe)

type Result a = Either J a

err :: String -> Int -> J
err code n = object [("code", str code), ("version", if n == 0 then Null else num n), ("message", str code)]

failAt code n = Left (err code n)

ensure condition code n = unless condition (failAt code n)

strings v = isArray v && all isString (items v)

defaulted v k d = if has v k then get v k else d

checkHash v = case if isString v then C.decode (text v) else Nothing of
  Nothing -> "not-base58"
  Just b
    | B.length b == 34 && B.take 2 b == B.pack [0x12, 0x20] -> "ok"
    | otherwise -> "unsupported-algorithm"

validKey v = isString v && isJust (C.publicKey (text v))

methodKey v = do
  let s = text v
  if not ("did:key:" `isPrefixOf` s)
    then Nothing
    else do
      let (a, b) = break (== '#') (drop 8 s)
      if b == '#' : a && isJust (C.publicKey a) then Just a else Nothing

signingInput :: J -> J -> B.ByteString
signingInput document config = C.sha (jcs config) <> C.sha (jcs document)

sign :: J -> String -> J -> J
sign document seed options = set config "proofValue" (str ("z" ++ C.encode (C.signBytes seed (signingInput document config))))
  where
    mk = C.multikey seed
    config = object $ [("type", str "DataIntegrityProof"), ("cryptosuite", str "eddsa-jcs-2022"), ("verificationMethod", defaulted options "verificationMethod" (str ("did:key:" ++ mk ++ "#" ++ mk))), ("proofPurpose", str "assertionMethod")] ++ [("created", get options "created") | has options "created"]

verify :: J -> J -> Bool
verify document proof = fromMaybe False $ do
  unlessMaybe (get proof "type" == str "DataIntegrityProof" && get proof "cryptosuite" == str "eddsa-jcs-2022" && get proof "proofPurpose" == str "assertionMethod")
  mk <- methodKey (get proof "verificationMethod")
  let value = text (get proof "proofValue")
  unlessMaybe ("z" `isPrefixOf` value)
  signature <- C.decode (drop 1 value)
  key <- C.publicKey mk
  pure (C.verifyBytes key (signingInput document (remove proof "proofValue")) signature)
  where
    unlessMaybe True = Just (); unlessMaybe False = Nothing

scid :: J -> String
scid e = C.hash (jcs (remove e "proof"))

entryHash :: J -> String -> String
entryHash e previous = C.hash (jcs (set (remove e "proof") "versionId" (str previous)))

replace old new s
  | null old = s
  | null s = ""
  | old `isPrefixOf` s = new ++ replace old new (drop (length old) s)
  | otherwise = head s : replace old new (tail s)

logLines "" = []
logLines s = let (a, b) = break (== '\n') s in a : if null b then [] else logLines (tail b)

parseUnsafe s = either error id (parse s)

create :: J -> J
create input = object [("log", str (jcs signed ++ "\n")), ("scid", str identifier), ("versionId", get entry "versionId")]
  where
    p = foldl (\a (k, v) -> set a k v) (object [("logVersion", str "vh-log:1.0"), ("scid", str "{SCID}")]) (fields (get input "parameters"))
    preliminary = object [("versionId", str "{SCID}"), ("versionTime", get input "versionTime"), ("parameters", p), ("state", get input "state")]
    identifier = scid preliminary
    restored = parseUnsafe (replace "{SCID}" identifier (jcs preliminary))
    entry = set restored "versionId" (str ("1-" ++ entryHash restored identifier))
    signed = set entry "proof" (array [sign entry (text s) (object [("created", get input "versionTime")]) | s <- items (get input "signers")])

update :: J -> J
update input = object [("log", str (old ++ (if last old == '\n' then "" else "\n") ++ jcs signed ++ "\n")), ("versionId", get entry "versionId")]
  where
    old = text (get input "log")
    previous = text (get (parseUnsafe (last (logLines old))) "versionId")
    preliminary = object [("versionId", str previous), ("versionTime", get input "versionTime"), ("parameters", defaulted input "parameters" (object [])), ("state", get input "state")]
    n = read (takeWhile (/= '-') previous) :: Integer
    entry = set preliminary "versionId" (str (show (n + 1) ++ "-" ++ entryHash preliminary previous))
    signed = set entry "proof" (array [sign entry (text s) (object [("created", get input "versionTime")]) | s <- items (get input "signers")])

time v = do
  let s = text v
  if length s `notElem` [20, 25] || drop 19 s `notElem` ["Z", "+00:00"]
    then Nothing
    else do
      let parts = [take 4 s, take 2 (drop 5 s), take 2 (drop 8 s), take 2 (drop 11 s), take 2 (drop 14 s), take 2 (drop 17 s)]
      if map (s !!) [4, 7, 10, 13, 16] /= "--T::" || not (all (all (`elem` ['0' .. '9'])) parts)
        then Nothing
        else do
          ns <- traverse readMaybe parts :: Maybe [Integer]
          case ns of
            [y, mo, d, h, mi, se] -> do
              day <- fromGregorianValid y (fromInteger mo) (fromInteger d)
              if h > 23 || mi > 59 || se > 59 then Nothing else Just (toModifiedJulianDay day * 86400 + h * 3600 + mi * 60 + se)
            _ -> Nothing

parameters raw previous n = do
  ensure (all ((/= Null) . snd) (fields raw)) "invalid-parameter" n
  ensure ((isJust previous || has raw "logVersion") && (not (has raw "logVersion") || get raw "logVersion" == str "vh-log:1.0")) "unsupported-log-version" n
  ensure (case previous of Just _ -> not (has raw "scid"); Nothing -> isString (get raw "scid") && has raw "updateKeys") "invalid-parameter" n
  when (has raw "updateKeys") $ ensure (strings (get raw "updateKeys") && all validKey (items (get raw "updateKeys"))) "invalid-parameter" n
  when (has raw "nextKeyHashes") $ ensure (strings (get raw "nextKeyHashes") && all ((== "ok") . checkHash) (items (get raw "nextKeyHashes"))) "invalid-parameter" n
  let initial = fromMaybe (object [("nextKeyHashes", array []), ("witness", Null), ("watchers", array []), ("ttl", num 3600)]) previous
      merged = foldl (\p k -> if has raw k then set p k (get raw k) else p) initial ["logVersion", "scid", "updateKeys", "nextKeyHashes", "witness", "watchers", "ttl"]
      p = set merged "deactivated" (defaulted raw "deactivated" (Boolean False))
  p' <-
    if not (has raw "witness")
      then pure p
      else do
        let w = get raw "witness"
        ensure (isObject w) "invalid-parameter" n
        if null (fields w)
          then pure (set p "witness" Null)
          else do
            let ws = get w "witnesses"
                threshold = get w "threshold"
                ids = map (text . (`get` "id")) (items ws)
                validWitness x = let id = get x "id" in isString id && "did:key:" `isPrefixOf` text id && isJust (C.publicKey (drop 8 (text id)))
            ensure (isArray ws && not (null (items ws)) && all validWitness (items ws)) "invalid-parameter" n
            ensure (S.size (S.fromList ids) == length ids && integer threshold && number threshold >= 1 && number threshold <= fromIntegral (length ids)) "invalid-parameter" n
            pure (set p "witness" (object [("threshold", threshold), ("witnesses", ws)]))
  let watchers = get raw "watchers"
      url v =
        let s = text v; authority = if "https://" `isPrefixOf` s then drop 8 s else if "http://" `isPrefixOf` s then drop 7 s else ""
         in all (\c -> c >= '!' && c <= '~') s && not (null authority) && head authority `notElem` "/?#"
  when (has raw "watchers") $ ensure (strings watchers && all url (items watchers)) "invalid-parameter" n
  ensure (get p' "deactivated" `elem` [Boolean True, Boolean False] && integer (get p' "ttl") && number (get p' "ttl") >= 0 && number (get p' "ttl") <= 2147483648) "invalid-parameter" n
  case previous of
    Just old | not (null (items (get old "nextKeyHashes"))) -> do
      ensure (has raw "updateKeys" && has raw "nextKeyHashes") "prerotation-violation" n
      ensure (all (\k -> str (C.hash (text k)) `elem` items (get old "nextKeyHashes")) (items (get raw "updateKeys"))) "prerotation-violation" n
    _ -> pure ()
  pure p'

data Entry = Entry {entry :: J, params :: J, version :: Int, instant :: Integer, rule :: J} deriving (Show)

data Log = Log {entries :: [Entry], rawLines :: [String], failure :: Maybe J} deriving (Show)

verifyEntry e previous now = do
  let n = maybe 1 ((+ 1) . version) previous
  ensure (maybe True ((/= Boolean True) . (`get` "deactivated") . params) previous) "entry-after-deactivation" n
  ensure (map fst (fields e) == ["parameters", "proof", "state", "versionId", "versionTime"] && isString (get e "versionId") && isString (get e "versionTime") && isObject (get e "parameters") && isObject (get e "state") && isArray (get e "proof")) "invalid-entry" n
  p <- parameters (get e "parameters") (params <$> previous) n
  let keys = case previous of Just old | null (items (get (params old) "nextKeyHashes")) -> get (params old) "updateKeys"; _ -> get p "updateKeys"
      witnessRule = case previous of Just old | not (has (get e "parameters") "witness" && get (params old) "witness" == Null) -> get (params old) "witness"; _ -> get p "witness"
  ensure (not (null (items (get e "proof")))) "invalid-proof" n
  mapM_
    ( \proof -> do
        mk <- maybe (failAt "invalid-proof" n) Right (methodKey (get proof "verificationMethod"))
        ensure (str mk `elem` items keys) "unauthorized-key" n
        ensure (verify (remove e "proof") proof) "invalid-proof" n
    )
    (items (get e "proof"))
  let (ns, rest) = break (== '-') (text (get e "versionId")); h = drop 1 rest
  ensure (not (null ns) && head ns `elem` ['1' .. '9'] && all (`elem` ['0' .. '9']) ns && (readMaybe ns :: Maybe Integer) == Just (fromIntegral n) && not (null h) && '-' `notElem` h) "invalid-version-id" n
  let status = checkHash (str h)
  ensure (status /= "not-base58") "invalid-version-id" n
  ensure (status == "ok") "invalid-hash-algorithm" n
  ensure (entryHash e (maybe (text (get p "scid")) (text . (`get` "versionId") . entry) previous) == h) "entry-hash-mismatch" n
  t <- maybe (failAt "invalid-version-time" n) Right (time (get e "versionTime"))
  ensure (maybe True ((< t) . instant) previous) "invalid-version-time" n
  ensure (t <= now + 300) "future-version-time" n
  when (not (isJust previous)) $ do
    let id = get p "scid"; status = checkHash id
    ensure (status /= "unsupported-algorithm") "invalid-hash-algorithm" n
    ensure (status == "ok") "scid-mismatch" n
    let restored = parseUnsafe (replace (text id) "{SCID}" (jcs (set (remove e "proof") "versionId" (str "{SCID}"))))
    ensure (scid restored == text id) "scid-mismatch" n
  pure (Entry e p n t witnessRule)

verifyLog log witness now
  | null ls = Log [] ls (Just (err "invalid-log" 0))
  | otherwise = witnessing checked
  where
    ls = logLines log
    checked = walk [] (zip [1 ..] ls)
    walk es [] = Log es ls Nothing
    walk es ((i, line) : rest) = case do
      e <- either (const (failAt "invalid-log" i)) Right (parse line)
      ensure (isObject e) "invalid-log" i
      verifyEntry e (listToMaybe (reverse es)) now of
      Left error -> Log es ls (Just error)
      Right e -> walk (es ++ [e]) rest
    witnessing v = case find (isJust . snd) [(i, witnessError v i e) | (i, e) <- zip [0 ..] (entries v)] of
      Nothing -> v
      Just (i, Just code) -> v {entries = take i (entries v), failure = Just (err code (i + 1))}
      _ -> v
    witnessError v i e
      | rule e == Null = Nothing
      | not (isArray file) || not (all validRow (items file)) = Just "invalid-witness-file"
      | S.size ids < ceiling (number (get (rule e) "threshold")) = Just "witness-threshold-not-met"
      | otherwise = Nothing
      where
        file = fromMaybe (array []) witness
        validRow r = isObject r && isString (get r "versionId") && isArray (get r "proof")
        allowed = map (text . (`get` "id")) (items (get (rule e) "witnesses"))
        later = map ((`get` "versionId") . entry) (drop i (entries v))
        ids = S.fromList ["did:key:" ++ mk | r <- items file, get r "versionId" `elem` later, proof <- items (get r "proof"), Just mk <- [methodKey (get proof "verificationMethod")], ("did:key:" ++ mk) `elem` allowed, verify (object [("versionId", get r "versionId")]) proof]

lineValue line = either (const Null) id (parse line)

lineId line = let v = get (lineValue line) "versionId" in if isString v then v else Null

retained v source id = do
  let (ns, rest) = break (== '-') (text id)
  ensure (not (null ns) && head ns `elem` ['1' .. '9'] && all (`elem` ['0' .. '9']) ns && not (null rest)) "invalid-option" 0
  let n = read ns :: Integer
  if n > fromIntegral (length (entries v))
    then pure [object [("code", str "retained-version-not-found"), ("message", str "retained version not found")]]
    else do
      let actual = get (entry (entries v !! (fromInteger n - 1))) "versionId"
      ensureFork (actual == id) (fromInteger n) [("retained", id), (source, actual)]
      pure []

ensureFork condition n copies = unless condition $ Left (set (err "fork-detected" n) "fork" (object [("version", num n), ("copies", array [object [("source", str s), ("versionId", v)] | (s, v) <- copies])]))

result v options warnings copies = do
  chosen <-
    if has options "versionId"
      then do
        let target = find ((== get options "versionId") . (`get` "versionId") . entry) es
        when (not (isJust target) && get options "versionId" `elem` map lineId (drop (length es) ls)) (Left (fromMaybe Null (failure v)))
        pure target
      else
        if has options "versionNumber"
          then do
            let n = number (get options "versionNumber")
            if n <= fromIntegral (length es) then pure (Just (es !! (truncate n - 1))) else if n <= fromIntegral (length ls) then Left (fromMaybe Null (failure v)) else pure Nothing
          else
            if has options "versionTime"
              then do
                let t = fromMaybe 0 (time (get options "versionTime"))
                case failure v of
                  Just error | maybe False (<= t) (time (get (lineValue (ls !! length es)) "versionTime")) -> Left error
                  _ -> pure (find ((<= t) . instant) (reverse es))
              else pure (listToMaybe (reverse es))
  target <- maybe (failAt "not-found" 0) Right chosen
  let first = head es
      lastEntry = last es
      ws = warnings ++ maybe [] (\e -> [object [("code", str "invalid-entries"), ("message", get e "message")]]) (failure v)
      meta =
        object $
          [ ("versionId", get (entry target) "versionId"),
            ("versionTime", get (entry target) "versionTime"),
            ("versionNumber", num (version target)),
            ("created", get (entry first) "versionTime"),
            ("updated", get (entry lastEntry) "versionTime"),
            ("scid", get (params first) "scid"),
            ("deactivated", get (params lastEntry) "deactivated"),
            ("ttl", get (params lastEntry) "ttl"),
            ("witness", get (params lastEntry) "witness"),
            ("watchers", get (params lastEntry) "watchers"),
            ("updateKeys", get (params target) "updateKeys"),
            ("nextKeyHashes", get (params target) "nextKeyHashes"),
            ("warnings", array ws)
          ]
            ++ maybe [] (\c -> [("copies", array c)]) copies
  pure (object [("valid", Boolean True), ("state", get (entry target) "state"), ("metadata", meta), ("firstInvalidVersion", maybe Null (const (num (length es + 1))) (failure v)), ("error", fromMaybe Null (failure v))])
  where
    es = entries v; ls = rawLines v

resolveCopies input now options = do
  let primary = object $ [("source", str "primary"), ("log", get input "log")] ++ [("witness", get input "witness") | has input "witness"]
      allCopies = primary : items (get input "copies")
      logs = map (\c -> verifyLog (text (get c "log")) (if has c "witness" then Just (get c "witness") else Nothing) now) allCopies
      unavailable = [i | (i, c) <- zip [0 ..] allCopies, has c "unavailable"]
      initialStatus = M.fromList [(i, "unavailable") | i <- unavailable]
      warning code i message = object [("code", str code), ("source", get (allCopies !! i) "source"), ("message", message)]
      initialWarnings = [warning "copy-unavailable" i (get (allCopies !! i) "unavailable") | i <- unavailable]
      available = [i | i <- [0 .. length allCopies - 1], i `notElem` unavailable]
      (invalids, rest) = break (not . isJust . failure . (logs !!)) available
      status = M.union initialStatus (M.fromList [(i, "invalid") | i <- invalids])
      warnings = initialWarnings ++ [warning "copy-invalid" i (str "copy fails verification") | i <- invalids]
  case rest of
    [] -> Left (fromMaybe Null (failure (head logs)))
    ref0 : _ -> do
      let step (ref, states, ws) i
            | M.member i states || i == ref0 = pure (ref, states, ws)
            | null cl = invalid
            | length cl <= length rl && lineId (last cl) == get (entry (entries r !! (length cl - 1))) "versionId" = pure (ref, states, ws)
            | length cl > length rl && lineId (cl !! (length rl - 1)) == get (entry (last (entries r))) "versionId" && not (isJust (failure c)) = pure (i, states, ws)
            | isJust (failure c) = invalid
            | otherwise = do
                let k = fromMaybe (min (length rl) (length cl)) (findIndex (uncurry (/=)) (zip (map lineId rl) (map lineId cl)))
                    at ls = if k < length ls then lineId (ls !! k) else str ""
                ensureFork False (k + 1) [(text (get (allCopies !! ref) "source"), at rl), (text (get (allCopies !! i) "source"), at cl)]
                pure (ref, states, ws)
            where
              r = logs !! ref
              c = logs !! i
              rl = rawLines r
              cl = rawLines c
              invalid = pure (ref, M.insert i "invalid" states, ws ++ [warning "copy-invalid" i (str "copy fails verification")])
      (ref, states, ws) <- foldM step (ref0, status, warnings) [0 .. length allCopies - 1]
      let r = logs !! ref
      retainedWarnings <- if has input "retainedVersionId" then retained r (text (get (allCopies !! ref) "source")) (get input "retainedVersionId") else pure []
      let report i = object $ [("source", get (allCopies !! i) "source"), ("status", str state)] ++ [("versionId", id) | state /= "unavailable", id /= Null]
            where
              ls = rawLines (logs !! i)
              id = maybe Null lineId (listToMaybe (reverse ls))
              state = M.findWithDefault (if length ls < length (rawLines r) then "behind" else "current") i states
          reports = map report [0 .. length allCopies - 1]
          behind = [warning "copy-behind" i (str "copy is behind") | (i, c) <- zip [0 ..] reports, get c "status" == str "behind"]
          count = length [c | c <- reports, get c "status" `elem` [str "current", str "behind"]]
      ensure (fromIntegral count >= number (defaulted options "minCopies" (num 1))) "min-copies-not-met" 0
      result r options (ws ++ retainedWarnings ++ behind) (Just reports)

resolve :: J -> J
resolve input = either (\e -> object [("valid", Boolean False), ("error", e)]) id $ do
  now <- maybe (failAt "invalid-option" 0) Right (time (get input "now"))
  let options = if get input "options" == Null then object [] else get input "options"
  ensure (isObject options && all ((`elem` ["versionId", "versionTime", "versionNumber", "minCopies"]) . fst) (fields options)) "invalid-option" 0
  ensure (length (filter (has options) ["versionId", "versionTime", "versionNumber"]) <= 1) "invalid-option" 0
  ensure (not (has options "versionId") || isString (get options "versionId")) "invalid-option" 0
  ensure (not (has options "versionTime") || isJust (time (get options "versionTime"))) "invalid-option" 0
  mapM_ (\k -> when (has options k) (ensure (integer (get options k) && number (get options k) >= 1) "invalid-option" 0)) ["versionNumber", "minCopies"]
  if has input "copies" || number (defaulted options "minCopies" (num 1)) > 1
    then resolveCopies input now options
    else do
      let v = verifyLog (text (get input "log")) (if has input "witness" then Just (get input "witness") else Nothing) now
      when (null (entries v)) (Left (fromMaybe Null (failure v)))
      warnings <- if has input "retainedVersionId" then retained v "primary" (get input "retainedVersionId") else pure []
      result v options warnings Nothing

dispatch :: String -> J -> J
dispatch op input = case op of
  "jcs" -> object [("output", str (jcs (parseUnsafe (text (get input "text")))))]
  "hash" -> object [("output", str (C.hash (text (get input "data"))))]
  "key-hash" -> object [("output", str (C.hash (text (get input "multikey"))))]
  "multikey" -> object [("multikey", str (C.multikey (text (get input "seed"))))]
  "scid" -> object [("scid", str (scid (get input "entry")))]
  "entry-hash" -> object [("hash", str (entryHash (get input "entry") (text (get input "previousVersionId"))))]
  "sign" -> object [("proof", sign (get input "document") (text (get input "seed")) input)]
  "verify" -> object [("valid", Boolean (verify (get input "document") (get input "proof")))]
  "witness" -> object [("proof", sign (object [("versionId", get input "versionId")]) (text (get input "seed")) input)]
  "create" -> create input
  "update" -> update input
  "resolve" -> resolve input
  _ -> error ("unknown operation " ++ op)
