-- | did:vh (docs/didvh-profile.md). A did:vh DID log has the same format and
-- verification as a VH-Log log, so it is verified by the VH-Log code with the
-- did:vh specialisation. This module adds the DID syntax, the srcLog/srcWitness
-- and DID URL rules, the resolution options, and DID Resolution metadata and
-- errors.
module DidVh
  ( DidVhError (..),
    didVhMethod,
    parseDid,
    specialisation,
    createDid,
    updateDid,
    checkRef,
    srcReferences,
    parseDidUrl,
    resolveDid,
    dispatch,
  )
where

import Control.Monad (forM_, unless, when)
import qualified Data.ByteString as B
import Data.Char (isAlpha, isAlphaNum, isAsciiLower, isDigit, isHexDigit, digitToInt, ord, toLower)
import Data.List (isPrefixOf, isSuffixOf)
import Data.Maybe (fromMaybe, isJust, isNothing)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Json
import VHLog (Specialisation (..), logLines, needsWitnessing, resolveWith, time)
import qualified VHLog

-- | A did:vh error code (invalidDid, invalidDidUrl, invalidOptions, notFound,
-- featureNotSupported, logForked, insufficientCopies), with the VH-Log error
-- report behind it where there is one.
data DidVhError = DidVhError {errorCode :: String, errorMessage :: String, vhLogError :: Maybe J}

didVhMethod, didPrefix :: String
didVhMethod = "did:vh:1.0"
didPrefix = "did:vh:"

base58 :: String
base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

-- ---------------------------------------------------------------- the DID

-- | The SCID of a did:vh DID, or Nothing if it does not match the ABNF.
parseDid :: J -> Maybe String
parseDid (String s)
  | didPrefix `isPrefixOf` s && length scid == 46 && all (`elem` base58) scid = Just scid
  where
    scid = drop (length didPrefix) s
parseDid _ = Nothing

-- | A natural number with no leading zeros.
natural :: String -> Bool
natural s = not (null s) && all isDigit s && (s == "0" || head s /= '0')

-- | A well-formed @method@ value: @did:vh:<major>.<minor>@.
methodSyntax :: String -> Bool
methodSyntax s
  | didPrefix `isPrefixOf` s = let (major, rest) = break (== '.') (drop (length didPrefix) s) in natural major && take 1 rest == "." && natural (drop 1 rest)
  | otherwise = False

-- | The did:vh specialisation of VH-Log: @method@ instead of @logVersion@, a
-- closed parameter set, and @state.id@ = @did:vh:<SCID>@ in every entry. With
-- an expected SCID, the log's SCID must also be that of the DID being resolved.
specialisation :: Maybe String -> Specialisation
specialisation expected = Specialisation "method" didVhMethod (Just methodSyntax) True (Just stateOk)
  where
    stateOk state scid = maybe True (== scid) expected && get state "id" == str (didPrefix ++ scid)

-- ---------------------------------------------------------------- create / update

-- | Creates a did:vh DID log: {document, parameters, versionTime, signers} ->
-- {log, did, scid, versionId}. Like VH-Log generation, it does not validate its input.
createDid :: J -> J
createDid input = set created "did" (str (didPrefix ++ text (get created "scid")))
  where
    created = VHLog.createWith (specialisation Nothing) (object [("state", get input "document"), ("parameters", get input "parameters"), ("versionTime", get input "versionTime"), ("signers", get input "signers")])

-- | Appends an entry: {log, document, parameters?, versionTime, signers} -> {log, versionId}.
updateDid :: J -> J
updateDid input = VHLog.update (set (remove input "document") "state" (get input "document"))

-- ---------------------------------------------------------------- shared URL checks

-- | UTF-8 encoding of a character.
utf8 :: Char -> [Int]
utf8 c = map fromIntegral (B.unpack (TE.encodeUtf8 (T.singleton c)))

-- | Percent-decodes @s@ as UTF-8, or Nothing if an escape or the UTF-8 is malformed.
percentDecode :: String -> Maybe String
percentDecode s = bytes s >>= \bs -> either (const Nothing) (Just . T.unpack) (TE.decodeUtf8' (B.pack (map fromIntegral bs)))
  where
    bytes ('%' : a : b : rest) | isHexDigit a && isHexDigit b = ((digitToInt a * 16 + digitToInt b) :) <$> bytes rest
    bytes ('%' : _) = Nothing
    bytes (c : rest) = (utf8 c ++) <$> bytes rest
    bytes [] = Just []

-- | Unicode White_Space (profile §3.2).
whitespace :: Char -> Bool
whitespace c = let n = ord c in (n >= 0x09 && n <= 0x0d) || n `elem` [0x20, 0x85, 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000] || (n >= 0x2000 && n <= 0x200a)

splitOn :: Char -> String -> [String]
splitOn sep s = case break (== sep) s of
  (a, []) -> [a]
  (a, _ : rest) -> a : splitOn sep rest

isOctet :: String -> Bool
isOctet s = length s <= 3 && natural s && (read s :: Int) <= 255

isLoopbackHost :: String -> Bool
isLoopbackHost host = host `elem` ["localhost", "[::1]"] || (length parts == 4 && all isOctet parts && head parts == "127")
  where
    parts = splitOn '.' host

isDomainName :: String -> Bool
isDomainName host = not (null name) && length name <= 253 && not (all isDigit (last labels)) && all label labels
  where
    name = if "." `isSuffixOf` host then init host else host
    labels = splitOn '.' name
    -- an all-digit last label is an IPv4 literal, or ends in a number
    label l = not (null l) && length l <= 63 && all (\c -> isAsciiLower c || isDigit c || c == '-') l && head l /= '-' && last l /= '-'

-- | Splits @scheme:rest@ (profile §3.1 steps 1–2); Nothing unless the value is
-- printable ASCII with a scheme. The scheme is lowercased.
splitScheme :: J -> Maybe (String, String)
splitScheme (String s)
  | not (null s) && all (\c -> c >= '!' && c <= '~') s,
    (scheme@(c : cs), ':' : rest) <- break (== ':') s,
    isAlpha c && all (\x -> isAlphaNum x || x `elem` "+.-") cs =
      Just (map toLower scheme, rest)
splitScheme _ = Nothing

-- | Checks an http(s) authority (profile §3.1 step 4).
checkAuthority :: String -> Bool -> Bool
checkAuthority authority http
  | '@' `elem` authority = False
  | otherwise = case hostPort of
      Nothing -> False
      Just (host, port) ->
        maybe True (\p -> not (null p) && length p <= 5 && all isDigit p && (read p :: Int) <= 65535) port
          && if http then isLoopbackHost (lower host) else take 1 host /= "[" && isDomainName (lower host)
  where
    lower = map toLower
    hostPort
      | take 1 authority == "[" = case break (== ']') authority of
          (_, []) -> Nothing
          (inside, _ : after) -> case after of
            [] -> Just (inside ++ "]", Nothing)
            ':' : p -> Just (inside ++ "]", Just p)
            _ -> Nothing
      | otherwise = case break (== ':') authority of
          (host, []) -> Just (host, Nothing)
          (host, _ : p) -> Just (host, Just p)

-- | Checks the segments of a path that starts with @/@ (profile §3). Each is
-- percent-decoded and must not be @.@ or @..@ or contain @/@, @\\@ or NUL. With
-- @strict@ (the src DID URL parameter), it must also be non-empty and not start
-- or end with whitespace.
checkSegments :: String -> Bool -> Bool
checkSegments path strict = all segmentOk (splitOn '/' (drop 1 path))
  where
    segmentOk raw = case percentDecode raw of
      Nothing -> False
      Just s -> s `notElem` [".", ".."] && not (any (`elem` "/\\\0") s) && (not strict || (not (null s) && not (whitespace (head s)) && not (whitespace (last s))))

-- ---------------------------------------------------------------- srcLog / srcWitness

-- | Validates a srcLog or srcWitness reference, which names a file (profile
-- §3.1), and returns its kind: web, loopback, file or other. Fails with invalidOptions.
checkRef :: J -> Either DidVhError String
checkRef ref = do
  (scheme, rest) <- maybe (invalid "not a printable-ASCII absolute URL") Right (splitScheme ref)
  when ('#' `elem` rest) $ invalid "must not have a fragment"
  case scheme of
    _ | scheme `elem` ["https", "http"] -> do
      unless ("//" `isPrefixOf` rest) $ invalid "missing authority"
      let (authority, after) = break (`elem` "/?") (drop 2 rest)
          path = takeWhile (/= '?') after
      unless (checkAuthority authority (scheme == "http")) $ invalid (if scheme == "http" then "http is only allowed with a loopback host" else "invalid https host")
      when (null path) $ invalid "must have a path"
      unless (checkSegments path False) $ invalid "invalid path segment"
      pure (if scheme == "http" then "loopback" else "web")
    "file" -> do
      when ('?' `elem` rest) $ invalid "must not have a query"
      path <-
        if "//" `isPrefixOf` rest
          then do
            let (host, path) = break (== '/') (drop 2 rest)
            when (null path) $ invalid "file URL needs an absolute path"
            unless (map toLower host `elem` ["", "localhost"]) $ invalid "file URL host must be empty or localhost"
            pure path
          else do
            unless ("/" `isPrefixOf` rest) $ invalid "file URL needs an absolute path"
            pure rest
      unless (checkSegments path False) $ invalid "invalid path segment"
      pure "file"
    _ -> do
      when (null rest) $ invalid "empty URL"
      pure "other"
  where
    invalid why = Left (DidVhError "invalidOptions" ("reference " ++ jcs ref ++ ": " ++ why) Nothing)

-- ---------------------------------------------------------------- the src DID URL parameter

-- | Validates a (percent-decoded) src DID URL parameter and derives the srcLog
-- and srcWitness references from it (profile §3.2). Fails with invalidDidUrl.
srcReferences :: String -> Either DidVhError (String, String)
srcReferences src = do
  (scheme, rest) <- maybe (invalid "not a printable-ASCII absolute URL") Right (splitScheme (str src))
  when (any (`elem` "?#") rest) $ invalid "must not have a query or fragment"
  when (scheme `elem` ["http", "file"]) $ invalid (scheme ++ " is not allowed in a DID URL")
  unless ("//" `isPrefixOf` rest && length rest > 2 && rest !! 2 /= '/') $ invalid "not a hierarchical URL with an authority"
  let base = if "/" `isSuffixOf` rest then init rest else rest
  when (scheme == "https") $ do
    let (authority, path) = break (== '/') (drop 2 base)
    unless (checkAuthority authority False) $ invalid "invalid https host"
    unless (null path || checkSegments path True) $ invalid "invalid path segment"
  let location = scheme ++ ":" ++ base
  pure (location ++ "/did.jsonl", location ++ "/did-witness.json")
  where
    invalid why = Left (DidVhError "invalidDidUrl" ("src " ++ jcs (str src) ++ ": " ++ why) Nothing)

-- ---------------------------------------------------------------- DID URLs

-- | Parses a did:vh DID URL as a dereferencer does (profile §4) into
-- {did, options, fragment?}: src becomes the srcLog and srcWitness options, and
-- the version parameters become the options of the same name. Fails with invalidDidUrl.
parseDidUrl :: J -> Either DidVhError J
parseDidUrl (String url) = do
  let (beforeFragment, fragment) = break (== '#') url
      (did, query) = break (== '?') beforeFragment
  when (isNothing (parseDid (str did))) $ invalid "not a did:vh DID"
  options <- if null query then pure [] else go [] (splitOn '&' (drop 1 query))
  pure (object ([("did", str did), ("options", object options)] ++ [("fragment", str (drop 1 fragment)) | not (null fragment)]))
  where
    invalid why = Left (DidVhError "invalidDidUrl" (jcs (str url) ++ ": " ++ why) Nothing)
    go options [] = pure options
    go options (pair : rest) = do
      let (rawKey, rawValue) = break (== '=') pair
      when (null rawValue) $ invalid ("query parameter " ++ jcs (str pair) ++ " has no value")
      (key, value) <- case (percentDecode rawKey, percentDecode (drop 1 rawValue)) of
        (Just k, Just v) -> pure (k, v)
        _ -> invalid "malformed percent-encoding"
      when (key `elem` optionOnly) $ invalid (key ++ " is a resolution option, not a DID URL parameter")
      if key `notElem` ["src", "versionId", "versionTime", "versionNumber"]
        then go options rest
        else do
          let name = if key == "src" then "srcLog" else key
          when (name `elem` map fst options) $ invalid (key ++ " given more than once")
          added <- case key of
            "src" -> do
              (srcLog, srcWitness) <- srcReferences value
              pure [("srcLog", str srcLog), ("srcWitness", str srcWitness)]
            "versionNumber" -> do
              unless (natural value && value /= "0" && length value <= 16) $ invalid "versionNumber must be a positive integer"
              pure [("versionNumber", Number (fromInteger (read value)))]
            _ -> pure [(key, str value)]
          go (options ++ added) rest
    optionOnly = ["didLog", "didWitness", "srcLog", "srcWitness", "checkWatchers", "extraWatchers", "minCopies", "includeDidLog"]
parseDidUrl other = Left (DidVhError "invalidDidUrl" (jcs other ++ ": not a string") Nothing)

-- ---------------------------------------------------------------- resolve

isWatcherUrl :: J -> Bool
isWatcherUrl (String s) = all (\c -> c >= '!' && c <= '~') s && not (null authority) && head authority `notElem` "/?#"
  where
    authority
      | "https://" `isPrefixOf` s = drop 8 s
      | "http://" `isPrefixOf` s = drop 7 s
      | otherwise = ""
isWatcherUrl _ = False

-- | did:vh resolution options validation (profile §5 step 2).
validateOptions :: J -> Bool -> Either DidVhError ()
validateOptions o remote = do
  check (isObject o) "resolution options must be an object"
  check (has o "didLog" /= has o "srcLog") "exactly one of didLog and srcLog must be given"
  check (not (has o "didWitness" && has o "srcWitness")) "at most one of didWitness and srcWitness may be given"
  check (not (has o "didLog") || isString (get o "didLog")) "didLog must be a string"
  check (not (has o "didWitness") || isArray (get o "didWitness")) "didWitness must be an array"
  forM_ ["srcLog", "srcWitness"] $ \key -> when (has o key) $ do
    kind <- checkRef (get o key)
    check (not (remote && kind `elem` ["file", "loopback"])) (key ++ ": a resolver that serves other systems must not use local file or loopback references")
  check (length (filter (has o) ["versionId", "versionTime", "versionNumber"]) <= 1) "at most one of versionId, versionTime and versionNumber may be given"
  check (not (has o "versionId") || isString (get o "versionId")) "versionId must be a string"
  check (not (has o "versionTime") || isJust (time (get o "versionTime"))) "versionTime must be a whole-second UTC ISO 8601 time"
  check (not (has o "versionNumber") || positiveInteger (get o "versionNumber")) "versionNumber must be a positive integer"
  let c = get o "checkWatchers"
  check (not (has o "checkWatchers") || c == str "all" || (integer c && number c >= 0)) "checkWatchers must be a non-negative integer or \"all\""
  let w = get o "extraWatchers"
  check (not (has o "extraWatchers") || (isArray w && all (\u -> isWatcherUrl u && "https://" `isPrefixOf` text u) (items w))) "extraWatchers must be an array of https URLs"
  check (not (has o "minCopies") || positiveInteger (get o "minCopies")) "minCopies must be a positive integer"
  check (not (has o "includeDidLog") || get o "includeDidLog" `elem` [Boolean True, Boolean False]) "includeDidLog must be a boolean"
  where
    check ok why = unless ok (Left (DidVhError "invalidOptions" why Nothing))
    positiveInteger v = integer v && number v >= 1

errorFor :: String -> String
errorFor code = case code of
  "not-found" -> "notFound"
  "invalid-option" -> "invalidOptions"
  "fork-detected" -> "logForked"
  "min-copies-not-met" -> "insufficientCopies"
  "unsupported-log-version" -> "featureNotSupported"
  _ -> "invalidDid"

-- | did:vh @resolve(did, resolutionOptions)@ (profile §5), with the resolver's
-- clock @now@ (ISO 8601) and whether it serves other systems (@remote@). This
-- resolver is offline: it verifies a log passed in didLog (and didWitness), and
-- returns featureNotSupported when it would have to retrieve anything.
resolveDid :: J -> J -> J -> Bool -> J
resolveDid did options now remote = either failure id $ do
  scid <- maybe (Left (DidVhError "invalidDid" (jcs did ++ " is not a did:vh DID") Nothing)) Right (parseDid did)
  validateOptions options remote
  when (has options "srcLog") $ unsupported "this resolver does not retrieve srcLog references"
  when ((has options "checkWatchers" && get options "checkWatchers" /= Number 0) || not (null (items (get options "extraWatchers")))) $
    unsupported "this resolver does not retrieve copies from watchers"
  let spec = specialisation (Just scid)
      log = text (get options "didLog")
      witnessed = needsWitnessing spec log (fromMaybe 0 (time now))
  when (witnessed && has options "srcWitness") $ unsupported "this resolver does not retrieve srcWitness references"
  let vhOptions = object [(k, get options k) | k <- ["versionId", "versionTime", "versionNumber", "minCopies"], has options k]
      input = object ([("log", str log), ("now", now), ("options", vhOptions)] ++ [("witness", get options "didWitness") | has options "didWitness"])
      result = resolveWith spec input
      vhError = get result "error"
  when (get result "valid" /= Boolean True) $ Left (DidVhError (errorFor (text (get vhError "code"))) (text (get vhError "message")) (Just vhError))
  let selected = any (has options) ["versionId", "versionTime", "versionNumber"]
  -- Entries after the last valid one may change the document or its keys (profile §5).
  when (not selected && get vhError "code" == str "unsupported-log-version") $ Left (DidVhError "featureNotSupported" (text (get vhError "message")) (Just vhError))
  let m = get result "metadata"
      metadata = object ([(k, get m k) | k <- ["versionId", "versionTime", "created", "updated", "scid", "deactivated", "ttl", "watchers"]] ++ [("witness", get m "witness") | get m "witness" /= Null])
      lines' = logLines log
      valid = case get result "firstInvalidVersion" of
        Null -> length lines'
        n -> truncate (number n) - 1
      included =
        if get options "includeDidLog" == Boolean True
          then [("didLog", str (concatMap (++ "\n") (take valid lines')))] ++ [("didWitness", if has options "didWitness" then get options "didWitness" else array []) | witnessed]
          else []
      meta = object ([("contentType", str "application/did+json")] ++ [("warnings", get m "warnings") | not (null (items (get m "warnings")))] ++ included)
      -- A deactivated DID's document is returned only for an explicit version selector (profile §5).
      document = if get m "deactivated" == Boolean True && not selected then Null else get result "state"
  pure (object [("didResolutionMetadata", meta), ("didDocument", document), ("didDocumentMetadata", metadata)])
  where
    unsupported why = Left (DidVhError "featureNotSupported" why Nothing)
    failure (DidVhError code message vh) =
      object
        [ ("didResolutionMetadata", object [("error", str code), ("problemDetails", object ([("title", str code), ("detail", str message)] ++ maybe [] (\v -> [("vhLog", v)]) vh))]),
          ("didDocument", Null),
          ("didDocumentMetadata", object [])
        ]

-- | The didvh-* driver operations (docs/interop-protocol.md, "did:vh
-- operations"), with the @didvh-@ prefix removed. @didvh-resolve@ needs @now@.
dispatch :: String -> J -> J
dispatch op input = case op of
  "create" -> createDid input
  "update" -> updateDid input
  "resolve" -> resolveDid (get input "did") (if has input "options" then get input "options" else object []) (get input "now") (get input "remote" == Boolean True)
  "ref" -> rejected (\kind -> [("kind", str kind)]) (checkRef (get input "ref"))
  "src" -> rejected (\(srcLog, srcWitness) -> [("srcLog", str srcLog), ("srcWitness", str srcWitness)]) (if isString (get input "src") then srcReferences (text (get input "src")) else Left (DidVhError "invalidDidUrl" "src must be a string" Nothing))
  "did-url" -> rejected fields (parseDidUrl (get input "didUrl"))
  _ -> error ("unknown operation didvh-" ++ op)
  where
    rejected ok = either (\e -> object [("valid", Boolean False), ("error", str (errorCode e))]) (\v -> object (("valid", Boolean True) : ok v))
