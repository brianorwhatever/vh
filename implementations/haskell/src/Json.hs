module Json (J(..), object, array, str, num, get, has, set, remove, fields, items, text, number, isObject, isArray, isString, integer, parse, jcs) where
import qualified Data.Map.Strict as M
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.ByteString as B
import Data.Ratio ((%))
import Data.Char
import Data.List (intercalate, sortOn)
import Numeric (showHex, floatToDigits)
import Text.ParserCombinators.ReadP hiding (get)

data J = Object (M.Map String J) | Array [J] | String String | Number Double | Boolean Bool | Null deriving (Eq,Show)
object = Object . M.fromList
array = Array
str = String
num :: Integral a => a -> J
num = Number . fromIntegral
get (Object m) k = M.findWithDefault Null k m
get _ _ = Null
has (Object m) k = M.member k m
has _ _ = False
set (Object m) k v = Object (M.insert k v m)
set _ k v = object [(k,v)]
remove (Object m) k = Object (M.delete k m)
remove v _ = v
fields (Object m) = M.toList m
fields _ = []
items (Array a) = a
items _ = []
text (String s) = s
text _ = ""
number (Number d) = d
number _ = 0
isObject (Object _) = True
isObject _ = False
isArray (Array _) = True
isArray _ = False
isString (String _) = True
isString _ = False
integer (Number d) = not (isNaN d || isInfinite d) && d == fromInteger (truncate d)
integer _ = False

parse :: String -> Either String J
parse s = case readP_to_S (space *> value <* space <* eof) s of
  [] -> Left "invalid JSON"
  xs -> Right (fst (last xs))
  where
    space = skipMany (satisfy (`elem` " \t\r\n"))
    token p = space *> p <* space
    value = token (obj <++ arr <++ (String <$> quoted) <++ literal <++ numeric)
    obj = object <$> between (char '{' *> space) (char '}') (sepBy pair (token (char ',')))
    pair = do k <- token quoted; _ <- token (char ':'); v <- value; pure (k,v)
    arr = Array <$> between (char '[' *> space) (char ']') (sepBy value (token (char ',')))
    literal = (string "true" >> pure (Boolean True)) <++ (string "false" >> pure (Boolean False)) <++ (string "null" >> pure Null)
    quoted = between (char '"') (char '"') (many character)
    character = satisfy (\c -> c >= ' ' && c /= '"' && c /= '\\' && (ord c < 0xd800 || ord c > 0xdfff)) <++ do
      _ <- char '\\'; c <- getCharP
      case c of
        '"' -> pure '"'; '\\' -> pure '\\'; '/' -> pure '/'; 'b' -> pure '\b'; 'f' -> pure '\f'; 'n' -> pure '\n'; 'r' -> pure '\r'; 't' -> pure '\t'
        'u' -> do
          n <- hex4
          if n >= 0xd800 && n <= 0xdbff then do
            _ <- string "\\u"; low <- hex4
            if low >= 0xdc00 && low <= 0xdfff then pure (chr (0x10000+(n-0xd800)*1024+low-0xdc00)) else pfail
          else if n >= 0xdc00 && n <= 0xdfff then pfail else pure (chr n)
        _ -> pfail
    getCharP = satisfy (const True)
    hex4 = foldl (\n c -> n*16+digitToInt c) 0 <$> count 4 (satisfy isHexDigit)
    numeric = do
      sign <- option "" (string "-")
      whole <- string "0" <++ ((:) <$> satisfy (`elem` ['1'..'9']) <*> munch (`elem` ['0'..'9']))
      fraction <- option "" ((:) <$> char '.' <*> munch1 (`elem` ['0'..'9']))
      exponent <- option "" (do e <- satisfy (`elem` "eE"); s <- option "" ((:[]) <$> satisfy (`elem` "+-")); ds <- munch1 (`elem` ['0'..'9']); pure (e:s++ds))
      let d = read (sign++whole++fraction++exponent) :: Double
      if isInfinite d || isNaN d then pfail else pure (Number d)

jcs :: J -> String
jcs (Object m) = "{" ++ intercalate "," [quote k ++ ":" ++ jcs v | (k,v) <- sortOn (TE.encodeUtf16BE . T.pack . fst) (M.toList m)] ++ "}"
jcs (Array a) = "[" ++ intercalate "," (map jcs a) ++ "]"
jcs (String s) = quote s
jcs (Number d) = formatNumber d
jcs (Boolean True) = "true"
jcs (Boolean False) = "false"
jcs Null = "null"
quote s = '"' : concatMap escape s ++ "\""
  where
    escape '"' = "\\\""
    escape '\\' = "\\\\"
    escape '\b' = "\\b"
    escape '\f' = "\\f"
    escape '\n' = "\\n"
    escape '\r' = "\\r"
    escape '\t' = "\\t"
    escape c | c < ' ' = let h=showHex (ord c) "" in "\\u"++replicate (4-length h) '0'++h
             | ord c >= 0xd800 && ord c <= 0xdfff = error "lone surrogate"
             | otherwise = [c]
formatNumber d
  | isInfinite d || isNaN d = error "non-finite number"
  | d == 0 = "0"
  | otherwise = (if d < 0 then "-" else "") ++ body
  where
    (_,estimate) = floatToDigits 10 (abs d)
    exact = toRational (abs d)
    pow k | k>=0 = (10^k) % 1
          | otherwise = 1 % (10^(-k))
    candidates = [(round (exact * pow (precision-estimate)) :: Integer, estimate-precision) | precision <- [1..17]]
    (mantissa,exponent) = head [(m,e) | (m,e)<-candidates, (read (show m++"e"++show e) :: Double)==abs d]
    full = show mantissa
    digits = reverse (dropWhile (=='0') (reverse full))
    n = length full+exponent
    k = length digits
    body | n >= k && n <= 21 = digits ++ replicate (n-k) '0'
         | n > 0 && n <= 21 = take n digits ++ "." ++ drop n digits
         | n <= 0 && n > -6 = "0." ++ replicate (-n) '0' ++ digits
         | otherwise = take 1 digits ++ (if k>1 then "."++drop 1 digits else "") ++ "e" ++ (if n-1>=0 then "+" else "") ++ show (n-1)
