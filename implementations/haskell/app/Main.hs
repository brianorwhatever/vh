module Main where

import Control.DeepSeq (force)
import Control.Exception
import qualified Data.ByteString as B
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.List (isPrefixOf)
import Data.Time.Clock (getCurrentTime)
import Data.Time.Format (defaultTimeLocale, formatTime)
import qualified DidVh
import Json
import System.IO
import VHLog

main :: IO ()
main = do
  hSetBuffering stdout LineBuffering
  loop
  where
    loop = do
      eof <- hIsEOF stdin
      if eof
        then pure ()
        else do
          bytes <- B.hGetLine stdin
          now <- formatTime defaultTimeLocale "%Y-%m-%dT%H:%M:%SZ" <$> getCurrentTime
          let parsed = case TE.decodeUtf8' bytes of Left _ -> Left "invalid UTF-8"; Right t -> parse (T.unpack t)
              id = either (const Null) (`get` "id") parsed
              response = case parsed of
                Left e -> error e
                Right request -> object [("id", id), ("ok", Boolean True), ("result", run (text (get request "op")) (get request "input") now)]
          output <- try (evaluate (force (jcs response))) :: IO (Either SomeException String)
          let line = either (\e -> jcs (object [("id", id), ("ok", Boolean False), ("error", str (displayException e))])) (\x -> x) output
          B.hPutStr stdout (TE.encodeUtf8 (T.pack (line ++ "\n")))
          loop
    -- did:vh resolution uses the current time when the request gives none.
    run op input now
      | "didvh-" `isPrefixOf` op = DidVh.dispatch (drop 6 op) (if has input "now" then input else set input "now" (str now))
      | otherwise = dispatch op input
