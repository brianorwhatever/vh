module Main where
import Json
import VHLog
import Control.Exception
import Control.DeepSeq (force)
import System.IO
import qualified Data.ByteString as B
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
main :: IO ()
main = do
  hSetBuffering stdout LineBuffering
  loop
  where
    loop = do
      eof <- hIsEOF stdin
      if eof then pure () else do
        bytes <- B.hGetLine stdin
        let parsed = case TE.decodeUtf8' bytes of Left _ -> Left "invalid UTF-8"; Right t -> parse (T.unpack t)
            id = either (const Null) (`get` "id") parsed
            response = case parsed of
              Left e -> error e
              Right request -> object [("id",id),("ok",Boolean True),("result",dispatch (text (get request "op")) (get request "input"))]
        output <- try (evaluate (force (jcs response))) :: IO (Either SomeException String)
        let line = either (\e -> jcs (object [("id",id),("ok",Boolean False),("error",str (displayException e))])) (\x->x) output
        B.hPutStr stdout (TE.encodeUtf8 (T.pack (line++"\n")))
        loop
