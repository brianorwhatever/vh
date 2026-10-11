{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto (sha, hash, encode, decode, publicKey, multikey, signBytes, verifyBytes) where
import qualified Data.ByteString as B
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Char
import Data.List (elemIndex)
import Foreign
import Foreign.C.Types
import System.IO.Unsafe (unsafePerformIO)

foreign import ccall unsafe "crypto_hash_sha256" c_sha :: Ptr Word8 -> Ptr Word8 -> CULLong -> IO CInt
foreign import ccall unsafe "crypto_sign_seed_keypair" c_key :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall unsafe "crypto_sign_detached" c_sign :: Ptr Word8 -> Ptr CULLong -> Ptr Word8 -> CULLong -> Ptr Word8 -> IO CInt
foreign import ccall unsafe "crypto_sign_verify_detached" c_verify :: Ptr Word8 -> Ptr Word8 -> CULLong -> Ptr Word8 -> IO CInt
foreign import ccall unsafe "sodium_memzero" c_zero :: Ptr Word8 -> CSize -> IO ()

alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
encode bytes = replicate (B.length (B.takeWhile (==0) bytes)) '1' ++ go (B.foldl' (\n b -> n*256+fromIntegral b) (0::Integer) bytes)
  where go 0 = ""; go n = let(q,r)=n `divMod` 58 in go q++[alphabet!!fromInteger r]
decode s = do
  ds <- traverse (`elemIndex` alphabet) s
  let n=foldl (\a d -> a*58+fromIntegral d) (0::Integer) ds
      go 0=[]; go v=let(q,r)=v `divMod` 256 in fromInteger r:go q
  pure (B.pack (replicate (length (takeWhile (=='1') s)) 0 ++ reverse (go n)))
sha s = unsafePerformIO $ B.useAsCStringLen (TE.encodeUtf8 (T.pack s)) $ \(p,n) -> allocaBytes 32 $ \out -> do
  _ <- c_sha out (castPtr p) (fromIntegral n)
  B.packCStringLen (castPtr out,32)
{-# NOINLINE sha #-}
hash s = encode (B.pack [0x12,0x20] <> sha s)
publicKey ('z':s) = do b <- decode s; if B.length b==34 && B.take 2 b==B.pack [0xed,1] then Just (B.drop 2 b) else Nothing
publicKey _ = Nothing
seed hex | length hex==64 && all isHexDigit hex = B.pack (go hex)
         | otherwise = error "seed must be 32-byte hex"
  where go []=[]; go(a:b:xs)=fromIntegral(digitToInt a*16+digitToInt b):go xs; go _=error "seed"
withKey hex action = B.useAsCString (seed hex) $ \s -> allocaBytes 32 $ \pk -> allocaBytes 64 $ \sk -> do
  _ <- c_key pk sk (castPtr s)
  result <- action pk sk
  c_zero sk 64
  pure result
multikey hex = "z" ++ encode (B.pack [0xed,1] <> unsafePerformIO (withKey hex (\pk _ -> B.packCStringLen (castPtr pk,32))))
signBytes hex msg = unsafePerformIO $ withKey hex $ \_ sk -> B.useAsCStringLen msg $ \(p,n) -> allocaBytes 64 $ \sig -> do
  _ <- c_sign sig nullPtr (castPtr p) (fromIntegral n) sk
  B.packCStringLen (castPtr sig,64)
verifyBytes pk msg sig
  | B.length pk/=32 || B.length sig/=64 = False
  | otherwise = unsafePerformIO $ B.useAsCString pk $ \k -> B.useAsCString sig $ \s -> B.useAsCStringLen msg $ \(m,n) -> do
      status <- c_verify (castPtr s) (castPtr m) (fromIntegral n) (castPtr k)
      pure (status==0)
