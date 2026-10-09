defmodule VHLog.DocTest do
  use ExUnit.Case, async: true

  doctest VHLog
  doctest VHLog.Base58
  doctest VHLog.Error
  doctest VHLog.Hash
  doctest VHLog.JCS
  doctest VHLog.JSON
  doctest VHLog.Multikey
  doctest VHLog.Proof
  doctest VHLog.URL
  doctest VHLog.VersionTime
end
