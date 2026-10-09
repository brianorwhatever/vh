defmodule VHLog.MixProject do
  use Mix.Project

  def project do
    [
      app: :vh_log,
      version: "0.1.0",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      elixirc_options: [warnings_as_errors: true],
      deps: deps(),
      description: "Verifiable History Log (VH-Log) — vh-log-interop-0 profile",
      docs: [main: "VHLog"]
    ]
  end

  def application do
    [extra_applications: [:crypto]]
  end

  # No third-party dependencies: JSON comes from Elixir's built-in `JSON`
  # (OTP's `:json`), Ed25519 and SHA-256 from `:crypto`.
  defp deps, do: []
end
