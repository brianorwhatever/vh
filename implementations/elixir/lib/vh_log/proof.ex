defmodule VHLog.Proof do
  @moduledoc """
  `eddsa-jcs-2022` Data Integrity proofs (profile §2).

  The signing input is `SHA-256(JCS(proofConfig)) ‖ SHA-256(JCS(document))`,
  where `proofConfig` is the proof without `proofValue`. Neither side carries
  `@context`. `proofValue` is `"z" <> base58btc(signature)`.
  """

  alias VHLog.{Base58, Hash, JCS, Multikey}

  @cryptosuite "eddsa-jcs-2022"

  @typedoc "A proof as a decoded JSON object."
  @type t :: %{String.t() => term()}

  @typedoc """
  Options for `create/3`. `:cryptosuite` and `:proof_purpose` exist only to
  build invalid test vectors.
  """
  @type option ::
          {:verification_method, String.t()}
          | {:created, String.t()}
          | {:cryptosuite, String.t()}
          | {:proof_purpose, String.t()}

  @doc "The cryptosuite name."
  @spec cryptosuite() :: String.t()
  def cryptosuite, do: @cryptosuite

  @doc """
  The profile's verification method for a multikey: `did:key:<mk>#<mk>`.
  """
  @spec did_key_verification_method(String.t()) :: String.t()
  def did_key_verification_method(multikey), do: "did:key:#{multikey}##{multikey}"

  @doc ~S"""
  Returns the multikey named by a `did:key:<mk>#<mk>` verification method.

      iex> mk = "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
      iex> VHLog.Proof.multikey_from_verification_method("did:key:#{mk}##{mk}")
      {:ok, "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"}
      iex> VHLog.Proof.multikey_from_verification_method("did:key:#{mk}#key-1")
      :error
  """
  @spec multikey_from_verification_method(term()) :: {:ok, String.t()} | :error
  def multikey_from_verification_method("did:key:" <> rest) do
    with [multikey, fragment] <- :binary.split(rest, "#"),
         true <- multikey != "" and fragment == multikey,
         true <- Multikey.valid?(multikey) do
      {:ok, multikey}
    else
      _ -> :error
    end
  end

  def multikey_from_verification_method(_), do: :error

  @doc """
  Creates a proof over `document` with the key derived from `seed_hex`.
  `created` is omitted unless given.
  """
  @spec create(VHLog.JSON.value(), String.t(), [option()]) :: t()
  def create(document, seed_hex, opts \\ []) do
    keys = Multikey.from_seed(seed_hex)

    config =
      %{
        "type" => "DataIntegrityProof",
        "cryptosuite" => Keyword.get(opts, :cryptosuite, @cryptosuite),
        "verificationMethod" =>
          Keyword.get_lazy(opts, :verification_method, fn ->
            did_key_verification_method(keys.multikey)
          end),
        "proofPurpose" => Keyword.get(opts, :proof_purpose, "assertionMethod")
      }
      |> put_present("created", Keyword.get(opts, :created))

    signature = Multikey.sign(keys, signing_input(document, config))
    Map.put(config, "proofValue", "z" <> Base58.encode(signature))
  end

  @doc """
  Checks a proof's structure and signature over `document`. It does not check
  whether the key is authorised.
  """
  @spec verify(VHLog.JSON.value(), term()) :: boolean()
  def verify(
        document,
        %{
          "type" => "DataIntegrityProof",
          "cryptosuite" => @cryptosuite,
          "proofPurpose" => "assertionMethod",
          "verificationMethod" => vm,
          "proofValue" => "z" <> encoded
        } = proof
      ) do
    with {:ok, multikey} <- multikey_from_verification_method(vm),
         {:ok, public} <- Multikey.to_public_key(multikey),
         {:ok, signature} <- Base58.decode(encoded) do
      Multikey.verify(public, signing_input(document, Map.delete(proof, "proofValue")), signature)
    else
      _ -> false
    end
  end

  def verify(_document, _proof), do: false

  defp signing_input(document, config) do
    Hash.sha256(JCS.canonicalize(config)) <> Hash.sha256(JCS.canonicalize(document))
  end

  defp put_present(map, _key, nil), do: map
  defp put_present(map, key, value), do: Map.put(map, key, value)
end
