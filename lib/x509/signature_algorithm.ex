defmodule X509.SignatureAlgorithm do
  @moduledoc false

  import X509.ASN1

  # Returns a signature algorithm record for the given public key type and hash
  # algorithm; this is essentially the reverse of
  # `:public_key.pkix_sign_types/1`

  def new(hash, signature, type \\ :SignatureAlgorithm)

  def new(hash, %{algorithm: algorithm, engine: _}, type) do
    new(hash, algorithm, type)
  end

  def new(hash, rsa_private_key(), type) do
    new(hash, :rsa, type)
  end

  def new(hash, ec_private_key(), type) do
    new(hash, :ecdsa, type)
  end

  def new(hash, signature, :SignatureAlgorithm) do
    {oid, parameters} = algorithm(hash, signature)
    signature_algorithm(algorithm: oid, parameters: parameters)
  end

  def new(hash, signature, :CertificationRequest_signatureAlgorithm) do
    {oid, parameters} = algorithm(hash, signature)
    certification_request_signature_algorithm(algorithm: oid, parameters: parameters)
  end

  def new(hash, signature, :AlgorithmIdentifier) do
    # The AlgorithmIdentifier encoder in OTP's :public_key expects the
    # parameters to be passed in as a raw binary DER, rather than an ASN.1
    # OpenType record
    case algorithm(hash, signature) do
      {oid, {:asn1_OPENTYPE, parameters_der}} ->
        algorithm_identifier(algorithm: oid, parameters: parameters_der)

      {oid, :asn1_NOVALUE} ->
        algorithm_identifier(algorithm: oid)
    end
  end

  defp algorithm(:md5, :rsa), do: {oid(:md5WithRSAEncryption), null()}
  defp algorithm(:sha, :rsa), do: {oid(:sha1WithRSAEncryption), null()}
  defp algorithm(:sha, :ecdsa), do: {oid(:"ecdsa-with-SHA1"), :asn1_NOVALUE}
  defp algorithm(:sha224, :rsa), do: {oid(:sha224WithRSAEncryption), null()}
  defp algorithm(:sha224, :ecdsa), do: {oid(:"ecdsa-with-SHA224"), :asn1_NOVALUE}
  defp algorithm(:sha256, :rsa), do: {oid(:sha256WithRSAEncryption), null()}
  defp algorithm(:sha256, :ecdsa), do: {oid(:"ecdsa-with-SHA256"), :asn1_NOVALUE}
  defp algorithm(:sha384, :rsa), do: {oid(:sha384WithRSAEncryption), null()}
  defp algorithm(:sha384, :ecdsa), do: {oid(:"ecdsa-with-SHA384"), :asn1_NOVALUE}
  defp algorithm(:sha512, :rsa), do: {oid(:sha512WithRSAEncryption), null()}
  defp algorithm(:sha512, :ecdsa), do: {oid(:"ecdsa-with-SHA512"), :asn1_NOVALUE}

  defp algorithm(hash, :rsa) do
    raise ArgumentError, "Unsupported hashing algorithm for RSA signing: #{inspect(hash)}"
  end

  defp algorithm(hash, :ecdsa) do
    raise ArgumentError, "Unsupported hashing algorithm for ECDSA signing: #{inspect(hash)}"
  end
end
