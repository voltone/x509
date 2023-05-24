defmodule X509.ASN1 do
  @moduledoc false

  require Record
  alias X509.ASN1.OIDImport

  records = Record.extract_all(from_lib: "public_key/include/public_key.hrl")

  record_keys_normalized =
    Enum.map(Keyword.keys(records), fn rec ->
      key =
        rec
        |> Atom.to_string()
        |> String.replace("-", "")
        |> Macro.underscore()
        |> String.replace("otptbs_", "otp_tbs_")
        |> String.replace("certification_request_info_", "certification_request_")
        |> String.to_atom()

      case key do
        :attribute_pkcs10 -> :certification_request_attribute
        :tbs_cert_list_revoked_certificates_seqof -> :tbs_cert_list_revoked_certificate
        key -> key
      end
    end)

  @record_mappings Enum.zip(record_keys_normalized, records)

  Enum.each(@record_mappings, fn {name, {pubkey_name, definitions}} ->
    Record.defrecord(name, pubkey_name, definitions)
  end)

  # ASN.1 helpers
  def open_type(asn1_type, entity), do: open_type(:public_key.der_encode(asn1_type, entity))
  def open_type(der), do: {:asn1_OPENTYPE, der}
  def null, do: open_type(<<5, 0>>)

  # OIDs taken from :public_key's header files
  @oids OIDImport.from_lib("public_key/include/OTP-PUB-KEY.hrl") ++
          OIDImport.from_lib("public_key/include/PKCS-FRAME.hrl")

  # OIDs defined as macros, so they may be used in pattern matching
  for {name, oid} <- @oids do
    @name name
    @oid Macro.escape(oid)
    defmacro oid(@name) do
      @oid
    end
  end
end
