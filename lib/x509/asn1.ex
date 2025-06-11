defmodule X509.ASN1 do
  @moduledoc false

  require Record

  alias X509.ASN1.OIDImport
  alias X509.Util

  if Util.app_version(:public_key) >= [1, 18] do
    @additional_records [
      tbs_cert_list_signature: :TBSCertList_signature,
      certificate_list_algorithm_identifier: :CertificateList_algorithmIdentifier
    ]
  else
    @additional_records []
  end

  # Records to import from :public_key's HRL files, and their snake-case names
  @records [
             # RSA keys
             rsa_private_key: :RSAPrivateKey,
             rsa_public_key: :RSAPublicKey,

             # EC keys
             ec_private_key: :ECPrivateKey,
             ec_point: :ECPoint,

             # PrivateKeyInfo and SPKI
             private_key_info: :PrivateKeyInfo,
             private_key_info_private_key_algorithm: :PrivateKeyInfo_privateKeyAlgorithm,
             otp_subject_public_key_info: :OTPSubjectPublicKeyInfo,
             subject_public_key_info: :SubjectPublicKeyInfo,
             public_key_algorithm: :PublicKeyAlgorithm,
             algorithm_identifier: :AlgorithmIdentifier,

             # Names (RDNs)
             attribute_type_and_value: :AttributeTypeAndValue,

             # CSRs
             certification_request: :CertificationRequest,
             certification_request_info: :CertificationRequestInfo,
             certification_request_subject_pk_info: :CertificationRequestInfo_subjectPKInfo,
             certification_request_subject_pk_info_algorithm:
               :CertificationRequestInfo_subjectPKInfo_algorithm,
             certification_request_signature_algorithm: :CertificationRequest_signatureAlgorithm,
             certification_request_attribute: :"AttributePKCS-10",

             # Certificates
             certificate: :Certificate,
             otp_certificate: :OTPCertificate,
             tbs_certificate: :TBSCertificate,
             otp_tbs_certificate: :OTPTBSCertificate,
             signature_algorithm: :SignatureAlgorithm,
             validity: :Validity,
             extension: :Extension,
             basic_constraints: :BasicConstraints,
             authority_key_identifier: :AuthorityKeyIdentifier,
             access_description: :AccessDescription,

             # CRLs
             certificate_list: :CertificateList,
             tbs_cert_list: :TBSCertList,
             tbs_cert_list_revoked_certificate: :TBSCertList_revokedCertificates_SEQOF
           ] ++ @additional_records

  # The :ECPoint record is the only ASN.1 record defined in public_key.hrl;
  # all other records are in either OTP-PUB-KEY.hrl or PKCS-FRAME.hrl
  Enum.each(@records, fn
    {name, :ECPoint} ->
      Record.defrecord(
        name,
        :ECPoint,
        Record.extract(:ECPoint, from_lib: "public_key/include/public_key.hrl")
      )

    {name, record} ->
      Record.defrecord(
        name,
        record,
        try do
          Record.extract(record, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
        rescue
          ArgumentError ->
            Record.extract(record, from_lib: "public_key/include/PKCS-FRAME.hrl")
        end
      )
  end)

  # ASN.1 helpers
  def open_type(asn1_type, entity), do: open_type(:public_key.der_encode(asn1_type, entity))
  def open_type(der), do: {:asn1_OPENTYPE, der}
  def null, do: open_type(<<5, 0>>)

  # OIDs taken from :public_key's header files
  if Util.app_version(:public_key) >= [1, 18] do
    @oids OIDImport.from_lib("public_key/include/public_key.hrl")
  else
    @oids OIDImport.from_lib("public_key/include/OTP-PUB-KEY.hrl") ++
            OIDImport.from_lib("public_key/include/PKCS-FRAME.hrl")
  end

  # OIDs defined as a macro, so they may be used in pattern matching
  defmacro oid(name) do
    case @oids[name] do
      nil -> raise "Unknown OID key: #{inspect(name)}"
      value -> Macro.escape(value)
    end
  end
end
