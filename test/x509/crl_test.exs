defmodule X509.CRLTest do
  use ExUnit.Case
  import X509.ASN1

  doctest X509.CRL

  setup_all do
    ca_key = X509.PrivateKey.new_rsa(512)
    ca = X509.Certificate.self_signed(ca_key, "/CN=My Root CA", template: :root_ca)

    cert =
      X509.PrivateKey.new_rsa(512)
      |> X509.PublicKey.derive()
      |> X509.Certificate.new("/CN=Sample", ca, ca_key,
        extensions: [
          crl_distribution_points:
            X509.Certificate.Extension.crl_distribution_points(["http://localhost/test.crl"])
        ]
      )

    [
      ca: ca,
      ca_key: ca_key,
      cert: cert
    ]
  end

  test "RFC example" do
    assert {:ok, crl} =
             "test/data/rfc5280_CRL.crl"
             |> File.read!()
             |> X509.CRL.from_der()

    assert [entry] = X509.CRL.list(crl)
    assert 18 = X509.CRL.Entry.serial(entry)
    assert match?(X509.ASN1.extension(), X509.CRL.Entry.extension(entry, :reason_code))

    assert match?(
             %DateTime{year: 2004, month: 11, day: 19},
             X509.CRL.Entry.revocation_date(entry)
           )
  end

  test "not revoked", context do
    dp =
      context.cert
      |> X509.Certificate.extension(:crl_distribution_points)
      |> extension(:extnValue)
      |> hd

    crl = X509.CRL.new([], context.ca, context.ca_key)

    assert X509.CRL.valid?(crl, context.ca)
    crl_der = X509.CRL.to_der(crl)

    assert :valid =
             :public_key.pkix_crls_validate(context.cert, [{dp, {crl_der, crl}}],
               issuer_fun: {&issuer_fun/4, context.ca}
             )
  end

  test "revoked", context do
    dp =
      context.cert
      |> X509.Certificate.extension(:crl_distribution_points)
      |> extension(:extnValue)
      |> hd

    entry =
      X509.CRL.Entry.new(context.cert, DateTime.utc_now(), [
        X509.CRL.Extension.reason_code(:keyCompromise)
      ])

    crl = X509.CRL.new([entry], context.ca, context.ca_key)

    assert X509.CRL.valid?(crl, context.ca)
    crl_der = X509.CRL.to_der(crl)

    assert {:bad_cert, {:revoked, :keyCompromise}} =
             :public_key.pkix_crls_validate(context.cert, [{dp, {crl_der, crl}}],
               issuer_fun: {&issuer_fun/4, context.ca}
             )
  end

  # Stub for issuer resolution, good enough for testing :public_key's
  # processing of the specific sample CRL
  defp issuer_fun(_dp, _crl, _issuer_rdn, ca_cert) do
    {:ok, ca_cert, []}
  end
end
