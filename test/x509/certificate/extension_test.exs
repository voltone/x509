defmodule X509.Certificate.ExtensionTest do
  use ExUnit.Case
  import X509.ASN1
  doctest X509.Certificate.Extension

  setup_all do
    certs = %{
      root_ca:
        File.read!("test/data/Starfield Root Certificate Authority - G2.cer")
        |> X509.Certificate.from_der!(),
      int_ca:
        File.read!("test/data/Starfield Secure Certificate Authority - G2.cer")
        |> X509.Certificate.from_der!(),
      server: File.read!("test/data/*.tools.ietf.org.cer") |> X509.Certificate.from_der!(),
      ocsp_responder:
        File.read!("test/data/Starfield Validation Authority - G2.pem")
        |> X509.Certificate.from_pem!()
    }

    [certs: certs]
  end

  describe "find (through Certificate.extension/2)" do
    test "basic_constraints", %{certs: certs} do
      assert certs.root_ca
             |> X509.Certificate.extension(:basic_constraints)
             |> extension(:extnValue) ==
               {:BasicConstraints, true, :asn1_NOVALUE}
    end

    test "key_usage", %{certs: certs} do
      assert certs.root_ca
             |> X509.Certificate.extension(:key_usage)
             |> extension(:extnValue) ==
               [:keyCertSign, :cRLSign]
    end

    test "ext_key_usage", %{certs: certs} do
      assert certs.server
             |> X509.Certificate.extension(:ext_key_usage)
             |> extension(:extnValue) ==
               [{1, 3, 6, 1, 5, 5, 7, 3, 1}, {1, 3, 6, 1, 5, 5, 7, 3, 2}]
    end

    test "subject_key_identifier", %{certs: certs} do
      assert certs.int_ca
             |> X509.Certificate.extension(:subject_key_identifier)
             |> extension(:extnValue) ==
               <<37, 69, 129, 104, 80, 38, 56, 61, 59, 45, 44, 190, 205, 106, 217, 182, 61, 179,
                 102, 99>>
    end

    test "authority_key_identifier", %{certs: certs} do
      assert certs.int_ca
             |> X509.Certificate.extension(:authority_key_identifier)
             |> extension(:extnValue) ==
               {:AuthorityKeyIdentifier,
                <<124, 12, 50, 31, 167, 217, 48, 127, 196, 125, 104, 163, 98, 168, 161, 206, 171,
                  7, 91, 39>>, :asn1_NOVALUE, :asn1_NOVALUE}
    end

    test "subject_alt_name", %{certs: certs} do
      assert certs.server
             |> X509.Certificate.extension(:subject_alt_name)
             |> extension(:extnValue) ==
               [dNSName: ~c"*.tools.ietf.org", dNSName: ~c"tools.ietf.org"]
    end

    test "crl_distribution_points", %{certs: certs} do
      assert certs.server
             |> X509.Certificate.extension(:crl_distribution_points)
             |> extension(:extnValue) == [
               {:DistributionPoint,
                {:fullName,
                 [
                   uniformResourceIdentifier: ~c"http://crl.starfieldtech.com/sfig2s1-128.crl"
                 ]}, :asn1_NOVALUE, :asn1_NOVALUE}
             ]
    end

    test "authority_info_access", %{certs: certs} do
      assert certs.server
             |> X509.Certificate.extension(:authority_info_access)
             |> extension(:extnValue) == [
               {:AccessDescription, {1, 3, 6, 1, 5, 5, 7, 48, 1},
                {:uniformResourceIdentifier, ~c"http://ocsp.starfieldtech.com/"}},
               {:AccessDescription, {1, 3, 6, 1, 5, 5, 7, 48, 2},
                {:uniformResourceIdentifier,
                 ~c"http://certificates.starfieldtech.com/repository/sfig2.crt"}}
             ]
    end

    test "ocsp_nocheck", %{certs: certs} do
      assert certs.ocsp_responder
             |> X509.Certificate.extension(:ocsp_nocheck)
             |> extension(:extnValue) == <<5, 0>>
    end
  end
end
