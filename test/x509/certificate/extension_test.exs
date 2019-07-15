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
      assert extension(extnValue: {:BasicConstraints, true, :asn1_NOVALUE}) =
               X509.Certificate.extension(certs.root_ca, :basic_constraints)
    end

    test "key_usage", %{certs: certs} do
      assert extension(extnValue: [:keyCertSign, :cRLSign]) =
               X509.Certificate.extension(certs.root_ca, :key_usage)
    end

    test "ext_key_usage", %{certs: certs} do
      assert extension(extnValue: [{1, 3, 6, 1, 5, 5, 7, 3, 1}, {1, 3, 6, 1, 5, 5, 7, 3, 2}]) =
               X509.Certificate.extension(certs.server, :ext_key_usage)
    end

    test "subject_key_identifier", %{certs: certs} do
      assert extension(
               extnValue:
                 <<37, 69, 129, 104, 80, 38, 56, 61, 59, 45, 44, 190, 205, 106, 217, 182, 61, 179,
                   102, 99>>
             ) = X509.Certificate.extension(certs.int_ca, :subject_key_identifier)
    end

    test "authority_key_identifier", %{certs: certs} do
      assert extension(
               extnValue:
                 {:AuthorityKeyIdentifier,
                  <<124, 12, 50, 31, 167, 217, 48, 127, 196, 125, 104, 163, 98, 168, 161, 206,
                    171, 7, 91, 39>>, :asn1_NOVALUE, :asn1_NOVALUE}
             ) = X509.Certificate.extension(certs.int_ca, :authority_key_identifier)
    end

    test "subject_alt_name", %{certs: certs} do
      assert extension(extnValue: [dNSName: '*.tools.ietf.org', dNSName: 'tools.ietf.org']) =
               X509.Certificate.extension(certs.server, :subject_alt_name)
    end

    test "crl_distribution_points", %{certs: certs} do
      assert extension(
               extnValue: [
                 {:DistributionPoint,
                  {:fullName,
                   [
                     uniformResourceIdentifier: 'http://crl.starfieldtech.com/sfig2s1-128.crl'
                   ]}, :asn1_NOVALUE, :asn1_NOVALUE}
               ]
             ) = X509.Certificate.extension(certs.server, :crl_distribution_points)
    end

    test "authority_info_access", %{certs: certs} do
      assert extension(
               extnValue: [
                 {:AccessDescription, {1, 3, 6, 1, 5, 5, 7, 48, 1},
                  {:uniformResourceIdentifier, 'http://ocsp.starfieldtech.com/'}},
                 {:AccessDescription, {1, 3, 6, 1, 5, 5, 7, 48, 2},
                  {:uniformResourceIdentifier,
                   'http://certificates.starfieldtech.com/repository/sfig2.crt'}}
               ]
             ) = X509.Certificate.extension(certs.server, :authority_info_access)
    end

    test "ocsp_nocheck", %{certs: certs} do
      assert extension(extnValue: <<5, 0>>) =
               X509.Certificate.extension(certs.ocsp_responder, :ocsp_nocheck)
    end
  end
end
