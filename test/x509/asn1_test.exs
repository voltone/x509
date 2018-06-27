defmodule X509.ASN1Test do
  use ExUnit.Case
  import X509.ASN1

  test "OID extraction: OTP-PUB-KEY.hrl" do
    assert oid(:sha256WithRSAEncryption) == {1, 2, 840, 113_549, 1, 1, 11}
    assert oid(:"id-ce-subjectAltName") == {2, 5, 29, 17}
  end

  test "OID extraction: PKCS-FRAME.hrl" do
    assert oid(:"id-PBKDF2") == {1, 2, 840, 113_549, 1, 5, 12}
  end
end
