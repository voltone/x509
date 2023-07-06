defmodule X509.RDNSequenceTest do
  use ExUnit.Case
  doctest X509.RDNSequence

  test "countryName" do
    # Allow countryName length >2, even though strictly this is a violation of
    # the spec; OTP's :public_key does the same
    assert {:rdnSequence, _} = X509.RDNSequence.new("/C=Germany/O=ACME GmbH")
  end

  test "surname" do
    assert {:rdnSequence, _} = X509.RDNSequence.new("/SN=Erlang/GN=Agner Krarup")
  end
end
