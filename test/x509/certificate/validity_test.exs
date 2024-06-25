defmodule X509.Certificate.ValidityTest do
  use ExUnit.Case
  doctest X509.Certificate.Validity

  test "UTCTime and GeneralizedTime encoding" do
    {:ok, not_before, 0} = DateTime.from_iso8601("2022-01-01T00:00:00Z")
    {:ok, not_after, 0} = DateTime.from_iso8601("2051-12-31T23:59:59Z")
    validity = X509.Certificate.Validity.new(not_before, not_after)
    assert <<der::binary>> = :public_key.der_encode(:Validity, validity)

    assert {:Validity, {:utcTime, ~c"220101000000Z"}, {:generalTime, ~c"20511231235959Z"}} =
             :public_key.der_decode(:Validity, der)
  end
end
