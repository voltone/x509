defmodule X509.RDNSequenceTest do
  use ExUnit.Case

  alias X509.Util

  doctest X509.RDNSequence

  test "simple case" do
    if Util.app_version(:public_key) >= [1, 18] do
      assert {:rdnSequence,
              [
                [{:SingleAttribute, {2, 5, 4, 6}, {:correct, ~c"US"}}],
                [{:SingleAttribute, {2, 5, 4, 3}, {:utf8String, "Bob"}}]
              ]} = X509.RDNSequence.new("/C=US/CN=Bob")
    else
      assert {:rdnSequence,
              [
                [{:AttributeTypeAndValue, {2, 5, 4, 6}, <<19, 2, 85, 83>>}],
                [{:AttributeTypeAndValue, {2, 5, 4, 3}, <<12, 3, 66, 111, 98>>}]
              ]} = X509.RDNSequence.new("/C=US/CN=Bob")
    end
  end

  test "UTF string" do
    if Util.app_version(:public_key) >= [1, 18] do
      assert {:rdnSequence,
              [
                [{:SingleAttribute, {2, 5, 4, 6}, {:correct, ~c"CN"}}],
                [{:SingleAttribute, {2, 5, 4, 42}, {:utf8String, "麗"}}]
              ]} = X509.RDNSequence.new("C=CN, givenName=麗")
    else
      assert {:rdnSequence,
              [
                [{:AttributeTypeAndValue, {2, 5, 4, 6}, <<19, 2, 67, 78>>}],
                [{:AttributeTypeAndValue, {2, 5, 4, 42}, <<12, 3, 233, 186, 151>>}]
              ]} = X509.RDNSequence.new("C=CN, givenName=麗")
    end
  end

  test "keyword list" do
    if Util.app_version(:public_key) >= [1, 18] do
      assert {:rdnSequence,
              [
                [{:SingleAttribute, {2, 5, 4, 3}, {:utf8String, "Elixir"}}]
              ]} = X509.RDNSequence.new(commonName: "Elixir")
    else
      assert {:rdnSequence,
              [
                [{:AttributeTypeAndValue, {2, 5, 4, 3}, <<12, 6, 69, 108, 105, 120, 105, 114>>}]
              ]} = X509.RDNSequence.new(commonName: "Elixir")
    end
  end

  test "unknown attribute" do
    assert_raise FunctionClauseError, fn ->
      X509.RDNSequence.new(language: "Elixir")
    end
  end

  test "illegal attribute value" do
    assert_raise ArgumentError, fn ->
      X509.RDNSequence.new("C=!!")
    end
  end

  test "countryName" do
    # Allow countryName length >2, even though strictly this is a violation of
    # the spec; OTP's :public_key does the same
    assert {:rdnSequence, _} = X509.RDNSequence.new("/C=Germany/O=ACME GmbH")
  end

  test "surname" do
    assert {:rdnSequence, _} = X509.RDNSequence.new("/SN=Erlang/GN=Agner Krarup")
  end
end
