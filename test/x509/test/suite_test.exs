defmodule X509.Test.SuiteTest do
  use ExUnit.Case
  import X509.ASN1

  # Some basic sanity checks only; real testing is done as part of
  # X509.Test.Server testing

  test :new do
    rsa_suite = X509.Test.Suite.new(key_type: {:rsa, 1024})
    assert %X509.Test.Suite{} = rsa_suite
    assert match?(rsa_private_key(), rsa_suite.server_key)

    ec_suite = X509.Test.Suite.new(key_type: {:ec, :secp256r1})
    assert %X509.Test.Suite{} = ec_suite
    assert match?(ec_private_key(), ec_suite.server_key)
  end

  test :sni_fun do
    suite = X509.Test.Suite.new()
    assert is_function(X509.Test.Suite.sni_fun(suite), 1)
  end
end
