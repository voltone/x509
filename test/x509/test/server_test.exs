defmodule X509.Test.ServerTest do
  # This test module serves two purposes:
  #
  #   * To perform sanity tests on the `X509.Test.Suite` and
  #     `X509.Test.Server` modules
  #   * To serve as an example for using those modules to test a TLS client
  #
  # The client being tested by this module is Erlang/OTP's built-in HTTP
  # client, `httpc`. To adapt the test cases for other clients, update the
  # `request/3` function
  #
  # The `setup_all` hook starts an `X509.Test.Server` instance, configured to
  # respond with a basic HTTP response. To test non-HTTP clients, modify the
  # response or replace `X509.Test.Server` with a suitable stub or server
  # implementation. In the latter case, make sure to set the `ssl` options as
  # described in the `X509.Test.Suite.sni_fun/1` documenation.
  #
  # Add `log_alert: true` to the call to request/3 to get more information on
  # a failing scenario, e.g.
  # `request(context.uri, context.suite.cacerts, log_alert: true)`

  use ExUnit.Case
  import TestHelper
  require Logger

  @http_response ["HTTP/1.1 200 OK", "Content-Length: 2", "Connection: close", "", "OK"]
                 |> Enum.join("\r\n")

  setup_all do
    # Ensure inets and ssl applications are started; httpc is part of inets
    Application.ensure_all_started(:inets)
    Application.ensure_all_started(:ssl)

    # Start the CRL responder
    crl_server_pid = start(X509.Test.CRLServer)
    crl_server_port = X509.Test.CRLServer.get_port(crl_server_pid)
    crl_server_uri = "http://localhost:#{crl_server_port}/"

    # Generate the set of test certificates and keys
    suite = X509.Test.Suite.new(crl_server: crl_server_uri)

    # Update the CRL server with the generated CRLs
    suite.crls
    |> Enum.each(fn {path, crl} ->
      X509.Test.CRLServer.put_crl(crl_server_pid, "/#{path}", crl)
    end)

    # Start the test server with a canned HTTP response, and get the TCP port
    # number of the server
    pid = start(X509.Test.Server, {suite, [response: @http_response]})
    port = X509.Test.Server.get_port(pid)

    [suite: suite, port: port]
  end

  def request(uri, cacerts, opts \\ [])

  def request(uri, :verify_none, opts) do
    request(uri, [], Keyword.put(opts, :verify, :verify_none))
  end

  def request(uri, cacerts, opts) do
    # Unfortunately OTP's `:ssl` application treats DER-list trust stores
    # differently from PEM-file stores; the difference seems to be in the way
    # the certificates are cached, and the result is that CRLs issued by root
    # CAs are not accepted unless the issuing CA was read from a PEM file; so
    # we need to create a temporary PEM file here...

    # Derive filename from `cacerts` contents, to generate a unique name for
    # each combination of certs
    # TODO: delete temporary files on completion?
    filename = "cacerts#{:erlang.phash2(cacerts)}.pem"
    cacertfile = write_cacerts!(filename, cacerts)

    ssl_defaults = [
      log_alert: false,
      verify: :verify_peer,
      # TODO: set partial_chain on OTP <21.1 (ssl < 9.0.2)
      # partial_chain: &partial_chain(&1, cacerts),
      crl_check: true,
      crl_cache: {:ssl_crl_cache, {:internal, [http: 30_000]}}
    ]

    ssl_opts =
      cond do
        version(:public_key) >= [1, 6] ->
          Keyword.put(ssl_defaults, :customize_hostname_check,
            match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
          )

        true ->
          ssl_defaults
      end
      |> Keyword.put(:cacertfile, cacertfile)
      |> Keyword.merge(opts)

    case :httpc.request(:get, {uri, []}, [ssl: ssl_opts], []) do
      {:ok, response} ->
        {:ok, response}

      {:error, {:failed_connect, info}} ->
        {:error, info |> List.keyfind(:inet, 0) |> elem(2)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  describe "valid" do
    setup context, do: [uri: 'https://valid.localtest.me:#{context.port}/']

    test "normal peer verification should succeed", context do
      assert {:ok, _} = request(context.uri, context.suite.cacerts)
    end

    test "without any peer verification should succeed", context do
      assert {:ok, _} = request(context.uri, :verify_none)
    end
  end

  describe "valid-missing-chain" do
    setup context, do: [uri: 'https://valid-missing-chain.localtest.me:#{context.port}/']

    test "normal peer verification should fail", context do
      assert {:error, {:tls_alert, 'unknown ca'}} = request(context.uri, context.suite.cacerts)
    end

    test "without any peer verification should succeed", context do
      assert {:ok, _} = request(context.uri, :verify_none)
    end

    if version(:ssl) >= [9, 0, 2] do
      # TODO: these three tests interfere with one another, perhaps because the
      # intermediate CA variants use the ame Subject value; check if there is a
      # way to enable all tests without the delay; calling
      # :ssl.clear_pem_cache() does not seem to help...

      test "with intermediate in CA store should succeed", context do
        # :timer.sleep(500)
        assert {:ok, _} = request(context.uri, context.suite.cacerts ++ context.suite.chain)
      end

      # test "with expired intermediate in CA store should fail", context do
      #   :timer.sleep(500)
      #
      #   assert {:error, {:tls_alert, 'certificate expired'}} =
      #            request(context.uri, context.suite.cacerts ++ context.suite.expired_chain)
      # end
      #
      # test "with revoked intermediate in CA store should fail", context do
      #   :timer.sleep(500)
      #
      #   assert {:error, {:tls_alert, 'certificate revoked'}} =
      #            request(context.uri, context.suite.cacerts ++ context.suite.revoked_chain)
      # end
    else
      # TODO: alternative approach with partial_chain?
      Logger.warn("Incomplete chain not supported by :public_key application; skipping test!")
    end
  end

  describe "valid-expired-chain" do
    setup context, do: [uri: 'https://valid-expired-chain.localtest.me:#{context.port}/']

    test "normal peer verification should fail", context do
      assert {:error, {:tls_alert, 'certificate expired'}} =
               request(context.uri, context.suite.cacerts)
    end

    test "without any peer verification should succeed", context do
      assert {:ok, _} = request(context.uri, :verify_none)
    end
  end

  describe "valid-revoked-chain" do
    setup context, do: [uri: 'https://valid-revoked-chain.localtest.me:#{context.port}/']

    test "normal peer verification should fail", context do
      assert {:error, {:tls_alert, 'certificate revoked'}} =
               request(context.uri, context.suite.cacerts)
    end

    test "without any peer verification should succeed", context do
      assert {:ok, _} = request(context.uri, :verify_none)
    end
  end

  describe "valid-wrong-key" do
    setup context, do: [uri: 'https://valid-wrong-key.localtest.me:#{context.port}/']

    test "normal peer verification should fail", context do
      assert {:error, {:tls_alert, 'decrypt error'}} = request(context.uri, context.suite.cacerts)
    end

    test "without any peer verification should fail", context do
      assert {:error, {:tls_alert, 'decrypt error'}} = request(context.uri, context.suite.cacerts)
    end
  end

  describe "valid-wrong-host" do
    setup context, do: [uri: 'https://valid-wrong-host.localtest.me:#{context.port}/']

    test "normal peer verification should fail", context do
      assert {:error, {:tls_alert, 'handshake failure'}} =
               request(context.uri, context.suite.cacerts)
    end

    test "without any peer verification should succed", context do
      assert {:ok, _} = request(context.uri, :verify_none)
    end
  end

  describe "valid-cross-signed" do
    setup context, do: [uri: 'https://valid-cross-signed.localtest.me:#{context.port}/']

    test "peer verification with cross-signing root CA should succeed", context do
      # Need to increase the default validation depth, because the cross-signed
      # chain is longer
      # TODO: figure out why this only works with 'best effort' CRL check
      assert {:ok, _} =
               request(context.uri, context.suite.alternate_cacerts,
                 depth: 2,
                 crl_check: :best_effort
               )
    end

    test "peer verification with new root CA should succeed", context do
      # TODO: remove the partial_chain option if/when OTP supports cross-signed
      # certificates properly
      assert {:ok, _} =
               request(context.uri, context.suite.cacerts,
                 partial_chain: &partial_chain(&1, context.suite.cacerts)
               )
    end

    test "peer verification with both CAs should succeed with depth=2", context do
      # TODO: figure out why this doesn't work with CRL checks on CA certificates
      assert {:ok, _} =
               request(context.uri, context.suite.alternate_cacerts ++ context.suite.cacerts,
                 depth: 2,
                 crl_check: :peer
               )

      # Reverse the order of the CAs and try again
      assert {:ok, _} =
               request(context.uri, context.suite.cacerts ++ context.suite.alternate_cacerts,
                 depth: 2,
                 crl_check: :peer
               )
    end

    # test "peer verification with both CAs should succeed with depth=1", context do
    #   # The new root CA must be selected, because using the cross-signing CA
    #   # would exceed the default maximum depth (1); this test case verifies
    #   # that the new root CA is selected regardless of its place in the trust
    #   # store relative to the cross-signing CA
    #
    #   # This scenario currently fails, because OTP builds only the chain with
    #   # the cross-signing CA, which is invalid due to the depth limitation, and
    #   # it doesn't explore alternative paths
    #   assert {:ok, _} =
    #            request(context.uri, context.suite.alternate_cacerts ++ context.suite.cacerts,
    #              crl_check: :peer
    #            )
    #
    #   # Reverse the order of the CAs and try again
    #   assert {:ok, _} =
    #            request(context.uri, context.suite.cacerts ++ context.suite.alternate_cacerts,
    #              crl_check: :peer
    #            )
    # end
  end

  if version(:public_key) >= [1, 6] do
    describe "wildcard" do
      test "valid.wildcard", context do
        uri = 'https://valid.wildcard.localtest.me:#{context.port}/'
        assert {:ok, _} = request(uri, context.suite.cacerts)
      end

      test "wildcard (no subdomain)", context do
        # Wildcard certificates are not valid for the parent domain, unless a
        # separate hostname SAN entry for that domain exists
        uri = 'https://wildcard.localtest.me:#{context.port}/'
        assert {:error, {:tls_alert, 'handshake failure'}} = request(uri, context.suite.cacerts)
      end

      test "invalid.subdomain.wildcard", context do
        # Wildcard certificates are not valid for sub-subdomains
        uri = 'https://invalid.subdomain.wildcard.localtest.me:#{context.port}/'
        assert {:error, {:tls_alert, 'handshake failure'}} = request(uri, context.suite.cacerts)
      end
    end
  else
    Logger.warn("Wildcard SAN not supported by :public_key application; skipping tests!")
  end

  describe "expired" do
    setup context, do: [uri: 'https://expired.localtest.me:#{context.port}/']

    test "normal peer verification should fail", context do
      assert {:error, {:tls_alert, 'certificate expired'}} =
               request(context.uri, context.suite.cacerts)
    end

    test "without any peer verification should succeed", context do
      assert {:ok, _} = request(context.uri, :verify_none)
    end
  end

  describe "revoked" do
    setup context, do: [uri: 'https://revoked.localtest.me:#{context.port}/']

    test "normal peer verification should fail", context do
      assert {:error, {:tls_alert, 'certificate revoked'}} =
               request(context.uri, context.suite.cacerts)
    end

    test "without any peer verification should succeed", context do
      assert {:ok, _} = request(context.uri, :verify_none)
    end
  end

  describe "selfsigned" do
    setup context, do: [uri: 'https://selfsigned.localtest.me:#{context.port}/']

    test "normal peer verification should fail", context do
      assert {:error, {:tls_alert, 'bad certificate'}} =
               request(context.uri, context.suite.cacerts)
    end

    test "without any peer verification should succeed", context do
      assert {:ok, _} = request(context.uri, :verify_none)
    end

    test "with certificate pinning should succeed", context do
      assert {:ok, _} =
               request(context.uri, [],
                 verify_fun:
                   pin_selfsigned_peer(context.suite.selfsigned, "selfsigned.localtest.me")
               )
    end
  end

  describe "selfsigned-wrong-key" do
    setup context, do: [uri: 'https://selfsigned-wrong-key.localtest.me:#{context.port}/']

    test "normal peer verification should fail", context do
      # Note that this fails with a 'bad certificate' error, because the
      # certificate is not trusted; the private key is never used, so the key
      # mismatch does not have any impact in this scenario
      assert {:error, {:tls_alert, 'bad certificate'}} =
               request(context.uri, context.suite.cacerts)
    end

    test "without any peer verification should fail", context do
      assert {:error, {:tls_alert, 'decrypt error'}} = request(context.uri, :verify_none)
    end

    test "with certificate pinning should fail", context do
      assert {:error, {:tls_alert, 'decrypt error'}} =
               request(context.uri, [],
                 verify_fun:
                   pin_selfsigned_peer(context.suite.selfsigned, "selfsigned.localtest.me")
               )
    end
  end

  describe "selfsigned-wrong-host" do
    setup context, do: [uri: 'https://selfsigned-wrong-host.localtest.me:#{context.port}/']

    test "normal peer verification should fail", context do
      assert {:error, {:tls_alert, 'bad certificate'}} =
               request(context.uri, context.suite.cacerts)
    end

    test "without any peer verification should succed", context do
      assert {:ok, _} = request(context.uri, :verify_none)
    end

    test "with certificate pinning should fail", context do
      assert {:error, {:tls_alert, 'bad certificate'}} =
               request(context.uri, [],
                 verify_fun:
                   pin_selfsigned_peer(
                     context.suite.selfsigned,
                     "selfsigned-wrong-host.localtest.me"
                   )
               )
    end
  end

  defp write_cacerts!(filename, certs) do
    path = Path.join(System.tmp_dir!(), filename)

    unless File.exists?(path) do
      pem =
        certs
        |> Enum.map(&certificate_der_to_pem/1)
        |> Enum.join()

      File.write!(path, pem)
    end

    path
  end

  defp certificate_der_to_pem(der) do
    der
    |> X509.Certificate.from_der!()
    |> X509.Certificate.to_pem()
  end

  # From https://github.com/hexpm/hex/blob/master/lib/hex/http/ssl.ex#L89
  defp partial_chain(certs, cacerts) do
    certs = Enum.map(certs, &{&1, :public_key.pkix_decode_cert(&1, :otp)})
    cacerts = Enum.map(cacerts, &:public_key.pkix_decode_cert(&1, :otp))

    trusted =
      Enum.find_value(certs, fn {der, cert} ->
        trusted? =
          Enum.find(cacerts, fn cacert ->
            extract_public_key_info(cacert) == extract_public_key_info(cert)
          end)

        if trusted?, do: der
      end)

    if trusted do
      {:trusted_ca, trusted}
    else
      :unknown_ca
    end
  end

  require Record

  Record.defrecordp(
    :certificate,
    :OTPCertificate,
    Record.extract(:OTPCertificate, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecordp(
    :tbs_certificate,
    :OTPTBSCertificate,
    Record.extract(:OTPTBSCertificate, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  defp extract_public_key_info(cert) do
    cert
    |> certificate(:tbsCertificate)
    |> tbs_certificate(:subjectPublicKeyInfo)
  end

  # Returns a verify_fun that expects the peer certificate to be a self-signed
  # certificate with a key pair matching the given certificate
  defp pin_selfsigned_peer(cert, hostname) do
    public_key = X509.Certificate.public_key(cert)

    fun = fn
      cert, {:bad_cert, :selfsigned_peer} = reason, public_key ->
        if X509.Certificate.public_key(cert) == public_key do
          # The key pair matches, but as far as OTP's :public_key is concerned
          # the certificate check failed, so it didn't check the hostname yet;
          # we need to perform hostname verification ourselves!

          hostname_check =
            if version(:public_key) >= [1, 6] do
              # Use customize_hostname_check/pkix_verify_hostname_match_fun only
              # on OTP 21
              :public_key.pkix_verify_hostname(cert,
                dns_id: to_charlist(hostname),
                match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
              )
            else
              :public_key.pkix_verify_hostname(cert,
                dns_id: to_charlist(hostname)
              )
            end

          case hostname_check do
            true -> {:valid, public_key}
            false -> {:fail, {:bad_cert, :hostname_check_failed}}
          end
        else
          {:fail, reason}
        end

      _cert, {:extension, _}, state ->
        {:unknown, state}

      _cert, _event, _state ->
        {:fail, {:badcert, :unknown_ca}}
    end

    {fun, public_key}
  end
end
