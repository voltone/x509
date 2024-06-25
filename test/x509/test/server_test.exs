defmodule X509.Test.ServerTest do
  # This test module serves two purposes:
  #
  #   * To perform sanity tests on the `X509.Test.Suite` and
  #     `X509.Test.Server` modules
  #   * To serve as an example for using those modules to test a TLS client
  #
  # The client being tested by this module is Erlang/OTP's built-in HTTP
  # client, `httpc`. To adapt for other clients, update the `request/2`
  # function, as described in the comments.
  #
  # Add `log_level: :debug` (OTP >=22) or `log_alert: true` (older OTP
  # versions)to the call to request/2 to get more information on a failing
  # scenario, e.g.:
  #
  #   ```
  #   request('https://valid.#{context.suite.domain}:#{context.port}/',
  #     cacertfile: context.cacertfile,
  #     log_level: :debug
  #   )
  #   ```
  #
  # Look for the keyword "ISSUE" to find comments throughout this file
  # documenting unexpected behaviour, interop issues or insecure defaults.

  use ExUnit.Case
  import X509.TestHelper

  #
  # Client under test
  #

  # This function invokes the TLS client under test. In this case we're using
  # Erlang/OTP's built-in HTTP client `httpc`, part of the `inets` application.
  #
  # To test another client, update this function as necessary. If the client is
  # not an HTTP client, remember to also update the test server response to
  # match the protocol the client is expecting.
  def request(uri, opts) do
    # ISSUE: `ssl` fails to perform CRL checks on certificates issued by
    # root CAs that were passed in via the `cacerts` option; to get the
    # connection to succeed, CRL checks have to be limited to the peer
    # certificate only
    # crl_check = (Keyword.has_key?(opts, :cacerts) && :peer) || true

    # ISSUE: CRL checks with OTP 23.2 and 23.1 are broken when passing CA
    # trust store as a list of DER binaries:
    # https://github.com/erlang/otp/issues/4589
    crl_check = !Keyword.has_key?(opts, :cacerts)

    # ISSUE: `httpc` requires explicit opt-in to peer certificate verification,
    # with HTTPS connections to misconfigured or malicious servers succeeding
    # without warning when using the default settings!
    ssl_defaults =
      [
        verify: :verify_peer,
        depth: 2,
        crl_check: crl_check,
        crl_cache: {:ssl_crl_cache, {:internal, [http: 30_000]}}
      ] ++ X509.Test.Server.log_opts()

    ssl_opts =
      cond do
        version(:public_key) >= [1, 6] ->
          # ISSUE: `httpc` does not leverage OTP 21's built-in hostname
          # verification function for HTTPS, causing connections to servers
          # with wildcard patterns in their certificate's Subject Alternative
          # Name (SAN) extension to fail
          Keyword.put(ssl_defaults, :customize_hostname_check,
            match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
          )

        true ->
          ssl_defaults
      end
      |> Keyword.merge(opts)

    case :httpc.request(:get, {uri, []}, [ssl: ssl_opts], []) do
      {:ok, response} ->
        {:ok, response}

      {:error, {:failed_connect, info}} ->
        # Return the TLS alert
        {:error, info |> List.keyfind(:inet, 0) |> elem(2)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  #
  # Test cases
  #

  describe "RSA, PEM" do
    setup [:rsa_suite, :create_pem_files]

    test "valid", context do
      assert {:ok, _} =
               request(~c"https://valid.#{context.suite.domain}:#{context.port}/",
                 cacertfile: context.cacertfile
               )
    end

    test "valid-missing-chain", context do
      assert {:error, {:tls_alert, reason}} =
               request(~c"https://valid-missing-chain.#{context.suite.domain}:#{context.port}/",
                 cacertfile: context.cacertfile
               )

      assert inspect(reason) =~ "unknown"
    end

    test "valid-missing-chain with intermediate in cacerts", context do
      # On OTP 21, `ssl` will fill in gaps in the server's chain using
      # intermediate CAs from the provided trust store
      if version(:ssl) >= [9, 0, 2] do
        assert {:ok, _} =
                 request(~c"https://valid-missing-chain.#{context.suite.domain}:#{context.port}/",
                   cacertfile: context.cacertfile_with_chain
                 )
      end
    end

    test "valid-expired-chain", context do
      assert {:error, {:tls_alert, reason}} =
               request(~c"https://valid-expired-chain.#{context.suite.domain}:#{context.port}/",
                 cacertfile: context.cacertfile
               )

      assert inspect(reason) =~ "expired"
    end

    test "valid-revoked-chain", context do
      assert {:error, {:tls_alert, reason}} =
               request(~c"https://valid-revoked-chain.#{context.suite.domain}:#{context.port}/",
                 cacertfile: context.cacertfile
               )

      assert inspect(reason) =~ "revoked"
    end

    test "valid-wrong-key", context do
      assert {:error, {:tls_alert, reason}} =
               request(~c"https://valid-wrong-key.#{context.suite.domain}:#{context.port}/",
                 cacertfile: context.cacertfile
               )

      assert inspect(reason) =~ ~r/decrypt|CertificateVerify/
    end

    test "valid-wrong-host", context do
      assert {:error, {:tls_alert, reason}} =
               request(~c"https://valid-wrong-host.#{context.suite.domain}:#{context.port}/",
                 cacertfile: context.cacertfile
               )

      assert inspect(reason) =~ "handshake"
    end

    # ISSUE: this test case fails, because `public_key` does not explore
    # alternate paths to complete the chain; instead, it only looks for CAs
    # in its CA store that can complete the chain presented by the peer;
    # it is possible to work around this using a `partial_chain` function,
    # but this short-circuits other certificate verification features, such
    # as revocation checks and path length constraint checking
    @tag :known_to_fail
    test "valid-cross-signed, cross-signed CA", context do
      assert {:ok, _} =
               request(~c"https://valid-cross-signed.#{context.suite.domain}:#{context.port}/",
                 cacertfile: context.cacertfile
               )
    end

    test "valid-cross-signed, cross-signing CA", context do
      # TODO: this only works with 'best effort' CRL checks; this may be an
      # issue with the test suite
      assert {:ok, _} =
               request(~c"https://valid-cross-signed.#{context.suite.domain}:#{context.port}/",
                 cacertfile: context.alternate_cacertfile,
                 crl_check: :best_effort
               )
    end

    test "valid.wildcard", context do
      # OTP 21 supports wildcard certificates with the Subject Alternate Name
      # extension, if configured properly (see `request/2` comments); on older
      # versions this test would fail
      if version(:public_key) >= [1, 6] do
        assert {:ok, _} =
                 request(~c"https://valid.wildcard.#{context.suite.domain}:#{context.port}/",
                   cacertfile: context.cacertfile
                 )
      end
    end

    test "wildcard, bare domain", context do
      assert {:error, {:tls_alert, reason}} =
               request(~c"https://wildcard.#{context.suite.domain}:#{context.port}/",
                 cacertfile: context.cacertfile
               )

      assert inspect(reason) =~ "handshake"
    end

    test "invalid.subdomain.wildcard", context do
      assert {:error, {:tls_alert, reason}} =
               request(
                 ~c"https://invalid.subdomain.wildcard.#{context.suite.domain}:#{context.port}/",
                 cacertfile: context.cacertfile
               )

      assert inspect(reason) =~ "handshake"
    end

    test "expired", context do
      assert {:error, {:tls_alert, reason}} =
               request(~c"https://expired.#{context.suite.domain}:#{context.port}/",
                 cacertfile: context.cacertfile
               )

      assert inspect(reason) =~ "expired"
    end

    test "revoked", context do
      assert {:error, {:tls_alert, reason}} =
               request(~c"https://revoked.#{context.suite.domain}:#{context.port}/",
                 cacertfile: context.cacertfile
               )

      assert inspect(reason) =~ "revoked"
    end

    test "selfsigned", context do
      assert {:error, {:tls_alert, reason}} =
               request(~c"https://selfsigned.#{context.suite.domain}:#{context.port}/",
                 cacertfile: context.cacertfile
               )

      assert inspect(reason) =~ "bad"
    end

    test "client-cert", context do
      assert {:error, error} =
               request(~c"https://client-cert.#{context.suite.domain}:#{context.port}/",
                 cacertfile: context.cacertfile
               )

      case error do
        {:tls_alert, reason} ->
          assert inspect(reason) =~ "handshake"

        {:ssl_error, _sock, {:tls_alert, reason}} ->
          assert {:certificate_required, _message} = reason

        _else ->
          # ISSUE: it seems that with recent OTP versions, the TLS handshake
          # sometimes fails with a socket error (socket_closed_remotely, einval)
          # rather than a TLS alert; perhaps this happens when a socket write
          # fails before the alert has been read. As a result we can't fail the
          # test un unexpected responses
          # flunk("Expected a handshake error, got #{inspect(error)}")
          :ignore
      end

      assert {:ok, _} =
               request(~c"https://client-cert.#{context.suite.domain}:#{context.port}/",
                 cacerts: context.suite.chain ++ context.suite.cacerts,
                 cert: X509.Certificate.to_der(context.suite.client),
                 key: {:RSAPrivateKey, X509.PrivateKey.to_der(context.suite.client_key)}
               )
    end
  end

  describe "RSA, DER" do
    setup [:rsa_suite]

    test "valid", context do
      assert {:ok, _} =
               request(~c"https://valid.#{context.suite.domain}:#{context.port}/",
                 cacerts: context.suite.cacerts
               )
    end

    test "valid-missing-chain", context do
      assert {:error, {:tls_alert, reason}} =
               request(~c"https://valid-missing-chain.#{context.suite.domain}:#{context.port}/",
                 cacerts: context.suite.cacerts
               )

      assert inspect(reason) =~ "unknown"
    end

    test "valid-missing-chain with intermediate in cacerts", context do
      # On OTP 21, `ssl` will fill in gaps in the server's chain using
      # intermediate CAs from the provided trust store
      if version(:ssl) >= [9, 0, 2] do
        # ISSUE: `ssl` fails to perform CRL checks on certificates issued by
        # certificates that were passed in via the `cacerts` option; since the
        # issuer of the peer certificate in this case is taken from `cacerts`,
        # no CRL checks can be performed
        assert {:ok, _} =
                 request(~c"https://valid-missing-chain.#{context.suite.domain}:#{context.port}/",
                   cacerts: context.suite.cacerts ++ context.suite.chain,
                   crl_check: false
                 )
      end
    end

    test "valid-expired-chain", context do
      assert {:error, {:tls_alert, reason}} =
               request(~c"https://valid-expired-chain.#{context.suite.domain}:#{context.port}/",
                 cacerts: context.suite.cacerts
               )

      assert inspect(reason) =~ "expired"
    end

    # ISSUE: this test case fails, because `ssl` does not handle CRL checks on
    # certificates issued by CAs passed in through `cacerts`
    @tag :known_to_fail
    test "valid-revoked-chain", context do
      assert {:error, {:tls_alert, reason}} =
               request(~c"https://valid-revoked-chain.#{context.suite.domain}:#{context.port}/",
                 cacerts: context.suite.cacerts
               )

      assert inspect(reason) =~ "revoked"
    end

    test "valid-wrong-key", context do
      assert {:error, {:tls_alert, reason}} =
               request(~c"https://valid-wrong-key.#{context.suite.domain}:#{context.port}/",
                 cacerts: context.suite.cacerts
               )

      assert inspect(reason) =~ ~r/decrypt|CertificateVerify/
    end

    test "valid-wrong-host", context do
      assert {:error, {:tls_alert, reason}} =
               request(~c"https://valid-wrong-host.#{context.suite.domain}:#{context.port}/",
                 cacerts: context.suite.cacerts
               )

      assert inspect(reason) =~ "handshake"
    end

    # ISSUE: this test case fails, because `public_key` does not explore
    # alternate paths to complete the chain; instead, it only looks for CAs
    # in its CA store that can complete the chain presented by the peer;
    # it is possible to work around this using a `partial_chain` function,
    # but this short-circuits other certificate verification features, such
    # as revocation checks and path length constraint checking
    @tag :known_to_fail
    test "valid-cross-signed, cross-signed CA", context do
      assert {:ok, _} =
               request(~c"https://valid-cross-signed.#{context.suite.domain}:#{context.port}/",
                 cacerts: context.suite.cacerts
               )
    end

    test "valid-cross-signed, cross-signing CA", context do
      # TODO: this does not work with CRL checks at all, not even peer-only;
      # this may be an issue with the test suite
      assert {:ok, _} =
               request(~c"https://valid-cross-signed.#{context.suite.domain}:#{context.port}/",
                 cacerts: context.suite.alternate_cacerts,
                 crl_check: false
               )
    end

    test "valid.wildcard", context do
      # OTP 21 supports wildcard certificates with the Subject Alternate Name
      # extension, if configured properly (see `request/2` comments); on older
      # versions this test would fail
      if version(:public_key) >= [1, 6] do
        assert {:ok, _} =
                 request(~c"https://valid.wildcard.#{context.suite.domain}:#{context.port}/",
                   cacerts: context.suite.cacerts
                 )
      end
    end

    test "wildcard, bare domain", context do
      assert {:error, {:tls_alert, reason}} =
               request(~c"https://wildcard.#{context.suite.domain}:#{context.port}/",
                 cacerts: context.suite.cacerts
               )

      assert inspect(reason) =~ "handshake"
    end

    test "invalid.subdomain.wildcard", context do
      assert {:error, {:tls_alert, reason}} =
               request(
                 ~c"https://invalid.subdomain.wildcard.#{context.suite.domain}:#{context.port}/",
                 cacerts: context.suite.cacerts
               )

      assert inspect(reason) =~ "handshake"
    end

    test "expired", context do
      assert {:error, {:tls_alert, reason}} =
               request(~c"https://expired.#{context.suite.domain}:#{context.port}/",
                 cacerts: context.suite.cacerts
               )

      assert inspect(reason) =~ "expired"
    end

    # ISSUE: CRL checks with OTP 23.2 and 23.1 are broken when passing CA
    # trust store as a list of DER binaries:
    # https://github.com/erlang/otp/issues/4589
    @tag :known_to_fail
    test "revoked", context do
      assert {:error, {:tls_alert, reason}} =
               request(~c"https://revoked.#{context.suite.domain}:#{context.port}/",
                 cacerts: context.suite.cacerts
               )

      assert inspect(reason) =~ "revoked"
    end

    test "selfsigned", context do
      assert {:error, {:tls_alert, reason}} =
               request(~c"https://selfsigned.#{context.suite.domain}:#{context.port}/",
                 cacerts: context.suite.cacerts
               )

      assert inspect(reason) =~ "bad"
    end

    test "client-cert", context do
      assert {:error, error} =
               request(~c"https://client-cert.#{context.suite.domain}:#{context.port}/",
                 cacerts: context.suite.cacerts
               )

      case error do
        {:tls_alert, reason} ->
          assert inspect(reason) =~ "handshake"

        {:ssl_error, _sock, {:tls_alert, reason}} ->
          assert {:certificate_required, _message} = reason

        _else ->
          # ISSUE: it seems that with recent OTP versions, the TLS handshake
          # sometimes fails with a socket error (socket_closed_remotely, einval)
          # rather than a TLS alert; perhaps this happens when a socket write
          # fails before the alert has been read. As a result we can't fail the
          # test un unexpected responses
          # flunk("Expected a handshake error, got #{inspect(error)}")
          :ignore
      end

      assert {:ok, _} =
               request(~c"https://client-cert.#{context.suite.domain}:#{context.port}/",
                 cacerts: context.suite.chain ++ context.suite.cacerts,
                 cert: X509.Certificate.to_der(context.suite.client),
                 key: {:RSAPrivateKey, X509.PrivateKey.to_der(context.suite.client_key)}
               )
    end
  end

  # ECDSA tests fail on older OTP releases, due to OTP-15203
  if version(:ssl) >= [8, 2, 6, 2] and version(:ssl) != [9, 0, 0] do
    describe "ECDSA, PEM" do
      setup [:ecdsa_suite, :create_pem_files]

      test "valid", context do
        assert {:ok, _} =
                 request(~c"https://valid.#{context.suite.domain}:#{context.port}/",
                   cacertfile: context.cacertfile
                 )
      end

      test "valid-missing-chain", context do
        assert {:error, {:tls_alert, reason}} =
                 request(~c"https://valid-missing-chain.#{context.suite.domain}:#{context.port}/",
                   cacertfile: context.cacertfile
                 )

        assert inspect(reason) =~ "unknown"
      end

      test "valid-missing-chain with intermediate in cacerts", context do
        # On OTP 21, `ssl` will fill in gaps in the server's chain using
        # intermediate CAs from the provided trust store
        if version(:ssl) >= [9, 0, 2] do
          assert {:ok, _} =
                   request(
                     ~c"https://valid-missing-chain.#{context.suite.domain}:#{context.port}/",
                     cacertfile: context.cacertfile_with_chain
                   )
        end
      end

      test "valid-expired-chain", context do
        assert {:error, {:tls_alert, reason}} =
                 request(~c"https://valid-expired-chain.#{context.suite.domain}:#{context.port}/",
                   cacertfile: context.cacertfile
                 )

        assert inspect(reason) =~ "expired"
      end

      test "valid-revoked-chain", context do
        assert {:error, {:tls_alert, reason}} =
                 request(~c"https://valid-revoked-chain.#{context.suite.domain}:#{context.port}/",
                   cacertfile: context.cacertfile
                 )

        assert inspect(reason) =~ "revoked"
      end

      test "valid-wrong-key", context do
        assert {:error, {:tls_alert, reason}} =
                 request(~c"https://valid-wrong-key.#{context.suite.domain}:#{context.port}/",
                   cacertfile: context.cacertfile
                 )

        assert inspect(reason) =~ ~r/decrypt|CertificateVerify/
      end

      test "valid-wrong-host", context do
        assert {:error, {:tls_alert, reason}} =
                 request(~c"https://valid-wrong-host.#{context.suite.domain}:#{context.port}/",
                   cacertfile: context.cacertfile
                 )

        assert inspect(reason) =~ "handshake"
      end

      # ISSUE: this test case fails, because `public_key` does not explore
      # alternate paths to complete the chain; instead, it only looks for CAs
      # in its CA store that can complete the chain presented by the peer;
      # it is possible to work around this using a `partial_chain` function,
      # but this short-circuits other certificate verification features, such
      # as revocation checks and path length constraint checking
      @tag :known_to_fail
      test "valid-cross-signed, cross-signed CA", context do
        assert {:ok, _} =
                 request(~c"https://valid-cross-signed.#{context.suite.domain}:#{context.port}/",
                   cacertfile: context.cacertfile
                 )
      end

      test "valid-cross-signed, cross-signing CA", context do
        # TODO: this only works with 'best effort' CRL checks; this may be an
        # issue with the test suite
        assert {:ok, _} =
                 request(~c"https://valid-cross-signed.#{context.suite.domain}:#{context.port}/",
                   cacertfile: context.alternate_cacertfile,
                   crl_check: :best_effort
                 )
      end

      test "valid.wildcard", context do
        # OTP 21 supports wildcard certificates with the Subject Alternate Name
        # extension, if configured properly (see `request/2` comments); on older
        # versions this test would fail
        if version(:public_key) >= [1, 6] do
          assert {:ok, _} =
                   request(~c"https://valid.wildcard.#{context.suite.domain}:#{context.port}/",
                     cacertfile: context.cacertfile
                   )
        end
      end

      test "wildcard, bare domain", context do
        assert {:error, {:tls_alert, reason}} =
                 request(~c"https://wildcard.#{context.suite.domain}:#{context.port}/",
                   cacertfile: context.cacertfile
                 )

        assert inspect(reason) =~ "handshake"
      end

      test "invalid.subdomain.wildcard", context do
        assert {:error, {:tls_alert, reason}} =
                 request(
                   ~c"https://invalid.subdomain.wildcard.#{context.suite.domain}:#{context.port}/",
                   cacertfile: context.cacertfile
                 )

        assert inspect(reason) =~ "handshake"
      end

      test "expired", context do
        assert {:error, {:tls_alert, reason}} =
                 request(~c"https://expired.#{context.suite.domain}:#{context.port}/",
                   cacertfile: context.cacertfile
                 )

        assert inspect(reason) =~ "expired"
      end

      test "revoked", context do
        assert {:error, {:tls_alert, reason}} =
                 request(~c"https://revoked.#{context.suite.domain}:#{context.port}/",
                   cacertfile: context.cacertfile
                 )

        assert inspect(reason) =~ "revoked"
      end

      test "selfsigned", context do
        assert {:error, {:tls_alert, reason}} =
                 request(~c"https://selfsigned.#{context.suite.domain}:#{context.port}/",
                   cacertfile: context.cacertfile
                 )

        assert inspect(reason) =~ "bad"
      end

      test "client-cert", context do
        assert {:error, error} =
                 request(~c"https://client-cert.#{context.suite.domain}:#{context.port}/",
                   cacertfile: context.cacertfile
                 )

        case error do
          {:tls_alert, reason} ->
            assert inspect(reason) =~ "handshake"

          {:ssl_error, _sock, {:tls_alert, reason}} ->
            assert {:certificate_required, _message} = reason

          _else ->
            # ISSUE: it seems that with recent OTP versions, the TLS handshake
            # sometimes fails with a socket error (socket_closed_remotely, einval)
            # rather than a TLS alert; perhaps this happens when a socket write
            # fails before the alert has been read. As a result we can't fail the
            # test un unexpected responses
            # flunk("Expected a handshake error, got #{inspect(error)}")
            :ignore
        end

        assert {:ok, _} =
                 request(~c"https://client-cert.#{context.suite.domain}:#{context.port}/",
                   cacerts: context.suite.chain ++ context.suite.cacerts,
                   cert: X509.Certificate.to_der(context.suite.client),
                   key: {:ECPrivateKey, X509.PrivateKey.to_der(context.suite.client_key)}
                 )
      end
    end

    describe "ECDSA, DER" do
      setup [:ecdsa_suite]

      test "valid", context do
        assert {:ok, _} =
                 request(~c"https://valid.#{context.suite.domain}:#{context.port}/",
                   cacerts: context.suite.cacerts
                 )
      end

      test "valid-missing-chain", context do
        assert {:error, {:tls_alert, reason}} =
                 request(~c"https://valid-missing-chain.#{context.suite.domain}:#{context.port}/",
                   cacerts: context.suite.cacerts
                 )

        assert inspect(reason) =~ "unknown"
      end

      test "valid-missing-chain with intermediate in cacerts", context do
        # On OTP 21, `ssl` will fill in gaps in the server's chain using
        # intermediate CAs from the provided trust store
        if version(:ssl) >= [9, 0, 2] do
          # ISSUE: `ssl` fails to perform CRL checks on certificates issued by
          # certificates that were passed in via the `cacerts` option; since the
          # issuer of the peer certificate in this case is taken from `cacerts`,
          # no CRL checks can be performed
          assert {:ok, _} =
                   request(
                     ~c"https://valid-missing-chain.#{context.suite.domain}:#{context.port}/",
                     cacerts: context.suite.cacerts ++ context.suite.chain,
                     crl_check: false
                   )
        end
      end

      test "valid-expired-chain", context do
        assert {:error, {:tls_alert, reason}} =
                 request(~c"https://valid-expired-chain.#{context.suite.domain}:#{context.port}/",
                   cacerts: context.suite.cacerts
                 )

        assert inspect(reason) =~ "expired"
      end

      # ISSUE: this test case fails, because `ssl` does not handle CRL checks on
      # certificates issued by CAs passed in through `cacerts`
      @tag :known_to_fail
      test "valid-revoked-chain", context do
        assert {:error, {:tls_alert, reason}} =
                 request(~c"https://valid-revoked-chain.#{context.suite.domain}:#{context.port}/",
                   cacerts: context.suite.cacerts
                 )

        assert inspect(reason) =~ "revoked"
      end

      test "valid-wrong-key", context do
        assert {:error, {:tls_alert, reason}} =
                 request(~c"https://valid-wrong-key.#{context.suite.domain}:#{context.port}/",
                   cacerts: context.suite.cacerts
                 )

        assert inspect(reason) =~ ~r/decrypt|CertificateVerify/
      end

      test "valid-wrong-host", context do
        assert {:error, {:tls_alert, reason}} =
                 request(~c"https://valid-wrong-host.#{context.suite.domain}:#{context.port}/",
                   cacerts: context.suite.cacerts
                 )

        assert inspect(reason) =~ "handshake"
      end

      # ISSUE: this test case fails, because `public_key` does not explore
      # alternate paths to complete the chain; instead, it only looks for CAs
      # in its CA store that can complete the chain presented by the peer;
      # it is possible to work around this using a `partial_chain` function,
      # but this short-circuits other certificate verification features, such
      # as revocation checks and path length constraint checking
      @tag :known_to_fail
      test "valid-cross-signed, cross-signed CA", context do
        assert {:ok, _} =
                 request(~c"https://valid-cross-signed.#{context.suite.domain}:#{context.port}/",
                   cacerts: context.suite.cacerts
                 )
      end

      test "valid-cross-signed, cross-signing CA", context do
        # TODO: this does not work with CRL checks at all, not even peer-only;
        # this may be an issue with the test suite
        assert {:ok, _} =
                 request(~c"https://valid-cross-signed.#{context.suite.domain}:#{context.port}/",
                   cacerts: context.suite.alternate_cacerts,
                   crl_check: false
                 )
      end

      test "valid.wildcard", context do
        # OTP 21 supports wildcard certificates with the Subject Alternate Name
        # extension, if configured properly (see `request/2` comments); on older
        # versions this test would fail
        if version(:public_key) >= [1, 6] do
          assert {:ok, _} =
                   request(~c"https://valid.wildcard.#{context.suite.domain}:#{context.port}/",
                     cacerts: context.suite.cacerts
                   )
        end
      end

      test "wildcard, bare domain", context do
        assert {:error, {:tls_alert, reason}} =
                 request(~c"https://wildcard.#{context.suite.domain}:#{context.port}/",
                   cacerts: context.suite.cacerts
                 )

        assert inspect(reason) =~ "handshake"
      end

      test "invalid.subdomain.wildcard", context do
        assert {:error, {:tls_alert, reason}} =
                 request(
                   ~c"https://invalid.subdomain.wildcard.#{context.suite.domain}:#{context.port}/",
                   cacerts: context.suite.cacerts
                 )

        assert inspect(reason) =~ "handshake"
      end

      test "expired", context do
        assert {:error, {:tls_alert, reason}} =
                 request(~c"https://expired.#{context.suite.domain}:#{context.port}/",
                   cacerts: context.suite.cacerts
                 )

        assert inspect(reason) =~ "expired"
      end

      # ISSUE: CRL checks with OTP 23.2 and 23.1 are broken when passing CA
      # trust store as a list of DER binaries:
      # https://github.com/erlang/otp/issues/4589
      @tag :known_to_fail
      test "revoked", context do
        assert {:error, {:tls_alert, reason}} =
                 request(~c"https://revoked.#{context.suite.domain}:#{context.port}/",
                   cacerts: context.suite.cacerts
                 )

        assert inspect(reason) =~ "revoked"
      end

      test "selfsigned", context do
        assert {:error, {:tls_alert, reason}} =
                 request(~c"https://selfsigned.#{context.suite.domain}:#{context.port}/",
                   cacerts: context.suite.cacerts
                 )

        assert inspect(reason) =~ "bad"
      end

      test "client-cert", context do
        assert {:error, error} =
                 request(~c"https://client-cert.#{context.suite.domain}:#{context.port}/",
                   cacerts: context.suite.cacerts
                 )

        case error do
          {:tls_alert, reason} ->
            assert inspect(reason) =~ "handshake"

          {:ssl_error, _sock, {:tls_alert, reason}} ->
            assert {:certificate_required, _message} = reason

          _else ->
            # ISSUE: it seems that with recent OTP versions, the TLS handshake
            # sometimes fails with a socket error (socket_closed_remotely, einval)
            # rather than a TLS alert; perhaps this happens when a socket write
            # fails before the alert has been read. As a result we can't fail the
            # test un unexpected responses
            # flunk("Expected a handshake error, got #{inspect(error)}")
            :ignore
        end

        assert {:ok, _} =
                 request(~c"https://client-cert.#{context.suite.domain}:#{context.port}/",
                   cacerts: context.suite.chain ++ context.suite.cacerts,
                   cert: X509.Certificate.to_der(context.suite.client),
                   key: {:ECPrivateKey, X509.PrivateKey.to_der(context.suite.client_key)}
                 )
      end
    end
  else
    X509.Logger.warn("ECDSA certificates can't be tested on the current OTP version")
  end

  #
  # Test setup callbacks and helper functions
  #

  # Canned response to be returned by the test server on established
  # connections
  @http_response ["HTTP/1.1 200 OK", "Content-Length: 2", "Connection: close", "", "OK"]
                 |> Enum.join("\r\n")

  # Global test setup: start required applications and CRL responder
  setup_all do
    # Ensure inets and ssl applications are started; httpc is part of inets
    Application.ensure_all_started(:inets)
    Application.ensure_all_started(:ssl)

    # Start the CRL responder
    crl_server_pid = start(X509.Test.CRLServer)
    crl_server_port = X509.Test.CRLServer.get_port(crl_server_pid)
    crl_server_uri = "http://localhost:#{crl_server_port}"

    [crl_server: %{pid: crl_server_pid, uri: crl_server_uri}]
  end

  # Setup for RSA testing
  defp rsa_suite(context) do
    new_suite(context, {:rsa, 1024}, "rsa")
  end

  # Setup for ECDSA testing
  if version(:ssl) >= [8, 2, 6, 2] and version(:ssl) != [9, 0, 0] do
    defp ecdsa_suite(context) do
      new_suite(context, {:ec, :secp256r1}, "ecdsa")
    end
  end

  # Generate a test suite, update the CRL responder and start a test server
  defp new_suite(context, key_type, prefix) do
    suite =
      X509.Test.Suite.new(key_type: key_type, crl_server: "#{context.crl_server.uri}/#{prefix}/")

    Enum.each(suite.crls, fn {path, crl} ->
      X509.Test.CRLServer.put_crl(context.crl_server.pid, "/#{prefix}/#{path}", crl)
    end)

    pid = start(X509.Test.Server, {suite, [response: @http_response]})
    port = X509.Test.Server.get_port(pid)

    [suite: suite, port: port]
  end

  # Create PEM files for various CA stores used in test cases
  defp create_pem_files(context) do
    tmp_dir =
      System.tmp_dir!()
      |> Path.join("x509_server_test#{System.get_pid()}")

    File.mkdir(tmp_dir)

    cacerts = certificates_der_to_pem(context.suite.cacerts)
    cacerts_and_chain = certificates_der_to_pem(context.suite.cacerts ++ context.suite.chain)
    alternate_cacerts = certificates_der_to_pem(context.suite.alternate_cacerts)

    # Ensure unique path names for different contents, to avoid caching issues
    cacertfile = Path.join(tmp_dir, "cacerts_#{:erlang.phash2(cacerts)}.pem")
    File.write!(cacertfile, cacerts)

    cacertfile_with_chain =
      Path.join(tmp_dir, "cacerts_and_chain_#{:erlang.phash2(cacerts_and_chain)}.pem")

    File.write!(cacertfile_with_chain, cacerts_and_chain)

    alternate_cacertfile = Path.join(tmp_dir, "alternate_cacerts_#{:erlang.phash2(cacerts)}.pem")
    File.write!(alternate_cacertfile, alternate_cacerts)

    on_exit(fn ->
      File.rm(cacertfile)
      File.rm(cacertfile_with_chain)
      File.rm(alternate_cacertfile)
      File.rmdir(tmp_dir)
    end)

    [
      cacertfile: cacertfile,
      cacertfile_with_chain: cacertfile_with_chain,
      alternate_cacertfile: alternate_cacertfile
    ]
  end

  # Convert a list of DER certificates to a single PEM string
  defp certificates_der_to_pem(list) do
    list
    |> Enum.map(&X509.Certificate.from_der!/1)
    |> Enum.map(&X509.Certificate.to_pem/1)
    |> Enum.join()
  end

  # Starts the GenServer in the specified module, using ExUnit's
  # `start_supervised` if available
  defp start(module, args \\ []) do
    {:ok, pid} =
      if version(:ex_unit) >= [1, 6] do
        # Assign a unique ID, to allow multiple servers to be running under
        # the ExUnit supervisor at the same time
        ExUnit.Callbacks.start_supervised({module, args}, id: make_ref())
      else
        module.start_link(args)
      end

    pid
  end
end
