defmodule X509.Test.Suite do
  @moduledoc """
  This module may be used to generate a suite of certificates for client or
  server testing, and offers an `sni_fun` hook for setting up a test scenario
  based on the requested hostname.

  ## Test scenarios:

  * `valid` - presenting a valid server certificate

  * `valid-missing-chain` - presenting a valid server certificate, but
    configured without the required intermediate CA; should be rejected unless
    peer verification is disabled or the intermediate CA is trusted by the
    client

  * `valid-expired-chain` - presenting a valid server certificate, but
    configured with an expired intermediate CA; should be rejected unless
    peer verification is disabled

  * `valid-revoked-chain` - presenting a valid server certificate, but
    configured with a revoked intermediate CA; should be rejected unless
    peer verification is disabled

  * `valid-wrong-key` - presenting a valid server certificate, but configured
    with the wrong private key; should always be rejected

  * `valid-wrong-host` - presenting a valid server certificate with a SAN
    hostname that does not match; should be rejected unless peer verification
    is disabled

  * `valid-cross-signed` - presenting a valid server certificate, cross-signed
    by an alternative root CA, and with a certificate chain that resolves to
    both the standard root CA and the cross-signing root CA

  * `valid.wildcard` - presenting a valid wildcard server certificate

  * `wildcard` - presenting a valid wildcard server certificate, but without
     a SAN hostname for the bare domain; should be rejected unless peer
     verification is disabled

  * `invalid.subdomain.wildcard` - presenting a valid wildcard server
     certificate, but accessed using an invalid nested subdomain; should be
     rejected unless peer verification is disabled

   * `expired` - presenting an expired server certificate; should be rejected
     unless peer verification is disabled

   * `revoked` - presenting a revoked server certificate; should be rejected
     unless peer verification is disabled

  * `selfsigned` - presenting a self-signed server certificate; should normally
    be rejected by a client unless server certificate verification is disabled
    or the client is configured to explicitly allow the specific certificate
    ('pinning')

  * `selfsigned-wrong-key` - presenting a self-signed server certificate, but
    configured with the wrong private key; should always be rejected

  * `selfsigned-wrong-host` - presenting a self-signed server certificate with
    a SAN hostname that does not match; should be rejected unless peer
    verification is disabled

  * `client-cert` - requires that the client present a valid certificate
  """

  defstruct [
    :domain,
    :key_type,
    :server_key,
    :other_key,
    :cacerts,
    :alternate_cacerts,
    :chain,
    :expired_chain,
    :revoked_chain,
    :alternate_chain,
    :valid,
    :wildcard,
    :expired,
    :revoked,
    :selfsigned,
    :client,
    :client_key,
    :crls
  ]

  @type t :: %__MODULE__{
          domain: String.t(),
          key_type:
            {:rsa, non_neg_integer()} | {:ec, :crypto.ec_named_curve() | :public_key.oid()},
          server_key: X509.PrivateKey.t(),
          other_key: X509.PrivateKey.t(),
          client_key: X509.PrivateKey.t(),
          cacerts: [binary()],
          alternate_cacerts: [binary()],
          chain: [binary()],
          expired_chain: [binary()],
          revoked_chain: [binary()],
          alternate_chain: [binary()],
          valid: X509.Certificate.t(),
          wildcard: X509.Certificate.t(),
          expired: X509.Certificate.t(),
          revoked: X509.Certificate.t(),
          selfsigned: X509.Certificate.t(),
          client: X509.Certificate.t(),
          crls: %{String.t() => X509.CRL.t()}
        }

  @default_opts [
    domain: "localtest.me",
    key_type: {:rsa, 1024}
  ]

  @seconds_per_day 24 * 60 * 60

  @doc """
  Builds and returns a new test suite.

  ## Options:

  * `:domain` - the test domain to use; any subdomain for the given domain
    needs to resolve to the IP address where the test server will be hosted,
    e.g. 127.0.0.1 or ::1; the default value is 'localtest.me', which requires
    Internet access during test execution
  * `:crl_server` - the base URL for a CRL server that may be used as a CRL DP;
    if none is specified, no CRL DPs are included in the generated
    certificates, and revocation scenarios are not supported
  * `:key_type` - the type of private keys to generate; may be set to `{:rsa,
    bits}` to select RSA keys of the given length, or `{:ec, curve}` to select
    ECC keys based on the given curve (default:
    `#{inspect(@default_opts[:key_type])}`)
  """
  @spec new(Keyword.t()) :: t()
  def new(opts \\ []) do
    opts = Keyword.merge(@default_opts, opts)
    crl_server = Keyword.get(opts, :crl_server)
    domain = Keyword.get(opts, :domain)
    key_type = Keyword.get(opts, :key_type)

    # Private keys
    root_ca_key = new_key(key_type)
    intermediate_ca_key = new_key(key_type)
    server_key = new_key(key_type)
    other_key = new_key(key_type)
    cross_signer_root_ca_key = new_key(key_type)
    client_key = new_key(key_type)

    # CA certificates
    root_ca =
      X509.Certificate.self_signed(root_ca_key, "/O=#{__MODULE__}/CN=Root CA", template: :root_ca)

    intermediate_ca =
      intermediate_ca_key
      |> X509.PublicKey.derive()
      |> X509.Certificate.new("/O=#{__MODULE__}/CN=Intermediate CA", root_ca, root_ca_key,
        template: :ca,
        extensions: crl_extensions(crl_server, "root_ca.crl")
      )

    # This intermediate CA has the same Subject as the regular (not expired)
    # intermediate, to allow it to be used with the same end-certificates;
    # please note that this can lead to unexpected behaviour when certificates
    # are retrieved from a cache by Subject only (not SKI or Issuer + S/N)
    expired_int_ca =
      intermediate_ca_key
      |> X509.PublicKey.derive()
      |> X509.Certificate.new("/O=#{__MODULE__}/CN=Intermediate CA", root_ca, root_ca_key,
        template: :ca,
        validity: X509.Certificate.Validity.days_from_now(-1, 30 * @seconds_per_day),
        extensions: crl_extensions(crl_server, "root_ca.crl")
      )

    # This intermediate CA has the same Subject as the regular (not revoked)
    # intermediate, to allow it to be used with the same end-certificates;
    # please note that this can lead to unexpected behaviour when certificates
    # are retrieved from a cache by Subject only (not SKI or Issuer + S/N)
    revoked_int_ca =
      intermediate_ca_key
      |> X509.PublicKey.derive()
      |> X509.Certificate.new("/O=#{__MODULE__}/CN=Intermediate CA", root_ca, root_ca_key,
        template: :ca,
        extensions: crl_extensions(crl_server, "root_ca.crl")
      )

    cross_signer_root_ca =
      X509.Certificate.self_signed(
        cross_signer_root_ca_key,
        "/O=#{__MODULE__}/CN=Alternative Root CA",
        template: :root_ca,
        extensions: [
          # This CA needs a longer path_len_constraint value, to account for
          # the cross-signed CA and its intermediate
          basic_constraints: X509.Certificate.Extension.basic_constraints(true, 2)
        ]
      )

    cross_signed_ca =
      root_ca_key
      |> X509.PublicKey.derive()
      |> X509.Certificate.new(
        "/O=#{__MODULE__}/CN=Root CA",
        cross_signer_root_ca,
        cross_signer_root_ca_key,
        template: :ca,
        extensions:
          [
            # The :ca template has a path_len_constraint value of 0, because it
            # is intended for intermediate CAs that issue end-certificates; this
            # cross-signed root needs a value of 1, to match the self-signed
            # variant and to allow for the intermediate CA
            basic_constraints: X509.Certificate.Extension.basic_constraints(true, 1)
          ] ++ crl_extensions(crl_server, "cross_signer_root_ca.crl")
      )

    # Server certificates

    valid =
      server_key
      |> X509.PublicKey.derive()
      |> X509.Certificate.new(
        "/O=#{__MODULE__}/CN=Server",
        intermediate_ca,
        intermediate_ca_key,
        extensions:
          [
            subject_alt_name:
              X509.Certificate.Extension.subject_alt_name([
                "localhost",
                "valid.#{domain}",
                "valid-missing-chain.#{domain}",
                "valid-revoked-chain.#{domain}",
                "valid-wrong-key.#{domain}",
                "valid-cross-signed.#{domain}",
                "client-cert.#{domain}"
              ])
          ] ++ crl_extensions(crl_server, "intermediate_ca.crl")
      )

    wildcard =
      server_key
      |> X509.PublicKey.derive()
      |> X509.Certificate.new(
        "/O=#{__MODULE__}/CN=Wildcard",
        intermediate_ca,
        intermediate_ca_key,
        extensions:
          [
            subject_alt_name:
              X509.Certificate.Extension.subject_alt_name([
                "*.localhost",
                "*.wildcard.#{domain}"
              ])
          ] ++ crl_extensions(crl_server, "intermediate_ca.crl")
      )

    expired =
      server_key
      |> X509.PublicKey.derive()
      |> X509.Certificate.new(
        "/O=#{__MODULE__}/CN=Expired",
        intermediate_ca,
        intermediate_ca_key,
        validity: X509.Certificate.Validity.days_from_now(-1, 30 * @seconds_per_day),
        extensions:
          [
            subject_alt_name:
              X509.Certificate.Extension.subject_alt_name([
                "localhost",
                "expired.#{domain}"
              ])
          ] ++ crl_extensions(crl_server, "intermediate_ca.crl")
      )

    revoked =
      server_key
      |> X509.PublicKey.derive()
      |> X509.Certificate.new(
        "/O=#{__MODULE__}/CN=Revoked",
        intermediate_ca,
        intermediate_ca_key,
        extensions:
          [
            subject_alt_name:
              X509.Certificate.Extension.subject_alt_name([
                "localhost",
                "revoked.#{domain}"
              ])
          ] ++ crl_extensions(crl_server, "intermediate_ca.crl")
      )

    # TODO: path-length-constraint exceeded server

    selfsigned =
      X509.Certificate.self_signed(
        server_key,
        "/O=#{__MODULE__}/CN=Self-signed",
        extensions: [
          subject_alt_name:
            X509.Certificate.Extension.subject_alt_name([
              "localhost",
              "selfsigned.#{domain}",
              "selfsigned-wrong-key.#{domain}"
            ])
        ]
      )

    client =
      client_key
      |> X509.PublicKey.derive()
      |> X509.Certificate.new(
        "/O=#{__MODULE__}/CN=Client",
        intermediate_ca,
        intermediate_ca_key
      )

    # CRLs

    crls =
      if is_nil(crl_server) do
        %{}
      else
        root_crl_entry =
          X509.CRL.Entry.new(revoked_int_ca, DateTime.utc_now(), [
            X509.CRL.Extension.reason_code(:superseded)
          ])

        root_crl =
          X509.CRL.new([root_crl_entry], root_ca, root_ca_key,
            extensions: [crl_number: X509.CRL.Extension.crl_number(299)]
          )

        cross_signer_root_crl =
          X509.CRL.new([], cross_signer_root_ca, cross_signer_root_ca_key,
            extensions: [crl_number: X509.CRL.Extension.crl_number(399)]
          )

        intermediate_ca_crl_entry =
          X509.CRL.Entry.new(revoked, DateTime.utc_now(), [
            X509.CRL.Extension.reason_code(:keyCompromise)
          ])

        intermediate_ca_crl =
          X509.CRL.new([intermediate_ca_crl_entry], intermediate_ca, intermediate_ca_key,
            extensions: [crl_number: X509.CRL.Extension.crl_number(199)]
          )

        %{
          "root_ca.crl" => root_crl,
          "cross_signer_root_ca.crl" => cross_signer_root_crl,
          "intermediate_ca.crl" => intermediate_ca_crl
        }
      end

    %__MODULE__{
      domain: domain,
      key_type: key_type,
      server_key: server_key,
      other_key: other_key,
      client_key: client_key,
      cacerts: [X509.Certificate.to_der(root_ca)],
      alternate_cacerts: [X509.Certificate.to_der(cross_signer_root_ca)],
      chain: [X509.Certificate.to_der(intermediate_ca)],
      expired_chain: [X509.Certificate.to_der(expired_int_ca)],
      revoked_chain: [X509.Certificate.to_der(revoked_int_ca)],
      alternate_chain: [
        X509.Certificate.to_der(intermediate_ca),
        X509.Certificate.to_der(cross_signed_ca)
      ],
      valid: valid,
      wildcard: wildcard,
      expired: expired,
      revoked: revoked,
      selfsigned: selfsigned,
      client: client,
      crls: crls
    }
  end

  @doc """
  Returns a suitable SNI (Server Name Indication) handler function for the
  given test suite. May be used to configure custom servers to act as a test
  suite endpoint.

  In addition to setting the `sni_fun` parameter to the return value of this
  function, the `reuse_sessions` parameter must be set to `false`. This
  ensures that a new handshake is performed on each connection.
  """
  @spec sni_fun(t()) :: (charlist() -> [Keyword.t()])
  def sni_fun(%__MODULE__{} = suite) do
    &sni_handler(suite, &1)
  end

  @doc false
  def sni_handler(%__MODULE__{domain: domain} = suite, server_name) when is_list(server_name) do
    host = to_string(server_name)

    if String.ends_with?(host, ".#{domain}") do
      scenario = String.replace_suffix(host, ".#{domain}", "")
      sni_handler(suite, scenario)
    else
      []
    end
  end

  def sni_handler(
        %__MODULE__{valid: valid, chain: chain, server_key: server_key},
        "valid"
      ) do
    [
      cert: X509.Certificate.to_der(valid),
      cacerts: chain,
      key: {:PrivateKeyInfo, X509.PrivateKey.to_der(server_key, wrap: true)}
    ]
  end

  def sni_handler(
        %__MODULE__{valid: valid, server_key: server_key},
        "valid-missing-chain"
      ) do
    [
      cert: X509.Certificate.to_der(valid),
      cacerts: [],
      key: {:PrivateKeyInfo, X509.PrivateKey.to_der(server_key, wrap: true)}
    ]
  end

  def sni_handler(
        %__MODULE__{valid: valid, expired_chain: chain, server_key: server_key},
        "valid-expired-chain"
      ) do
    [
      cert: X509.Certificate.to_der(valid),
      cacerts: chain,
      key: {:PrivateKeyInfo, X509.PrivateKey.to_der(server_key, wrap: true)}
    ]
  end

  def sni_handler(
        %__MODULE__{valid: valid, revoked_chain: chain, server_key: server_key},
        "valid-revoked-chain"
      ) do
    [
      cert: X509.Certificate.to_der(valid),
      cacerts: chain,
      key: {:PrivateKeyInfo, X509.PrivateKey.to_der(server_key, wrap: true)}
    ]
  end

  def sni_handler(
        %__MODULE__{valid: valid, chain: chain, other_key: other_key},
        "valid-wrong-key"
      ) do
    [
      cert: X509.Certificate.to_der(valid),
      cacerts: chain,
      key: {:PrivateKeyInfo, X509.PrivateKey.to_der(other_key, wrap: true)}
    ]
  end

  def sni_handler(
        %__MODULE__{valid: valid, chain: chain, server_key: server_key},
        "valid-wrong-host"
      ) do
    [
      cert: X509.Certificate.to_der(valid),
      cacerts: chain,
      key: {:PrivateKeyInfo, X509.PrivateKey.to_der(server_key, wrap: true)}
    ]
  end

  def sni_handler(
        %__MODULE__{valid: valid, alternate_chain: chain, server_key: server_key},
        "valid-cross-signed"
      ) do
    [
      cert: X509.Certificate.to_der(valid),
      cacerts: chain,
      key: {:PrivateKeyInfo, X509.PrivateKey.to_der(server_key, wrap: true)}
    ]
  end

  def sni_handler(
        %__MODULE__{wildcard: wildcard, chain: chain, server_key: server_key},
        "valid.wildcard"
      ) do
    [
      cert: X509.Certificate.to_der(wildcard),
      cacerts: chain,
      key: {:PrivateKeyInfo, X509.PrivateKey.to_der(server_key, wrap: true)}
    ]
  end

  def sni_handler(
        %__MODULE__{wildcard: wildcard, chain: chain, server_key: server_key},
        "wildcard"
      ) do
    [
      cert: X509.Certificate.to_der(wildcard),
      cacerts: chain,
      key: {:PrivateKeyInfo, X509.PrivateKey.to_der(server_key, wrap: true)}
    ]
  end

  def sni_handler(
        %__MODULE__{wildcard: wildcard, chain: chain, server_key: server_key},
        "invalid.subdomain.wildcard"
      ) do
    [
      cert: X509.Certificate.to_der(wildcard),
      cacerts: chain,
      key: {:PrivateKeyInfo, X509.PrivateKey.to_der(server_key, wrap: true)}
    ]
  end

  def sni_handler(
        %__MODULE__{expired: expired, chain: chain, server_key: server_key},
        "expired"
      ) do
    [
      cert: X509.Certificate.to_der(expired),
      cacerts: chain,
      key: {:PrivateKeyInfo, X509.PrivateKey.to_der(server_key, wrap: true)}
    ]
  end

  def sni_handler(
        %__MODULE__{revoked: revoked, chain: chain, server_key: server_key},
        "revoked"
      ) do
    [
      cert: X509.Certificate.to_der(revoked),
      cacerts: chain,
      key: {:PrivateKeyInfo, X509.PrivateKey.to_der(server_key, wrap: true)}
    ]
  end

  def sni_handler(
        %__MODULE__{selfsigned: selfsigned, server_key: server_key},
        "selfsigned"
      ) do
    [
      cert: X509.Certificate.to_der(selfsigned),
      key: {:PrivateKeyInfo, X509.PrivateKey.to_der(server_key, wrap: true)}
    ]
  end

  def sni_handler(
        %__MODULE__{selfsigned: selfsigned, other_key: other_key},
        "selfsigned-wrong-key"
      ) do
    [
      cert: X509.Certificate.to_der(selfsigned),
      key: {:PrivateKeyInfo, X509.PrivateKey.to_der(other_key, wrap: true)}
    ]
  end

  def sni_handler(
        %__MODULE__{selfsigned: selfsigned, server_key: server_key},
        "selfsigned-wrong-host"
      ) do
    [
      cert: X509.Certificate.to_der(selfsigned),
      key: {:PrivateKeyInfo, X509.PrivateKey.to_der(server_key, wrap: true)}
    ]
  end

  def sni_handler(
        %__MODULE__{valid: valid, chain: chain, server_key: server_key, cacerts: cacerts},
        "client-cert"
      ) do
    [
      cert: X509.Certificate.to_der(valid),
      cacerts: chain ++ cacerts,
      key: {:PrivateKeyInfo, X509.PrivateKey.to_der(server_key, wrap: true)},
      verify: :verify_peer,
      fail_if_no_peer_cert: true
    ]
  end

  def sni_handler(
        %__MODULE__{valid: valid, chain: chain, server_key: server_key},
        scenario
      ) do
    X509.Logger.warn("Unknown scenario: #{scenario}")

    [
      cert: X509.Certificate.to_der(valid),
      cacerts: chain,
      key: {:PrivateKeyInfo, X509.PrivateKey.to_der(server_key, wrap: true)}
    ]
  end

  defp crl_extensions(nil, _filename), do: []

  defp crl_extensions(crl_server, filename) do
    [
      crl_distribution_point:
        X509.Certificate.Extension.crl_distribution_points([
          crl_server |> URI.merge(filename) |> to_string()
        ])
    ]
  end

  defp new_key({:rsa, length}) do
    X509.PrivateKey.new_rsa(length)
  end

  defp new_key({:ec, curve}) do
    X509.PrivateKey.new_ec(curve)
  end
end
