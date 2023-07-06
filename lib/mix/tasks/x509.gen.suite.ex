defmodule Mix.Tasks.X509.Gen.Suite do
  @shortdoc "Generates a suite of test certificates"

  @default_path "priv/cert/suite"

  @warning """
  WARNING: only use the generated certificates for testing in a closed network
  environment, such as running a development server on `localhost`.
  For production, staging, or testing servers on the public internet, obtain a
  proper certificate, for example from [Let's Encrypt](https://letsencrypt.org).
  """

  @moduledoc """
  Generates a suite of test certificates.

      mix x509.gen.suite
      mix x509.gen.suite test.local

  Please refer to the documentation for `X509.Test.Suite` for information about
  the scenarios that may be tested using the generated certificates.

  #{@warning}

  ## Arguments

  This tasks takes a single, optional argument: the domain name to use in the
  hostnames embedded in the certificates. If no domain name is specified, the
  default domain from `X509.Test.Suite` will be used.

  Other (optional) arguments:

    * '--password' ('-p'): if set, an encrypted, password protected version of
      each private key will be created
    * `--crlserver` (`-c`): the base URL for the CRL server to be used for
      CRL distribution points
    * `--output` (`-o`): the path where the certificates and keys should be
      stored (default: #{@default_path})
    * `--force` (`-f`): overwrite existing files without prompting for
      confirmation

  Requires OTP 20 or later.
  """

  use Mix.Task
  import Mix.Generator

  @doc false
  def run(all_args) do
    {opts, args} =
      OptionParser.parse!(
        all_args,
        aliases: [p: :password, c: :crlserver, o: :output, f: :force],
        strict: [password: :string, crlserver: :string, output: :string, force: :boolean]
      )

    path = opts[:output] || @default_path
    password = opts[:password]
    crl_opts = [crl_server: opts[:crlserver]]
    force = opts[:force] || false

    suite_opts =
      case args do
        [] -> crl_opts
        [domain] -> Keyword.put(crl_opts, :domain, domain)
      end

    suite = X509.Test.Suite.new(suite_opts)

    server_key_pem = X509.PrivateKey.to_pem(suite.server_key)
    create_file(Path.join(path, "server_key.pem"), server_key_pem, force: force)

    if password do
      server_key_enc_pem = X509.PrivateKey.to_pem(suite.server_key, password: password)
      create_file(Path.join(path, "server_key_enc.pem"), server_key_enc_pem, force: force)
    end

    other_key_pem = X509.PrivateKey.to_pem(suite.other_key)
    create_file(Path.join(path, "other_key.pem"), other_key_pem, force: force)

    if password do
      other_key_enc_pem = X509.PrivateKey.to_pem(suite.other_key, password: password)
      create_file(Path.join(path, "other_key_enc.pem"), other_key_enc_pem, force: force)
    end

    client_key_pem = X509.PrivateKey.to_pem(suite.client_key)
    create_file(Path.join(path, "client_key.pem"), client_key_pem, force: force)

    if password do
      client_key_enc_pem = X509.PrivateKey.to_pem(suite.client_key, password: password)
      create_file(Path.join(path, "client_key_enc.pem"), client_key_enc_pem, force: force)
    end

    cacerts_pem =
      suite.cacerts
      |> Enum.map(&X509.Certificate.from_der!/1)
      |> Enum.map(&X509.Certificate.to_pem/1)
      |> Enum.join()

    create_file(Path.join(path, "cacerts.pem"), cacerts_pem, force: force)

    alternate_cacerts_pem =
      suite.alternate_cacerts
      |> Enum.map(&X509.Certificate.from_der!/1)
      |> Enum.map(&X509.Certificate.to_pem/1)
      |> Enum.join()

    create_file(Path.join(path, "alternate_cacerts.pem"), alternate_cacerts_pem, force: force)

    chain_pem =
      suite.chain
      |> Enum.map(&X509.Certificate.from_der!/1)
      |> Enum.map(&X509.Certificate.to_pem/1)
      |> Enum.join()

    create_file(Path.join(path, "chain.pem"), chain_pem, force: force)

    ca_and_chain_pem =
      (suite.cacerts ++ suite.chain)
      |> Enum.map(&X509.Certificate.from_der!/1)
      |> Enum.map(&X509.Certificate.to_pem/1)
      |> Enum.join()

    create_file(Path.join(path, "ca_and_chain.pem"), ca_and_chain_pem, force: force)

    expired_chain_pem =
      suite.expired_chain
      |> Enum.map(&X509.Certificate.from_der!/1)
      |> Enum.map(&X509.Certificate.to_pem/1)
      |> Enum.join()

    create_file(Path.join(path, "expired_chain.pem"), expired_chain_pem, force: force)

    revoked_chain_pem =
      suite.revoked_chain
      |> Enum.map(&X509.Certificate.from_der!/1)
      |> Enum.map(&X509.Certificate.to_pem/1)
      |> Enum.join()

    create_file(Path.join(path, "revoked_chain.pem"), revoked_chain_pem, force: force)

    alternate_chain_pem =
      suite.alternate_chain
      |> Enum.map(&X509.Certificate.from_der!/1)
      |> Enum.map(&X509.Certificate.to_pem/1)
      |> Enum.join()

    create_file(Path.join(path, "alternate_chain.pem"), alternate_chain_pem, force: force)

    valid_pem = X509.Certificate.to_pem(suite.valid)
    create_file(Path.join(path, "valid.pem"), valid_pem, force: force)

    wildcard_pem = X509.Certificate.to_pem(suite.wildcard)
    create_file(Path.join(path, "wildcard.pem"), wildcard_pem, force: force)

    expired_pem = X509.Certificate.to_pem(suite.expired)
    create_file(Path.join(path, "expired.pem"), expired_pem, force: force)

    revoked_pem = X509.Certificate.to_pem(suite.revoked)
    create_file(Path.join(path, "revoked.pem"), revoked_pem, force: force)

    selfsigned_pem = X509.Certificate.to_pem(suite.selfsigned)
    create_file(Path.join(path, "selfsigned.pem"), selfsigned_pem, force: force)

    client_pem = X509.Certificate.to_pem(suite.client)
    create_file(Path.join(path, "client.pem"), client_pem, force: force)

    for {name, crl} <- suite.crls do
      crl_der = X509.CRL.to_der(crl)
      create_file(Path.join(path, name), crl_der, force: force)
    end

    print_shell_instructions(path)
  end

  defp print_shell_instructions(path) do
    Mix.shell().info("""

    The certificates and keys can be found in #{path}.

    #{@warning}
    """)
  end
end
