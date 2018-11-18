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

    * `--crlserver` (`-c`): the base URL for the CRL server to be used for
      CRL distribution points
    * `--output` (`-o`): the path where the certificates and keys should be
      stored (default: #{@default_path})

  Requires OTP 20 or later.
  """

  use Mix.Task
  import Mix.Generator

  @doc false
  def run(all_args) do
    {opts, args} =
      OptionParser.parse!(
        all_args,
        aliases: [c: :crlserver, o: :output],
        strict: [crlserver: :string, output: :string]
      )

    path = opts[:output] || @default_path
    crl_opts = [crl_server: opts[:crlserver]]

    suite_opts =
      case args do
        [] -> crl_opts
        [domain] -> Keyword.put(crl_opts, :domain, domain)
      end

    suite = X509.Test.Suite.new(suite_opts)

    create_file(Path.join(path, "server_key.pem"), X509.PrivateKey.to_pem(suite.server_key))
    create_file(Path.join(path, "other_key.pem"), X509.PrivateKey.to_pem(suite.other_key))

    create_file(
      Path.join(path, "cacerts.pem"),
      suite.cacerts
      |> Enum.map(&X509.Certificate.from_der!/1)
      |> Enum.map(&X509.Certificate.to_pem/1)
      |> Enum.join()
    )

    create_file(
      Path.join(path, "alternate_cacerts.pem"),
      suite.alternate_cacerts
      |> Enum.map(&X509.Certificate.from_der!/1)
      |> Enum.map(&X509.Certificate.to_pem/1)
      |> Enum.join()
    )

    create_file(
      Path.join(path, "chain.pem"),
      suite.chain
      |> Enum.map(&X509.Certificate.from_der!/1)
      |> Enum.map(&X509.Certificate.to_pem/1)
      |> Enum.join()
    )

    create_file(
      Path.join(path, "expired_chain.pem"),
      suite.expired_chain
      |> Enum.map(&X509.Certificate.from_der!/1)
      |> Enum.map(&X509.Certificate.to_pem/1)
      |> Enum.join()
    )

    create_file(
      Path.join(path, "revoked_chain.pem"),
      suite.revoked_chain
      |> Enum.map(&X509.Certificate.from_der!/1)
      |> Enum.map(&X509.Certificate.to_pem/1)
      |> Enum.join()
    )

    create_file(
      Path.join(path, "alternate_chain.pem"),
      suite.alternate_chain
      |> Enum.map(&X509.Certificate.from_der!/1)
      |> Enum.map(&X509.Certificate.to_pem/1)
      |> Enum.join()
    )

    create_file(Path.join(path, "valid.pem"), X509.Certificate.to_pem(suite.valid))
    create_file(Path.join(path, "wildcard.pem"), X509.Certificate.to_pem(suite.wildcard))
    create_file(Path.join(path, "expired.pem"), X509.Certificate.to_pem(suite.expired))
    create_file(Path.join(path, "revoked.pem"), X509.Certificate.to_pem(suite.revoked))
    create_file(Path.join(path, "selfsigned.pem"), X509.Certificate.to_pem(suite.selfsigned))

    for {name, crl} <- suite.crls do
      create_file(Path.join(path, name), X509.CRL.to_der(crl))
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
