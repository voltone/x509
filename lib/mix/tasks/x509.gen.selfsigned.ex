defmodule Mix.Tasks.X509.Gen.Selfsigned do
  @shortdoc "Generates a self-signed certificate"

  @default_path "priv/cert/selfsigned"
  @default_name "Self-signed test certificate"
  @default_hostnames ["localhost"]

  @warning """
  WARNING: only use the generated certificate for testing in a closed network
  environment, such as running a development server on `localhost`.
  For production, staging, or testing servers on the public internet, obtain a
  proper certificate, for example from [Let's Encrypt](https://letsencrypt.org).

  NOTE: when using Google Chrome, open chrome://flags/#allow-insecure-localhost
  to enable the use of self-signed certificates on `localhost`.
  """

  @moduledoc """
  Generates a self-signed certificate for testing.

      mix x509.gen.selfsigned
      mix x509.gen.selfsigned my-app my-app.local my-app.internal.example.com

  Creates a private key and a self-signed certificate in PEM format. These
  files can be referenced in the `certfile` and `keyfile` parameters of an
  `:ssl` server.

  #{@warning}

  ## Arguments

  The list of hostnames, if none are specified, defaults to:

    * #{Enum.join(@default_hostnames, "\n  * ")}

  Other (optional) arguments:

    * `--output` (`-o`): the path and base filename for the certificate and
      key (default: #{@default_path})
    * `--name` (`-n`): the Common Name value in certificate's subject
      (default: "#{@default_name}")
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
        aliases: [n: :name, o: :output, f: :force],
        strict: [name: :string, output: :string, force: :boolean]
      )

    path = opts[:output] || @default_path
    name = opts[:name] || @default_name
    force = opts[:force] || false

    hostnames =
      case args do
        [] -> @default_hostnames
        list -> list
      end

    {certificate, private_key} = certificate_and_key(2048, name, hostnames)

    keyfile = path <> "_key.pem"
    certfile = path <> ".pem"

    create_file(keyfile, X509.PrivateKey.to_pem(private_key), force: force)
    create_file(certfile, X509.Certificate.to_pem(certificate), force: force)

    print_shell_instructions(keyfile, certfile)
  end

  @doc false
  def certificate_and_key(key_size, name, hostnames) do
    private_key = X509.PrivateKey.new_rsa(key_size)

    certificate =
      X509.Certificate.self_signed(
        private_key,
        "/CN=#{name}",
        template: :server,
        extensions: [
          subject_alt_name: X509.Certificate.Extension.subject_alt_name(hostnames)
        ]
      )

    {certificate, private_key}
  end

  defp print_shell_instructions(keyfile, certfile) do
    Mix.shell().info("""

    To use the certificate, pass the following `:ssl` options to the server
    socket or library:

        [certfile: "#{certfile}", keyfile: "#{keyfile}"]

    #{@warning}
    """)
  end
end
