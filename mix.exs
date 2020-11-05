defmodule X509.MixProject do
  use Mix.Project

  @version "0.8.2"

  def project do
    [
      app: :x509,
      version: @version,
      elixir: "~> 1.5",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      name: "X509",
      description: description(),
      package: package(),
      docs: docs(),
      source_url: "https://github.com/voltone/x509",
      xref: [exclude: [IEx, :epp_dodger]]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:crypto, :public_key, :logger, :ssl]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ex_doc, "~> 0.22", only: :dev}
    ]
  end

  defp description do
    "Elixir package for working with X.509 certificates, Certificate Signing " <>
      "Requests (CSRs), Certificate Revocation Lists (CRLs) and RSA/ECC key pairs"
  end

  defp package do
    [
      maintainers: ["Bram Verburg"],
      licenses: ["BSD-3-Clause"],
      links: %{"GitHub" => "https://github.com/voltone/x509"}
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md"],
      source_ref: "v#{@version}"
    ]
  end
end
