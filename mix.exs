defmodule X509.MixProject do
  use Mix.Project

  @source_url "https://github.com/voltone/x509"
  @version "0.8.9"

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
      xref: [exclude: [IEx, :epp_dodger]]
    ]
  end

  def application do
    [
      extra_applications: extra_applications(Mix.env())
    ]
  end

  defp extra_applications(:test) do
    extra_applications(:prod) ++ [:inets]
  end

  defp extra_applications(_env) do
    [:crypto, :public_key, :logger, :ssl]
  end

  defp deps do
    [
      {:ex_doc, ">= 0.0.0", only: :dev}
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
      links: %{
        "Changelog" => "#{@source_url}/blob/master/CHANGELOG.md",
        "GitHub" => @source_url
      }
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["CHANGELOG.md", "README.md"],
      source_ref: "v#{@version}",
      source_url: @source_url,
      formatters: ["html"]
    ]
  end
end
