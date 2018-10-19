defmodule X509.MixProject do
  use Mix.Project

  @version "0.5.0-dev"

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
      source_url: "https://github.com/voltone/x509"
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ex_doc, "~> 0.19", only: :dev}
    ]
  end

  defp description do
    """
    Package for working with certificates, CSRs and key pairs.
    """
  end

  defp package do
    [
      maintainers: ["Bram Verburg"],
      licenses: ["BSD 3-Clause"],
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
