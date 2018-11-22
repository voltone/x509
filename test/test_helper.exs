ExUnit.configure(exclude: :openssl)
ExUnit.start()

# Logger is not included in the `extra_applications` list in the application
# config in mix.exs, because it is not used at runtime. It is used in the
# X509.Test.Server tests, so we need to start it explicitly.
Application.ensure_all_started(:logger)

defmodule TestHelper do
  # Returns the version of the specified OTP application as a list of integers
  def version(application) do
    application
    |> Application.spec()
    |> Keyword.get(:vsn)
    |> to_string()
    |> String.split(".")
    |> Enum.map(&String.to_integer/1)
  end

  # Starts the GenServer in the specified module, using ExUnit's
  # `start_supervised` if available
  def start(module, args \\ []) do
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
