ExUnit.configure(exclude: :openssl)
ExUnit.start()

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
        ExUnit.Callbacks.start_supervised({module, args})
      else
        module.start_link(args)
      end

    pid
  end
end
