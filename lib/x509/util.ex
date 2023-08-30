defmodule X509.Util do
  @moduledoc false

  require Logger

  def app_version(application) do
    application
    |> Application.spec()
    |> Keyword.get(:vsn)
    |> to_string()
    |> String.split(".")
    |> Enum.map(&String.to_integer/1)
  end

  # Create a utility function that handles checking for the 
  # existence of Logger.warning/2 if not fallback to Logger.warn/2
  if macro_exported?(Logger, :warning, 2) do
    def warn(message, metadata \\ []) do
      Logger.warning(message, metadata)
    end
  else
    def warn(message, metadata \\ []) do
      Logger.warn(message, metadata)
    end
  end
end
