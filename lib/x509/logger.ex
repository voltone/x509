defmodule X509.Logger do
  @moduledoc false

  require Logger

  if Version.match?(System.version(), ">= 1.11.0") do
    def warn(message, metadata \\ []) do
      Logger.warning(message, metadata)
    end
  else
    def warn(message, metadata \\ []) do
      Logger.warn(message, metadata)
    end
  end
end
