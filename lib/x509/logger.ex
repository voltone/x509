defmodule X509.Logger do
  @moduledoc false
  alias X509.Util

  require Logger

  if Util.app_version(:logger) >= [1, 11, 0] do
    def warn(message, metadata \\ []) do
      Logger.warning(message, metadata)
    end
  else
    def warn(message, metadata \\ []) do
      Logger.warn(message, metadata)
    end
  end
end
