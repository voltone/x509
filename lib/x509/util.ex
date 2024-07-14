defmodule X509.Util do
  @moduledoc false

  def app_version(application) do
    application
    |> Application.spec()
    |> Keyword.get(:vsn)
    |> to_string()
    |> String.split(".")
    |> Enum.map(fn str ->
      {num, _} = Integer.parse(str)
      num
    end)
  end
end
