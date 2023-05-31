defmodule X509.ASN1.OIDImport do
  @moduledoc false

  # TODO: Remove when we require Elixir 1.15
  if function_exported?(Mix, :ensure_application!, 1) do
    Mix.ensure_application!(:syntax_tools)
  end

  def from_lib(file) do
    file
    |> from_lib_file()
    |> get_oids()
  end

  def from(file) do
    file
    |> from_file()
    |> get_oids()
  end

  # Parse an Erlang header file without preprocessing, and extract any OID
  # definitions
  defp get_oids(file) do
    case :epp_dodger.parse_file(file) do
      {:ok, tree} ->
        tree
        |> Enum.map(&filter_and_map_oid/1)
        |> Enum.reject(&is_nil/1)

      other ->
        raise "error parsing file #{file}, got: #{inspect(other)}"
    end
  end

  # This clause matches a `-define()` with a tuple value; it returns a
  # name/value tuple if it turns out to be an OID, or nil otherwise
  defp filter_and_map_oid(
         {:tree, :attribute, _,
          {:attribute, {:atom, _, :define},
           [{:atom, _, name}, {:tree, :tuple, {:attr, _, [], _}, list}]}}
       ) do
    # If all values in the tuple are integers; reconstruct the tuple
    # and return it with the name
    if Enum.all?(list, &match?({:integer, _, _}, &1)) do
      {
        name,
        list
        |> Enum.map(&elem(&1, 2))
        |> List.to_tuple()
      }
    else
      nil
    end
  end

  defp filter_and_map_oid(_), do: nil

  # From Record.Extractor
  defp from_lib_file(file) do
    [app | path] = :filename.split(String.to_charlist(file))

    case :code.lib_dir(List.to_atom(app)) do
      {:error, _} ->
        raise ArgumentError, "lib file #{file} could not be found"

      libpath ->
        :filename.join([libpath | path])
    end
  end

  # From Record.Extractor
  defp from_file(file) do
    file = String.to_charlist(file)

    case :code.where_is_file(file) do
      :non_existing -> file
      realfile -> realfile
    end
  end
end
