defmodule X509.Test.CRLServer do
  @moduledoc """
  Simple CRL responder for use in test suites.
  """
  use GenServer

  @doc """
  Starts a CRL responder.

  ## Options:

  * `:port` - the TCP port to listen on; defaults to 0, meaning an ephemeral
    port is selected by the operating system, which may be retrieved using
    `get_port/1`
  """
  @spec start_link(Keyword.t()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc """
  Returns the TCP port number on which the specified X509.Test.Server instance
  is listening.
  """
  @spec get_port(pid()) :: :inet.port_number()
  def get_port(pid) do
    GenServer.call(pid, :get_port)
  end

  @doc """
  Adds or updates the CRL at the given path.
  """
  @spec put_crl(pid(), String.t(), X509.CRL.t()) :: :ok
  def put_crl(pid, path, crl) do
    GenServer.call(pid, {:put_crl, path, crl})
  end

  # Callbacks

  defmodule State do
    @moduledoc false
    defstruct [:listen_socket, :port, :crl_map]
  end

  @impl true
  def init(opts) do
    port = Keyword.get(opts, :port, 0)

    with {:ok, listen_socket} <- :gen_tcp.listen(port, []),
         {:ok, {_, port}} <- :inet.sockname(listen_socket),
         {:ok, _} <- :prim_inet.async_accept(listen_socket, -1) do
      {:ok, %State{listen_socket: listen_socket, port: port, crl_map: %{}}}
    else
      error ->
        {:stop, error}
    end
  end

  @impl true
  def handle_call(:get_port, _from, %State{port: port} = state) do
    {:reply, port, state}
  end

  @impl true
  def handle_call({:put_crl, path, crl}, _from, %State{crl_map: crl_map} = state) do
    {:reply, :ok, %{state | crl_map: Map.put(crl_map, path, crl)}}
  end

  @impl true
  def handle_info({:inet_async, listen_socket, _ref, {:ok, socket}}, state) do
    :inet_db.register_socket(socket, :inet_tcp)

    pid =
      spawn_link(fn ->
        receive do
          :start -> worker(socket, state.crl_map)
        after
          250 -> :gen_tcp.close(socket)
        end
      end)

    :gen_tcp.controlling_process(socket, pid)
    send(pid, :start)
    {:ok, _} = :prim_inet.async_accept(listen_socket, -1)
    {:noreply, state}
  end

  defp worker(socket, crl_map) do
    :inet.setopts(socket, packet: :http_bin)

    case :gen_tcp.recv(socket, 0) do
      {:ok, {:http_request, :GET, {:abs_path, path}, {1, 1}}} ->
        :inet.setopts(socket, packet: :httph_bin)
        flush_headers(socket, path, crl_map)

      _ ->
        :gen_tcp.close(socket)
    end
  end

  defp flush_headers(socket, path, crl_map) do
    case :gen_tcp.recv(socket, 0) do
      {:ok, {:http_header, _, _, _, _}} ->
        flush_headers(socket, path, crl_map)

      {:ok, :http_eoh} ->
        case Map.get(crl_map, path) do
          nil ->
            X509.Logger.warn("No CRL defined for #{path}")
            respond(socket, 404)
            :gen_tcp.close(socket)

          crl ->
            # Logger.info("CRL requested: #{path}")
            respond(socket, 200, X509.CRL.to_der(crl))
            :gen_tcp.close(socket)
        end

      _ ->
        :gen_tcp.close(socket)
    end
  end

  defp respond(socket, 404) do
    :gen_tcp.send(socket, [
      "HTTP/1.1 404 Not found\r\n",
      "Content-Length: 0\r\n",
      "Connection: close\r\n",
      "\r\n"
    ])
  end

  defp respond(socket, 200, der) do
    :gen_tcp.send(socket, [
      "HTTP/1.1 200 OK\r\n",
      "Content-Type: application/x-pkcs7-crl\r\n",
      "Content-Length: #{byte_size(der)}\r\n",
      "Connection: close\r\n",
      "\r\n",
      der
    ])
  end
end
