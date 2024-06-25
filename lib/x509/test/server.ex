defmodule X509.Test.Server do
  @moduledoc """
  Simple TLS server for hosting `X509.Test.Suite` scenarios.
  """
  use GenServer

  alias X509.Util

  @doc """
  Starts a test server for the given test suite.

  ## Options:

  * `:port` - the TCP port to listen on; defaults to 0, meaning an ephemeral
    port is selected by the operating system, which may be retrieved using
    `get_port/1`
  * `:response` - the data to send back to clients when a successful connection
    is established (default: "OK")
  """
  @spec start_link({X509.Test.Suite.t(), Keyword.t()}) :: GenServer.on_start()
  def start_link({suite, opts}) do
    GenServer.start_link(__MODULE__, [suite, opts])
  end

  @doc """
  Returns the TCP port number on which the specified X509.Test.Server instance
  is listening.
  """
  @spec get_port(pid()) :: :inet.port_number()
  def get_port(pid) do
    GenServer.call(pid, :get_port)
  end

  # Callbacks

  defmodule State do
    @moduledoc false
    defstruct [:listen_socket, :port, :suite, :response]
  end

  @impl true
  def init([suite, opts]) do
    Application.ensure_all_started(:ssl)

    port = Keyword.get(opts, :port, 0)
    response = Keyword.get(opts, :response, "OK")

    with {:ok, listen_socket} <- :gen_tcp.listen(port, []),
         {:ok, {_, port}} <- :inet.sockname(listen_socket),
         {:ok, _} <- :prim_inet.async_accept(listen_socket, -1) do
      {:ok, %State{listen_socket: listen_socket, port: port, suite: suite, response: response}}
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
  def handle_info({:inet_async, listen_socket, _ref, {:ok, socket}}, state) do
    :inet_db.register_socket(socket, :inet_tcp)

    pid =
      spawn_link(fn ->
        receive do
          :start -> worker(socket, state.suite, state.response)
        after
          250 -> :gen_tcp.close(socket)
        end
      end)

    :gen_tcp.controlling_process(socket, pid)
    send(pid, :start)
    {:ok, _} = :prim_inet.async_accept(listen_socket, -1)
    {:noreply, state}
  end

  defp worker(socket, suite, response) do
    # Default certificates and keys, which are overriden by sni_fun according
    # to the specific test case. OTP 27 requires that valid certificates and
    # keys are passed to the listener socket.
    default_cert = X509.Certificate.to_der(suite.valid)
    default_key = {:PrivateKeyInfo, X509.PrivateKey.to_der(suite.server_key, wrap: true)}
    default_cacerts = suite.chain

    opts =
      [
        active: false,
        cert: default_cert,
        key: default_key,
        cacerts: default_cacerts,
        sni_fun: X509.Test.Suite.sni_fun(suite),
        reuse_sessions: false
      ] ++ log_opts()

    case handshake(socket, opts, 1000) do
      {:ok, ssl_socket} ->
        flush(ssl_socket)
        :ssl.send(ssl_socket, response)
        :ssl.close(ssl_socket)

      {:error, _reason} ->
        :gen_tcp.close(socket)
    end
  end

  if Code.ensure_loaded?(:ssl) and function_exported?(:ssl, :handshake, 3) do
    defp handshake(socket, opts, timeout) do
      :ssl.handshake(socket, opts, timeout)
    end
  else
    defp handshake(socket, opts, timeout) do
      :ssl.ssl_accept(socket, opts, timeout)
    end
  end

  defp flush(ssl_socket) do
    case :ssl.recv(ssl_socket, 0, 100) do
      {:ok, _data} ->
        flush(ssl_socket)

      _done ->
        :done
    end
  end

  def log_opts do
    if Util.app_version(:ssl) >= [9, 3] do
      [log_level: :emergency]
    else
      [log_alert: false]
    end
  end
end
