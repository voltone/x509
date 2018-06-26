defmodule X509Test do
  use ExUnit.Case
  doctest X509

  test "greets the world" do
    assert X509.hello() == :world
  end
end
