ExUnit.configure(exclude: [:openssl, :known_to_fail])
ExUnit.start()

# Logger is not included in the `extra_applications` list in the application
# config in mix.exs, because it is not used at runtime. It is used in the
# X509.Test.Server tests, so we need to start it explicitly.
Application.ensure_all_started(:logger)
