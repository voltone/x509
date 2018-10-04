# Changes

## v0.4.0

### Enhancements


## v0.3.0

This release paves the way for some changes in the way PEM and DER
decoding works. Eventually there will be six functions in each module, as
implemented in `X509.CSR` in this version. The generic functions in the `X509`
module will eventually be removed, with the exception of the`X509.from_pem/2`
function, which returns a (possibly filtered) list of entities found in the
PEM string.

In the next version, all `from_der` and `from_pem` functions (except for the
one in `X509`) will return `:ok` / `:error` tuples, so please update existing
code to use the new `from_der!` and `from_pem!` functions instead: their return
value on success will always be just the module's primary record type.

### Breaking changes

  * [X509.Certificate] `from_der/2` and `from_pem/2` now return `nil` in case
    of failure, for consistency with the current behaviour of other modules;
    use the new `from_der!/2` and `from_pem!/2` to get the old behaviour of
    raising an exception

### Enhancements

  * [X509.Certificate] Add `from_der!/2` and `from_pem!/2`
  * [X509.CSR] Add `to_der/1`, `to_pem/1`, `from_der!/1`, `from_der/1`,
    `from_pem!/1` and `from_pem/1`
  * [X509.PrivateKey] Add `from_der!/2` and `from_pem!/2`
  * [X509.PublicKey] Add `from_der!/2` and `from_pem!/2`
  * Support Elixir v1.7 and ExDoc v0.19

### Deprecations

The `to_der`, `to_pem` and `from_der` functions in the X509 top-level module
have been deprecated. Please use their entity-specific functions in the
appropriate module instead. The deprecated functions will be removed in an
upcoming release, prior to v1.0.

## v0.2.0

### Breaking changes

  * [X509.Certificate] Primary type has been changed from `:Certificate` to `:OTPCertificate`; the `new/[4,5]` and `self_signed/[2,3]` functions now return an `:OTPCertificate` record

### Enhancements

  * [X509] `to_der` and `to_pem` now delegate now support `:OTPCertificate` records, by delegating to `X509.Certificate`
  * [X509.Certificate] Added certificate-specific implementations of `to_der`, `to_pem`, `from_der` and `from_pem`

## v0.1.0

First public release
