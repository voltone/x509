# Changelog

## v0.8.8 (2023-08-30)

### Fixes

* Avoid Logger.warn deprecation warning on recent Elixir versions

## v0.8.7 (2023-05-31)

### Fixes

* Compatibility with Elixir 1.15

## v0.8.6 (2023-04-04)

### Fixes

* Compatibility with Erlang/OTP 25.3

## v0.8.5 (2022-05-25)

### Fixes

* [X509.Test.Server] Use `:ssl.handshake/3` if available

## v0.8.4 (2022-03-01)

### Fixes

* [X509.RDNSequence] Fix handling of surname attribute

## v0.8.3 (2021-06-07)

### Enhancements

* [X509.PublicKey] Support 'engine' reference for private keys in `derive/1`
* [X509.CSR] Support 'engine' reference for private keys in `new/2,3`
* [X509.CSR] Add `:public_key` option for `new/3`

## v0.8.2 (2020-11-05)

### Fixes

* Support for Elixir v1.11

## v0.8.1 (2020-02-29)

### Fixes

* [X509.Certificate] Support both 'plain' and 'otp' `rdnSequence` records
* [X509.CSR] Support both 'plain' and 'otp' `rdnSequence` records

## v0.8.0 (2019-12-09)

### Enhancements

* [X509.CSR] Add support for extension requests

## v0.7.0 (2019-07-15)

### Enhancements

* [X509.Certificate.Template] Add OCSP responder template
* [X509.Certificate.Extension] Add support for Authority Information Access
  and OCSP Nocheck extensions

### Fixes

* [X509.RDNSequence] Handle `teletexString` encoding (7-bit only, for now)
* [X509.PrivateKey] Documentation fixes

## v0.6.0 (2019-06-18)

### Enhancements

* [X509.PrivateKey] Allow encryption of PEM output
* [X509.Test.Suite] Include 'localhost' in all certifictes
* [X509.Test.Suite] Generate client certificate and associated key
* [X509.Test.Server] Add 'client-cert' endpoint for testing with client
  certificate
* [`x509.gen.suite` Mix task] Add --force option
* [`x509.gen.suite` Mix task] Add --password option
* [`x509.gen.suite` Mix task] Generate 'ca_and_chain.pem' file
* [`x509.gen.selfsigned` Mix task] Add --force option

## v0.5.4 (2019-04-15)

### Enhancements

* [X509.RDNSequence] Relax length restriction on `countryName` attribute

## v0.5.3 (2019-03-14)

### Fixes

* [X509.RDNSequence] Support more attribute types in `to_string/1`

## v0.5.2 (2019-02-21)

### Enhancements

* [X509.Certificate] Add `version/1`, `subject/2` and `issuer/2`
* [X509.RDNSequence] Add `get_attr/2`

## v0.5.1 (2019-01-03)

### Fixes

* [X509.Certificate.Validity] The record type returned for GeneralizedTime,
  used for dates from 2050 forward, was not recognized by OTP, causing
  certificate creation and encoding to fail (#24)

## v0.5.0 (2018-11-27)

### Enhancements

  * [X509.CRL] New module for generating and parsing Certificate Revocation
    Lists (CRLs)
  * [X509.CRL.Entry] New module: CRL entries
  * [X509.CRL.Extension] New module: CRL extensions
  * [X509.Certificate.Extension] Add support for the CRL Distribution Point
    extension
  * [X509.Test.Suite] New module for generating test suites for TLS client
    testing
  * [X509.Test.Server] New module: simple server for hosting test suites
  * Add `x509.gen.suite` Mix task
  * Add `x509.test_server` Mix task

### Fixes

  * [X509.Certificate.Validity] The `days_from_now/2` function used to
    calculate the `not_after` timestamp relative to the `not_before` value
    (including the `backdate_seconds` shift); it is now set relative to the
    current time

## v0.4.0 (2018-10-19)

### Breaking changes

All `from_der` and `from_pem` functions now return an `:error` tuple on failure
instead of `nil`, and wrap their result in a `:ok` tuple in case of success.
The only exception is the `from_pem` function in X509, which returns a
(possibly empty) list.

  * [X509] Removed `to_der/1`, `to_pem/1` and `from_der/2`
  * [X509.Certificate] Changed the return values of `from_der/1` and
    `from_pem/1,2`, as described above

### Enhancements

  * Add `x509.gen.selfsigned` Mix task
  * The various `from_pem` and `from_pem!` functions are now more lenient: they
    scan for the first PEM entry of an appropriate type instead of requiring
    that it be the only entry
  * [X509.Certificate] Add `serial/1` to extract a certificate's serial number
  * [X509.Certificate.Template] The length of randomly generated serial numbers
    can now be specified using a `{:random, n}` tuple in the `:serial` field,
    where `n` is the length in bytes; the default is `{:random, 8}`, equivalent
    to the previous default

### Fixes

  * [X509.Certificate] Fixed the typespec for second parameter of
    `from_der!/2`, `from_der/2`, `from_pem!/2` and `from_pem/2`
  * [X509.Certificate] Extract the correct RDN from issuer certificate (#13)
  * [X509.Certificate.Extensions] `subject_key_identifier/1` returned an AKI
    record rather than SKI record for ECC keys (#10)
  * [X509.PublicKey] Documentation: corrected the default value for the
    `wrap` option for RSA keys in `to_der/1` and `to_pem/1`

## v0.3.0 (2018-09-22)

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

## v0.2.0 (2018-07-24)

### Breaking changes

  * [X509.Certificate] Primary type has been changed from `:Certificate` to `:OTPCertificate`; the `new/[4,5]` and `self_signed/[2,3]` functions now return an `:OTPCertificate` record

### Enhancements

  * [X509] `to_der` and `to_pem` now delegate now support `:OTPCertificate` records, by delegating to `X509.Certificate`
  * [X509.Certificate] Added certificate-specific implementations of `to_der`, `to_pem`, `from_der` and `from_pem`

## v0.1.0 (2018-07-02)

First public release
