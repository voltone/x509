# Changes

## v0.2.0

### Breaking changes

  * [X509.Certificate] Primary type has been changed from `:Certificate` to `:OTPCertificate`; the `new/[4,5]` and `self_signed/[2,3]` functions now return an `:OTPCertificate` record

### Enhancements

  * [X509] `to_der` and `to_pem` now delegate now support `:OTPCertificate` records, by delegating to `X509.Certificate`
  * [X509.Certificate] Added certificate-specific implementations of `to_der`, `to_pem`, `from_der` and `from_pem`

### Fixes
