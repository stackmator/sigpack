# sigpack

[![crates.io](https://img.shields.io/crates/v/sigpack.svg)](https://crates.io/crates/sigpack)
[![docs.rs](https://docs.rs/sigpack/badge.svg)](https://docs.rs/sigpack)
[![CI](https://github.com/stackmator/sigpack/actions/workflows/ci.yml/badge.svg)](https://github.com/stackmator/sigpack/actions/workflows/ci.yml)
[![license](https://img.shields.io/crates/l/sigpack.svg)](#license)

**Store data inside an Authenticode-signed Windows PE — without breaking the signature.**

`sigpack` hides arbitrary bytes in the digital signature of a `.exe`/`.dll`/`.sys`
file. The file keeps its valid Microsoft Authenticode signature: Windows,
`signtool`, `Get-AuthenticodeSignature` and every other verifier still report it
as **signed and valid**. No private key is needed, and the original signature is
not touched.

## Why this works

An Authenticode signature is a PKCS#7 `SignedData` structure. Its `SignerInfo`
has two sets of attributes:

| Attribute set | Covered by the signature? | Typical use |
| --- | --- | --- |
| **authenticated attributes** | Yes | content type, message digest, signing time |
| **unauthenticated attributes** | **No** | countersignatures, RFC 3161 timestamps |

The signer's key signs the *authenticated* attributes only. The *unauthenticated*
attributes are, by design, ignored by verifiers — that is exactly where timestamp
authorities put their tokens. `sigpack` writes a private attribute with OID
`1.3.6.1.4.1.42921.1.2.1` (the same one `osslsigncode --add-blob` uses) into that
bag.

Because `sigpack` only edits that unsigned bag and the length octets of its
ancestors, **every byte the signature covers is preserved verbatim**. A file that
validated before still validates after:

```
PS> Get-AuthenticodeSignature signed.exe             -> Valid
PS> sigpack add signed.exe payload.bin
PS> Get-AuthenticodeSignature signed.exe             -> Valid   # still!
```

This is useful for watermarking builds, per-customer identifiers, build
provenance, license tags, or shipping metadata with an already-signed binary
without reaching for the code-signing key again.

## Install

```console
cargo install --path .
```

## CLI

```console
# Embed a blob into the first Authenticode signature (edits in place)
sigpack add signed.exe payload.bin

# ...or write the result somewhere else
sigpack add signed.exe payload.bin -o watermarked.exe

# Read blobs back
sigpack list watermarked.exe
#0 (16 bytes): license-id=42

# Extract them verbatim to files (works for binary payloads too)
sigpack list watermarked.exe --extract ./out
# ./out/watermarked.0.blob
```

## Library

```rust
let image = std::fs::read("signed.exe")?;
let watermarked = sigpack::add_blob(&image, b"license-id=42")?;
std::fs::write("watermarked.exe", &watermarked)?;

let blobs = sigpack::list_blobs(&watermarked)?;
assert_eq!(blobs, vec![b"license-id=42".to_vec()]);
```

The core is format-agnostic too: `sigpack::authenticode::add_blob_to_signed_data`
and `blobs_in_signed_data` operate directly on a DER-encoded PKCS#7 `SignedData`.

## Compatibility

* Blobs are interoperable with `osslsigncode --add-blob` / `--extract-data`.
* Unknown unauthenticated attributes are ignored by Windows and by signing tools,
  so nothing else is affected.
* The blob is stored in a `UTF8String` but is written as raw octets without
  UTF-8 validation, so arbitrary binary payloads are fine.

## Limitations

* Only Windows PE images are supported for now (the certificate table in the PE
  security data directory). MSI/CAB store their signature elsewhere.
* The blob is *not* covered by the signature. It can be read and altered by
  anyone, exactly like any other unauthenticated attribute. Do not use it for
  tamper-proof data.
* The crate reads and rewrites the signature; it does not create or verify
  signatures.

## Releasing

CI (`.github/workflows/ci.yml`) runs formatting, clippy, unit tests and a
real signed-PE round-trip on `windows-latest`. To publish, add a
`CARGO_REGISTRY_TOKEN` repository secret and push a tag matching the
`Cargo.toml` version:

```console
git tag v0.1.0
git push origin v0.1.0
```

`.github/workflows/publish.yml` verifies the tag, runs the tests and publishes
with `cargo publish`. It can also be run manually from the Actions tab; the
**Dry run** checkbox defaults to on, in which case it only runs
`cargo publish --dry-run` and uploads nothing.

## License

Licensed under either of Apache-2.0 or MIT at your option.
