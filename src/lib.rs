//! Embed arbitrary data inside the Authenticode signature of a signed Windows
//! PE without breaking the signature.
//!
//! # The idea
//!
//! An Authenticode signature is a PKCS#7 `SignedData` structure whose
//! `SignerInfo` contains two bags of attributes:
//!
//! * **authenticated attributes** — hashed and signed by the code-signing key;
//!   changing them invalidates the signature.
//! * **unauthenticated attributes** — explicitly *not* covered by the
//!   signature. Signing tools use them for countersignatures and timestamps, and
//!   verifiers ignore any attribute they do not understand.
//!
//! `sigpack` stores a blob as a private attribute in the unauthenticated bag
//! (the `1.3.6.1.4.1.42921.1.2.1` OID, the same one `osslsigncode` uses). Every
//! byte that the signature covers is preserved verbatim, so a file that was
//! signed before remains valid after the blob is added.
//!
//! # Example
//!
//! ```no_run
//! # fn main() -> Result<(), sigpack::Error> {
//! let image = std::fs::read("signed.exe")?;
//! let watermarked = sigpack::add_blob(&image, b"license-id=42")?;
//! std::fs::write("watermarked.exe", &watermarked)?;
//!
//! let blobs = sigpack::list_blobs(&watermarked)?;
//! assert_eq!(blobs, vec![b"license-id=42".to_vec()]);
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

mod asn1;
pub mod authenticode;
mod error;
mod pe;

pub use authenticode::UNAUTHENTICATED_BLOB_OID;
pub use error::{Error, Result};
pub use pe::{CertEntry, PeFile};

/// Add `blob` to the Authenticode signature of a signed PE image, returning the
/// modified image.
///
/// The existing signature stays valid because the blob is written to an
/// unauthenticated attribute.
pub fn add_blob(pe_image: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    let mut pe = PeFile::parse(pe_image.to_vec())?;
    let signature = pe.first_signature()?;
    let updated = authenticode::add_blob_to_signed_data(&signature, blob)?;
    pe.replace_first_signature(&updated)?;
    Ok(pe.into_bytes())
}

/// List the blobs stored in the Authenticode signature of a signed PE image.
pub fn list_blobs(pe_image: &[u8]) -> Result<Vec<Vec<u8>>> {
    let pe = PeFile::parse(pe_image.to_vec())?;
    let signature = pe.first_signature()?;
    authenticode::blobs_in_signed_data(&signature)
}
