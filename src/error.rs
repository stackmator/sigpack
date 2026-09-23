use std::io;

/// Errors returned by `sigpack`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("not a PE image: {0}")]
    NotPe(String),

    #[error("the PE file has no attribute certificate table (it is not signed)")]
    NoCertificateTable,

    #[error("the PE file has no PKCS#7 Authenticode signature")]
    NoSignature,

    #[error("malformed DER: {0}")]
    Der(String),

    #[error("unexpected ASN.1 structure: {0}")]
    Asn1(String),

    #[error(
        "cannot grow the certificate table from {old} to {new} bytes in place because data follows it"
    )]
    CertificateTableOverflow { old: usize, new: usize },
}

pub type Result<T> = std::result::Result<T, Error>;
