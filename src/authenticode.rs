//! Reading and writing data hidden in the `unauthenticatedAttributes` of an
//! Authenticode `SignerInfo`.
//!
//! The `unauthenticatedAttributes` field is, by definition, not covered by the
//! signer's signature. Every authenticated field — including the authenticated
//! attributes that the RSA/ECDSA signature actually signs — is left byte-for-byte
//! intact, so the stored blob can be added or replaced without breaking the
//! existing signature. This is the same trick used by
//! `osslsigncode --add-blob` and is fully transparent: tools that do not know
//! about the blob simply ignore the extra attribute.

use der::Encode;
use der::asn1::ObjectIdentifier;

use crate::asn1::{self, Node};
use crate::error::{Error, Result};

/// OID of the private attribute used for the blob (osslsigncode's
/// `SPC_UNAUTHENTICATED_DATA_BLOB_OBJID`).
pub const UNAUTHENTICATED_BLOB_OID: &str = "1.3.6.1.4.1.42921.1.2.1";

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const UTF8_STRING: u8 = 0x0c;
const OID: u8 = 0x06;
const CONTEXT_0: u8 = 0xa0;
const CONTEXT_1: u8 = 0xa1;

/// Append `blob` to the first signer's unauthenticated attributes of a
/// DER-encoded PKCS#7 `SignedData`, returning the re-encoded structure.
///
/// Authenticated bytes are preserved, so an existing signature stays valid.
pub fn add_blob_to_signed_data(signed_data: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    let (mut root, _) = Node::parse_prefix(signed_data)?;
    let attribute = Node::parse(&build_blob_attribute(blob)?)?;
    let signer_info = first_signer_info_mut(&mut root)?;

    let existing = signer_info.children().and_then(|children| {
        children
            .iter()
            .position(|child| child.tag_byte() == CONTEXT_1)
    });

    match existing {
        Some(index) => {
            let children = signer_info
                .children_mut()
                .expect("constructed element has children");
            let unauth = &mut children[index];
            let values = unauth.children_mut().ok_or_else(|| {
                Error::Asn1("unauthenticatedAttributes is not constructed".into())
            })?;
            values.push(attribute);
        }
        None => {
            let children = signer_info
                .children_mut()
                .ok_or_else(|| Error::Asn1("SignerInfo is not a SEQUENCE".into()))?;
            children.push(Node::constructed(CONTEXT_1, vec![attribute]));
        }
    }

    Ok(root.encode())
}

/// All blobs stored in the first signer's unauthenticated attributes.
pub fn blobs_in_signed_data(signed_data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let (root, _) = Node::parse_prefix(signed_data)?;
    let signer_info = first_signer_info(&root)?;

    let mut blobs = Vec::new();
    let Some(attributes) = signer_info
        .children()
        .and_then(|children| children.iter().find(|child| child.tag_byte() == CONTEXT_1))
        .and_then(Node::children)
    else {
        return Ok(blobs);
    };

    for attribute in attributes {
        let Some(parts) = attribute.children() else {
            continue;
        };
        if parts.len() != 2 || !is_blob_oid(&parts[0]) {
            continue;
        }
        let Some(values) = parts[1].children() else {
            continue;
        };
        for value in values {
            if value.tag_byte() == UTF8_STRING
                && let Some(bytes) = value.as_primitive()
            {
                blobs.push(bytes.to_vec());
            }
        }
    }

    Ok(blobs)
}

fn build_blob_attribute(blob: &[u8]) -> Result<Vec<u8>> {
    let oid = blob_oid()
        .to_der()
        .map_err(|error| Error::Asn1(format!("failed to encode blob OID: {error}")))?;
    // The blob is carried in a UTF8String for compatibility with osslsigncode.
    // It is stored as raw octets without UTF-8 validation.
    let value = asn1::tlv(UTF8_STRING, blob);
    let set = asn1::tlv(SET, &value);

    let mut body = Vec::with_capacity(oid.len() + set.len());
    body.extend_from_slice(&oid);
    body.extend_from_slice(&set);
    Ok(asn1::tlv(SEQUENCE, &body))
}

fn is_blob_oid(node: &Node) -> bool {
    node.tag_byte() == OID && node.as_primitive() == Some(blob_oid().as_bytes())
}

fn blob_oid() -> ObjectIdentifier {
    ObjectIdentifier::new(UNAUTHENTICATED_BLOB_OID).expect("blob OID is a valid constant")
}

fn first_signer_info(root: &Node) -> Result<&Node> {
    let signed_data = signed_data(root)?;
    let fields = signed_data
        .children()
        .ok_or_else(|| Error::Asn1("SignedData is not a SEQUENCE".into()))?;
    let signer_infos = fields
        .last()
        .ok_or_else(|| Error::Asn1("SignedData has no signerInfos".into()))?;
    if signer_infos.tag_byte() != SET {
        return Err(Error::Asn1("signerInfos SET not found".into()));
    }
    signer_infos
        .children()
        .and_then(|children| children.first())
        .ok_or_else(|| Error::Asn1("signerInfos is empty".into()))
}

fn first_signer_info_mut(root: &mut Node) -> Result<&mut Node> {
    let signed_data = signed_data_mut(root)?;
    let fields = signed_data
        .children_mut()
        .ok_or_else(|| Error::Asn1("SignedData is not a SEQUENCE".into()))?;
    let signer_infos = fields
        .last_mut()
        .ok_or_else(|| Error::Asn1("SignedData has no signerInfos".into()))?;
    if signer_infos.tag_byte() != SET {
        return Err(Error::Asn1("signerInfos SET not found".into()));
    }
    signer_infos
        .children_mut()
        .and_then(|children| children.first_mut())
        .ok_or_else(|| Error::Asn1("signerInfos is empty".into()))
}

fn signed_data(root: &Node) -> Result<&Node> {
    let content_info = root
        .children()
        .ok_or_else(|| Error::Asn1("ContentInfo is not a SEQUENCE".into()))?;
    let explicit = content_info
        .get(1)
        .ok_or_else(|| Error::Asn1("ContentInfo is missing its content".into()))?;
    if explicit.tag_byte() != CONTEXT_0 {
        return Err(Error::Asn1(
            "ContentInfo content is not [0] EXPLICIT".into(),
        ));
    }
    explicit
        .children()
        .and_then(|children| children.first())
        .ok_or_else(|| Error::Asn1("SignedData is missing".into()))
}

fn signed_data_mut(root: &mut Node) -> Result<&mut Node> {
    let content_info = root
        .children_mut()
        .ok_or_else(|| Error::Asn1("ContentInfo is not a SEQUENCE".into()))?;
    let explicit = content_info
        .get_mut(1)
        .ok_or_else(|| Error::Asn1("ContentInfo is missing its content".into()))?;
    if explicit.tag_byte() != CONTEXT_0 {
        return Err(Error::Asn1(
            "ContentInfo content is not [0] EXPLICIT".into(),
        ));
    }
    explicit
        .children_mut()
        .and_then(|children| children.first_mut())
        .ok_or_else(|| Error::Asn1("SignedData is missing".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        asn1::tlv(tag, content)
    }

    fn oid(value: &str) -> Vec<u8> {
        ObjectIdentifier::new(value).unwrap().to_der().unwrap()
    }

    fn attribute(attr_oid: &str, value: &[u8]) -> Vec<u8> {
        let mut body = oid(attr_oid);
        body.extend_from_slice(&tlv(SET, value));
        tlv(SEQUENCE, &body)
    }

    /// A structurally valid (but cryptographically meaningless) PKCS#7
    /// `SignedData` with one signer and one authenticated attribute.
    fn synthetic_signed_data() -> (Vec<u8>, Vec<u8>) {
        let signed_attrs = tlv(
            CONTEXT_0,
            &attribute("1.2.840.113549.1.9.4", &tlv(0x04, &[0xaa; 32])),
        );

        let mut signer_info = tlv(0x02, &[1]);
        let mut sid = tlv(0x30, &[]);
        sid.extend_from_slice(&tlv(0x02, &[1]));
        signer_info.extend_from_slice(&tlv(0x30, &sid));
        let mut digest_alg = oid("2.16.840.1.101.3.4.2.1");
        digest_alg.extend_from_slice(&tlv(0x05, &[]));
        signer_info.extend_from_slice(&tlv(0x30, &digest_alg));
        signer_info.extend_from_slice(&signed_attrs);
        let mut enc_alg = oid("1.2.840.113549.1.1.1");
        enc_alg.extend_from_slice(&tlv(0x05, &[]));
        signer_info.extend_from_slice(&tlv(0x30, &enc_alg));
        signer_info.extend_from_slice(&tlv(0x04, &[0xde, 0xad, 0xbe, 0xef]));

        let mut signed_data = tlv(0x02, &[1]);
        signed_data.extend_from_slice(&tlv(SET, &[]));
        let mut encap = oid("1.2.840.113549.1.7.1");
        encap.extend_from_slice(&tlv(CONTEXT_0, &tlv(0x04, &[])));
        signed_data.extend_from_slice(&tlv(SEQUENCE, &encap));
        signed_data.extend_from_slice(&tlv(SET, &tlv(SEQUENCE, &signer_info)));

        let mut content_info = oid("1.2.840.113549.1.7.2");
        content_info.extend_from_slice(&tlv(CONTEXT_0, &tlv(SEQUENCE, &signed_data)));
        (tlv(SEQUENCE, &content_info), signed_attrs)
    }

    #[test]
    fn adds_and_reads_back_a_blob() {
        let (signed_data, _) = synthetic_signed_data();
        assert!(blobs_in_signed_data(&signed_data).unwrap().is_empty());

        let updated = add_blob_to_signed_data(&signed_data, b"hello").unwrap();
        assert_eq!(
            blobs_in_signed_data(&updated).unwrap(),
            vec![b"hello".to_vec()]
        );
    }

    #[test]
    fn preserves_authenticated_attributes_verbatim() {
        let (signed_data, signed_attrs) = synthetic_signed_data();
        let updated = add_blob_to_signed_data(&signed_data, b"payload").unwrap();

        let found = updated
            .windows(signed_attrs.len())
            .any(|window| window == signed_attrs.as_slice());
        assert!(found, "the signed attribute bytes must survive untouched");
    }

    #[test]
    fn supports_binary_payloads() {
        let (signed_data, _) = synthetic_signed_data();
        let blob: Vec<u8> = (0..=255).collect();

        let updated = add_blob_to_signed_data(&signed_data, &blob).unwrap();
        assert_eq!(blobs_in_signed_data(&updated).unwrap(), vec![blob]);
    }

    #[test]
    fn appends_multiple_blobs() {
        let (signed_data, _) = synthetic_signed_data();
        let once = add_blob_to_signed_data(&signed_data, b"first").unwrap();
        let twice = add_blob_to_signed_data(&once, b"second").unwrap();

        assert_eq!(
            blobs_in_signed_data(&twice).unwrap(),
            vec![b"first".to_vec(), b"second".to_vec()]
        );
    }

    #[test]
    fn tolerates_trailing_padding() {
        let (signed_data, _) = synthetic_signed_data();
        let mut padded = signed_data.clone();
        padded.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0]);

        let updated = add_blob_to_signed_data(&padded, b"x").unwrap();
        assert_eq!(blobs_in_signed_data(&updated).unwrap(), vec![b"x".to_vec()]);
    }
}
