//! A tiny, byte-preserving DER tree.
//!
//! The whole point of this module is that adding a blob must not disturb the
//! bytes that the existing signature covers. A generic ASN.1 library will
//! round-trip a structure and, in doing so, may re-order or re-encode parts of
//! it (for example the authenticated attributes that the RSA signature is
//! computed over). To avoid that we decode the DER into a tree that keeps the
//! original encoding of every node, mutate only the tiny slice we care about,
//! and re-encode.
//!
//! Length octets of a node are copied verbatim whenever the node's content
//! length is unchanged. As a result every untouched subtree is reproduced
//! byte-for-byte, and only the ancestors of the inserted node get a freshly
//! computed length.

use crate::error::{Error, Result};

const CONSTRUCTED: u8 = 0x20;
const HIGH_TAG_NUMBER: u8 = 0x1f;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Content {
    Primitive(Vec<u8>),
    Constructed(Vec<Node>),
}

/// A single DER TLV element.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    tag: Vec<u8>,
    len: Vec<u8>,
    orig_len: usize,
    content: Content,
}

impl Node {
    /// Parse a single top-level DER element, rejecting trailing bytes.
    pub fn parse(input: &[u8]) -> Result<Self> {
        let (node, consumed) = Self::parse_prefix(input)?;
        if consumed != input.len() {
            return Err(Error::Der("trailing data after top-level element".into()));
        }
        Ok(node)
    }

    /// Parse a single top-level DER element and report how many bytes it used.
    ///
    /// Authenticode pads the PKCS#7 blob to an 8-byte boundary inside the
    /// `WIN_CERTIFICATE` record, so callers that read a signature out of a PE
    /// see trailing padding and use this instead of [`Node::parse`].
    pub fn parse_prefix(input: &[u8]) -> Result<(Self, usize)> {
        let mut pos = 0;
        let node = Self::parse_at(input, &mut pos)?;
        Ok((node, pos))
    }

    fn parse_at(input: &[u8], pos: &mut usize) -> Result<Self> {
        let first = *input
            .get(*pos)
            .ok_or_else(|| Error::Der("unexpected end of input while reading tag".into()))?;
        *pos += 1;

        let tag = if first & HIGH_TAG_NUMBER == HIGH_TAG_NUMBER {
            let mut tag = vec![first];
            loop {
                let byte = *input
                    .get(*pos)
                    .ok_or_else(|| Error::Der("unexpected end of input in tag".into()))?;
                *pos += 1;
                tag.push(byte);
                if byte & 0x80 == 0 {
                    break;
                }
            }
            tag
        } else {
            vec![first]
        };

        let len_byte = *input
            .get(*pos)
            .ok_or_else(|| Error::Der("unexpected end of input while reading length".into()))?;
        *pos += 1;

        let (length, len) = if len_byte & 0x80 == 0 {
            (len_byte as usize, vec![len_byte])
        } else {
            let count = (len_byte & 0x7f) as usize;
            if count == 0 {
                return Err(Error::Der("indefinite length is not valid DER".into()));
            }
            if count > std::mem::size_of::<usize>() {
                return Err(Error::Der("length is too large for this platform".into()));
            }
            let mut len = vec![len_byte];
            let mut length = 0usize;
            for _ in 0..count {
                let byte = *input
                    .get(*pos)
                    .ok_or_else(|| Error::Der("unexpected end of input in length".into()))?;
                *pos += 1;
                len.push(byte);
                length = (length << 8) | byte as usize;
            }
            (length, len)
        };

        let end = pos
            .checked_add(length)
            .ok_or_else(|| Error::Der("content length overflows".into()))?;
        if end > input.len() {
            return Err(Error::Der("content length exceeds input".into()));
        }
        let body = &input[*pos..end];

        let content = if tag[0] & CONSTRUCTED != 0 {
            let mut children = Vec::new();
            let mut inner = 0;
            while inner < body.len() {
                children.push(Self::parse_at(body, &mut inner)?);
            }
            Content::Constructed(children)
        } else {
            Content::Primitive(body.to_vec())
        };

        *pos = end;
        Ok(Node {
            tag,
            len,
            orig_len: length,
            content,
        })
    }

    /// The first (and usually only) identifier octet.
    pub fn tag_byte(&self) -> u8 {
        self.tag[0]
    }

    /// Children of a constructed element, or `None` for a primitive one.
    pub fn children(&self) -> Option<&[Node]> {
        match &self.content {
            Content::Constructed(children) => Some(children),
            Content::Primitive(_) => None,
        }
    }

    pub fn children_mut(&mut self) -> Option<&mut Vec<Node>> {
        match &mut self.content {
            Content::Constructed(children) => Some(children),
            Content::Primitive(_) => None,
        }
    }

    /// Raw content octets of a primitive element.
    pub fn as_primitive(&self) -> Option<&[u8]> {
        match &self.content {
            Content::Primitive(body) => Some(body),
            Content::Constructed(_) => None,
        }
    }

    fn content_len(&self) -> usize {
        match &self.content {
            Content::Primitive(body) => body.len(),
            Content::Constructed(children) => children.iter().map(Node::encoded_len).sum(),
        }
    }

    /// Number of octets this node occupies once encoded.
    pub fn encoded_len(&self) -> usize {
        let content_len = self.content_len();
        let len_len = if content_len == self.orig_len {
            self.len.len()
        } else {
            length_of_length(content_len)
        };
        self.tag.len() + len_len + content_len
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode_into(&mut out);
        out
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.tag);

        let mut body = Vec::new();
        match &self.content {
            Content::Primitive(bytes) => body.extend_from_slice(bytes),
            Content::Constructed(children) => {
                for child in children {
                    child.encode_into(&mut body);
                }
            }
        }

        if body.len() == self.orig_len {
            out.extend_from_slice(&self.len);
        } else {
            encode_length(body.len(), out);
        }
        out.extend_from_slice(&body);
    }

    /// Build a constructed element from already-parsed children.
    pub fn constructed(tag: u8, children: Vec<Node>) -> Self {
        let content_len: usize = children.iter().map(Node::encoded_len).sum();
        let mut len = Vec::new();
        encode_length(content_len, &mut len);
        Node {
            tag: vec![tag],
            len,
            orig_len: content_len,
            content: Content::Constructed(children),
        }
    }
}

/// Encode a TLV from a tag byte and raw content octets.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 5 + content.len());
    out.push(tag);
    encode_length(content.len(), &mut out);
    out.extend_from_slice(content);
    out
}

fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let bytes = len.to_be_bytes();
    let first = bytes
        .iter()
        .position(|&b| b != 0)
        .expect("non-zero length has at least one non-zero byte");
    let significant = &bytes[first..];
    out.push(0x80 | significant.len() as u8);
    out.extend_from_slice(significant);
}

fn length_of_length(len: usize) -> usize {
    if len < 0x80 {
        1
    } else {
        let significant = (usize::BITS - len.leading_zeros()).div_ceil(8) as usize;
        1 + significant
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlvs_use_minimal_der_lengths() {
        assert_eq!(tlv(0x04, &[0; 0]), vec![0x04, 0x00]);
        assert_eq!(tlv(0x04, &[0; 127]), {
            let mut expected = vec![0x04, 0x7f];
            expected.extend_from_slice(&[0; 127]);
            expected
        });
        assert_eq!(tlv(0x04, &[0; 128]), {
            let mut expected = vec![0x04, 0x81, 0x80];
            expected.extend_from_slice(&[0; 128]);
            expected
        });
        assert_eq!(tlv(0x04, &[0; 256]), {
            let mut expected = vec![0x04, 0x82, 0x01, 0x00];
            expected.extend_from_slice(&[0; 256]);
            expected
        });
    }

    #[test]
    fn round_trips_unchanged() {
        let inner = tlv(0x02, &[0x2a]);
        let mut seq = tlv(0x06, &[0x2b, 0x06, 0x01]);
        seq.extend_from_slice(&inner);
        let mut root = tlv(0x30, &seq);
        root.extend_from_slice(&tlv(0xa1, &tlv(0x0c, b"nested")));
        let root = tlv(0x30, &root);

        let node = Node::parse(&root).unwrap();
        assert_eq!(node.encode(), root);
    }

    #[test]
    fn parse_rejects_trailing_bytes_and_prefix_tolerates_them() {
        let mut input = tlv(0x04, b"abc");
        input.extend_from_slice(&[0, 0]);

        assert!(Node::parse(&input).is_err());
        let (node, consumed) = Node::parse_prefix(&input).unwrap();
        assert_eq!(consumed, 5);
        assert_eq!(node.as_primitive(), Some(b"abc".as_slice()));
    }
}
