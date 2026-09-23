//! Just enough PE/COFF parsing to find and rewrite the attribute certificate
//! table (the `IMAGE_DIRECTORY_ENTRY_SECURITY` data directory).
//!
//! The Authenticode digest covers everything in the file *except* the
//! certificate table itself (the data-directory entry is zeroed and the table
//! bytes are skipped). That is what makes it possible to modify a signature
//! after the fact without invalidating it: as long as the bytes before the
//! certificate table are left untouched, the digest still matches.

use crate::error::{Error, Result};

const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;

#[derive(Clone, Copy, Debug)]
pub struct CertEntry {
    pub offset: usize,
    pub length: usize,
    pub revision: u16,
    pub cert_type: u16,
}

/// A parsed PE image with its raw bytes.
pub struct PeFile {
    data: Vec<u8>,
    cert_dir_offset: usize,
    cert_offset: usize,
    cert_size: usize,
}

impl PeFile {
    pub fn parse(data: Vec<u8>) -> Result<Self> {
        if data.len() < 0x40 || &data[0..2] != b"MZ" {
            return Err(Error::NotPe("missing DOS 'MZ' header".into()));
        }

        let e_lfanew = read_u32(&data, 0x3c)? as usize;
        if &data.get(e_lfanew..e_lfanew + 4).unwrap_or_default() != b"PE\0\0" {
            return Err(Error::NotPe("missing PE signature".into()));
        }

        let coff = e_lfanew + 4;
        let optional_header_size = read_u16(&data, coff + 16)? as usize;
        let optional = coff + 20;
        if optional_header_size < 2 {
            return Err(Error::NotPe("optional header is too small".into()));
        }

        let magic = read_u16(&data, optional)?;
        let (num_dirs_offset, dirs_offset) = match magic {
            0x010b => (optional + 92, optional + 96),
            0x020b => (optional + 108, optional + 112),
            other => {
                return Err(Error::NotPe(format!(
                    "unsupported optional header magic 0x{other:04x}"
                )));
            }
        };

        let num_dirs = read_u32(&data, num_dirs_offset)? as usize;
        if num_dirs <= IMAGE_DIRECTORY_ENTRY_SECURITY {
            return Err(Error::NoCertificateTable);
        }

        let cert_dir_offset = dirs_offset + IMAGE_DIRECTORY_ENTRY_SECURITY * 8;
        if cert_dir_offset + 8 > data.len() {
            return Err(Error::NotPe(
                "security data directory is out of bounds".into(),
            ));
        }

        let cert_offset = read_u32(&data, cert_dir_offset)? as usize;
        let cert_size = read_u32(&data, cert_dir_offset + 4)? as usize;
        if cert_offset == 0 || cert_size == 0 {
            return Err(Error::NoCertificateTable);
        }
        if cert_offset
            .checked_add(cert_size)
            .filter(|end| *end <= data.len())
            .is_none()
        {
            return Err(Error::NotPe("certificate table is out of bounds".into()));
        }

        Ok(Self {
            data,
            cert_dir_offset,
            cert_offset,
            cert_size,
        })
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    /// Enumerate the `WIN_CERTIFICATE` records in the certificate table.
    pub fn certificate_entries(&self) -> Result<Vec<CertEntry>> {
        let mut entries = Vec::new();
        let end = self.cert_offset + self.cert_size;
        let mut offset = self.cert_offset;
        while offset + 8 <= end {
            let length = read_u32(&self.data, offset)? as usize;
            if length == 0 {
                break;
            }
            if offset + length > end || length < 8 {
                return Err(Error::NotPe("malformed WIN_CERTIFICATE entry".into()));
            }
            entries.push(CertEntry {
                offset,
                length,
                revision: read_u16(&self.data, offset + 4)?,
                cert_type: read_u16(&self.data, offset + 6)?,
            });
            // Records are 8-byte aligned.
            offset += length.div_ceil(8) * 8;
        }
        Ok(entries)
    }

    /// The DER-encoded PKCS#7 of the first Authenticode (`PKCS_SIGNED_DATA`) entry.
    pub fn first_signature(&self) -> Result<Vec<u8>> {
        let entry = self
            .certificate_entries()?
            .into_iter()
            .find(|entry| entry.cert_type == WIN_CERT_TYPE_PKCS_SIGNED_DATA)
            .ok_or(Error::NoSignature)?;
        Ok(self.data[entry.offset + 8..entry.offset + entry.length].to_vec())
    }

    /// Replace the DER payload of the first Authenticode entry, rebuilding the
    /// certificate table around it.
    pub fn replace_first_signature(&mut self, der: &[u8]) -> Result<()> {
        let entries = self.certificate_entries()?;
        let target = entries
            .iter()
            .position(|entry| entry.cert_type == WIN_CERT_TYPE_PKCS_SIGNED_DATA)
            .ok_or(Error::NoSignature)?;

        let mut table = Vec::with_capacity(self.cert_size);
        for (index, entry) in entries.iter().enumerate() {
            if index == target {
                append_win_certificate(&mut table, entry.revision, entry.cert_type, der);
            } else {
                table.extend_from_slice(&self.data[entry.offset..entry.offset + entry.length]);
                while !table.len().is_multiple_of(8) {
                    table.push(0);
                }
            }
        }

        self.write_certificate_table(&table)
    }

    fn write_certificate_table(&mut self, table: &[u8]) -> Result<()> {
        let at_end_of_file = self.cert_offset + self.cert_size == self.data.len();
        let new_size = table.len();

        if at_end_of_file {
            // Safe to grow or shrink: everything the digest covers stays put.
            self.data.truncate(self.cert_offset);
            self.data.extend_from_slice(table);
            self.set_directory(self.cert_offset, new_size)?;
        } else if new_size <= self.cert_size {
            // Overwrite in place and zero the remainder so the offset of any
            // trailing data is unchanged.
            self.data[self.cert_offset..self.cert_offset + new_size].copy_from_slice(table);
            for byte in
                &mut self.data[self.cert_offset + new_size..self.cert_offset + self.cert_size]
            {
                *byte = 0;
            }
        } else {
            return Err(Error::CertificateTableOverflow {
                old: self.cert_size,
                new: new_size,
            });
        }
        Ok(())
    }

    fn set_directory(&mut self, offset: usize, size: usize) -> Result<()> {
        let offset = u32::try_from(offset)
            .map_err(|_| Error::NotPe("certificate table offset exceeds 4 GiB".into()))?;
        let size = u32::try_from(size)
            .map_err(|_| Error::NotPe("certificate table size exceeds 4 GiB".into()))?;
        self.data[self.cert_dir_offset..self.cert_dir_offset + 4]
            .copy_from_slice(&offset.to_le_bytes());
        self.data[self.cert_dir_offset + 4..self.cert_dir_offset + 8]
            .copy_from_slice(&size.to_le_bytes());
        Ok(())
    }
}

fn append_win_certificate(table: &mut Vec<u8>, revision: u16, cert_type: u16, der: &[u8]) {
    let aligned = (8 + der.len()).div_ceil(8) * 8;
    // `dwLength` includes the padding and must be a multiple of 8.
    table.extend_from_slice(&(aligned as u32).to_le_bytes());
    table.extend_from_slice(&revision.to_le_bytes());
    table.extend_from_slice(&cert_type.to_le_bytes());
    table.extend_from_slice(der);
    while !table.len().is_multiple_of(8) {
        table.push(0);
    }
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| Error::NotPe(format!("truncated header at 0x{offset:x}")))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| Error::NotPe(format!("truncated header at 0x{offset:x}")))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}
