// SPDX-License-Identifier: MIT

//! TLS record-layer framing.
//!
//! A TLS record has a five-byte header (`type: u8`, `version: u16`, `length:
//! u16`) followed by up to `2^14` bytes of payload. [`parse_records`] peels
//! complete records off the front of a byte slice and returns them along
//! with the number of bytes consumed. The caller is expected to retain any
//! trailing bytes for the next call — this is how we handle TLS records that
//! span multiple TCP segments.

use crate::error::{Error, Result};

/// A single TLS record header value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum TlsRecordType {
    /// `change_cipher_spec` (`20`).
    ChangeCipherSpec,
    /// `alert` (`21`).
    Alert,
    /// `handshake` (`22`).
    Handshake,
    /// `application_data` (`23`).
    ApplicationData,
    /// Any other record type observed on the wire.
    Other(u8),
}

impl TlsRecordType {
    /// Decode the one-byte wire value.
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            20 => Self::ChangeCipherSpec,
            21 => Self::Alert,
            22 => Self::Handshake,
            23 => Self::ApplicationData,
            other => Self::Other(other),
        }
    }
}

/// A borrowed view of a single TLS record.
#[derive(Clone, Copy, Debug)]
pub struct TlsRecord<'a> {
    /// The record type from the header byte.
    pub record_type: TlsRecordType,
    /// The legacy `TLSPlaintext.legacy_record_version` field (typically
    /// `0x0303` for TLS 1.2/1.3 records).
    pub legacy_version: u16,
    /// The record payload (already length-bounded by the record header).
    pub payload: &'a [u8],
}

/// Maximum TLS record payload length permitted by RFC 8446 (`2^14 = 16384`).
pub const MAX_RECORD_PAYLOAD: usize = 16_384;

/// Header length of a `TLSPlaintext` record (type + version + length).
pub const RECORD_HEADER_LEN: usize = 5;

/// Parse as many complete TLS records from `buf` as possible.
///
/// Returns the vector of records and the number of bytes consumed. Any
/// trailing bytes (an incomplete final record) are left in `buf` for the
/// caller to prepend to the next batch.
///
/// # Errors
///
/// Returns [`Error::Parse`] if a record header advertises a payload larger
/// than [`MAX_RECORD_PAYLOAD`]. Truncated records at the end of the buffer
/// are *not* an error — they simply do not appear in the returned vector.
pub fn parse_records(buf: &[u8]) -> Result<(Vec<TlsRecord<'_>>, usize)> {
    let mut records = Vec::new();
    let mut cursor = 0;

    while buf.len() - cursor >= RECORD_HEADER_LEN {
        let header = &buf[cursor..cursor + RECORD_HEADER_LEN];
        let record_type = TlsRecordType::from_u8(header[0]);
        let legacy_version = u16::from_be_bytes([header[1], header[2]]);
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));

        if length > MAX_RECORD_PAYLOAD {
            return Err(Error::Parse(format!(
                "record payload length {length} exceeds maximum {MAX_RECORD_PAYLOAD}"
            )));
        }

        let record_end = cursor + RECORD_HEADER_LEN + length;
        if record_end > buf.len() {
            // Incomplete record; leave it for the next call.
            break;
        }

        records.push(TlsRecord {
            record_type,
            legacy_version,
            payload: &buf[cursor + RECORD_HEADER_LEN..record_end],
        });

        cursor = record_end;
    }

    Ok((records, cursor))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![kind, 0x03, 0x03];
        out.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn returns_empty_on_empty_input() {
        let (records, consumed) = parse_records(&[]).unwrap();
        assert!(records.is_empty());
        assert_eq!(consumed, 0);
    }

    #[test]
    fn parses_single_record() {
        let bytes = record(22, &[0xaa, 0xbb, 0xcc]);
        let (records, consumed) = parse_records(&bytes).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record_type, TlsRecordType::Handshake);
        assert_eq!(records[0].payload, &[0xaa, 0xbb, 0xcc]);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn leaves_incomplete_trailer() {
        let mut bytes = record(23, &[1, 2, 3, 4]);
        // Append a truncated header (only 3 bytes of the next 5-byte header).
        bytes.extend_from_slice(&[22, 0x03, 0x03]);
        let (records, consumed) = parse_records(&bytes).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(consumed, 9);
    }

    #[test]
    fn leaves_incomplete_payload() {
        let mut bytes = record(23, &[1, 2, 3, 4]);
        // Advertise a 10-byte record but only provide 2 payload bytes.
        bytes.extend_from_slice(&[22, 0x03, 0x03, 0x00, 0x0a, 0xff, 0xff]);
        let (records, consumed) = parse_records(&bytes).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(consumed, 9);
    }

    #[test]
    fn rejects_oversize_record() {
        let bytes = [22, 0x03, 0x03, 0xff, 0xff];
        let err = parse_records(&bytes).unwrap_err();
        assert!(matches!(err, Error::Parse(_)));
    }

    #[test]
    fn never_panics_on_random_input() {
        // A tiny smoke test; the fuzz-lite pass lives in tests/parser_integration.rs.
        for len in 0u16..64 {
            let bytes: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i & 0xff).unwrap_or(0))
                .collect();
            let _ = parse_records(&bytes);
        }
    }
}
