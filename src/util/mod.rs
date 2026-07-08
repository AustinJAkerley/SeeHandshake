// SPDX-License-Identifier: MIT

//! Small shared helpers used across the crate.

/// Format a byte slice as lowercase hex, useful for diagnostic logging of
/// short handshake fields.
///
/// Not intended for large buffers.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encodes_expected() {
        assert_eq!(hex(&[0x00, 0xff, 0xa5]), "00ffa5");
    }

    #[test]
    fn hex_of_empty_is_empty() {
        assert_eq!(hex(&[]), "");
    }
}
