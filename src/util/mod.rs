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

/// Format `bytes` as space-separated lowercase hex pairs, e.g. `aa bb cc`.
///
/// Intended for short fields displayed in the UI detail view (random,
/// session_id, extension bodies up to a few hundred bytes). No wrapping.
#[must_use]
pub fn hex_inline(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        use std::fmt::Write;
        if i > 0 {
            out.push(' ');
        }
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Format `bytes` as a classic hex dump: `0000: XX XX XX XX  |....|` per
/// `line_width` bytes. Suitable for rendering ciphertext previews and record
/// bodies in the detail view.
///
/// `line_width` clamped to `[1, 64]`.
#[must_use]
pub fn hex_dump(bytes: &[u8], line_width: usize) -> String {
    let width = line_width.clamp(1, 64);
    let mut out = String::new();
    for (row, chunk) in bytes.chunks(width).enumerate() {
        use std::fmt::Write;
        let offset = row * width;
        let _ = write!(out, "{offset:04x}:  ");
        for b in chunk {
            let _ = write!(out, "{b:02x} ");
        }
        // Pad the hex column so ASCII sidebars align across rows.
        for _ in chunk.len()..width {
            out.push_str("   ");
        }
        out.push(' ');
        out.push('|');
        for b in chunk {
            if (0x20..0x7f).contains(b) {
                out.push(*b as char);
            } else {
                out.push('.');
            }
        }
        out.push('|');
        out.push('\n');
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

    #[test]
    fn hex_inline_spaces_pairs() {
        assert_eq!(hex_inline(&[0xaa, 0xbb, 0xcc]), "aa bb cc");
    }

    #[test]
    fn hex_dump_renders_offset_and_ascii() {
        let dump = hex_dump(b"hello!", 16);
        assert!(dump.starts_with("0000:"));
        assert!(dump.contains("|hello!|"));
    }

    #[test]
    fn hex_dump_wraps_at_line_width() {
        let dump = hex_dump(&[0u8; 32], 16);
        // Two rows: 0x0000 and 0x0010.
        assert!(dump.contains("0000:"));
        assert!(dump.contains("0010:"));
    }
}
