// SPDX-License-Identifier: MIT

//! TLS-level enumerations used across the crate.
//!
//! Values are stored as their IANA-registered numeric codes so that unknown
//! codes round-trip cleanly. Human-readable rendering is provided via
//! [`std::fmt::Display`] implementations that fall back to `Unknown(0x1234)`
//! for unregistered codepoints.

use serde::{Deserialize, Serialize};

/// Wire-format TLS version identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TlsVersion {
    /// SSL 3.0 (`0x0300`). Deprecated; included for completeness.
    Ssl30,
    /// TLS 1.0 (`0x0301`).
    Tls10,
    /// TLS 1.1 (`0x0302`).
    Tls11,
    /// TLS 1.2 (`0x0303`).
    Tls12,
    /// TLS 1.3 (`0x0304`).
    Tls13,
    /// Any other version identifier observed on the wire.
    Other(u16),
}

impl TlsVersion {
    /// Decode a two-byte wire value.
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        match v {
            0x0300 => Self::Ssl30,
            0x0301 => Self::Tls10,
            0x0302 => Self::Tls11,
            0x0303 => Self::Tls12,
            0x0304 => Self::Tls13,
            other => Self::Other(other),
        }
    }
}

impl std::fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsVersion::Ssl30 => f.write_str("SSL 3.0"),
            TlsVersion::Tls10 => f.write_str("TLS 1.0"),
            TlsVersion::Tls11 => f.write_str("TLS 1.1"),
            TlsVersion::Tls12 => f.write_str("TLS 1.2"),
            TlsVersion::Tls13 => f.write_str("TLS 1.3"),
            TlsVersion::Other(v) => write!(f, "Unknown(0x{v:04x})"),
        }
    }
}

/// IANA cipher-suite identifier.
///
/// Both the TLS 1.3 MTI suites and the most common TLS 1.2 AEAD suites are
/// named. Any other value is preserved in [`CipherSuite::Other`] and rendered
/// with its hex code.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CipherSuite {
    /// `TLS_AES_128_GCM_SHA256` (`0x1301`).
    Aes128GcmSha256,
    /// `TLS_AES_256_GCM_SHA384` (`0x1302`).
    Aes256GcmSha384,
    /// `TLS_CHACHA20_POLY1305_SHA256` (`0x1303`).
    Chacha20Poly1305Sha256,
    /// `TLS_AES_128_CCM_SHA256` (`0x1304`).
    Aes128CcmSha256,
    /// `TLS_AES_128_CCM_8_SHA256` (`0x1305`).
    Aes128Ccm8Sha256,
    /// `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (`0xc02b`).
    EcdheEcdsaAes128GcmSha256,
    /// `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` (`0xc02c`).
    EcdheEcdsaAes256GcmSha384,
    /// `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (`0xc02f`).
    EcdheRsaAes128GcmSha256,
    /// `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` (`0xc030`).
    EcdheRsaAes256GcmSha384,
    /// `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256` (`0xcca9`).
    EcdheEcdsaChacha20Poly1305Sha256,
    /// `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256` (`0xcca8`).
    EcdheRsaChacha20Poly1305Sha256,
    /// `TLS_RSA_WITH_AES_128_GCM_SHA256` (`0x009c`).
    RsaAes128GcmSha256,
    /// `TLS_RSA_WITH_AES_256_GCM_SHA384` (`0x009d`).
    RsaAes256GcmSha384,
    /// Any other cipher suite observed on the wire.
    Other(u16),
}

impl CipherSuite {
    /// Decode a two-byte wire value.
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        match v {
            0x1301 => Self::Aes128GcmSha256,
            0x1302 => Self::Aes256GcmSha384,
            0x1303 => Self::Chacha20Poly1305Sha256,
            0x1304 => Self::Aes128CcmSha256,
            0x1305 => Self::Aes128Ccm8Sha256,
            0xc02b => Self::EcdheEcdsaAes128GcmSha256,
            0xc02c => Self::EcdheEcdsaAes256GcmSha384,
            0xc02f => Self::EcdheRsaAes128GcmSha256,
            0xc030 => Self::EcdheRsaAes256GcmSha384,
            0xcca9 => Self::EcdheEcdsaChacha20Poly1305Sha256,
            0xcca8 => Self::EcdheRsaChacha20Poly1305Sha256,
            0x009c => Self::RsaAes128GcmSha256,
            0x009d => Self::RsaAes256GcmSha384,
            other => Self::Other(other),
        }
    }
}

impl std::fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CipherSuite::Aes128GcmSha256 => f.write_str("TLS_AES_128_GCM_SHA256"),
            CipherSuite::Aes256GcmSha384 => f.write_str("TLS_AES_256_GCM_SHA384"),
            CipherSuite::Chacha20Poly1305Sha256 => f.write_str("TLS_CHACHA20_POLY1305_SHA256"),
            CipherSuite::Aes128CcmSha256 => f.write_str("TLS_AES_128_CCM_SHA256"),
            CipherSuite::Aes128Ccm8Sha256 => f.write_str("TLS_AES_128_CCM_8_SHA256"),
            CipherSuite::EcdheEcdsaAes128GcmSha256 => {
                f.write_str("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")
            }
            CipherSuite::EcdheEcdsaAes256GcmSha384 => {
                f.write_str("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")
            }
            CipherSuite::EcdheRsaAes128GcmSha256 => {
                f.write_str("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
            }
            CipherSuite::EcdheRsaAes256GcmSha384 => {
                f.write_str("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
            }
            CipherSuite::EcdheEcdsaChacha20Poly1305Sha256 => {
                f.write_str("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256")
            }
            CipherSuite::EcdheRsaChacha20Poly1305Sha256 => {
                f.write_str("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256")
            }
            CipherSuite::RsaAes128GcmSha256 => f.write_str("TLS_RSA_WITH_AES_128_GCM_SHA256"),
            CipherSuite::RsaAes256GcmSha384 => f.write_str("TLS_RSA_WITH_AES_256_GCM_SHA384"),
            CipherSuite::Other(v) => write!(f, "Unknown(0x{v:04x})"),
        }
    }
}

/// IANA `NamedGroup` (curve / DH group) identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum NamedGroup {
    /// `secp256r1` / P-256 (`0x0017`).
    Secp256r1,
    /// `secp384r1` / P-384 (`0x0018`).
    Secp384r1,
    /// `secp521r1` / P-521 (`0x0019`).
    Secp521r1,
    /// `x25519` (`0x001d`).
    X25519,
    /// `x448` (`0x001e`).
    X448,
    /// `ffdhe2048` (`0x0100`).
    Ffdhe2048,
    /// `ffdhe3072` (`0x0101`).
    Ffdhe3072,
    /// `ffdhe4096` (`0x0102`).
    Ffdhe4096,
    /// `x25519_kyber768_draft00` hybrid (`0x6399`).
    X25519Kyber768Draft00,
    /// `X25519MLKEM768` post-quantum hybrid (`0x11ec`).
    X25519MlKem768,
    /// `SecP256r1MLKEM768` post-quantum hybrid (`0x11eb`).
    SecP256r1MlKem768,
    /// Any other group observed on the wire.
    Other(u16),
}

impl NamedGroup {
    /// Decode a two-byte wire value.
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        match v {
            0x0017 => Self::Secp256r1,
            0x0018 => Self::Secp384r1,
            0x0019 => Self::Secp521r1,
            0x001d => Self::X25519,
            0x001e => Self::X448,
            0x0100 => Self::Ffdhe2048,
            0x0101 => Self::Ffdhe3072,
            0x0102 => Self::Ffdhe4096,
            0x6399 => Self::X25519Kyber768Draft00,
            0x11ec => Self::X25519MlKem768,
            0x11eb => Self::SecP256r1MlKem768,
            other => Self::Other(other),
        }
    }
}

impl std::fmt::Display for NamedGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NamedGroup::Secp256r1 => f.write_str("secp256r1"),
            NamedGroup::Secp384r1 => f.write_str("secp384r1"),
            NamedGroup::Secp521r1 => f.write_str("secp521r1"),
            NamedGroup::X25519 => f.write_str("x25519"),
            NamedGroup::X448 => f.write_str("x448"),
            NamedGroup::Ffdhe2048 => f.write_str("ffdhe2048"),
            NamedGroup::Ffdhe3072 => f.write_str("ffdhe3072"),
            NamedGroup::Ffdhe4096 => f.write_str("ffdhe4096"),
            NamedGroup::X25519Kyber768Draft00 => f.write_str("x25519_kyber768_draft00"),
            NamedGroup::X25519MlKem768 => f.write_str("X25519MLKEM768"),
            NamedGroup::SecP256r1MlKem768 => f.write_str("SecP256r1MLKEM768"),
            NamedGroup::Other(v) => write!(f, "Unknown(0x{v:04x})"),
        }
    }
}

/// Application-Layer Protocol Negotiation identifier.
///
/// Stored as the raw ALPN token (an octet string, at most 255 bytes long
/// per [RFC 7301]). We do not restrict this to a fixed set because ALPN is
/// extensible and new protocol identifiers appear regularly.
///
/// [RFC 7301]: https://www.rfc-editor.org/rfc/rfc7301
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AlpnProtocol(pub String);

impl AlpnProtocol {
    /// Construct from raw bytes, replacing non-UTF-8 sequences with the
    /// Unicode replacement character.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(String::from_utf8_lossy(bytes).into_owned())
    }
}

impl std::fmt::Display for AlpnProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_version_round_trips_named_values() {
        assert_eq!(TlsVersion::from_u16(0x0304), TlsVersion::Tls13);
        assert_eq!(TlsVersion::Tls13.to_string(), "TLS 1.3");
    }

    #[test]
    fn tls_version_preserves_unknown() {
        assert_eq!(TlsVersion::from_u16(0x7f1c), TlsVersion::Other(0x7f1c));
        assert_eq!(TlsVersion::from_u16(0x7f1c).to_string(), "Unknown(0x7f1c)");
    }

    #[test]
    fn cipher_suite_names_tls13_mtis() {
        assert_eq!(CipherSuite::from_u16(0x1301), CipherSuite::Aes128GcmSha256);
        assert_eq!(
            CipherSuite::Chacha20Poly1305Sha256.to_string(),
            "TLS_CHACHA20_POLY1305_SHA256"
        );
    }

    #[test]
    fn named_group_recognizes_x25519() {
        assert_eq!(NamedGroup::from_u16(0x001d), NamedGroup::X25519);
    }

    #[test]
    fn alpn_from_bytes_lossy() {
        assert_eq!(AlpnProtocol::from_bytes(b"h2").to_string(), "h2");
    }
}
