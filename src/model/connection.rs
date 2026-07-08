// SPDX-License-Identifier: MIT

//! Connection identifiers and per-connection state.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::model::handshake::HandshakeInfo;

/// A canonical four-tuple identifying a TCP flow.
///
/// The key is *canonicalized* so that both directions of the same flow map
/// to the same value. The client endpoint (identified by the presence of the
/// TLS `ClientHello`, or, in its absence, by the numerically smaller
/// `(ip, port)` pair) is stored in the `client_*` fields.
///
/// # Examples
///
/// ```
/// use std::net::{IpAddr, Ipv4Addr};
/// use seehandshake::model::ConnectionKey;
///
/// let a = ConnectionKey::canonical(
///     IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 54321,
///     IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443,
/// );
/// let b = ConnectionKey::canonical(
///     IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443,
///     IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 54321,
/// );
/// assert_eq!(a, b);
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct ConnectionKey {
    /// The client (or lower-endpoint) IP address.
    pub client_ip: IpAddr,
    /// The client (or lower-endpoint) TCP port.
    pub client_port: u16,
    /// The server (or higher-endpoint) IP address.
    pub server_ip: IpAddr,
    /// The server (or higher-endpoint) TCP port.
    pub server_port: u16,
}

impl ConnectionKey {
    /// Build a canonicalized key from an arbitrary observed source and
    /// destination.
    ///
    /// If neither side is a well-known TLS server port (443, 8443), the
    /// endpoint with the numerically smaller `(ip, port)` pair is treated
    /// as the "client" so that both packet directions collapse to the same
    /// key.
    #[must_use]
    pub fn canonical(a_ip: IpAddr, a_port: u16, b_ip: IpAddr, b_port: u16) -> Self {
        let a_is_server = is_tls_server_port(a_port);
        let b_is_server = is_tls_server_port(b_port);

        let (client_ip, client_port, server_ip, server_port) = match (a_is_server, b_is_server) {
            (false, true) => (a_ip, a_port, b_ip, b_port),
            (true, false) => (b_ip, b_port, a_ip, a_port),
            _ => {
                // Ambiguous: neither or both look like server ports. Fall back
                // to lexicographic ordering to guarantee canonicalization.
                if (a_ip, a_port) <= (b_ip, b_port) {
                    (a_ip, a_port, b_ip, b_port)
                } else {
                    (b_ip, b_port, a_ip, a_port)
                }
            }
        };

        Self {
            client_ip,
            client_port,
            server_ip,
            server_port,
        }
    }
}

impl std::fmt::Display for ConnectionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} \u{2192} {}:{}",
            self.client_ip, self.client_port, self.server_ip, self.server_port
        )
    }
}

/// Direction of a packet relative to the canonicalized [`ConnectionKey`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// Client-to-server traffic.
    ClientToServer,
    /// Server-to-client traffic.
    ServerToClient,
}

/// Aggregated per-connection state maintained by the tracker.
#[derive(Clone, Debug, Serialize)]
pub struct ConnectionState {
    /// The canonical identifier.
    pub key: ConnectionKey,
    /// Milliseconds since the Unix epoch at which the connection was first
    /// seen.
    pub first_seen_ms: u64,
    /// Milliseconds since the Unix epoch at which the most recent packet
    /// was observed.
    pub last_seen_ms: u64,
    /// The reconstructed handshake, updated in place as more messages
    /// arrive.
    pub handshake: HandshakeInfo,
}

const TLS_WELL_KNOWN_PORTS: &[u16] = &[443, 8443];

fn is_tls_server_port(port: u16) -> bool {
    TLS_WELL_KNOWN_PORTS.contains(&port)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn canonicalizes_by_well_known_port() {
        let ephem = 54321u16;
        let k1 = ConnectionKey::canonical(v4(10, 0, 0, 1), ephem, v4(1, 1, 1, 1), 443);
        let k2 = ConnectionKey::canonical(v4(1, 1, 1, 1), 443, v4(10, 0, 0, 1), ephem);
        assert_eq!(k1, k2);
        assert_eq!(k1.client_ip, v4(10, 0, 0, 1));
        assert_eq!(k1.server_port, 443);
    }

    #[test]
    fn canonicalizes_by_lexicographic_when_ambiguous() {
        // Neither port is a known TLS server port.
        let k1 = ConnectionKey::canonical(v4(10, 0, 0, 2), 5000, v4(10, 0, 0, 1), 6000);
        let k2 = ConnectionKey::canonical(v4(10, 0, 0, 1), 6000, v4(10, 0, 0, 2), 5000);
        assert_eq!(k1, k2);
        // 10.0.0.1:6000 < 10.0.0.2:5000, so client_ip = .1.
        assert_eq!(k1.client_ip, v4(10, 0, 0, 1));
        assert_eq!(k1.client_port, 6000);
    }

    #[test]
    fn works_across_ipv4_and_ipv6() {
        let k = ConnectionKey::canonical(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            54000,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            443,
        );
        assert_eq!(k.server_port, 443);
    }
}
