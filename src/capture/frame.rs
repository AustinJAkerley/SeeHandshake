// SPDX-License-Identifier: MIT

//! Owned link-layer frames and helpers for extracting TCP payloads.

use std::net::IpAddr;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};

/// An owned copy of a captured link-layer frame.
///
/// The capture backend hands ownership of the bytes to downstream stages
/// so that the parser thread does not have to hold onto pcap-managed
/// buffers.
#[derive(Clone, Debug)]
pub struct Frame {
    /// Wall-clock timestamp when the frame was captured (seconds since the
    /// Unix epoch).
    pub timestamp_secs: u64,
    /// Microseconds within [`Self::timestamp_secs`].
    pub timestamp_usecs: u32,
    /// Raw frame bytes, starting at the Ethernet header (or link-layer
    /// equivalent).
    pub bytes: Vec<u8>,
}

/// A decoded TCP segment: five-tuple plus payload.
#[derive(Clone, Debug)]
pub struct TcpSegment<'a> {
    /// Source IP address.
    pub src_ip: IpAddr,
    /// Destination IP address.
    pub dst_ip: IpAddr,
    /// Source TCP port.
    pub src_port: u16,
    /// Destination TCP port.
    pub dst_port: u16,
    /// TCP payload (may be empty).
    pub payload: &'a [u8],
}

/// Extract the TCP five-tuple and payload from a link-layer frame.
///
/// Returns `None` if the frame is not TCP-over-IPv4 or TCP-over-IPv6, or if
/// parsing fails at any layer. Malformed frames are silently dropped;
/// downstream stages never see them.
#[must_use]
pub fn extract_tcp(frame_bytes: &[u8]) -> Option<TcpSegment<'_>> {
    let sliced = SlicedPacket::from_ethernet(frame_bytes).ok()?;

    let (src_ip, dst_ip) = match sliced.net.as_ref()? {
        NetSlice::Ipv4(ipv4) => {
            let hdr = ipv4.header();
            (
                IpAddr::V4(hdr.source_addr()),
                IpAddr::V4(hdr.destination_addr()),
            )
        }
        NetSlice::Ipv6(ipv6) => {
            let hdr = ipv6.header();
            (
                IpAddr::V6(hdr.source_addr()),
                IpAddr::V6(hdr.destination_addr()),
            )
        }
        NetSlice::Arp(_) => return None,
    };

    let TransportSlice::Tcp(tcp) = sliced.transport? else {
        return None;
    };

    let payload = tcp.payload();

    Some(TcpSegment {
        src_ip,
        dst_ip,
        src_port: tcp.source_port(),
        dst_port: tcp.destination_port(),
        payload,
    })
}
