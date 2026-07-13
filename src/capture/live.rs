// SPDX-License-Identifier: MIT

//! Live libpcap-backed [`PacketSource`] implementation.

use pcap::{Active, Capture, Device};

use crate::capture::frame::Frame;
use crate::capture::PacketSource;
use crate::error::{Error, Result};

/// A live capture handle backed by libpcap.
pub struct LivePcapSource {
    handle: Capture<Active>,
}

impl LivePcapSource {
    /// Open a capture handle on the given interface with the given BPF
    /// filter.
    ///
    /// Uses a small read timeout (100 ms) so that the capture loop can
    /// interleave polling with shutdown checks without busy-waiting.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Capture`] on any libpcap failure (open, activation,
    /// or BPF compilation/attachment).
    pub fn open(interface: &str, bpf: &str) -> Result<Self> {
        let device = Device::from(interface);
        let mut handle = Capture::from_device(device)
            .map_err(|e| Error::Capture(e.to_string()))?
            .promisc(false)
            .snaplen(65535)
            .timeout(100)
            .immediate_mode(true)
            .open()
            .map_err(|e| Error::Capture(e.to_string()))?;

        handle
            .filter(bpf, true)
            .map_err(|e| Error::Capture(format!("BPF `{bpf}`: {e}")))?;

        Ok(Self { handle })
    }

    /// Open a live capture on the operating system's default interface.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Capture`] if no default device can be found or if
    /// [`LivePcapSource::open`] fails on the resolved device.
    pub fn open_default(bpf: &str) -> Result<Self> {
        let device = Device::lookup()
            .map_err(|e| Error::Capture(e.to_string()))?
            .ok_or_else(|| Error::Capture("no default network device found".into()))?;
        Self::open(&device.name, bpf)
    }
}

impl PacketSource for LivePcapSource {
    fn next_frame(&mut self) -> Result<Option<Frame>> {
        match self.handle.next_packet() {
            Ok(pkt) => {
                let ts = pkt.header.ts;
                Ok(Some(Frame {
                    timestamp_secs: u64::try_from(ts.tv_sec).unwrap_or(0),
                    timestamp_usecs: u32::try_from(ts.tv_usec).unwrap_or(0),
                    bytes: pkt.data.to_vec(),
                }))
            }
            Err(pcap::Error::TimeoutExpired | pcap::Error::NoMorePackets) => Ok(None),
            Err(e) => Err(Error::Capture(e.to_string())),
        }
    }
}
