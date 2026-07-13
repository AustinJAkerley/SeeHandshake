// SPDX-License-Identifier: MIT

//! Enumeration of local network interfaces.

use crate::error::{Error, Result};

/// A network interface as reported by libpcap.
#[derive(Clone, Debug)]
pub struct Interface {
    /// Interface name (`eth0`, `en0`, `\Device\NPF_{...}`).
    pub name: String,
    /// Human-readable description, if the OS provides one.
    pub description: Option<String>,
}

/// Enumerate available network interfaces.
///
/// # Errors
///
/// Returns [`Error::Capture`] if libpcap fails to enumerate devices (for
/// example, on Linux this can happen when the caller lacks
/// `CAP_NET_RAW`).
pub fn list_interfaces() -> Result<Vec<Interface>> {
    let devices = pcap::Device::list().map_err(|e| Error::Capture(e.to_string()))?;
    Ok(devices
        .into_iter()
        .map(|d| Interface {
            name: d.name,
            description: (!d.desc.as_deref().unwrap_or_default().is_empty())
                .then(|| d.desc.unwrap_or_default()),
        })
        .collect())
}
