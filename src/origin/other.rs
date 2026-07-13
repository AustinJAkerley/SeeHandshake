// SPDX-License-Identifier: MIT

//! No-op origin resolver used on operating systems where socket-to-process
//! lookup is not implemented.

use std::net::SocketAddr;

use crate::origin::{Origin, OriginResolver};

/// Resolver that always returns [`Origin::Unsupported`].
pub struct NullOriginResolver;

impl OriginResolver for NullOriginResolver {
    fn resolve(&mut self, _a: SocketAddr, _b: SocketAddr) -> Origin {
        Origin::Unsupported
    }
}
