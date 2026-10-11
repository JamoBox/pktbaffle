//! Helpers shared between integration-test crates. Each test file pulls in the
//! whole module, so not every item is used by every crate.
#![allow(dead_code)]

pub mod ebpf_interp;
pub mod packets;
