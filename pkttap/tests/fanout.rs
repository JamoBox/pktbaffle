//! Tests for `FanoutGroup` (issue #91), Linux only.
//!
//! Real fanout distribution requires a live network interface and elevated
//! privileges (raw `AF_PACKET` sockets), so it cannot run in CI. This file
//! tests the parts of the API reachable without a working capture:
//!   - `into_captures(0)` is rejected before any socket is opened
//!   - Opening on a non-existent interface fails cleanly (not a panic)
//!   - The builder methods compile and chain as documented

#![cfg(target_os = "linux")]

use pkttap::{FanoutGroup, FanoutMode};

#[test]
fn into_captures_zero_is_rejected() {
    let group = FanoutGroup::new("lo", FanoutMode::Hash);
    let result = group.into_captures(0);
    assert!(result.is_err(), "n=0 should be rejected");
}

#[test]
fn missing_interface_returns_error_not_panic() {
    let group = FanoutGroup::new("__pkttap_no_such_iface__", FanoutMode::LoadBalance)
        .promiscuous(true)
        .snaplen(1500)
        .group_id(1234);
    let result = group.into_captures(2);
    assert!(result.is_err());
}

#[test]
fn filter_and_builder_methods_chain() {
    // Exercises the builder surface end-to-end (rejected only because the
    // interface doesn't exist, not because a method call panicked).
    let result = FanoutGroup::new("__pkttap_no_such_iface__", FanoutMode::CpuAffinity)
        .filter("tcp port 443")
        .promiscuous(false)
        .snaplen(65535)
        .into_captures(1);
    assert!(result.is_err());
}
