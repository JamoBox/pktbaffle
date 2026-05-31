//! Tests that enforce semver compliance for public API changes.
//!
//! `Primitive::Net6` was added (new variant on an exhaustive enum) and
//! `Primitive::PppoeSession` changed from a unit variant to a struct variant.
//! Both are semver-breaking changes that require a version bump to 0.2.0 and
//! the addition of `#[non_exhaustive]` to prevent future additions from being
//! silent breaks.

use pktbaffle::{ast::Primitive, compile, parse, LinkType, Target};

// ── Version must reflect the breaking API changes ─────────────────────────────

/// The two breaking changes introduced since 0.1.0 — `Primitive::Net6` (new
/// exhaustive variant) and `Primitive::PppoeSession` (unit → struct variant) —
/// require the crate version to be at least 0.2.0 per semver convention that
/// 0.x → 0.(x+1) signals a breaking release.
#[test]
fn crate_version_reflects_breaking_changes() {
    let version = env!("CARGO_PKG_VERSION");
    let parts: Vec<u32> = version.split('.').map(|s| s.parse().unwrap_or(0)).collect();
    let (major, minor) = (parts[0], parts[1]);
    assert!(
        major > 0 || minor >= 2,
        "crate version {version} does not reflect the breaking changes introduced \
         since 0.1.0; expected >= 0.2.0 (Primitive::Net6 added, \
         PppoeSession changed from unit to struct variant)"
    );
}

// ── Primitive::PppoeSession struct variant is functional ──────────────────────

/// `pppoes` with no session ID parses to `PppoeSession { session_id: None }`.
#[test]
fn pppoes_no_id_parses_to_none() {
    let expr = parse("pppoes").unwrap();
    match expr {
        pktbaffle::ast::Expr::Primitive(Primitive::PppoeSession { session_id }) => {
            assert_eq!(session_id, None);
        }
        other => panic!("expected PppoeSession{{None}}, got {other:?}"),
    }
}

/// `pppoes 42` parses to `PppoeSession { session_id: Some(42) }`.
#[test]
fn pppoes_with_id_parses_to_some() {
    let expr = parse("pppoes 42").unwrap();
    match expr {
        pktbaffle::ast::Expr::Primitive(Primitive::PppoeSession { session_id }) => {
            assert_eq!(session_id, Some(42));
        }
        other => panic!("expected PppoeSession{{Some(42)}}, got {other:?}"),
    }
}

/// `pppoes 100` produces strictly more BPF instructions than bare `pppoes`
/// because it must also check the session ID field.
#[test]
fn pppoes_with_id_emits_more_insns_than_bare() {
    let bare = compile("pppoes", LinkType::Ethernet, Target::Classic)
        .unwrap()
        .as_classic()
        .unwrap()
        .instructions()
        .len();
    let with_id = compile("pppoes 100", LinkType::Ethernet, Target::Classic)
        .unwrap()
        .as_classic()
        .unwrap()
        .instructions()
        .len();
    assert!(
        with_id > bare,
        "pppoes 100 ({with_id} insns) should be longer than pppoes ({bare} insns)"
    );
}

/// Session IDs at the u16 boundary compile without error.
#[test]
fn pppoes_max_session_id_compiles() {
    compile("pppoes 65535", LinkType::Ethernet, Target::Classic)
        .expect("pppoes 65535 must compile");
}

// ── Primitive::Net6 is functional ────────────────────────────────────────────

/// `net 2001:db8::/32` parses to a `Net6` primitive with the correct address
/// and prefix length.
#[test]
fn net6_parses_correctly() {
    use pktbaffle::ast::{Dir, Expr};
    let expr = parse("net 2001:db8::/32").unwrap();
    match expr {
        Expr::Primitive(Primitive::Net6 { net, dir }) => {
            assert_eq!(
                net.addr,
                "2001:db8::".parse::<std::net::Ipv6Addr>().unwrap()
            );
            assert_eq!(net.prefix_len, 32);
            assert_eq!(dir, Dir::SrcOrDst);
        }
        other => panic!("expected Net6, got {other:?}"),
    }
}

/// `src net <ipv6>/<prefix>` sets direction `Src`.
#[test]
fn net6_src_direction_parses() {
    use pktbaffle::ast::{Dir, Expr};
    let expr = parse("src net 2001:db8::/32").unwrap();
    match expr {
        Expr::Primitive(Primitive::Net6 { dir, .. }) => {
            assert_eq!(dir, Dir::Src);
        }
        other => panic!("expected Net6, got {other:?}"),
    }
}

/// `dst net <ipv6>/<prefix>` sets direction `Dst`.
#[test]
fn net6_dst_direction_parses() {
    use pktbaffle::ast::{Dir, Expr};
    let expr = parse("dst net 2001:db8::/32").unwrap();
    match expr {
        Expr::Primitive(Primitive::Net6 { dir, .. }) => {
            assert_eq!(dir, Dir::Dst);
        }
        other => panic!("expected Net6, got {other:?}"),
    }
}

/// A /128 net6 (single host) compiles to a valid program.
#[test]
fn net6_slash128_compiles() {
    compile("net 2001:db8::1/128", LinkType::Ethernet, Target::Classic)
        .expect("net 2001:db8::1/128 must compile");
}

/// A /0 net6 prefix compiles to a valid program (matches any IPv6 address).
#[test]
fn net6_slash0_compiles() {
    // Note: leading-:: syntax (e.g. "::/0") is a known parser gap (issue #23).
    // Use a non-abbreviated form here; the /0 prefix covers the whole space.
    compile("net 2001:db8::/0", LinkType::Ethernet, Target::Classic)
        .expect("net 2001:db8::/0 must compile");
}

/// Prefix length > 128 is rejected with a parse error.
#[test]
fn net6_out_of_range_prefix_is_error() {
    let result = compile("net 2001:db8::/129", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_err(),
        "prefix /129 should be rejected, got {:?}",
        result.ok()
    );
}
