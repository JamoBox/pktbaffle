# Changelog

All notable changes to this project are documented here.

## [0.2.0] - 2026-06-15

### Breaking changes

- Internal modules (`lexer`, `parser`, `codegen`) are now sealed — they are no longer accessible from outside the crate. Only the public API surface (`compile`, `ast`, `vm`, error types) remains stable.
- `ast` types are now marked `#[non_exhaustive]`. Match arms must include a wildcard to remain forward-compatible.

### pktbaffle — new features

- **IPv6 network prefix filters** — `net 2001:db8::/32` and similar CIDR expressions now compile correctly.
- **`ip protochain` / `ip6 protochain`** — follow extension-header chains to match an inner protocol.
- **Named protocol keywords after `ip proto` / `ip6 proto`** — e.g. `ip proto tcp` in addition to numeric values.
- **Arithmetic and bitwise operators in byte-access expressions** — `tcp[0] & 0xf0 = 0x60`, `ip[2:2] + 20 > 40`, etc.
- **Arithmetic expressions in byte-access offset positions** — `ip[ip[0]&0xf*4]` and similar computed offsets.
- **`expr`-vs-`expr` byte-access comparisons** — compare two byte-access sub-expressions directly.
- **Raw link-layer byte access without `ether` prefix** — `link[0:6]` as an alias for `ether[0:6]`.
- **Leading-`::` IPv6 addresses in the lexer** — `::1`, `::ffff:192.0.2.1`, and `::` now lex correctly.
- **Classful network shorthand** — `net 10` expands to `net 10.0.0.0/8` as libpcap does.
- **`pppoes` with optional session ID** — `pppoes 100` is now accepted.
- **`ether proto` named keywords** — e.g. `ether proto ip` in addition to hex literals.
- **VLAN inner-protocol filter** — `vlan and ip` correctly shifts ethertype/proto load offsets.

### pktbaffle — fixes and optimisations

- Fixed parser stack overflow triggered by deeply nested expressions (found via fuzzing).
- Fixed `parse_net` integer overflow on malformed CIDR input (found via fuzzing).
- Fixed negative byte-access offsets: they are now rejected at parse time rather than panicking.
- Fixed VLAN inner-protocol codegen: ethertype and protocol load offsets are now shifted correctly.
- Fixed lexer misidentifying all-zero IPv6 segments as a MAC address.
- Fixed digit-first IPv6 address lexing regression introduced in 0.1.
- **cBPF codegen optimiser** — path-fact guard elision, OR guard hoisting, and peephole passes reduce average instruction count.

### pkttap — new features

- No user-visible feature changes in this release; pkttap tracks the pktbaffle 0.2 API.

### pkttap — fixes

- Raised `libc` minimum version floor to `0.2.140` to guarantee `libc::ifreq` availability on all supported platforms.

## [0.1.0] - initial release

First public release of `pktbaffle` (cBPF/eBPF compiler) and `pkttap` (cross-platform packet capture).
