# Changelog

All notable changes to **pktbaffle** are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **`and` / `or` precedence now matches libpcap** (#128). The parser gave `and`
  higher precedence than `or`; libpcap (`%left OR AND`, pcap-filter(7)) gives
  `and`, `or` and juxtaposition *equal* precedence, left-associative. This is a
  **behaviour change** for unparenthesised filters where an `or` is followed
  later by an `and`: `port 22 or port 80 and host 10.0.0.1` is now
  `(port 22 or port 80) and host 10.0.0.1` (previously
  `port 22 or (port 80 and host 10.0.0.1)`), in both the cBPF and eBPF
  backends. `a and b or c` and `not` binding are unchanged. Add parentheses
  to keep the old grouping.
- **eBPF backend**: 16- and 32-bit packet fields were loaded with a plain
  `LDX MEM` and compared in host byte order against network-order constants, so
  on little-endian hosts (x86_64, arm64) nearly every filter (`tcp`, `ip`,
  `host`, `port`, `vlan`, `ip[2:2] = 40`, ...) never matched. Every multi-byte
  packet load is now followed by `BPF_END` (`be16` / `be32`), which makes the
  program correct on both endiannesses and keeps ordered comparisons and
  arithmetic working. (#129)
- **Parser no longer panics on overflowing byte-access offsets** (#134).
  `ip[(1<<63)/-1]` (`i64::MIN / -1`) aborted `compile()` / `parse()` with
  "attempt to divide with overflow", and `ip[1<<63]` was silently compiled as
  `ip[0]`. Division and `<<` inside `[...]` are now overflow-checked, and an
  offset outside `i32` is rejected instead of truncated; all of these return
  `Err(ParseError)`. In-range offset expressions are unchanged.
- **Parser no longer overflows the stack on deeply nested byte-access
  offsets** (#135). `(` and unary `-` inside `[...]` (`ip[((((...1))))]`,
  `ip[-----...1]`) recursed without a limit, so a few KB of filter text
  aborted the process with an uncatchable stack overflow. Offset nesting now
  draws on the same depth budget as parenthesised expressions and returns
  `Err(ParseError)` past 31 nested `(` (or 127 chained unary `-`); libpcap
  accepts thousands (#199 tracks raising limits). Shallower nesting is
  unchanged. Chains of `not` / `!` are not covered by this fix.
- **No stack overflow on long `and` / `or` / `not` chains** (#149).
  `a or b or ...`, `a and b and ...` and `!!!...x` build an AST one level
  deep per term, and dropping it, emitting cBPF or eBPF, and (for `!`)
  parsing it recursed per term: a few hundred terms aborted a debug build on
  a 1 MiB stack, a few thousand a release build. The parser, both code
  generators and `Drop for ast::Expr` are now iterative, so `compile()` and
  `parse()` return `Ok` or `Err` at any chain length (a 1000-host
  `host a or host b ...` list compiles for `Target::Extended`, as in libpcap).
  Generated code is unchanged. `ast::Expr` now implements `Drop`, so its
  fields can no longer be moved out by destructuring a value (match on a
  reference instead).
- **Up to 9995 nested parentheses are accepted, as in libpcap** (#199). The
  parser rejected 128 or more nested parentheses (with a message that said
  "max 128 levels"), and the old limit itself could overflow a 256 KiB stack
  in a debug build. Parentheses are now parsed with an explicit stack instead
  of recursion, and the limit matches libpcap 1.10.3, which accepts 9995
  around a primitive and rejects 9996; past it, `Err(ParseError)` names the
  limit. Offset expressions inside `[...]` keep their own unchanged limits
  (31 nested `(`, 127 unary `-`), now independent of the surrounding
  parentheses.

### Added

- `ebpf::Insn::be16` / `Insn::be32` constructors and the `BPF_END`, `BPF_TO_LE`
  and `BPF_TO_BE` opcode constants.
- Execution-based tests for the eBPF backend: a test-only reference interpreter
  (selectable host endianness) and a parity table checking eBPF verdicts
  against the cBPF VM. No change to the crate's dependencies. (#219)

## [0.2.0] - 2026-07-30

### Changed (breaking)

- Internal modules (`lexer`, `parser`, `codegen`) are now sealed — they are no
  longer accessible from outside the crate. Only the public API surface
  (`compile`, `ast`, `vm`, error types) remains stable.
- `ast` types are now marked `#[non_exhaustive]`. Match arms must include a
  wildcard to remain forward-compatible.

### Added

- **IPv6 network prefix filters** — `net 2001:db8::/32` and similar CIDR
  expressions now compile correctly.
- **`ip protochain` / `ip6 protochain`** — follow extension-header chains to
  match an inner protocol.
- **Named protocol keywords after `ip proto` / `ip6 proto`** — e.g.
  `ip proto tcp` in addition to numeric values.
- **Arithmetic and bitwise operators in byte-access expressions** —
  `tcp[0] & 0xf0 = 0x60`, `ip[2:2] + 20 > 40`, etc.
- **Arithmetic expressions in byte-access offset positions** —
  `ip[ip[0]&0xf*4]` and similar computed offsets.
- **`expr`-vs-`expr` byte-access comparisons** — compare two byte-access
  sub-expressions directly.
- **Raw link-layer byte access without `ether` prefix** — `link[0:6]` as an
  alias for `ether[0:6]`.
- **Leading-`::` IPv6 addresses in the lexer** — `::1`, `::ffff:192.0.2.1`,
  and `::` now lex correctly.
- **Classful network shorthand** — `net 10` expands to `net 10.0.0.0/8` as
  libpcap does.
- **`pppoes` with optional session ID** — `pppoes 100` is now accepted.
- **`ether proto` named keywords** — e.g. `ether proto ip` in addition to hex
  literals.
- **VLAN inner-protocol filter** — `vlan and ip` correctly shifts
  ethertype/proto load offsets.

### Fixed

- Parser stack overflow triggered by deeply nested expressions (found via
  fuzzing).
- `parse_net` integer overflow on malformed CIDR input (found via fuzzing).
- Negative byte-access offsets are now rejected at parse time rather than
  panicking.
- VLAN inner-protocol codegen: ethertype and protocol load offsets are now
  shifted correctly.
- Lexer misidentifying all-zero IPv6 segments as a MAC address.
- Digit-first IPv6 address lexing regression introduced in 0.1.
- **`vm` interpreter**: out-of-range `M[]` scratch accesses now abort the
  program (drop the packet) instead of silently reading 0 / no-opping the
  store, matching the existing behavior for out-of-range packet loads.
  Sized-load offset arithmetic is now guarded with `checked_add` so a crafted
  offset can't overflow.

### Performance

- **cBPF codegen optimiser** — path-fact guard elision, OR guard hoisting,
  and peephole passes reduce average instruction count.
- **VM dispatch** — instruction dispatch (class, ALU op, JMP op, sized-load
  size) now goes through `match` statements instead of if/else-if chains,
  letting the compiler lower it to a jump table on the interpreter's hot
  path.

## [0.1.0] - initial release

First public release of `pktbaffle` (cBPF/eBPF compiler).
