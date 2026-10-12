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
- **Compile time is linear in the length of `and` / `or` / `not` chains**
  (#202). Several codegen steps re-walked or re-copied everything before
  them: cBPF recomputed guard sets at every `or` and rescanned for a leading
  `vlan` at every `and`, both backends copied the accumulated failure list at
  every `and`, and jump threading chased every `ja` trampoline chain to its
  end. A 32000-term `tcp or ...` took 8.6 s (release) and a 32000-term
  `tcp and ...` 2.4 s; they now take about 18 ms and 9 ms, and
  `optimizer::optimize` on 64004 chained `ja`s about 1 ms instead of 1.5 s.
  Generated code is unchanged.
- **`ast::Expr` clones, compares and debug-prints long chains without
  overflowing the stack** (#229). The derived `Clone`, `PartialEq` and `Debug`
  recursed once per tree level, so `expr.clone()`, `expr == other` or
  `{:?}` on a parsed 1,000-term `or` chain aborted a 256 KiB stack and
  100,000 terms a 2 MiB one. `Clone` and `==` now use an explicit stack and
  behave exactly as before at any depth. `Debug` output is unchanged (`{:?}`
  and `{:#?}`) for trees up to 128 levels deep; anything nested deeper is
  printed as `..`, so a million-term chain formats to a short string.
- **Integer literals follow C syntax, as in libpcap** (#157). A leading `0`
  now makes a literal octal: `tcp port 010` is port 8, `ip[010]` is `ip[8]`,
  `ip proto 017` is protocol 15, `vlan 010` is VLAN 8, `ether proto 0100` is
  0x40, `len = 0100` is 64 and `net 10.0.0.0/010` is a /8 (all were read as
  decimal, so they compiled but matched different packets). A leading-zero
  literal with an 8 or 9 (`tcp port 08`, `ether proto 0800`, `vlan 08`) is now
  an error, as in libpcap ("number 08 contains non-octal digit"); write
  `0x0800`. `0` and `00` are still 0, and `/0x8` is now accepted as a prefix
  length (it was rejected). **Behaviour change** for filters that relied on
  zero-padded numbers being decimal. A literal over 32 bits is rejected at
  lex time with a `ParseError` naming it (as libpcap's "overflows 32 bits");
  a malformed number (`0x`, `12abc`) now reports the same way instead of as
  an `unexpected character` `LexError` (#210 tracks the rest of the
  diagnostics).
- **Dotted IPv4 literals accept zero-padded octets** (#191). `host 010.1.2.3`,
  `host 1.2.3.04`, `host 192.168.001.001`, `net 010.0.0.0/8` and
  `net 10.0.0.0 mask 255.255.255.000` failed with `unexpected character` at
  the start of the token (the 1-3 octet forms already worked). Each octet is
  decimal with leading zeros allowed, as in libpcap (`010` is 10, not octal),
  for any number of octets. A bad octet (`10.256.0.1`, `1.2.3.4.5`) is now a
  `ParseError` naming the literal ("invalid IPv4 address '10.256.0.1' at
  offset 5") instead of a `LexError` quoting its first digit.
- **`/` before a prefix length is an ordinary token, so spacing, hex and
  `::` networks work** (#194, #173). The lexer glued `/<decimal digits>` onto
  a preceding IPv4 or IPv6 literal, except after an address starting with
  `::`, and the parser took any number after an address as the prefix. Now
  `/` is always lexed on its own and `parse_net` reads `/` followed by an
  ordinary integer. Accepted, as in libpcap: `net 10.0.0.0 / 8`,
  `net 10.0.0.0 /8`, `net 10.0.0.0/ 8`, `net 10.0.0.0/0x8`,
  `net 2001:db8:: /32`, and every network written with a leading `::`
  (`net ::/0`, `net ::1/128`, `net ::ffff:0:0/96`, `ip6 net ::/32`,
  `src net ::1/128`; these failed with "IPv6 net requires a CIDR prefix
  length"). `host ::1/128` is accepted as a /128 (any other length after
  `host`, or an IPv4 `host x/len`, is an error, as in libpcap). **Behaviour
  change:** a number with no `/` after an address, which was read as a
  prefix length (`net 10.0.0.0 8`, `net 10 8`, `src net 192.168.1.0 24 and
  port 80`), and `net 10 mask 255.0.0.0`, are now errors (libpcap: syntax
  error). A missing or non-numeric length (`net 10.0.0.0/`) is a
  `ParseError` instead of a `LexError` with a misleading offset.
- **Errors for malformed numbers and prefix lengths point at the problem**
  (#210). `net 10.0.0.0/` and `net 10.0.0.0/abc` reported
  `unexpected character '/' at offset 13` (one past the `/`, and past the end
  of the input for a trailing `/`); `port 12abc`, `host 10.0.0.256`,
  `ip[0x]=1` and `port 99999999999999999999` reported their first digit (or a
  hard-coded `'0'`) as "unexpected". With #157, #191 and #194 these are now a
  `ParseError` naming the literal and its offset ("invalid number '12abc' at
  offset 5", "invalid IPv4 address '10.0.0.256' at offset 5", "expected a
  prefix length after '/' at offset 12"), and every remaining `LexError`
  satisfies `filter[offset..].starts_with(ch)`. A literal over 32 bits is the
  same kind of error whether it fits in 64 bits (`greater 4294967296`) or not.
  Code matching `Error::LexError` for these inputs must also match
  `Error::ParseError`; the rejected set is unchanged.
- **A bare integer is an IPv4 host or net** (#190). `host 10` and
  `net 256` were rejected, and `net 0` was a /8. Now, as in libpcap, `host N`
  (also `src host`, `dst host`, `src N`, `ip host`, `host 0x0a000001`) is the
  exact address N (`host 10` is 0.0.0.10), and `net N` shifts N and an
  all-ones mask left a byte at a time until the top byte is non-zero:
  `net 256` is 1.0.0.0/16, `net 300` 1.44.0.0/16, `net 65536` 1.0.0.0/24,
  `net 16777216` 1.0.0.0/32. `net 1` to `net 255` are still /8.
  **Behaviour change:** `net 0` is now 0.0.0.0/32 (an exact address, as in
  libpcap) instead of 0.0.0.0/8. Values above 32 bits are still rejected.
  (`host`/`net` programs still omit libpcap's ARP/RARP legs, see #140.)
- **Dotted IPv4 `host` / `net` take their mask from the octets written, as
  libpcap** (#158). The lexer zero-padded `10.0` and `10.0.0` and forgot how
  many octets there were, so `net` guessed the prefix from trailing zero
  octets (`net 10.0.0.0` was /8, `net 192.168.1.0` /24, `net 10.0` /8) and
  `host 10.1` was the exact host 10.1.0.0. Now the mask is 8 bits per octet
  written: `net 10.0.0.0` and `net 192.168.1.0` match only that address,
  `net 10.0` is /16, `net 10.0.0` and `net 10.1.0` are /24, and `host 10.1` /
  `host 10.1.2` match the /16 / /24 they start. `net 10`, `net 192.168`,
  `net 10.0.1` and explicit `/len` or `mask` are unchanged. **Behaviour
  change:** filters that relied on `net a.b.c.0` meaning the whole /24 (or
  `a.0.0.0` the /8) now match one address; write the prefix. A bare short
  address with no `host` or `net` (`10.1`) is now an error instead of the
  host 10.1.0.0. (An unqualified full address such as `10.0.0.1` is still
  taken as `host`.)

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
