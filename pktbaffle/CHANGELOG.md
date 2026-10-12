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
- **`ast::IpNet::from_prefix` no longer panics or wraps for a prefix length
  above 32** (#187). `from_prefix(addr, 33)` (or 64, 255, ...) panicked with
  "attempt to subtract with overflow" in debug builds and returned a wrong
  mask in release builds (33 gave `0x80000000`), which `compile()` accepted
  silently. The signature is unchanged, so out-of-range lengths are now
  **clamped to /32** (mask `0xffff_ffff`) and documented as such; 0-32 are
  unchanged. `net 10.0.0.0/33` in a filter string is still a parse error, as
  in libpcap 1.10.3.
- **`vm::run` no longer hangs on 32-bit targets for a `ja` with a huge `k`**
  (#188). The jump target was computed with `wrapping_add`, so on i686 /
  armv7 / wasm32 `ja 0xFFFFFFFF` jumped to itself and `[ld #1, ja 0xFFFFFFFE,
  ret]` looped back to the start, and the call never returned (64-bit targets
  returned `false`). A target that overflows `usize`, or lies past the end of
  the program, now makes the VM return `false` on every pointer width.
  Programs from `compile()` are unaffected.
- **The VM returns `false` for malformed cBPF opcodes instead of running them
  as valid ones** (#201). `vm::run` / `Program::matches` documented `false`
  for an invalid instruction but decoded opcodes by masking bit fields, so
  `RET|X` (`0x0e`) returned `k`, MISC `0xff` ran as `txa`, `LD|H|LEN`,
  `LD|B|IMM`, `ST` with stray bits, `NEG|X` and `LDX|H|IMM` all executed, and
  `matches` returned `true`. Only exact cBPF opcodes now run, as in libpcap's
  `bpf_filter()` (which `abort()`s on the others) and the kernel's
  `bpf_check_classic()` (`EINVAL`). `Display` for `Insn` / `Program` prints an
  unknown opcode as `.word    0x000e  ; invalid opcode` instead of an ordinary
  mnemonic. Programs from `compile()` are unaffected.
- **`compile(.., Target::Classic)` no longer returns programs over
  `BPF_MAXINSNS`** (#203). A long straight-line filter (`ip[0]+1+1+...`, 4200
  terms, 4204 instructions) compiled to `Ok`, and the kernel then rejected it
  with an opaque `EINVAL` from `setsockopt(SO_ATTACH_FILTER)`, which accepts
  at most 4096 instructions. `compile` (and `codegen::compile`) now returns
  `Err(CodegenError)` ("filter expression is too complex: ...") for a classic
  program longer than 4096 instructions; exactly 4096 still compiles.
  libpcap 1.10.3 returns the oversized program from `pcap_compile` and only
  fails at `pcap_setfilter`, so this is a deliberate, earlier failure.
  `Target::Extended` is unaffected. The limit is exported as the new
  `pktbaffle::bpf::BPF_MAXINSNS` constant and documented in the README and the
  `compile` / `Target::Classic` rustdoc.

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
