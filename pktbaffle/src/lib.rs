//! **pktbaffle** — compile libpcap-style packet filter expressions into
//! classic BPF (cBPF) or extended BPF (eBPF) programs.
//!
//! # Overview
//!
//! `pktbaffle` turns the same filter syntax used by `tcpdump` and
//! `pcap_compile(3)` into compact bytecode with no C runtime dependency.
//! The output can be attached to a raw socket with `SO_ATTACH_FILTER`
//! (classic BPF) or loaded into an XDP / TC hook (extended BPF).
//!
//! # Quick start
//!
//! ```rust
//! use pktbaffle::{compile, LinkType, Target};
//!
//! // Classic BPF — attach to a raw socket with SO_ATTACH_FILTER
//! let prog = compile("tcp port 443", LinkType::Ethernet, Target::Classic).unwrap();
//! assert!(prog.len() > 0);
//! let bytes = prog.to_le_bytes(); // 8 bytes per instruction, little-endian
//!
//! // eBPF — load into an XDP or TC program
//! let prog = compile("tcp port 443", LinkType::Ethernet, Target::Extended).unwrap();
//! let bytes = prog.to_le_bytes();
//! ```
//!
//! # Filter syntax
//!
//! The filter language is a subset of the libpcap expression syntax.
//! Primitives can be combined with `and`, `or`, `not` (or `!`);
//! juxtaposition is treated as AND.
//!
//! | Expression | Matches |
//! |---|---|
//! | `host 192.168.1.1` | IPv4 src or dst |
//! | `src host 10.0.0.1` | IPv4 source only |
//! | `net 10.0.0.0/8` | Any address in 10.0.0.0/8 |
//! | `tcp port 443` | TCP to/from port 443 |
//! | `udp portrange 1024-65535` | UDP ephemeral ports |
//! | `port 80 or port 443` | HTTP or HTTPS |
//! | `tcp and not port 22` | TCP excluding SSH |
//! | `ether host aa:bb:cc:dd:ee:ff` | Ethernet MAC address |
//! | `vlan 100` | VLAN-tagged, ID 100 |
//! | `mpls` | Any MPLS-labeled packet |
//! | `ip multicast` | IPv4 multicast destination |
//! | `ip6 and tcp port 80` | IPv6 HTTP traffic |
//! | `len <= 64` | Packets ≤ 64 bytes |
//! | `tcp[13] & 0x02 != 0` | TCP SYN flag (raw byte access) |
//!
//! # Compilation pipeline
//!
//! Calling [`compile`] runs the following stages in sequence:
//!
//! 1. **Lex** ([`lexer::lex`]) — tokenise the input string into a
//!    [`Vec<lexer::Spanned>`][lexer::Spanned].
//! 2. **Parse** ([`parser::parse`]) — build an [`ast::Expr`] tree.
//! 3. **Codegen** ([`codegen::compile`] or [`ebpf_codegen::compile`]) — emit
//!    BPF instructions with a two-pass jump-patch strategy. The classic
//!    backend tracks facts proven on the fall-through path (ethertype,
//!    protocol, transport offset) so compound filters check each guard once.
//! 4. **Optimize** ([`optimizer::optimize`], classic BPF only) — thread
//!    jumps through `ja` trampolines, drop redundant loads, and remove
//!    unreachable instructions.
//!
//! You can stop after any stage if you only need the intermediate
//! representation. [`parse`] is a convenience wrapper for steps 1–2.
//!
//! # Link types
//!
//! [`LinkType`] tells the compiler how to interpret packet offsets:
//!
//! | Variant | Header | Typical use |
//! |---|---|---|
//! | [`LinkType::Ethernet`] | 14-byte Ethernet II | `AF_PACKET` / `pcap` |
//! | [`LinkType::RawIp`] | None — packet starts at IP | `SOCK_RAW` + `IPPROTO_*` |
//! | [`LinkType::LinuxSll`] | 16-byte Linux SLL | `any` interface in `pcap` |
//!
//! # Feature flags
//!
//! | Feature | Description |
//! |---|---|
//! | `vm` | Enable the software cBPF interpreter (`bpf::Program::matches`) |

pub mod ast;
pub mod bpf;
pub mod codegen;
pub mod ebpf;
pub mod ebpf_codegen;
pub mod error;
pub mod lexer;
pub mod optimizer;
pub mod parser;
#[cfg(feature = "vm")]
pub mod vm;

pub use codegen::LinkType;
pub use error::{Error, Result};

// Re-export instruction types for downstream code that inspects programs.
pub use bpf::Insn;

/// Compilation target: classic BPF or extended BPF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// Classic BPF (cBPF) — for `SO_ATTACH_FILTER` / raw socket filters.
    Classic,
    /// Extended BPF (eBPF) — for XDP, TC, and other modern hooks.
    Extended,
}

/// A compiled packet filter program, either cBPF or eBPF.
#[derive(Debug, Clone)]
pub enum Program {
    Classic(bpf::Program),
    Extended(ebpf::Program),
}

impl Program {
    /// Number of instructions in the program.
    pub fn len(&self) -> usize {
        match self {
            Program::Classic(p) => p.len(),
            Program::Extended(p) => p.len(),
        }
    }

    /// Returns `true` if the program contains no instructions.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Encode the program as raw bytes (8 bytes per instruction, little-endian).
    ///
    /// The layout matches the kernel's `struct sock_filter` (cBPF) or
    /// `struct bpf_insn` (eBPF), making the output ready for direct use
    /// with kernel APIs such as `SO_ATTACH_FILTER` or `bpf(2)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use pktbaffle::{compile, LinkType, Target};
    /// let prog = compile("tcp", LinkType::Ethernet, Target::Classic).unwrap();
    /// let bytes = prog.to_le_bytes();
    /// assert_eq!(bytes.len() % 8, 0); // always a multiple of 8
    /// ```
    pub fn to_le_bytes(&self) -> Vec<u8> {
        match self {
            Program::Classic(p) => p.to_le_bytes(),
            Program::Extended(p) => p.to_le_bytes(),
        }
    }

    /// Return the classic BPF instruction slice.
    ///
    /// # Panics
    ///
    /// Panics if this is an eBPF program. Use [`as_classic`][Program::as_classic]
    /// for a non-panicking alternative.
    pub fn instructions(&self) -> &[bpf::Insn] {
        self.as_classic()
            .expect("instructions() called on an eBPF program; use as_extended() instead")
            .instructions()
    }

    /// Return a reference to the inner [`bpf::Program`], or `None` if this is an eBPF program.
    ///
    /// # Example
    ///
    /// ```rust
    /// use pktbaffle::{compile, LinkType, Target};
    /// let prog = compile("tcp", LinkType::Ethernet, Target::Classic).unwrap();
    /// let cbpf = prog.as_classic().expect("should be cBPF");
    /// assert!(cbpf.len() > 0);
    /// ```
    pub fn as_classic(&self) -> Option<&bpf::Program> {
        match self {
            Program::Classic(p) => Some(p),
            Program::Extended(_) => None,
        }
    }

    /// Return a reference to the inner [`ebpf::Program`], or `None` if this is a classic BPF program.
    ///
    /// # Example
    ///
    /// ```rust
    /// use pktbaffle::{compile, LinkType, Target};
    /// let prog = compile("tcp", LinkType::Ethernet, Target::Extended).unwrap();
    /// let ebpf = prog.as_extended().expect("should be eBPF");
    /// assert!(ebpf.len() > 0);
    /// ```
    pub fn as_extended(&self) -> Option<&ebpf::Program> {
        match self {
            Program::Classic(_) => None,
            Program::Extended(p) => Some(p),
        }
    }
}

/// Parse and compile a filter expression into a [`Program`].
///
/// # Errors
///
/// Returns [`Error::LexError`] for unrecognised characters,
/// [`Error::ParseError`] for grammatically invalid expressions, and
/// [`Error::CodegenError`] for constructs that cannot be represented in
/// the chosen target for the chosen link type.
pub fn compile(filter: &str, link: LinkType, target: Target) -> Result<Program> {
    let tokens = lexer::lex(filter)?;
    let ast = parser::parse(&tokens)?;
    match target {
        Target::Classic => codegen::compile(&ast, link).map(Program::Classic),
        Target::Extended => ebpf_codegen::compile(&ast, link).map(Program::Extended),
    }
}

/// Parse a filter expression string into an [`ast::Expr`] without generating code.
///
/// Useful for inspecting or transforming the filter tree before compilation,
/// or for validating syntax without committing to a [`Target`] or [`LinkType`].
///
/// # Errors
///
/// Returns [`Error::LexError`] or [`Error::ParseError`] on invalid input.
///
/// # Example
///
/// ```rust
/// use pktbaffle::parse;
///
/// let expr = parse("host 192.168.1.1 and tcp port 22").unwrap();
/// // Inspect the AST:
/// println!("{expr:#?}");
/// ```
pub fn parse(filter: &str) -> Result<ast::Expr> {
    let tokens = lexer::lex(filter)?;
    parser::parse(&tokens)
}
