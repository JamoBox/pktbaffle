//! **pktbaffle** — compile libpcap-style packet filter expressions into
//! classic BPF (cBPF) or extended BPF (eBPF) programs.
//!
//! # Quick start
//!
//! ```rust
//! use pktbaffle::{compile, LinkType, Target};
//!
//! // Classic BPF (for SO_ATTACH_FILTER / raw sockets)
//! let prog = compile("tcp port 443", LinkType::Ethernet, Target::Classic).unwrap();
//! let bytes = prog.to_le_bytes(); // 8 bytes per instruction, little-endian
//!
//! // eBPF (for XDP / TC hooks)
//! let prog = compile("tcp port 443", LinkType::Ethernet, Target::Extended).unwrap();
//! let bytes = prog.to_le_bytes(); // 8 bytes per instruction, little-endian
//! ```

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

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Encode the program as raw bytes (8 bytes per instruction, little-endian).
    pub fn to_le_bytes(&self) -> Vec<u8> {
        match self {
            Program::Classic(p) => p.to_le_bytes(),
            Program::Extended(p) => p.to_le_bytes(),
        }
    }

    /// Return the classic BPF instruction slice.
    /// Panics if this is an eBPF program — use `as_classic()` for a safe variant.
    pub fn instructions(&self) -> &[bpf::Insn] {
        self.as_classic()
            .expect("instructions() called on an eBPF program; use as_extended() instead")
            .instructions()
    }

    /// Return a reference to the inner [`bpf::Program`], or `None` if eBPF.
    pub fn as_classic(&self) -> Option<&bpf::Program> {
        match self {
            Program::Classic(p) => Some(p),
            Program::Extended(_) => None,
        }
    }

    /// Return a reference to the inner [`ebpf::Program`], or `None` if classic.
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

/// Parse a filter expression string into an AST without generating code.
pub fn parse(filter: &str) -> Result<ast::Expr> {
    let tokens = lexer::lex(filter)?;
    parser::parse(&tokens)
}
