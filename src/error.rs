//! Error types returned by all fallible operations in this crate.

use std::fmt;

/// All errors that [`compile`][crate::compile] and [`parse`][crate::parse] can return.
///
/// Each variant corresponds to a stage in the compilation pipeline:
/// lexing, parsing, or code generation.
#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    /// The input string contained a character the tokeniser does not recognise.
    ///
    /// `offset` is the byte position in the original filter string where the
    /// unexpected character was found.
    LexError { offset: usize, ch: char },
    /// The token stream did not conform to the filter grammar.
    ParseError { message: String },
    /// The filter is grammatically valid but cannot be expressed in BPF —
    /// for example, `inbound`/`outbound` direction primitives are not
    /// representable in standard BPF bytecode.
    CodegenError { message: String },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::LexError { offset, ch } => {
                write!(f, "unexpected character {:?} at offset {}", ch, offset)
            }
            Error::ParseError { message } => write!(f, "parse error: {}", message),
            Error::CodegenError { message } => write!(f, "codegen error: {}", message),
        }
    }
}

impl std::error::Error for Error {}

/// Convenience `Result` alias used throughout this crate.
pub type Result<T> = std::result::Result<T, Error>;
