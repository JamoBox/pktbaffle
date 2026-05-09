use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    /// Unexpected character at the given byte offset.
    LexError { offset: usize, ch: char },
    /// Parser encountered something unexpected.
    ParseError { message: String },
    /// Code generation hit an unsupported construct.
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

pub type Result<T> = std::result::Result<T, Error>;
