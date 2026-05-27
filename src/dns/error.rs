
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("Buffer overflow at position {0}")]
    BufferOverflow(usize),
    #[error("Too many compression jumps")]
    TooManyJumps,
    #[error("Label length is too large: {0} > 63")]
    LabelTooLarge(usize),
    #[error("I/O Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("UTF-8 Error")]
    Utf8(#[from] std::str::Utf8Error),
}

/// "Custom exception" for DNS Packet Buffer parsing.
pub type Result<T> = std::result::Result<T, DnsError>;
