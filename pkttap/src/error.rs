use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Filter(pktbaffle::Error),
    Pcap(pcap_file::PcapError),
    Platform(String),
    PermissionDenied,
    /// No packet is currently available. Returned by [`crate::Capture::next`]
    /// when the capture was opened in non-blocking mode (via
    /// [`crate::CaptureBuilder::nonblocking`]) and no data is ready.
    WouldBlock,
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::Filter(e) => write!(f, "filter error: {e}"),
            Error::Pcap(e) => write!(f, "pcap error: {e}"),
            Error::Platform(s) => write!(f, "platform error: {s}"),
            Error::PermissionDenied => write!(
                f,
                "permission denied — packet capture requires elevated privileges (root / CAP_NET_RAW)"
            ),
            Error::WouldBlock => write!(f, "no packet available (non-blocking capture)"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Filter(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            Error::PermissionDenied
        } else {
            Error::Io(e)
        }
    }
}

impl From<pktbaffle::Error> for Error {
    fn from(e: pktbaffle::Error) -> Self {
        Error::Filter(e)
    }
}

impl From<pcap_file::PcapError> for Error {
    fn from(e: pcap_file::PcapError) -> Self {
        Error::Pcap(e)
    }
}
