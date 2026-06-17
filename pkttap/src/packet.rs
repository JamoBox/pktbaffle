use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub use pktbaffle::codegen::LinkType;

/// A borrowed view of a single captured packet, valid only for the current
/// iteration step.
///
/// `PacketRef` borrows its bytes directly from the capture source's internal
/// buffer, so capturing a packet performs no heap allocation. The borrow is
/// tied to `&mut Capture`, so it ends at the next call to
/// [`Capture::next`](crate::Capture::next) — a `PacketRef` therefore cannot be
/// stored across iterations. Call [`to_owned`](PacketRef::to_owned) to obtain an
/// owned [`Packet`] you can retain.
///
/// ```no_run
/// # use pkttap::Capture;
/// # fn example() -> pkttap::Result<()> {
/// let mut cap = Capture::from_file("dump.pcap").open()?;
/// while let Some(pkt) = cap.next()? {
///     // Borrowed — process it before the next iteration.
///     println!("{} bytes", pkt.data().len());
///     // To keep it: let owned = pkt.to_owned();
/// }
/// # Ok(()) }
/// ```
///
/// A `PacketRef` cannot be held across a second `next()` call — the borrow of
/// the capture forbids it. This is the lending-iterator contract, enforced at
/// compile time:
///
/// ```compile_fail
/// # use pkttap::Capture;
/// # fn example() -> pkttap::Result<()> {
/// let mut cap = Capture::from_file("dump.pcap").open()?;
/// let first = cap.next()?;          // borrows `cap`
/// let second = cap.next()?;         // ERROR: cannot borrow `cap` again while `first` lives
/// drop((first, second));
/// # Ok(()) }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct PacketRef<'a> {
    data: &'a [u8],
    timestamp: SystemTime,
    orig_len: u32,
    link_type: LinkType,
}

impl<'a> PacketRef<'a> {
    /// Construct a borrowed packet from raw capture parts. The timestamp is
    /// built from `ts_sec`/`ts_nsec` since the Unix epoch — the form the
    /// platform capture backends produce.
    pub(crate) fn new(
        data: &'a [u8],
        ts_sec: u64,
        ts_nsec: u32,
        orig_len: u32,
        link_type: LinkType,
    ) -> Self {
        let timestamp = UNIX_EPOCH + Duration::new(ts_sec, ts_nsec);
        Self {
            data,
            timestamp,
            orig_len,
            link_type,
        }
    }

    /// Raw packet bytes (up to snaplen), borrowed from the capture source.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Capture timestamp.
    pub fn timestamp(&self) -> SystemTime {
        self.timestamp
    }

    /// On-wire length before any snaplen truncation.
    pub fn orig_len(&self) -> u32 {
        self.orig_len
    }

    /// Link-layer framing of the capture source.
    pub fn link_type(&self) -> LinkType {
        self.link_type
    }

    /// Returns true if the packet was truncated by snaplen.
    pub fn is_truncated(&self) -> bool {
        self.data.len() < self.orig_len as usize
    }

    /// Copy this borrowed view into an owned [`Packet`] that outlives the
    /// current iteration step. This is the explicit allocation point: call it
    /// only for packets you need to retain.
    pub fn to_owned(&self) -> Packet {
        Packet {
            data: self.data.to_vec(),
            timestamp: self.timestamp,
            orig_len: self.orig_len,
            link_type: self.link_type,
        }
    }
}

/// An owned captured packet, produced by [`PacketRef::to_owned`].
///
/// Holds its own copy of the packet bytes, so unlike [`PacketRef`] it can be
/// stored, moved, and retained across iterations. Borrow it back as a
/// [`PacketRef`] with [`as_ref`](Packet::as_ref) — e.g. to hand it to
/// [`Dump::write_packet`](crate::Dump::write_packet).
#[derive(Debug, Clone)]
pub struct Packet {
    data: Vec<u8>,
    timestamp: SystemTime,
    orig_len: u32,
    link_type: LinkType,
}

impl Packet {
    /// Construct an owned packet from raw parts.
    pub fn new(data: Vec<u8>, timestamp: SystemTime, orig_len: u32, link_type: LinkType) -> Self {
        Self {
            data,
            timestamp,
            orig_len,
            link_type,
        }
    }

    /// Raw packet bytes (up to snaplen).
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Capture timestamp.
    pub fn timestamp(&self) -> SystemTime {
        self.timestamp
    }

    /// On-wire length before any snaplen truncation.
    pub fn orig_len(&self) -> u32 {
        self.orig_len
    }

    /// Link-layer framing of the capture source.
    pub fn link_type(&self) -> LinkType {
        self.link_type
    }

    /// Returns true if the packet was truncated by snaplen.
    pub fn is_truncated(&self) -> bool {
        self.data.len() < self.orig_len as usize
    }

    /// Borrow this owned packet as a [`PacketRef`].
    ///
    /// Named `as_ref` for symmetry with the borrowed/owned split; it returns a
    /// `PacketRef` by value (which is itself a borrow) rather than `&Self`, so
    /// it intentionally does not implement the `AsRef` trait.
    #[allow(clippy::should_implement_trait)]
    pub fn as_ref(&self) -> PacketRef<'_> {
        PacketRef {
            data: &self.data,
            timestamp: self.timestamp,
            orig_len: self.orig_len,
            link_type: self.link_type,
        }
    }

    /// Consume the packet, returning ownership of its raw byte buffer.
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }
}
