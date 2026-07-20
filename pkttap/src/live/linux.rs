//! Linux live capture via AF_PACKET raw socket + SO_ATTACH_FILTER.
//!
//! Uses a pre-allocated receive buffer to avoid per-packet heap allocation.
//! The kernel applies the cBPF filter before copying, so only matching
//! packets reach userspace.
//!
//! # Timestamps
//!
//! Two modes are supported, selected by [`TimestampMode`]:
//!
//! - **`Software`** (default): `SO_TIMESTAMPNS` is enabled on the socket.
//!   The kernel records a `timespec` at the moment the packet enters the
//!   receive queue — accurate to ≈1 μs and far more reliable than calling
//!   `SystemTime::now()` after `recvfrom()` returns. The timestamp is
//!   delivered as `SCM_TIMESTAMPNS` ancillary data via `recvmsg()`.
//!
//! - **`Hardware`**: `SO_TIMESTAMPING` is enabled with hardware + software
//!   fallback flags. The kernel delivers `SCM_TIMESTAMPING` ancillary data
//!   containing three `timespec` values; we use the raw hardware field
//!   (`scm_timestamping[2]`) when non-zero, otherwise fall back to the
//!   software field (`scm_timestamping[0]`). NICs that do not support
//!   hardware timestamping report a zero `timespec` for the hardware field;
//!   check `ethtool -T <iface>` to see what your NIC supports.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::error::{Error, Result};
use crate::packet::{LinkType, PacketRef};
use crate::stats::CaptureStats;
use crate::timestamp::TimestampMode;

// Linux socket constants not always exposed by std
const AF_PACKET: libc::c_int = 17;
const ETH_P_ALL: u16 = 0x0003;
const SOL_SOCKET: libc::c_int = 1;
const SO_ATTACH_FILTER: libc::c_int = 26;
/// `SO_TIMESTAMPNS` — delivers a `timespec` via `SCM_TIMESTAMPNS` ancillary data.
const SO_TIMESTAMPNS: libc::c_int = 35;
/// `SO_TIMESTAMPING` — delivers an `scm_timestamping` struct (3× `timespec`) via
/// `SCM_TIMESTAMPING` ancillary data.
const SO_TIMESTAMPING: libc::c_int = 37;
const SOL_PACKET: libc::c_int = 263;
#[allow(dead_code)] // Reserved for future TPACKET_V3 ring-buffer support (ADR 0002).
const PACKET_VERSION: libc::c_int = 10;
const PACKET_STATISTICS: libc::c_int = 6;
const SIOCGIFINDEX: libc::c_ulong = 0x8933;

// SO_TIMESTAMPING flags (linux/net_tstamp.h)
/// Request hardware Rx timestamp from the NIC.
const SOF_TIMESTAMPING_RX_HARDWARE: u32 = 1 << 2;
/// Also request a software Rx timestamp (used as fallback).
const SOF_TIMESTAMPING_RX_SOFTWARE: u32 = 1 << 3;
/// Report the software timestamp in scm_timestamping[0].
const SOF_TIMESTAMPING_SOFTWARE: u32 = 1 << 4;
/// Report the raw (unmodified) hardware timestamp in scm_timestamping[2].
const SOF_TIMESTAMPING_RAW_HARDWARE: u32 = 1 << 6;

// SCM types returned in ancillary data (same numeric values as the SO_ options)
const SCM_TIMESTAMPNS: libc::c_int = SO_TIMESTAMPNS;
const SCM_TIMESTAMPING: libc::c_int = SO_TIMESTAMPING;

/// Kernel counter struct returned by getsockopt(SOL_PACKET, PACKET_STATISTICS).
/// Reading this resets the kernel counters to zero, so LinuxLive accumulates
/// across calls to preserve the total-since-open semantics.
#[repr(C)]
struct TpacketStats {
    tp_packets: u32,
    tp_drops: u32,
}

fn arphrd_to_link_type(arphrd: u32) -> LinkType {
    match arphrd {
        // ARPHRD_ETHER=1, ARPHRD_LOOPBACK=772: AF_PACKET on loopback prepends a
        // fake 14-byte Ethernet header, so BPF programs compiled for Ethernet work.
        1 | 772 => LinkType::Ethernet,
        _ => LinkType::RawIp,
    }
}

/// Query the link type of an interface before opening a socket, by reading
/// the ARPHRD type from sysfs.
pub fn query_link_type(iface: &str) -> Result<LinkType> {
    let path = format!("/sys/class/net/{iface}/type");
    let s = std::fs::read_to_string(&path)
        .map_err(|_| Error::Platform(format!("cannot read link type for {iface}")))?;
    let arphrd: u32 = s
        .trim()
        .parse()
        .map_err(|_| Error::Platform(format!("invalid ARPHRD value for {iface}")))?;
    Ok(arphrd_to_link_type(arphrd))
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const pktbaffle::bpf::Insn,
}

/// `scm_timestamping` as returned in `SCM_TIMESTAMPING` ancillary data.
/// Contains three `timespec` values (software, deprecated hw-transformed, raw hw).
#[repr(C)]
struct ScmTimestamping {
    /// Software timestamp (kernel receive queue).
    ts_sw: libc::timespec,
    /// Deprecated hardware-transformed timestamp — do not use.
    ts_hw_deprecated: libc::timespec,
    /// Raw hardware timestamp from the NIC (zero if unsupported).
    ts_hw_raw: libc::timespec,
}

pub struct LinuxLive {
    fd: OwnedFd,
    buf: Vec<u8>,
    /// Ancillary data buffer for `recvmsg()`.
    cmsg_buf: Vec<u8>,
    snaplen: usize,
    link_type: LinkType,
    timestamp_mode: TimestampMode,
    /// Accumulated totals across PACKET_STATISTICS reads (kernel resets on each read).
    recv_acc: u64,
    drop_acc: u64,
}

impl LinuxLive {
    pub fn open(
        iface: &str,
        filter: Option<&pktbaffle::bpf::Program>,
        snaplen: u32,
        promiscuous: bool,
        timestamp_mode: TimestampMode,
    ) -> Result<Self> {
        let snaplen = snaplen as usize;

        // AF_PACKET / SOCK_RAW socket capturing all ethertypes
        let raw_fd =
            unsafe { libc::socket(AF_PACKET, libc::SOCK_RAW, ETH_P_ALL.to_be() as libc::c_int) };
        if raw_fd < 0 {
            return Err(super::io_err());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        // Attach BPF filter before binding so we don't receive unfiltered frames
        if let Some(prog) = filter {
            let insns = prog.instructions();
            let fprog = SockFprog {
                len: insns.len() as u16,
                filter: insns.as_ptr(),
            };
            let rc = unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    SOL_SOCKET,
                    SO_ATTACH_FILTER,
                    &fprog as *const _ as *const libc::c_void,
                    std::mem::size_of::<SockFprog>() as libc::socklen_t,
                )
            };
            if rc < 0 {
                return Err(super::io_err());
            }
        }

        // Enable kernel timestamping based on requested mode.
        // This must be done before bind() so that the first received packets
        // already carry timestamps.
        match timestamp_mode {
            TimestampMode::Software => {
                // SO_TIMESTAMPNS: kernel stores a timespec in SCM_TIMESTAMPNS cmsg.
                let one: libc::c_int = 1;
                let rc = unsafe {
                    libc::setsockopt(
                        fd.as_raw_fd(),
                        SOL_SOCKET,
                        SO_TIMESTAMPNS,
                        &one as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    )
                };
                if rc < 0 {
                    return Err(super::io_err());
                }
            }
            TimestampMode::Hardware => {
                // SO_TIMESTAMPING with hardware + software fallback flags.
                // SOF_TIMESTAMPING_RX_SOFTWARE / SOF_TIMESTAMPING_SOFTWARE ensure
                // scm_timestamping[0] is always populated even when the NIC does
                // not support hardware timestamping, giving us a reliable fallback.
                let flags: u32 = SOF_TIMESTAMPING_RX_HARDWARE
                    | SOF_TIMESTAMPING_RAW_HARDWARE
                    | SOF_TIMESTAMPING_RX_SOFTWARE
                    | SOF_TIMESTAMPING_SOFTWARE;
                let rc = unsafe {
                    libc::setsockopt(
                        fd.as_raw_fd(),
                        SOL_SOCKET,
                        SO_TIMESTAMPING,
                        &flags as *const _ as *const libc::c_void,
                        std::mem::size_of::<u32>() as libc::socklen_t,
                    )
                };
                if rc < 0 {
                    return Err(super::io_err());
                }
            }
        }

        // Resolve interface index
        let ifindex = iface_index(fd.as_raw_fd(), iface)?;

        // Enable promiscuous mode if requested
        if promiscuous {
            let mreq = libc::packet_mreq {
                mr_ifindex: ifindex,
                mr_type: libc::PACKET_MR_PROMISC as u16,
                mr_alen: 0,
                mr_address: [0; 8],
            };
            let rc = unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    SOL_PACKET,
                    libc::PACKET_ADD_MEMBERSHIP,
                    &mreq as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::packet_mreq>() as libc::socklen_t,
                )
            };
            if rc < 0 {
                return Err(super::io_err());
            }
        }

        // Bind to the specific interface
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = AF_PACKET as u16;
        addr.sll_protocol = ETH_P_ALL.to_be();
        addr.sll_ifindex = ifindex;
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(super::io_err());
        }

        let link_type = query_link_type(iface).unwrap_or(LinkType::Ethernet);

        // Size the ancillary data buffer to accommodate the largest cmsg we may
        // receive. SCM_TIMESTAMPING carries ScmTimestamping (3 × timespec = 24 bytes);
        // the CMSG_SPACE macro rounds up to alignment. We size for that plus a
        // comfortable margin for any extra cmsgs the kernel might include.
        let cmsg_space = unsafe {
            libc::CMSG_SPACE(std::mem::size_of::<ScmTimestamping>() as libc::c_uint) as usize
        };

        Ok(Self {
            fd,
            buf: vec![0u8; snaplen.max(65535)],
            cmsg_buf: vec![0u8; cmsg_space.max(256)],
            snaplen,
            link_type,
            timestamp_mode,
            recv_acc: 0,
            drop_acc: 0,
        })
    }

    pub fn link_type(&self) -> LinkType {
        self.link_type
    }

    /// Return cumulative capture statistics.
    ///
    /// The kernel resets its `PACKET_STATISTICS` counters each time they are
    /// read; this method accumulates the deltas so callers always see totals
    /// from the start of the capture.
    pub fn stats(&mut self) -> Result<CaptureStats> {
        let mut ts: TpacketStats = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<TpacketStats>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                SOL_PACKET,
                PACKET_STATISTICS,
                &mut ts as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if rc < 0 {
            return Err(super::io_err());
        }
        self.recv_acc += ts.tp_packets as u64;
        self.drop_acc += ts.tp_drops as u64;
        Ok(CaptureStats {
            received: self.recv_acc,
            dropped: self.drop_acc,
            if_dropped: 0,
        })
    }

    /// Set or clear `O_NONBLOCK` on the capture socket via `fcntl`.
    ///
    /// When non-blocking mode is active, [`Self::next_packet`] returns
    /// `Ok(None)` immediately if no packet is available, rather than blocking.
    pub fn set_nonblocking(&self, nb: bool) -> Result<()> {
        let flags = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(super::io_err());
        }
        let new_flags = if nb {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };
        let rc = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_SETFL, new_flags) };
        if rc < 0 {
            return Err(super::io_err());
        }
        Ok(())
    }

    /// Return the next packet, blocking unless `O_NONBLOCK` was set via
    /// [`Self::set_nonblocking`].
    ///
    /// Uses `recvmsg()` to receive both packet data and ancillary timestamp
    /// data in a single syscall. The timestamp is read from the
    /// kernel-provided ancillary data selected by [`TimestampMode`]; see the
    /// module docs for details.
    ///
    /// Returns `Ok(None)` when non-blocking mode is active and no packet is
    /// ready (EAGAIN / EWOULDBLOCK).
    pub fn next_packet(&mut self) -> Result<Option<PacketRef<'_>>> {
        loop {
            let mut src: libc::sockaddr_ll = unsafe { std::mem::zeroed() };

            let mut iov = libc::iovec {
                iov_base: self.buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: self.buf.len(),
            };

            let mut mhdr: libc::msghdr = unsafe { std::mem::zeroed() };
            mhdr.msg_name = &mut src as *mut libc::sockaddr_ll as *mut libc::c_void;
            mhdr.msg_namelen = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
            mhdr.msg_iov = &mut iov;
            mhdr.msg_iovlen = 1;
            mhdr.msg_control = self.cmsg_buf.as_mut_ptr() as *mut libc::c_void;
            mhdr.msg_controllen = self.cmsg_buf.len();

            let n = unsafe { libc::recvmsg(self.fd.as_raw_fd(), &mut mhdr, 0) };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    return Ok(None);
                }
                return Err(e.into());
            }
            let n = n as usize;
            let orig_len = n as u32;
            let n = n.min(self.snaplen);

            // Extract timestamp from ancillary data.
            let (ts_sec, ts_nsec) = extract_timestamp(&mhdr, self.timestamp_mode);

            // Zero-copy: borrow the receive buffer rather than allocating. The
            // EINTR `continue` path above never creates this borrow, so the
            // slice is born only on the return path — keeping the lending
            // iterator in safe Rust. A TPACKET_V3 mmap ring (which would also
            // eliminate the per-packet recvmsg syscall) is deferred; see
            // ADR 0002 and the dedicated ring-buffer issue.
            return Ok(Some(PacketRef::new(
                &self.buf[..n],
                ts_sec,
                ts_nsec,
                orig_len,
                self.link_type,
            )));
        }
    }
}

/// Extract a (seconds, nanoseconds) timestamp from `recvmsg()` ancillary data.
///
/// For `TimestampMode::Software`, we look for `SCM_TIMESTAMPNS` which contains
/// a single `timespec`. For `TimestampMode::Hardware`, we look for
/// `SCM_TIMESTAMPING` which contains `ScmTimestamping` (3× `timespec`); we
/// prefer the raw hardware field and fall back to the software field.
///
/// If no recognised cmsg is found (e.g. the kernel is very old), we fall back
/// to `SystemTime::now()` as a last resort — this matches the pre-#88 behaviour
/// and is safe even on paths that should never reach it.
fn extract_timestamp(mhdr: &libc::msghdr, mode: TimestampMode) -> (u64, u32) {
    // SAFETY: we only read cmsg headers within the buffer we provided and that
    // the kernel has filled; all pointer arithmetic uses the CMSG_* macros.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(mhdr);
        while !cmsg.is_null() {
            let level = (*cmsg).cmsg_level;
            let ty = (*cmsg).cmsg_type;

            if level == SOL_SOCKET {
                match mode {
                    TimestampMode::Software if ty == SCM_TIMESTAMPNS => {
                        // SCM_TIMESTAMPNS delivers a single timespec.
                        let data = libc::CMSG_DATA(cmsg) as *const libc::timespec;
                        let ts = std::ptr::read_unaligned(data);
                        return timespec_to_pair(ts);
                    }
                    TimestampMode::Hardware if ty == SCM_TIMESTAMPING => {
                        // SCM_TIMESTAMPING delivers ScmTimestamping (3 × timespec).
                        let data = libc::CMSG_DATA(cmsg) as *const ScmTimestamping;
                        let scts = std::ptr::read_unaligned(data);
                        // Prefer raw hardware timestamp; fall back to software.
                        let ts = if scts.ts_hw_raw.tv_sec != 0 || scts.ts_hw_raw.tv_nsec != 0 {
                            scts.ts_hw_raw
                        } else {
                            scts.ts_sw
                        };
                        return timespec_to_pair(ts);
                    }
                    _ => {}
                }
            }

            cmsg = libc::CMSG_NXTHDR(mhdr, cmsg);
        }
    }

    // Fallback: no matching cmsg found. This should not happen when the socket
    // option was set successfully, but guard against it defensively.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    (now.as_secs(), now.subsec_nanos())
}

/// Convert a `libc::timespec` to `(seconds, nanoseconds)`.
fn timespec_to_pair(ts: libc::timespec) -> (u64, u32) {
    (ts.tv_sec as u64, ts.tv_nsec as u32)
}

fn iface_index(fd: libc::c_int, name: &str) -> Result<libc::c_int> {
    if name.len() >= libc::IFNAMSIZ {
        return Err(Error::Platform(format!("interface name too long: {name}")));
    }
    let mut ifreq: libc::ifreq = unsafe { std::mem::zeroed() };
    let bytes = name.as_bytes();
    let dst = &mut ifreq.ifr_name;
    for (i, &b) in bytes.iter().enumerate() {
        dst[i] = b as libc::c_char;
    }
    let rc = unsafe { libc::ioctl(fd, SIOCGIFINDEX, &ifreq) };
    if rc < 0 {
        return Err(super::io_err());
    }
    Ok(unsafe { ifreq.ifr_ifru.ifru_ifindex })
}

/// List network interfaces by reading /proc/net/dev.
pub fn list_interfaces() -> Result<Vec<String>> {
    let content = std::fs::read_to_string("/proc/net/dev")?;
    let mut ifaces = Vec::new();
    for line in content.lines().skip(2) {
        let name = line.split(':').next().unwrap_or("").trim();
        if !name.is_empty() {
            ifaces.push(name.to_owned());
        }
    }
    Ok(ifaces)
}

/// Return the default interface for live capture: the first non-loopback
/// interface reported by the kernel.
pub fn default_interface() -> Result<String> {
    list_interfaces()?
        .into_iter()
        .find(|name| name != "lo")
        .ok_or_else(|| Error::Platform("no non-loopback interface found".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests verify that the libc symbols required by the live capture
    // implementation are present. They act as compile-time guards: `ifreq` was
    // only added in libc 0.2.137, so any floor below that fails to compile here,
    // ensuring the Cargo.toml lower bound (0.2.140) stays honest.

    use super::*;

    #[test]
    fn libc_packet_mreq_fields_accessible() {
        let mreq = libc::packet_mreq {
            mr_ifindex: 0,
            mr_type: 0,
            mr_alen: 0,
            mr_address: [0; 8],
        };
        assert_eq!(mreq.mr_ifindex, 0);
    }

    #[test]
    fn libc_ifreq_zeroed() {
        let ifreq: libc::ifreq = unsafe { std::mem::zeroed() };
        assert_eq!(ifreq.ifr_name[0], 0);
    }

    #[test]
    fn libc_ifnamsiz_is_sensible() {
        // IFNAMSIZ has been 16 on Linux since the kernel was first written;
        // any value in [8, 64] is acceptable for our length check.
        assert!(libc::IFNAMSIZ >= 8 && libc::IFNAMSIZ <= 64);
    }

    #[test]
    fn libc_fcntl_constants_present() {
        let _f_getfl = libc::F_GETFL;
        let _f_setfl = libc::F_SETFL;
        let _o_nonblock = libc::O_NONBLOCK;
    }

    #[test]
    fn so_timestamping_flags_have_expected_values() {
        // These constants are ABI — they must match linux/net_tstamp.h exactly.
        assert_eq!(SOF_TIMESTAMPING_RX_HARDWARE, 1 << 2);
        assert_eq!(SOF_TIMESTAMPING_RX_SOFTWARE, 1 << 3);
        assert_eq!(SOF_TIMESTAMPING_SOFTWARE, 1 << 4);
        assert_eq!(SOF_TIMESTAMPING_RAW_HARDWARE, 1 << 6);
    }

    #[test]
    fn timestamp_mode_default_is_software() {
        assert_eq!(TimestampMode::default(), TimestampMode::Software);
    }

    #[test]
    fn timespec_to_pair_converts_correctly() {
        let ts = libc::timespec {
            tv_sec: 1_700_000_000,
            tv_nsec: 123_456_789,
        };
        let (sec, ns) = timespec_to_pair(ts);
        assert_eq!(sec, 1_700_000_000u64);
        assert_eq!(ns, 123_456_789u32);
    }
}
