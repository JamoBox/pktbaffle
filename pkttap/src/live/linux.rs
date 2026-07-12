//! Linux live capture via AF_PACKET raw socket + SO_ATTACH_FILTER.
//!
//! Uses a pre-allocated receive buffer to avoid per-packet heap allocation.
//! The kernel applies the cBPF filter before copying, so only matching
//! packets reach userspace.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::error::{Error, Result};
use crate::packet::{LinkType, PacketRef};
use crate::stats::CaptureStats;

// Linux socket constants not always exposed by std
const AF_PACKET: libc::c_int = 17;
const ETH_P_ALL: u16 = 0x0003;
const SOL_SOCKET: libc::c_int = 1;
const SO_ATTACH_FILTER: libc::c_int = 26;
const SO_TIMESTAMP: libc::c_int = 29;
/// `SCM_TIMESTAMP` equals `SO_TIMESTAMP` on Linux; libc does not expose it for
/// Linux (the definition is commented out in libc's source), so we define it
/// ourselves.
const SCM_TIMESTAMP: libc::c_int = 29;
const SOL_PACKET: libc::c_int = 263;
#[allow(dead_code)] // Reserved for future TPACKET_V3 ring-buffer support (ADR 0002).
const PACKET_VERSION: libc::c_int = 10;
const PACKET_STATISTICS: libc::c_int = 6;
const SIOCGIFINDEX: libc::c_ulong = 0x8933;

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

pub struct LinuxLive {
    fd: OwnedFd,
    buf: Vec<u8>,
    snaplen: usize,
    link_type: LinkType,
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

        // Enable SO_TIMESTAMP so the kernel records the packet arrival time and
        // delivers it as ancillary data on recvmsg(). This is more accurate than
        // calling SystemTime::now() after recvfrom() returns, which can be
        // 10–100 µs later under load.
        let one: libc::c_int = 1;
        let rc = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                SOL_SOCKET,
                SO_TIMESTAMP,
                &one as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(super::io_err());
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

        Ok(Self {
            fd,
            buf: vec![0u8; snaplen.max(65535)],
            snaplen,
            link_type,
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
    /// The timestamp is read from the kernel-provided `SO_TIMESTAMP` ancillary
    /// data delivered by `recvmsg()`. This is the moment the kernel received the
    /// packet, which is 10–100 µs earlier than when userspace reads it under
    /// load. Falls back to `SystemTime::now()` if no ancillary timestamp is
    /// present.
    ///
    /// Returns `Ok(None)` when non-blocking mode is active and no packet is
    /// ready (EAGAIN / EWOULDBLOCK).
    pub fn next_packet(&mut self) -> Result<Option<PacketRef<'_>>> {
        loop {
            let fd = self.fd.as_raw_fd();

            let mut iov = libc::iovec {
                iov_base: self.buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: self.buf.len(),
            };
            // 128 bytes is always enough for a single cmsghdr + timeval.
            let mut cmsg_buf = [0u8; 128];
            let mut src: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut mhdr = libc::msghdr {
                msg_name: &mut src as *mut libc::sockaddr_ll as *mut libc::c_void,
                msg_namelen: std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                msg_iov: &mut iov,
                msg_iovlen: 1,
                msg_control: cmsg_buf.as_mut_ptr() as *mut libc::c_void,
                msg_controllen: cmsg_buf.len(),
                msg_flags: 0,
            };

            let n = unsafe { libc::recvmsg(fd, &mut mhdr, 0) };
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

            // Use the kernel-recorded arrival time from SO_TIMESTAMP ancillary
            // data; fall back to SystemTime::now() if unavailable.
            let ts = extract_so_timestamp(&mhdr).unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
            });

            // Zero-copy: borrow the receive buffer rather than allocating. The
            // EINTR `continue` path above never creates this borrow, so the
            // slice is born only on the return path — keeping the lending
            // iterator in safe Rust. A TPACKET_V3 mmap ring (which would also
            // eliminate the per-packet recvmsg syscall) is deferred; see
            // ADR 0002 and the dedicated ring-buffer issue.
            return Ok(Some(PacketRef::new(
                &self.buf[..n],
                ts.as_secs(),
                ts.subsec_nanos(),
                orig_len,
                self.link_type,
            )));
        }
    }
}

/// Walk the ancillary data chain in `mhdr` and return the `SO_TIMESTAMP`
/// kernel arrival time as a `Duration` since the Unix epoch, or `None` if
/// no such control message is present.
fn extract_so_timestamp(mhdr: &libc::msghdr) -> Option<std::time::Duration> {
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(mhdr) };
    while !cmsg.is_null() {
        let hdr = unsafe { &*cmsg };
        if hdr.cmsg_level == SOL_SOCKET && hdr.cmsg_type == SCM_TIMESTAMP {
            // SAFETY: the kernel placed a valid `timeval` at CMSG_DATA; we copy
            // it out via MaybeUninit to avoid alignment assumptions.
            let tv = unsafe {
                let data = libc::CMSG_DATA(cmsg);
                let mut tv = std::mem::MaybeUninit::<libc::timeval>::uninit();
                std::ptr::copy_nonoverlapping(
                    data,
                    tv.as_mut_ptr() as *mut u8,
                    std::mem::size_of::<libc::timeval>(),
                );
                tv.assume_init()
            };
            return Some(std::time::Duration::new(
                tv.tv_sec as u64,
                (tv.tv_usec as u32) * 1000,
            ));
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(mhdr, cmsg) };
    }
    None
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

    /// SO_TIMESTAMP and SCM_TIMESTAMP must both equal 29 on Linux.
    #[test]
    fn so_timestamp_constant_value() {
        assert_eq!(SO_TIMESTAMP, 29);
        assert_eq!(SCM_TIMESTAMP, 29);
    }

    /// `extract_so_timestamp` must return `None` when `msg_controllen` is zero
    /// (i.e. no ancillary data present), exercising the fallback path.
    #[test]
    fn extract_so_timestamp_empty_returns_none() {
        let mhdr: libc::msghdr = unsafe { std::mem::zeroed() };
        assert!(extract_so_timestamp(&mhdr).is_none());
    }

    #[test]
    fn libc_fcntl_constants_present() {
        let _f_getfl = libc::F_GETFL;
        let _f_setfl = libc::F_SETFL;
        let _o_nonblock = libc::O_NONBLOCK;
    }
}
