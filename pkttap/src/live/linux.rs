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

    /// Block until the next packet arrives and return it.
    pub fn next_packet(&mut self) -> Result<PacketRef<'_>> {
        loop {
            let mut src: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut src_len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;

            let n = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    self.buf.as_mut_ptr() as *mut libc::c_void,
                    self.buf.len(),
                    0,
                    &mut src as *mut libc::sockaddr_ll as *mut libc::sockaddr,
                    &mut src_len,
                )
            };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e.into());
            }
            let n = n as usize;
            let orig_len = n as u32;
            let n = n.min(self.snaplen);

            // Timestamp from the socket (best effort via SO_TIMESTAMP would
            // be more accurate, but CLOCK_REALTIME is simpler for now)
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();

            // Zero-copy: borrow the receive buffer rather than allocating. The
            // EINTR `continue` path above never creates this borrow, so the
            // slice is born only on the return path — keeping the lending
            // iterator in safe Rust. A TPACKET_V3 mmap ring (which would also
            // eliminate the per-packet recvfrom syscall) is deferred; see
            // ADR 0002 and the dedicated ring-buffer issue.
            return Ok(PacketRef::new(
                &self.buf[..n],
                now.as_secs(),
                now.subsec_nanos(),
                orig_len,
                self.link_type,
            ));
        }
    }
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
}
