//! Linux live capture via AF_PACKET raw socket + SO_ATTACH_FILTER.
//!
//! Uses a pre-allocated receive buffer to avoid per-packet heap allocation.
//! The kernel applies the cBPF filter before copying, so only matching
//! packets reach userspace.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::error::{Error, Result};
use crate::packet::{LinkType, Packet};

// Linux socket constants not always exposed by std
const AF_PACKET: libc::c_int = 17;
const ETH_P_ALL: u16 = 0x0003;
const SOL_SOCKET: libc::c_int = 1;
const SO_ATTACH_FILTER: libc::c_int = 26;
const SOL_PACKET: libc::c_int = 263;
#[allow(dead_code)] // Reserved for future TPACKET_V3 ring-buffer support (ADR 0002).
const PACKET_VERSION: libc::c_int = 10;
const SIOCGIFINDEX: libc::c_ulong = 0x8933;

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
        })
    }

    pub fn link_type(&self) -> LinkType {
        self.link_type
    }

    /// Block until the next packet arrives and return it.
    pub fn next_packet(&mut self) -> Result<Packet> {
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

            let data = self.buf[..n].to_vec();
            return Ok(Packet::new(
                data,
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
