//! macOS live capture via /dev/bpf* character devices + BIOCSETF.
//!
//! The kernel applies the cBPF filter via BIOCSETF before returning data,
//! so only matching packets reach userspace. Each read() returns one or more
//! BPF-framed packets; we parse the bpf_hdr prefix from each.

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::error::{Error, Result};
use crate::packet::{LinkType, Packet};

// BPF ioctl codes (macOS)
const BIOCSETIF: libc::c_ulong = 0x8020426c;
const BIOCSETF: libc::c_ulong = 0x80104267;
const BIOCIMMEDIATE: libc::c_ulong = 0x80044270;
const BIOCPROMISC: libc::c_ulong = 0x20004269;
const BIOCGBLEN: libc::c_ulong = 0x40044266;
const BIOCGDLT: libc::c_ulong = 0x4004426a;

/// Query the link type of an interface using getifaddrs / AF_LINK.
/// This is a pre-open estimate; BIOCGDLT (called inside open()) is authoritative.
pub fn query_link_type(iface: &str) -> Result<LinkType> {
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    let rc = unsafe { libc::getifaddrs(&mut ifap) };
    if rc < 0 {
        return Err(super::io_err());
    }
    let mut result = LinkType::Ethernet;
    let mut cur = ifap;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_string_lossy();
        if name == iface && !ifa.ifa_addr.is_null() {
            let sa_family = unsafe { (*ifa.ifa_addr).sa_family } as libc::c_int;
            if sa_family == libc::AF_LINK {
                let sdl = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_dl) };
                // IFT_ETHER=0x06; everything else defaults to Ethernet since
                // DLT_NULL (loopback) is not yet supported in pktbaffle codegen.
                result = if sdl.sdl_type == 0x06 {
                    LinkType::Ethernet
                } else {
                    LinkType::Ethernet
                };
                break;
            }
        }
        cur = ifa.ifa_next;
    }
    unsafe { libc::freeifaddrs(ifap) };
    Ok(result)
}

#[repr(C)]
struct BpfProgram {
    bf_len: u32,
    bf_insns: *const pktbaffle::bpf::Insn,
}

/// bpf_hdr as laid out on macOS (timeval is 2×i64 on 64-bit)
#[repr(C)]
struct BpfHdr {
    bh_tstamp_sec: i64,
    bh_tstamp_usec: i64,
    bh_caplen: u32,
    bh_datalen: u32,
    bh_hdrlen: u16,
}

pub struct MacosLive {
    fd: OwnedFd,
    buf: Vec<u8>,
    buf_filled: usize,
    buf_pos: usize,
    snaplen: usize,
    link_type: LinkType,
}

impl MacosLive {
    pub fn open(
        iface: &str,
        filter: Option<&pktbaffle::bpf::Program>,
        snaplen: u32,
        promiscuous: bool,
    ) -> Result<Self> {
        let fd = open_bpf_device()?;

        // Set immediate mode so read() returns as soon as a packet arrives
        let one: libc::c_uint = 1;
        let rc = unsafe { libc::ioctl(fd.as_raw_fd(), BIOCIMMEDIATE, &one) };
        if rc < 0 {
            return Err(super::io_err());
        }

        // Bind to interface
        let iface_c =
            CString::new(iface).map_err(|_| Error::Platform("invalid interface name".into()))?;
        let mut ifreq: libc::ifreq = unsafe { std::mem::zeroed() };
        let bytes = iface_c.as_bytes_with_nul();
        for (i, &b) in bytes.iter().enumerate().take(libc::IFNAMSIZ) {
            ifreq.ifr_name[i] = b as libc::c_char;
        }
        let rc = unsafe { libc::ioctl(fd.as_raw_fd(), BIOCSETIF, &ifreq) };
        if rc < 0 {
            return Err(super::io_err());
        }

        // Query the actual data link type from the kernel (authoritative)
        let mut dlt: libc::c_uint = 0;
        let dlt_rc = unsafe { libc::ioctl(fd.as_raw_fd(), BIOCGDLT, &mut dlt) };
        let link_type = if dlt_rc >= 0 {
            super::dlt_to_link_type(dlt)
        } else {
            LinkType::Ethernet
        };

        // Enable promiscuous mode
        if promiscuous {
            let rc = unsafe { libc::ioctl(fd.as_raw_fd(), BIOCPROMISC) };
            if rc < 0 {
                return Err(super::io_err());
            }
        }

        // Attach BPF filter
        if let Some(prog) = filter {
            let insns = prog.instructions();
            let bpf_prog = BpfProgram {
                bf_len: insns.len() as u32,
                bf_insns: insns.as_ptr(),
            };
            let rc = unsafe { libc::ioctl(fd.as_raw_fd(), BIOCSETF, &bpf_prog) };
            if rc < 0 {
                return Err(super::io_err());
            }
        }

        // Query kernel buffer size
        let mut kbuf_len: libc::c_uint = 0;
        unsafe { libc::ioctl(fd.as_raw_fd(), BIOCGBLEN, &mut kbuf_len) };
        let buf_size = (kbuf_len as usize).max(snaplen as usize).max(65535);

        Ok(Self {
            fd,
            buf: vec![0u8; buf_size],
            buf_filled: 0,
            buf_pos: 0,
            snaplen: snaplen as usize,
            link_type,
        })
    }

    pub fn link_type(&self) -> LinkType {
        self.link_type
    }

    pub fn next_packet(&mut self) -> Result<Packet> {
        loop {
            // If there's data remaining in the buffer, parse the next BPF frame
            if self.buf_pos < self.buf_filled {
                if let Some(pkt) = self.parse_next_frame() {
                    return Ok(pkt);
                }
            }

            // Read a fresh batch from the BPF device
            let n = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    self.buf.as_mut_ptr() as *mut libc::c_void,
                    self.buf.len(),
                )
            };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e.into());
            }
            self.buf_filled = n as usize;
            self.buf_pos = 0;
        }
    }

    fn parse_next_frame(&mut self) -> Option<Packet> {
        let hdr_size = std::mem::size_of::<BpfHdr>();
        if self.buf_pos + hdr_size > self.buf_filled {
            return None;
        }
        let hdr = unsafe {
            std::ptr::read_unaligned(self.buf.as_ptr().add(self.buf_pos) as *const BpfHdr)
        };
        let data_start = self.buf_pos + hdr.bh_hdrlen as usize;
        let cap = (hdr.bh_caplen as usize).min(self.snaplen);
        let data_end = data_start + cap;
        if data_end > self.buf_filled {
            return None;
        }
        let data = self.buf[data_start..data_end].to_vec();

        // Advance past this frame (BPF frames are word-aligned)
        let frame_len = hdr.bh_hdrlen as usize + hdr.bh_caplen as usize;
        self.buf_pos += word_align(frame_len);

        Some(Packet::new(
            data,
            hdr.bh_tstamp_sec as u64,
            hdr.bh_tstamp_usec as u32 * 1000,
            hdr.bh_datalen,
            self.link_type,
        ))
    }
}

/// Open the first available /dev/bpfN device.
fn open_bpf_device() -> Result<OwnedFd> {
    for n in 0..256 {
        let path = CString::new(format!("/dev/bpf{n}")).unwrap();
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
        if fd >= 0 {
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        let errno = unsafe { *libc::__error() };
        if errno == libc::EBUSY {
            continue;
        }
        break;
    }
    Err(Error::Platform("no available /dev/bpf device found".into()))
}

#[inline]
fn word_align(n: usize) -> usize {
    (n + 3) & !3
}

/// List network interfaces via getifaddrs.
pub fn list_interfaces() -> Result<Vec<String>> {
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    let rc = unsafe { libc::getifaddrs(&mut ifap) };
    if rc < 0 {
        return Err(super::io_err());
    }
    let mut names = Vec::new();
    let mut cur = ifap;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        if !names.contains(&name) {
            names.push(name);
        }
        cur = ifa.ifa_next;
    }
    unsafe { libc::freeifaddrs(ifap) };
    Ok(names)
}

/// Return the default interface for live capture: the first non-loopback
/// interface reported by getifaddrs. Loopback interfaces are named lo, lo0, etc.
pub fn default_interface() -> Result<String> {
    list_interfaces()?
        .into_iter()
        .find(|name| !name.starts_with("lo"))
        .ok_or_else(|| Error::Platform("no non-loopback interface found".into()))
}
