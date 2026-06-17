//! macOS live capture via /dev/bpf* character devices + BIOCSETF.
//!
//! The kernel applies the cBPF filter via BIOCSETF before returning data,
//! so only matching packets reach userspace. Each read() returns one or more
//! BPF-framed packets; we parse the bpf_hdr prefix from each.

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::error::{Error, Result};
use crate::packet::{LinkType, PacketRef};

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

    pub fn next_packet(&mut self) -> Result<PacketRef<'_>> {
        let link_type = self.link_type;
        loop {
            // If there's data remaining in the buffer, parse the next BPF frame.
            // parse_next_frame returns Copy index metadata (not a borrow), so the
            // PacketRef's slice is created only here on the return path — the
            // fall-through to read() below never holds it. This keeps the lending
            // iterator in safe Rust (see ADR 0002).
            if self.buf_pos < self.buf_filled {
                if let Some(meta) = self.parse_next_frame() {
                    return Ok(PacketRef::new(
                        &self.buf[meta.start..meta.end],
                        meta.ts_sec,
                        meta.ts_nsec,
                        meta.orig_len,
                        link_type,
                    ));
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

    /// Parse the BPF frame at `buf_pos`, returning Copy index metadata and
    /// advancing `buf_pos` past the (word-aligned) frame. Returns `None` if the
    /// remaining buffer does not hold a complete frame, signalling the caller to
    /// read a fresh batch. Delegates the pure offset arithmetic to
    /// [`parse_bpf_frame`] so it can be unit-tested without a BPF device.
    fn parse_next_frame(&mut self) -> Option<FrameMeta> {
        let (meta, next_pos) =
            parse_bpf_frame(&self.buf, self.buf_pos, self.buf_filled, self.snaplen)?;
        self.buf_pos = next_pos;
        Some(meta)
    }
}

/// Copy index metadata for a single parsed BPF frame: the buffer byte range
/// holding the packet plus its timestamp and on-wire length. Returned instead of
/// a borrow so the `PacketRef` slice is constructed only at the caller's return.
#[derive(Clone, Copy)]
struct FrameMeta {
    start: usize,
    end: usize,
    ts_sec: u64,
    ts_nsec: u32,
    orig_len: u32,
}

/// Pure parser for the BPF frame at `buf[pos..filled]`. Returns the frame's
/// index metadata and the word-aligned buffer position of the next frame, or
/// `None` when the remaining bytes do not contain a complete header + caplen
/// payload. Side-effect-free so it can be exercised by unit tests against a
/// synthetic buffer.
fn parse_bpf_frame(
    buf: &[u8],
    pos: usize,
    filled: usize,
    snaplen: usize,
) -> Option<(FrameMeta, usize)> {
    let hdr_size = std::mem::size_of::<BpfHdr>();
    if pos + hdr_size > filled {
        return None;
    }
    let hdr = unsafe { std::ptr::read_unaligned(buf.as_ptr().add(pos) as *const BpfHdr) };
    let data_start = pos + hdr.bh_hdrlen as usize;
    let cap = (hdr.bh_caplen as usize).min(snaplen);
    let data_end = data_start + cap;
    if data_end > filled {
        return None;
    }

    // Advance past this frame (BPF frames are word-aligned).
    let frame_len = hdr.bh_hdrlen as usize + hdr.bh_caplen as usize;
    let next_pos = pos + word_align(frame_len);

    Some((
        FrameMeta {
            start: data_start,
            end: data_end,
            ts_sec: hdr.bh_tstamp_sec as u64,
            ts_nsec: hdr.bh_tstamp_usec as u32 * 1000,
            orig_len: hdr.bh_datalen,
        },
        next_pos,
    ))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialize one BPF frame (header + payload, word-aligned) the way the
    /// kernel lays it out in the read buffer. `bh_hdrlen` is set to the struct
    /// size so the payload begins immediately after the header.
    fn frame_bytes(sec: i64, usec: i64, datalen: u32, payload: &[u8]) -> Vec<u8> {
        let hdr_size = std::mem::size_of::<BpfHdr>();
        let hdr = BpfHdr {
            bh_tstamp_sec: sec,
            bh_tstamp_usec: usec,
            bh_caplen: payload.len() as u32,
            bh_datalen: datalen,
            bh_hdrlen: hdr_size as u16,
        };
        let mut out = vec![0u8; hdr_size];
        unsafe {
            std::ptr::copy_nonoverlapping(
                &hdr as *const BpfHdr as *const u8,
                out.as_mut_ptr(),
                hdr_size,
            );
        }
        out.extend_from_slice(payload);
        out.resize(word_align(hdr_size + payload.len()), 0); // trailing alignment padding
        out
    }

    #[test]
    fn parses_single_frame() {
        let hdr_size = std::mem::size_of::<BpfHdr>();
        let payload = [0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let buf = frame_bytes(1234, 567_000, 5, &payload);

        let (meta, next_pos) = parse_bpf_frame(&buf, 0, buf.len(), 65535).expect("frame");
        assert_eq!(&buf[meta.start..meta.end], &payload);
        assert_eq!(meta.start, hdr_size);
        assert_eq!(meta.end, hdr_size + 5);
        assert_eq!(meta.ts_sec, 1234);
        assert_eq!(meta.ts_nsec, 567_000 * 1000);
        assert_eq!(meta.orig_len, 5);
        assert_eq!(next_pos, word_align(hdr_size + 5));
    }

    #[test]
    fn walks_two_frames_in_one_batch() {
        let p1 = [1u8, 2, 3];
        let p2 = [9u8, 8, 7, 6, 5];
        let mut buf = frame_bytes(10, 0, 3, &p1);
        buf.extend(frame_bytes(20, 0, 5, &p2));
        let filled = buf.len();

        let (m1, next) = parse_bpf_frame(&buf, 0, filled, 65535).expect("frame 1");
        assert_eq!(&buf[m1.start..m1.end], &p1);
        assert_eq!(m1.ts_sec, 10);

        let (m2, _) = parse_bpf_frame(&buf, next, filled, 65535).expect("frame 2");
        assert_eq!(&buf[m2.start..m2.end], &p2);
        assert_eq!(m2.ts_sec, 20);
    }

    #[test]
    fn snaplen_truncates_captured_range() {
        let payload = [0u8; 100];
        let buf = frame_bytes(0, 0, 100, &payload);
        let (meta, _) = parse_bpf_frame(&buf, 0, buf.len(), 20).expect("frame");
        // Captured range is clamped to snaplen; orig_len still reflects datalen.
        assert_eq!(meta.end - meta.start, 20);
        assert_eq!(meta.orig_len, 100);
    }

    #[test]
    fn incomplete_header_returns_none() {
        let buf = frame_bytes(0, 0, 4, &[1, 2, 3, 4]);
        // Pretend the kernel only filled the first few bytes of the header.
        assert!(parse_bpf_frame(&buf, 0, 4, 65535).is_none());
    }

    #[test]
    fn payload_past_filled_returns_none() {
        let hdr_size = std::mem::size_of::<BpfHdr>();
        let buf = frame_bytes(0, 0, 10, &[0u8; 10]);
        // Header is complete but the claimed caplen runs past `filled`.
        assert!(parse_bpf_frame(&buf, 0, hdr_size + 4, 65535).is_none());
    }
}
