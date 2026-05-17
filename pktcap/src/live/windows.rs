//! Windows live capture via Npcap (dynamically loaded wpcap.dll).
//!
//! wpcap.dll is loaded at first use from the Npcap install path
//! (%SystemRoot%\System32\Npcap\) with a fallback to the system directory.
//! The binary compiles and starts without Npcap present; open() and
//! list_interfaces() return a clear error if the DLL cannot be found.
//!
//! See ADR 0003.

use std::ffi::{CStr, CString};
use std::slice;
use std::sync::OnceLock;

use libloading::Library;

use crate::error::{Error, Result};
use crate::packet::{LinkType, Packet};

// ── C types ──────────────────────────────────────────────────────────────────

const PCAP_ERRBUF_SIZE: usize = 256;

// Opaque pcap session handle.
#[repr(C)]
struct PcapT {
    _opaque: u8,
}

// struct timeval on Windows: both fields are long (32-bit).
#[repr(C)]
struct Timeval {
    tv_sec: i32,
    tv_usec: i32,
}

// Packet header returned by pcap_next_ex.
#[repr(C)]
struct PcapPkthdr {
    ts: Timeval,
    caplen: u32,
    len: u32,
}

// Passed to pcap_setfilter — same layout as Linux sock_fprog / macOS bpf_program.
#[repr(C)]
struct BpfProgram {
    bf_len: u32,
    bf_insns: *const pktbaffle::bpf::Insn,
}

// Linked list of interfaces returned by pcap_findalldevs.
#[repr(C)]
struct PcapIf {
    next: *mut PcapIf,
    name: *const i8,
    description: *const i8,
    addresses: *mut u8, // pcap_addr_t* — not inspected
    flags: u32,
}


// ── Dynamic function table ────────────────────────────────────────────────────

struct NpcapLib {
    // Kept alive so the DLL is not unloaded while the function pointers live.
    _lib: Library,
    pcap_open_live:
        unsafe extern "C" fn(*const i8, i32, i32, i32, *mut i8) -> *mut PcapT,
    pcap_close: unsafe extern "C" fn(*mut PcapT),
    pcap_setfilter: unsafe extern "C" fn(*mut PcapT, *mut BpfProgram) -> i32,
    pcap_datalink: unsafe extern "C" fn(*mut PcapT) -> i32,
    pcap_next_ex:
        unsafe extern "C" fn(*mut PcapT, *mut *const PcapPkthdr, *mut *const u8) -> i32,
    pcap_findalldevs: unsafe extern "C" fn(*mut *mut PcapIf, *mut i8) -> i32,
    pcap_freealldevs: unsafe extern "C" fn(*mut PcapIf),
    pcap_geterr: unsafe extern "C" fn(*mut PcapT) -> *const i8,
}

// SAFETY: Library and raw fn pointers are both Send+Sync on Windows.
unsafe impl Send for NpcapLib {}
unsafe impl Sync for NpcapLib {}

impl NpcapLib {
    fn load() -> std::result::Result<Self, String> {
        let lib = load_wpcap_dll().map_err(|e| e.to_string())?;
        unsafe {
            macro_rules! sym {
                ($name:literal, $ty:ty) => {
                    *lib.get::<$ty>($name)
                        .map_err(|e| format!("wpcap.dll missing {}: {e}", stringify!($name)))?
                };
            }
            let pcap_open_live = sym!(
                b"pcap_open_live\0",
                unsafe extern "C" fn(*const i8, i32, i32, i32, *mut i8) -> *mut PcapT
            );
            let pcap_close =
                sym!(b"pcap_close\0", unsafe extern "C" fn(*mut PcapT));
            let pcap_setfilter = sym!(
                b"pcap_setfilter\0",
                unsafe extern "C" fn(*mut PcapT, *mut BpfProgram) -> i32
            );
            let pcap_datalink =
                sym!(b"pcap_datalink\0", unsafe extern "C" fn(*mut PcapT) -> i32);
            let pcap_next_ex = sym!(
                b"pcap_next_ex\0",
                unsafe extern "C" fn(
                    *mut PcapT,
                    *mut *const PcapPkthdr,
                    *mut *const u8,
                ) -> i32
            );
            let pcap_findalldevs = sym!(
                b"pcap_findalldevs\0",
                unsafe extern "C" fn(*mut *mut PcapIf, *mut i8) -> i32
            );
            let pcap_freealldevs =
                sym!(b"pcap_freealldevs\0", unsafe extern "C" fn(*mut PcapIf));
            let pcap_geterr =
                sym!(b"pcap_geterr\0", unsafe extern "C" fn(*mut PcapT) -> *const i8);

            Ok(NpcapLib {
                _lib: lib,
                pcap_open_live,
                pcap_close,
                pcap_setfilter,
                pcap_datalink,
                pcap_next_ex,
                pcap_findalldevs,
                pcap_freealldevs,
                pcap_geterr,
            })
        }
    }
}

fn load_wpcap_dll() -> std::result::Result<Library, libloading::Error> {
    // Try Npcap's dedicated directory first, then the system directory (WinPcap
    // legacy / manually placed DLL), then bare name (PATH lookup).
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let candidates = [
        format!("{system_root}\\System32\\Npcap\\wpcap.dll"),
        format!("{system_root}\\System32\\wpcap.dll"),
        "wpcap.dll".to_owned(),
    ];
    let mut last_err = None;
    for path in &candidates {
        match unsafe { Library::new(path) } {
            Ok(lib) => return Ok(lib),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap())
}

static NPCAP: OnceLock<std::result::Result<NpcapLib, String>> = OnceLock::new();

fn npcap() -> Result<&'static NpcapLib> {
    NPCAP
        .get_or_init(NpcapLib::load)
        .as_ref()
        .map_err(|e| Error::Platform(format!("Npcap not available: {e}")))
}

// ── Interface helpers ─────────────────────────────────────────────────────────

/// Walk the pcap_if_t list and return the device's internal name for `iface`.
///
/// Matches first by description (case-insensitive), then by name. If `iface`
/// starts with `\Device\` it is returned as-is (raw device path escape hatch).
unsafe fn resolve_device_name(alldevs: *mut PcapIf, iface: &str) -> Option<String> {
    if iface.starts_with("\\Device\\") || iface.starts_with("\\\\Device\\") {
        return Some(iface.to_owned());
    }
    let iface_lower = iface.to_lowercase();
    let mut cur = alldevs;
    while !cur.is_null() {
        let dev = &*cur;
        let name = if dev.name.is_null() {
            String::new()
        } else {
            CStr::from_ptr(dev.name).to_string_lossy().into_owned()
        };
        let desc = if dev.description.is_null() {
            String::new()
        } else {
            CStr::from_ptr(dev.description)
                .to_string_lossy()
                .into_owned()
        };
        if desc.to_lowercase() == iface_lower || name.to_lowercase() == iface_lower {
            return Some(name);
        }
        cur = dev.next;
    }
    None
}

/// Open a temporary pcap handle, run `f`, close it. Used by query_link_type.
unsafe fn with_temp_handle<T>(
    lib: &NpcapLib,
    device: &CString,
    f: impl FnOnce(*mut PcapT) -> T,
) -> Result<T> {
    let mut errbuf = [0i8; PCAP_ERRBUF_SIZE];
    let handle = (lib.pcap_open_live)(
        device.as_ptr(),
        65535,
        0,  // non-promiscuous
        100,
        errbuf.as_mut_ptr(),
    );
    if handle.is_null() {
        let msg = CStr::from_ptr(errbuf.as_ptr())
            .to_string_lossy()
            .into_owned();
        return Err(Error::Platform(format!("pcap_open_live failed: {msg}")));
    }
    let result = f(handle);
    (lib.pcap_close)(handle);
    Ok(result)
}

fn alldevs_to_vec(lib: &NpcapLib) -> Result<(*mut PcapIf, Vec<String>)> {
    let mut alldevs: *mut PcapIf = std::ptr::null_mut();
    let mut errbuf = [0i8; PCAP_ERRBUF_SIZE];
    let rc = unsafe { (lib.pcap_findalldevs)(&mut alldevs, errbuf.as_mut_ptr()) };
    if rc < 0 {
        let msg = unsafe { CStr::from_ptr(errbuf.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        return Err(Error::Platform(format!("pcap_findalldevs failed: {msg}")));
    }
    let mut names = Vec::new();
    let mut cur = alldevs;
    while !cur.is_null() {
        let dev = unsafe { &*cur };
        let friendly = if !dev.description.is_null() {
            unsafe { CStr::from_ptr(dev.description) }
                .to_string_lossy()
                .into_owned()
        } else if !dev.name.is_null() {
            unsafe { CStr::from_ptr(dev.name) }
                .to_string_lossy()
                .into_owned()
        } else {
            String::new()
        };
        if !friendly.is_empty() {
            names.push(friendly);
        }
        cur = dev.next;
    }
    Ok((alldevs, names))
}

// ── Public API ────────────────────────────────────────────────────────────────

pub struct WindowsLive {
    // SAFETY: pcap_t is not aliased; we only access it through &mut self.
    handle: *mut PcapT,
    snaplen: usize,
    link_type: LinkType,
}

unsafe impl Send for WindowsLive {}

impl WindowsLive {
    pub fn open(
        iface: &str,
        filter: Option<&pktbaffle::bpf::Program>,
        snaplen: u32,
        promiscuous: bool,
    ) -> Result<Self> {
        let lib = npcap()?;

        let (alldevs, _) = alldevs_to_vec(lib)?;
        let device_name = unsafe { resolve_device_name(alldevs, iface) };
        unsafe { (lib.pcap_freealldevs)(alldevs) };

        let device_name = device_name.ok_or_else(|| {
            Error::Platform(format!("interface not found: {iface}"))
        })?;
        let device_c = CString::new(device_name)
            .map_err(|_| Error::Platform("invalid interface name".into()))?;

        let mut errbuf = [0i8; PCAP_ERRBUF_SIZE];
        let handle = unsafe {
            (lib.pcap_open_live)(
                device_c.as_ptr(),
                snaplen as i32,
                if promiscuous { 1 } else { 0 },
                100, // 100 ms read timeout; next_packet loops on timeout
                errbuf.as_mut_ptr(),
            )
        };
        if handle.is_null() {
            let msg = unsafe { CStr::from_ptr(errbuf.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            return Err(Error::Platform(format!("pcap_open_live failed: {msg}")));
        }

        let dlt = unsafe { (lib.pcap_datalink)(handle) };
        let link_type = super::dlt_to_link_type(dlt as u32);

        if let Some(prog) = filter {
            let insns = prog.instructions();
            let mut bpf_prog = BpfProgram {
                bf_len: insns.len() as u32,
                bf_insns: insns.as_ptr(),
            };
            let rc = unsafe { (lib.pcap_setfilter)(handle, &mut bpf_prog) };
            if rc < 0 {
                let msg = unsafe {
                    CStr::from_ptr((lib.pcap_geterr)(handle))
                        .to_string_lossy()
                        .into_owned()
                };
                unsafe { (lib.pcap_close)(handle) };
                return Err(Error::Platform(format!("pcap_setfilter failed: {msg}")));
            }
        }

        Ok(Self {
            handle,
            snaplen: snaplen as usize,
            link_type,
        })
    }

    pub fn link_type(&self) -> LinkType {
        self.link_type
    }

    pub fn next_packet(&mut self) -> Result<Packet> {
        let lib = npcap()?;
        loop {
            let mut hdr_ptr: *const PcapPkthdr = std::ptr::null();
            let mut data_ptr: *const u8 = std::ptr::null();
            let rc = unsafe {
                (lib.pcap_next_ex)(self.handle, &mut hdr_ptr, &mut data_ptr)
            };
            match rc {
                1 => {
                    let hdr = unsafe { &*hdr_ptr };
                    let cap = (hdr.caplen as usize).min(self.snaplen);
                    let data =
                        unsafe { slice::from_raw_parts(data_ptr, cap).to_vec() };
                    return Ok(Packet::new(
                        data,
                        hdr.ts.tv_sec as u64,
                        hdr.ts.tv_usec as u32 * 1000,
                        hdr.len,
                        self.link_type,
                    ));
                }
                0 => continue, // read timeout, no packet — retry
                _ => {
                    let msg = unsafe {
                        CStr::from_ptr((lib.pcap_geterr)(self.handle))
                            .to_string_lossy()
                            .into_owned()
                    };
                    return Err(Error::Platform(format!("pcap_next_ex failed: {msg}")));
                }
            }
        }
    }
}

impl Drop for WindowsLive {
    fn drop(&mut self) {
        if let Ok(lib) = npcap() {
            unsafe { (lib.pcap_close)(self.handle) };
        }
    }
}

/// Query the link type by opening a temporary capture handle and reading the DLT.
pub fn query_link_type(iface: &str) -> Result<LinkType> {
    let lib = npcap()?;

    let (alldevs, _) = alldevs_to_vec(lib)?;
    let device_name = unsafe { resolve_device_name(alldevs, iface) };
    unsafe { (lib.pcap_freealldevs)(alldevs) };

    let device_name = device_name.ok_or_else(|| {
        Error::Platform(format!("interface not found: {iface}"))
    })?;
    let device_c = CString::new(device_name)
        .map_err(|_| Error::Platform("invalid interface name".into()))?;

    let dlt = unsafe {
        with_temp_handle(lib, &device_c, |h| (lib.pcap_datalink)(h))?
    };
    Ok(super::dlt_to_link_type(dlt as u32))
}

/// List available network interfaces by their friendly names.
pub fn list_interfaces() -> Result<Vec<String>> {
    let lib = npcap()?;
    let (alldevs, names) = alldevs_to_vec(lib)?;
    unsafe { (lib.pcap_freealldevs)(alldevs) };
    Ok(names)
}
