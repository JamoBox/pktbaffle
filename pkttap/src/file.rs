//! pcap / pcapng file reading via the `pcap-file` crate.
//!
//! The BPF VM (pktbaffle `vm` feature) applies the filter in userspace
//! against each packet's raw bytes.
//!
//! Each packet's bytes are copied once into a reusable `scratch` buffer and
//! yielded as a borrowed [`PacketRef`]. The buffer grows to the largest packet
//! seen and is then reused, so steady-state capture performs no per-packet heap
//! allocation. (`pcap-file` itself reads into a reused internal buffer and would
//! let us borrow directly, but the filter-skip loop here would then hit the
//! borrow checker's lending limitation; copying into our own buffer keeps the
//! code in safe Rust.)

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::Block;
use pcap_file::pcapng::PcapNgReader;

use crate::capture::{compile_filter, FilterSpec};
use crate::codec::datalink_to_link_type;
use crate::error::{Error, Result};
use crate::packet::{LinkType, PacketRef};

/// Copy index metadata for one packet read into the scratch buffer: the number
/// of bytes written plus its timestamp, on-wire length, and link type. Returned
/// (Copy) instead of a borrow so the `PacketRef` slice is built only at the
/// caller's return point.
#[derive(Clone, Copy)]
struct PktMeta {
    len: usize,
    ts_sec: u64,
    ts_nsec: u32,
    orig_len: u32,
    link_type: LinkType,
}

enum Inner {
    Pcap(PcapReader<BufReader<File>>),
    PcapNg(PcapNgReader<BufReader<File>>),
}

pub struct FileCapture {
    inner: Inner,
    filter: Option<pktbaffle::bpf::Program>,
    link_type: LinkType,
    /// Link types indexed by pcapng interface ID (populated as IDBs are read).
    idb_link_types: Vec<LinkType>,
    /// Reusable per-packet byte buffer that yielded `PacketRef`s borrow from.
    scratch: Vec<u8>,
}

impl FileCapture {
    pub fn open(path: &Path, filter: Option<FilterSpec>) -> Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        use std::io::BufRead;
        let mut reader = reader;
        let magic = {
            let buf = reader.fill_buf().map_err(Error::Io)?;
            if buf.len() < 4 {
                return Err(Error::Platform("file too short".into()));
            }
            [buf[0], buf[1], buf[2], buf[3]]
        };

        let is_pcapng = magic == [0x0A, 0x0D, 0x0D, 0x0A];

        if is_pcapng {
            let ng = PcapNgReader::new(reader).map_err(Error::Pcap)?;
            // IDB link types are discovered as blocks are read; Ethernet is used
            // as the compilation default since the SHB carries no global DLT.
            let link_type = LinkType::Ethernet;
            let compiled = compile_filter(filter, link_type)?;
            Ok(Self {
                inner: Inner::PcapNg(ng),
                filter: compiled,
                link_type,
                idb_link_types: Vec::new(),
                scratch: Vec::new(),
            })
        } else {
            let pcap = PcapReader::new(reader).map_err(Error::Pcap)?;
            let link_type = datalink_to_link_type(pcap.header().datalink);
            let compiled = compile_filter(filter, link_type)?;
            Ok(Self {
                inner: Inner::Pcap(pcap),
                filter: compiled,
                link_type,
                idb_link_types: Vec::new(),
                scratch: Vec::new(),
            })
        }
    }

    pub fn link_type(&self) -> LinkType {
        self.link_type
    }

    /// Returns the next matching packet, or `None` at EOF.
    pub fn next_packet(&mut self) -> Result<Option<PacketRef<'_>>> {
        loop {
            // Read the next packet's bytes into `self.scratch`, returning Copy
            // metadata. `self.inner` and `self.scratch` are disjoint fields, so
            // borrowing the reader and writing the buffer at once is fine.
            let meta = match &mut self.inner {
                Inner::Pcap(r) => fetch_pcap(r, &mut self.scratch, self.link_type)?,
                Inner::PcapNg(r) => fetch_pcapng(r, &mut self.scratch, &mut self.idb_link_types)?,
            };
            let Some(meta) = meta else { return Ok(None) };

            // self.inner is no longer borrowed here, so we can borrow self.filter.
            // On a filter miss we `continue`, which never holds the slice below —
            // so the borrowed PacketRef is created only on the return path.
            if let Some(prog) = &self.filter {
                if !prog.matches(&self.scratch[..meta.len]) {
                    continue;
                }
            }

            return Ok(Some(PacketRef::new(
                &self.scratch[..meta.len],
                meta.ts_sec,
                meta.ts_nsec,
                meta.orig_len,
                meta.link_type,
            )));
        }
    }
}

/// Copy `src` into `scratch` (reusing its capacity) and return the byte count.
fn fill_scratch(scratch: &mut Vec<u8>, src: &[u8]) -> usize {
    scratch.clear();
    scratch.extend_from_slice(src);
    scratch.len()
}

fn fetch_pcap(
    r: &mut PcapReader<BufReader<File>>,
    scratch: &mut Vec<u8>,
    link_type: LinkType,
) -> Result<Option<PktMeta>> {
    match r.next_packet() {
        None => Ok(None),
        Some(Err(e)) => Err(Error::Pcap(e)),
        Some(Ok(pkt)) => {
            let ts = pkt.timestamp;
            let len = fill_scratch(scratch, &pkt.data);
            Ok(Some(PktMeta {
                len,
                ts_sec: ts.as_secs(),
                ts_nsec: ts.subsec_nanos(),
                orig_len: pkt.orig_len,
                link_type,
            }))
        }
    }
}

fn fetch_pcapng(
    r: &mut PcapNgReader<BufReader<File>>,
    scratch: &mut Vec<u8>,
    idb_types: &mut Vec<LinkType>,
) -> Result<Option<PktMeta>> {
    loop {
        match r.next_block() {
            None => return Ok(None),
            Some(Err(e)) => return Err(Error::Pcap(e)),
            Some(Ok(block)) => match block {
                Block::InterfaceDescription(idb) => {
                    idb_types.push(datalink_to_link_type(idb.linktype));
                    continue;
                }
                Block::EnhancedPacket(epb) => {
                    let link_type = idb_types
                        .get(epb.interface_id as usize)
                        .copied()
                        .unwrap_or(LinkType::Ethernet);
                    let ts = epb.timestamp;
                    let len = fill_scratch(scratch, &epb.data);
                    return Ok(Some(PktMeta {
                        len,
                        ts_sec: ts.as_secs(),
                        ts_nsec: ts.subsec_nanos(),
                        orig_len: epb.original_len,
                        link_type,
                    }));
                }
                Block::SimplePacket(spb) => {
                    let link_type = idb_types.first().copied().unwrap_or(LinkType::Ethernet);
                    let len = fill_scratch(scratch, &spb.data);
                    return Ok(Some(PktMeta {
                        len,
                        ts_sec: 0,
                        ts_nsec: 0,
                        orig_len: spb.original_len,
                        link_type,
                    }));
                }
                Block::Packet(pb) => {
                    let link_type = idb_types
                        .get(pb.interface_id as usize)
                        .copied()
                        .unwrap_or(LinkType::Ethernet);
                    // PacketBlock timestamp is in microseconds since epoch
                    let ts_usec = pb.timestamp;
                    let len = fill_scratch(scratch, &pb.data);
                    return Ok(Some(PktMeta {
                        len,
                        ts_sec: ts_usec / 1_000_000,
                        ts_nsec: ((ts_usec % 1_000_000) * 1000) as u32,
                        orig_len: pb.original_len,
                        link_type,
                    }));
                }
                _ => continue,
            },
        }
    }
}
