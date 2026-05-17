//! pcap / pcapng file reading via the `pcap-file` crate.
//!
//! The BPF VM (pktbaffle `vm` feature) applies the filter in userspace
//! against each packet's raw bytes.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::Block;
use pcap_file::pcapng::PcapNgReader;
use pcap_file::DataLink;

use pktbaffle::{compile, Target};

use crate::capture::FilterSpec;
use crate::error::{Error, Result};
use crate::packet::{LinkType, Packet};

fn datalink_to_link_type(dl: DataLink) -> LinkType {
    match dl {
        DataLink::ETHERNET => LinkType::Ethernet,
        DataLink::RAW => LinkType::RawIp,
        DataLink::LINUX_SLL => LinkType::LinuxSll,
        _ => LinkType::Ethernet,
    }
}

// Intermediate owned packet data extracted from the match arm so that
// subsequent borrows of `self` are not blocked by the reader borrow.
struct RawPkt {
    data: Vec<u8>,
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
            let compiled = compile_file_filter(filter, link_type)?;
            Ok(Self {
                inner: Inner::PcapNg(ng),
                filter: compiled,
                link_type,
                idb_link_types: Vec::new(),
            })
        } else {
            let pcap = PcapReader::new(reader).map_err(Error::Pcap)?;
            let link_type = datalink_to_link_type(pcap.header().datalink);
            let compiled = compile_file_filter(filter, link_type)?;
            Ok(Self {
                inner: Inner::Pcap(pcap),
                filter: compiled,
                link_type,
                idb_link_types: Vec::new(),
            })
        }
    }

    pub fn link_type(&self) -> LinkType {
        self.link_type
    }

    /// Returns the next matching packet, or `None` at EOF.
    pub fn next_packet(&mut self) -> Result<Option<Packet>> {
        loop {
            // Extract owned data from the reader, releasing the borrow on self.inner
            // before we borrow self.filter below.
            let raw = match &mut self.inner {
                Inner::Pcap(r) => fetch_pcap(r, self.link_type)?,
                Inner::PcapNg(r) => fetch_pcapng(r, &mut self.idb_link_types)?,
            };
            let raw = match raw {
                None => return Ok(None),
                Some(r) => r,
            };

            // self.inner is no longer borrowed here, so we can borrow self.filter.
            if let Some(prog) = &self.filter {
                if !prog.matches(&raw.data) {
                    continue;
                }
            }

            return Ok(Some(Packet::new(
                raw.data,
                raw.ts_sec,
                raw.ts_nsec,
                raw.orig_len,
                raw.link_type,
            )));
        }
    }
}

fn compile_file_filter(
    spec: Option<FilterSpec>,
    link: LinkType,
) -> Result<Option<pktbaffle::bpf::Program>> {
    match spec {
        None => Ok(None),
        Some(FilterSpec::Program(p)) => Ok(Some(p)),
        Some(FilterSpec::String(s)) => {
            let prog = compile(&s, link, Target::Classic)?;
            match prog {
                pktbaffle::Program::Classic(p) => Ok(Some(p)),
                pktbaffle::Program::Extended(_) => Err(Error::Platform(
                    "unexpected eBPF program for file capture".into(),
                )),
            }
        }
    }
}

fn fetch_pcap(r: &mut PcapReader<BufReader<File>>, link_type: LinkType) -> Result<Option<RawPkt>> {
    match r.next_packet() {
        None => Ok(None),
        Some(Err(e)) => Err(Error::Pcap(e)),
        Some(Ok(pkt)) => {
            let ts = pkt.timestamp;
            Ok(Some(RawPkt {
                data: pkt.data.into_owned(),
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
    idb_types: &mut Vec<LinkType>,
) -> Result<Option<RawPkt>> {
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
                    return Ok(Some(RawPkt {
                        data: epb.data.into_owned(),
                        ts_sec: ts.as_secs(),
                        ts_nsec: ts.subsec_nanos(),
                        orig_len: epb.original_len,
                        link_type,
                    }));
                }
                Block::SimplePacket(spb) => {
                    let link_type = idb_types.first().copied().unwrap_or(LinkType::Ethernet);
                    return Ok(Some(RawPkt {
                        data: spb.data.into_owned(),
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
                    return Ok(Some(RawPkt {
                        data: pb.data.into_owned(),
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
