//! pcap / pcapng file writing via the `pcap-file` crate.
//!
//! Format is chosen by file extension: `.pcap` → classic pcap,
//! `.pcapng` → pcapng. The caller must supply a `LinkType` before
//! calling `open()`.

use std::borrow::Cow;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use pcap_file::pcapng::{Block, PcapNgWriter};
use pcap_file::DataLink;

use crate::error::{Error, Result};
use crate::packet::{LinkType, Packet};

fn link_type_to_datalink(lt: LinkType) -> DataLink {
    match lt {
        LinkType::Ethernet => DataLink::ETHERNET,
        LinkType::RawIp => DataLink::RAW,
        LinkType::LinuxSll => DataLink::LINUX_SLL,
    }
}

enum Inner {
    Pcap(PcapWriter<File>),
    PcapNg(PcapNgWriter<File>),
}

/// A packet sink that writes to a pcap or pcapng file.
///
/// Open via [`Dump::to_file`] and its builder. Write packets one at a
/// time with [`write_packet`][Dump::write_packet]. Call [`flush`][Dump::flush]
/// for explicit durability; the internal buffer is also flushed on drop.
pub struct Dump {
    inner: Inner,
}

/// Builder for a [`Dump`].
pub struct DumpBuilder {
    path: PathBuf,
    link_type: Option<LinkType>,
}

impl Dump {
    /// Begin building a file dump at `path`.
    pub fn to_file(path: impl AsRef<Path>) -> DumpBuilder {
        DumpBuilder { path: path.as_ref().to_owned(), link_type: None }
    }

    /// Write one packet to the file.
    pub fn write_packet(&mut self, pkt: &Packet) -> Result<()> {
        let ts = pkt.timestamp.duration_since(UNIX_EPOCH).unwrap_or_default();
        match &mut self.inner {
            Inner::Pcap(w) => w
                .write_packet(&PcapPacket {
                    timestamp: ts,
                    orig_len: pkt.orig_len,
                    data: Cow::Borrowed(&pkt.data),
                })
                .map(|_| ())
                .map_err(Error::Pcap),
            Inner::PcapNg(w) => w
                .write_block(&Block::EnhancedPacket(EnhancedPacketBlock {
                    interface_id: 0,
                    timestamp: ts,
                    original_len: pkt.orig_len,
                    data: Cow::Borrowed(&pkt.data),
                    options: vec![],
                }))
                .map(|_| ())
                .map_err(Error::Pcap),
        }
    }

    /// Flush any internal buffer to the OS.
    ///
    /// `File`-backed writers have no Rust-level buffer, so this is a no-op
    /// that always returns `Ok(())`. It exists so callers can use a uniform
    /// flush-at-checkpoint pattern without conditional logic.
    pub fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Drop for Dump {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

impl DumpBuilder {
    /// Set the link-layer type recorded in the file header. Required.
    pub fn link_type(mut self, lt: LinkType) -> Self {
        self.link_type = Some(lt);
        self
    }

    /// Open the file and write the format header.
    ///
    /// Errors if `link_type` was not set, or if the file extension is not
    /// `.pcap` or `.pcapng`.
    pub fn open(self) -> Result<Dump> {
        let lt = self.link_type.ok_or_else(|| {
            Error::Platform("Dump::open requires a link type — call .link_type() on the builder".into())
        })?;

        let ext = self.path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        let file = File::create(&self.path)?;

        let inner = match ext.as_str() {
            "pcap" => {
                let header = PcapHeader {
                    datalink: link_type_to_datalink(lt),
                    ..Default::default()
                };
                let w = PcapWriter::with_header(file, header).map_err(Error::Pcap)?;
                Inner::Pcap(w)
            }
            "pcapng" => {
                let mut w = PcapNgWriter::new(file).map_err(Error::Pcap)?;
                w.write_block(&Block::InterfaceDescription(InterfaceDescriptionBlock {
                    linktype: link_type_to_datalink(lt),
                    snaplen: 65535,
                    options: vec![],
                }))
                .map_err(Error::Pcap)?;
                Inner::PcapNg(w)
            }
            other => {
                return Err(Error::Platform(format!(
                    "unknown extension '.{other}': Dump requires .pcap or .pcapng"
                )))
            }
        };

        Ok(Dump { inner })
    }
}
