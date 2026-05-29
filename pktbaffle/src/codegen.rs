//! BPF bytecode compiler.
//!
//! Each call to `emit_expr` returns two patch lists:
//! - `success`: instruction slots that must be patched to jump to the ACCEPT
//!   instruction once the final program length is known.
//! - `failure`: instruction slots that must be patched to jump to the DROP
//!   instruction.
//!
//! Primitives emit code that **falls through on success** (no explicit success
//! jump for the common case) and **branches on failure** (jf → DROP patch).
//! Short-circuit `SrcOrDst` checks need explicit success jumps that skip the
//! second address check; those are returned as success patches so AND parents
//! can resolve them to the start of the next child.

use std::net::{IpAddr, Ipv4Addr};

use crate::ast::*;
use crate::bpf::{Insn, Program, BPF_ACCEPT, BPF_DROP, BPF_LD, BPF_LEN};
use crate::error::{Error, Result};
use crate::optimizer::dedup_loads;

// ── Link type ────────────────────────────────────────────────────────────────

/// Which link-layer framing wraps the packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// IEEE 802.3 / Ethernet II (14-byte header).
    Ethernet,
    /// Raw IPv4 (no link-layer header).
    RawIp,
    /// Linux "cooked" capture (SLL/SLL2, 16-byte header).
    LinuxSll,
}

impl LinkType {
    /// Byte offset where the IP header begins.
    pub(crate) fn net_offset(self) -> u32 {
        match self {
            LinkType::Ethernet => 14,
            LinkType::RawIp => 0,
            LinkType::LinuxSll => 16,
        }
    }

    /// Byte offset of the Ethernet-type / protocol field, if present.
    pub(crate) fn ether_proto_offset(self) -> Option<u32> {
        match self {
            LinkType::Ethernet => Some(12),
            LinkType::LinuxSll => Some(14),
            LinkType::RawIp => None,
        }
    }
}

// ── Patch bookkeeping ─────────────────────────────────────────────────────────

/// A slot in an instruction that needs its jump offset filled in later.
#[derive(Debug, Clone, Copy)]
enum Patch {
    /// Patch the `jt` field of `insns[idx]`.
    Jt(usize),
    /// Patch the `jf` field of `insns[idx]`.
    Jf(usize),
    /// Patch the `k` field of a JA instruction at `insns[idx]`.
    Ja(usize),
}

/// The two patch lists returned by every emit call.
#[derive(Default)]
struct Patches {
    /// When resolved, these slots will jump to the ACCEPT instruction.
    success: Vec<Patch>,
    /// When resolved, these slots will jump to the DROP instruction.
    failure: Vec<Patch>,
}

// ── Compiler state ────────────────────────────────────────────────────────────

struct Codegen {
    insns: Vec<Insn>,
    link: LinkType,
}

impl Codegen {
    fn new(link: LinkType) -> Self {
        Self {
            insns: Vec::new(),
            link,
        }
    }

    fn push(&mut self, insn: Insn) -> usize {
        let idx = self.insns.len();
        self.insns.push(insn);
        idx
    }

    // Resolve a patch to point to `target_idx`.
    fn resolve(&mut self, patch: Patch, target_idx: usize) {
        match patch {
            Patch::Jt(i) => {
                self.insns[i].jt = Self::offset(i, target_idx, &self.insns);
            }
            Patch::Jf(i) => {
                self.insns[i].jf = Self::offset(i, target_idx, &self.insns);
            }
            Patch::Ja(i) => {
                let off = Self::offset(i, target_idx, &self.insns) as u32;
                self.insns[i].k = off;
            }
        }
    }

    fn resolve_all(&mut self, patches: Vec<Patch>, target_idx: usize) {
        for p in patches {
            self.resolve(p, target_idx);
        }
    }

    fn offset(from: usize, to: usize, _insns: &[Insn]) -> u8 {
        debug_assert!(to > from, "BPF jump target must be forward");
        let diff = to - from - 1;
        debug_assert!(
            diff <= 255,
            "BPF jump offset overflow; program is too large"
        );
        diff as u8
    }

    // ── expression dispatch ──────────────────────────────────────────────────

    fn emit_expr(&mut self, expr: &Expr) -> Result<Patches> {
        match expr {
            Expr::And(l, r) => self.emit_and(l, r),
            Expr::Or(l, r) => self.emit_or(l, r),
            Expr::Not(e) => self.emit_not(e),
            Expr::Primitive(p) => self.emit_primitive(p),
        }
    }

    /// AND: left falls through to right on success.
    fn emit_and(&mut self, left: &Expr, right: &Expr) -> Result<Patches> {
        let left_p = self.emit_expr(left)?;
        // Resolve left's explicit success jumps to the start of right.
        let right_start = self.insns.len();
        self.resolve_all(left_p.success, right_start);
        let right_p = self.emit_expr(right)?;
        Ok(Patches {
            success: right_p.success,
            failure: left_p.failure.into_iter().chain(right_p.failure).collect(),
        })
    }

    /// OR: left's failures redirect to right; left's implicit fall-through
    /// (success) jumps past right via an inserted JA.
    fn emit_or(&mut self, left: &Expr, right: &Expr) -> Result<Patches> {
        let left_p = self.emit_expr(left)?;
        // Unconditional jump inserted after left's fall-through success path.
        let ja_idx = self.push(Insn::ja(0));
        let right_start = self.insns.len();
        // Left's failures now try the right branch.
        self.resolve_all(left_p.failure, right_start);
        let right_p = self.emit_expr(right)?;
        // Collect all success patches: left's explicit success jumps +
        // the JA we just inserted + right's success patches.
        let mut success = left_p.success;
        success.push(Patch::Ja(ja_idx));
        success.extend(right_p.success);
        Ok(Patches {
            success,
            failure: right_p.failure,
        })
    }

    /// NOT: swap success ↔ failure, insert a JA to handle the fall-through
    /// success path of the inner expression (which becomes NOT's failure).
    fn emit_not(&mut self, inner: &Expr) -> Result<Patches> {
        let inner_p = self.emit_expr(inner)?;
        // Insert a JA that the inner fall-through (success) hits → NOT's failure.
        let ja_idx = self.push(Insn::ja(0));
        // inner_p.failure patches now point to NOT's success (fall-through past JA).
        // inner_p.success patches and the new JA become NOT's failure.
        let not_succ_start = self.insns.len();
        self.resolve_all(inner_p.failure, not_succ_start);
        Ok(Patches {
            success: Vec::new(), // fall-through is the success path
            failure: inner_p
                .success
                .into_iter()
                .chain(std::iter::once(Patch::Ja(ja_idx)))
                .collect(),
        })
    }

    // ── primitives ────────────────────────────────────────────────────────────

    fn emit_primitive(&mut self, prim: &Primitive) -> Result<Patches> {
        match prim {
            Primitive::Proto(p) => self.emit_proto(p),
            Primitive::Host { addr, dir } => self.emit_host(*addr, *dir),
            Primitive::Net { net, dir } => self.emit_net(net, *dir),
            Primitive::Port { port, dir, proto } => self.emit_port(*port, *dir, *proto),
            Primitive::PortRange { lo, hi, dir, proto } => {
                self.emit_portrange(*lo, *hi, *dir, *proto)
            }
            Primitive::EtherHost { addr, dir } => self.emit_ether_host(addr, *dir),
            Primitive::EtherProto(et) => self.emit_ethertype(*et as u32),
            Primitive::EtherMulticast => self.emit_ether_multicast(),
            Primitive::IpBroadcast => self.emit_ip_broadcast(),
            Primitive::IpMulticast => self.emit_ip_multicast(),
            Primitive::Ip6Multicast => self.emit_ip6_multicast(),
            Primitive::Vlan { id } => self.emit_vlan(*id),
            Primitive::Mpls { label } => self.emit_mpls(*label),
            Primitive::PppoeDiscovery => self.emit_ethertype(0x8863),
            Primitive::PppoeSession => self.emit_ethertype(0x8864),
            Primitive::Len { op, value } => self.emit_len(*op, *value),
            Primitive::Inbound | Primitive::Outbound => Err(Error::CodegenError {
                message: "inbound/outbound direction cannot be expressed in standard BPF".into(),
            }),
            Primitive::ByteAccess(ba) => self.emit_byte_access(ba),
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Emit `ldh_abs(off); jeq_k(expected)` and return a single jf-fail patch.
    fn check_halfword(&mut self, off: u32, expected: u32) -> Patches {
        self.push(Insn::ldh_abs(off));
        let idx = self.push(Insn::jeq_k(expected, 0, 0xff));
        Patches {
            success: vec![],
            failure: vec![Patch::Jf(idx)],
        }
    }

    fn check_byte(&mut self, off: u32, expected: u32) -> Patches {
        self.push(Insn::ldb_abs(off));
        let idx = self.push(Insn::jeq_k(expected, 0, 0xff));
        Patches {
            success: vec![],
            failure: vec![Patch::Jf(idx)],
        }
    }

    fn check_word(&mut self, off: u32, expected: u32) -> Patches {
        self.push(Insn::ldw_abs(off));
        let idx = self.push(Insn::jeq_k(expected, 0, 0xff));
        Patches {
            success: vec![],
            failure: vec![Patch::Jf(idx)],
        }
    }

    fn emit_ethertype(&mut self, et: u32) -> Result<Patches> {
        if let Some(off) = self.link.ether_proto_offset() {
            Ok(self.check_halfword(off, et))
        } else {
            // RawIp: IPv4 is implicit, others are unsupported.
            if et == 0x0800 {
                Ok(Patches::default()) // no-op: always IPv4
            } else {
                Err(Error::CodegenError {
                    message: format!("ethertype 0x{:04x} cannot be matched on RawIp captures", et),
                })
            }
        }
    }

    /// Emit an IPv4 ethertype guard.
    fn ip4_guard(&mut self) -> Result<Patches> {
        self.emit_ethertype(0x0800)
    }

    /// Emit: ethertype == 0x0800, then proto field == `proto_num`.
    fn emit_ip4_l4(&mut self, proto_num: u8) -> Result<Patches> {
        let mut p = self.ip4_guard()?;
        let off = self.link.net_offset() + 9; // IP protocol byte
        let q = self.check_byte(off, proto_num as u32);
        p.failure.extend(q.failure);
        p.success.extend(q.success);
        Ok(p)
    }

    fn emit_ip6_l4(&mut self, next_hdr: u8) -> Result<Patches> {
        let mut p = self.emit_ethertype(0x86dd)?;
        let off = self.link.net_offset() + 6; // IPv6 Next Header
        let q = self.check_byte(off, next_hdr as u32);
        p.failure.extend(q.failure);
        Ok(p)
    }

    // ── protocol ──────────────────────────────────────────────────────────────

    fn emit_proto(&mut self, proto: &Proto) -> Result<Patches> {
        match proto {
            Proto::Ip => self.emit_ethertype(0x0800),
            Proto::Ip6 => self.emit_ethertype(0x86dd),
            Proto::Arp => self.emit_ethertype(0x0806),
            Proto::Rarp => self.emit_ethertype(0x8035),
            Proto::Tcp => self.emit_ip4_l4(6),
            Proto::Udp => self.emit_ip4_l4(17),
            Proto::Icmp => self.emit_ip4_l4(1),
            Proto::Igmp => self.emit_ip4_l4(2),
            Proto::Sctp => self.emit_ip4_l4(132),
            Proto::Icmp6 => self.emit_ip6_l4(58),
            Proto::Num(n) => self.emit_ip4_l4(*n),
            Proto::Ip6Proto(n) => self.emit_ip6_l4(*n),
        }
    }

    // ── host ─────────────────────────────────────────────────────────────────

    fn emit_host(&mut self, addr: IpAddr, dir: Dir) -> Result<Patches> {
        match addr {
            IpAddr::V4(a) => self.emit_host4(a, dir),
            IpAddr::V6(a) => self.emit_host6(a, dir),
        }
    }

    fn emit_host4(&mut self, addr: Ipv4Addr, dir: Dir) -> Result<Patches> {
        let mut p = self.ip4_guard()?;
        let base = self.link.net_offset();
        let src_off = base + 12; // IPv4 source address
        let dst_off = base + 16; // IPv4 destination address
        let k = u32::from(addr);
        let q = self.check_addr4(k, src_off, dst_off, dir);
        p.failure.extend(q.failure);
        p.success.extend(q.success);
        Ok(p)
    }

    /// Emit a single-address 4-byte check with direction.
    fn check_addr4(&mut self, k: u32, src_off: u32, dst_off: u32, dir: Dir) -> Patches {
        match dir {
            Dir::Src => {
                self.push(Insn::ldw_abs(src_off));
                let i = self.push(Insn::jeq_k(k, 0, 0xff));
                Patches {
                    success: vec![],
                    failure: vec![Patch::Jf(i)],
                }
            }
            Dir::Dst => {
                self.push(Insn::ldw_abs(dst_off));
                let i = self.push(Insn::jeq_k(k, 0, 0xff));
                Patches {
                    success: vec![],
                    failure: vec![Patch::Jf(i)],
                }
            }
            Dir::SrcAndDst => {
                self.push(Insn::ldw_abs(src_off));
                let i1 = self.push(Insn::jeq_k(k, 0, 0xff));
                self.push(Insn::ldw_abs(dst_off));
                let i2 = self.push(Insn::jeq_k(k, 0, 0xff));
                Patches {
                    success: vec![],
                    failure: vec![Patch::Jf(i1), Patch::Jf(i2)],
                }
            }
            Dir::SrcOrDst => {
                // src matches → jt jumps past dst check (success shortcut).
                self.push(Insn::ldw_abs(src_off));
                let i_src = self.push(Insn::jeq_k(k, 0xff, 0)); // jt=success patch
                self.push(Insn::ldw_abs(dst_off));
                let i_dst = self.push(Insn::jeq_k(k, 0, 0xff));
                Patches {
                    success: vec![Patch::Jt(i_src)],
                    failure: vec![Patch::Jf(i_dst)],
                }
            }
        }
    }

    fn emit_host6(&mut self, addr: std::net::Ipv6Addr, dir: Dir) -> Result<Patches> {
        let mut p = self.emit_ethertype(0x86dd)?;
        let base = self.link.net_offset();
        let src_off = base + 8;
        let dst_off = base + 24;
        let segs = addr.segments();

        let check_ip6_addr = |cg: &mut Codegen, off: u32, fail: &mut Vec<Patch>| {
            for (i, &seg) in segs.iter().enumerate() {
                cg.push(Insn::ldh_abs(off + i as u32 * 2));
                let idx = cg.push(Insn::jeq_k(seg as u32, 0, 0xff));
                fail.push(Patch::Jf(idx));
            }
        };

        match dir {
            Dir::Src => check_ip6_addr(self, src_off, &mut p.failure),
            Dir::Dst => check_ip6_addr(self, dst_off, &mut p.failure),
            Dir::SrcAndDst => {
                check_ip6_addr(self, src_off, &mut p.failure);
                check_ip6_addr(self, dst_off, &mut p.failure);
            }
            Dir::SrcOrDst => {
                // Emit src check; on complete success skip dst check via JA.
                // Collect src failures; redirect them to dst check.
                let mut src_fails = Vec::new();
                check_ip6_addr(self, src_off, &mut src_fails);
                let ja_idx = self.push(Insn::ja(0)); // jump to success
                let dst_start = self.insns.len();
                // Resolve src failures to dst start.
                for fp in src_fails {
                    self.resolve(fp, dst_start);
                }
                check_ip6_addr(self, dst_off, &mut p.failure);
                p.success.push(Patch::Ja(ja_idx));
            }
        }
        Ok(p)
    }

    // ── network ───────────────────────────────────────────────────────────────

    fn emit_net(&mut self, net: &IpNet, dir: Dir) -> Result<Patches> {
        let mut p = self.ip4_guard()?;
        let base = self.link.net_offset();
        let src_off = base + 12;
        let dst_off = base + 16;
        let mask = net.mask;
        let masked = u32::from(net.addr) & mask;

        let check = |cg: &mut Codegen, off: u32, fail: &mut Vec<Patch>| {
            cg.push(Insn::ldw_abs(off));
            cg.push(Insn::and_k(mask));
            let idx = cg.push(Insn::jeq_k(masked, 0, 0xff));
            fail.push(Patch::Jf(idx));
        };

        match dir {
            Dir::Src => check(self, src_off, &mut p.failure),
            Dir::Dst => check(self, dst_off, &mut p.failure),
            Dir::SrcAndDst => {
                check(self, src_off, &mut p.failure);
                check(self, dst_off, &mut p.failure);
            }
            Dir::SrcOrDst => {
                self.push(Insn::ldw_abs(src_off));
                self.push(Insn::and_k(mask));
                let i_src = self.push(Insn::jeq_k(masked, 0xff, 0));
                self.push(Insn::ldw_abs(dst_off));
                self.push(Insn::and_k(mask));
                let i_dst = self.push(Insn::jeq_k(masked, 0, 0xff));
                p.success.push(Patch::Jt(i_src));
                p.failure.push(Patch::Jf(i_dst));
            }
        }
        Ok(p)
    }

    // ── port ─────────────────────────────────────────────────────────────────

    fn emit_port(&mut self, port: u16, dir: Dir, proto: Option<Proto>) -> Result<Patches> {
        let mut p = self.emit_port_prereqs(proto)?;
        let base = self.link.net_offset();
        // With X = IHL*4 (from MSH), transport header is at X + base.
        // Source port: transport+0, destination port: transport+2.
        let src_port_off = base; // IND: P[X + base + 0]
        let dst_port_off = base + 2; // IND: P[X + base + 2]
        let k = port as u32;

        match dir {
            Dir::Src => {
                self.push(Insn::ldh_ind(src_port_off));
                let i = self.push(Insn::jeq_k(k, 0, 0xff));
                p.failure.push(Patch::Jf(i));
            }
            Dir::Dst => {
                self.push(Insn::ldh_ind(dst_port_off));
                let i = self.push(Insn::jeq_k(k, 0, 0xff));
                p.failure.push(Patch::Jf(i));
            }
            Dir::SrcAndDst => {
                self.push(Insn::ldh_ind(src_port_off));
                let i1 = self.push(Insn::jeq_k(k, 0, 0xff));
                self.push(Insn::ldh_ind(dst_port_off));
                let i2 = self.push(Insn::jeq_k(k, 0, 0xff));
                p.failure.extend([Patch::Jf(i1), Patch::Jf(i2)]);
            }
            Dir::SrcOrDst => {
                self.push(Insn::ldh_ind(src_port_off));
                let i_src = self.push(Insn::jeq_k(k, 0xff, 0));
                self.push(Insn::ldh_ind(dst_port_off));
                let i_dst = self.push(Insn::jeq_k(k, 0, 0xff));
                p.success.push(Patch::Jt(i_src));
                p.failure.push(Patch::Jf(i_dst));
            }
        }
        Ok(p)
    }

    fn emit_portrange(
        &mut self,
        lo: u16,
        hi: u16,
        dir: Dir,
        proto: Option<Proto>,
    ) -> Result<Patches> {
        let mut p = self.emit_port_prereqs(proto)?;
        let base = self.link.net_offset();
        let src_port_off = base;
        let dst_port_off = base + 2;

        // Check lo <= A <= hi: jge lo (fail if A < lo), then jgt hi (fail if A > hi).
        let check_range = |cg: &mut Codegen, off: u32, fail: &mut Vec<Patch>| {
            cg.push(Insn::ldh_ind(off));
            // A >= lo? if not (A < lo) → fail
            let i_lo = cg.push(Insn::jge_k(lo as u32, 0, 0xff)); // jf=fail
            fail.push(Patch::Jf(i_lo));
            // A <= hi? jgt hi → fail (A > hi)
            let i_hi = cg.push(Insn::jgt_k(hi as u32, 0xff, 0)); // jt=fail
            fail.push(Patch::Jt(i_hi));
        };

        match dir {
            Dir::Src => check_range(self, src_port_off, &mut p.failure),
            Dir::Dst => check_range(self, dst_port_off, &mut p.failure),
            Dir::SrcAndDst => {
                check_range(self, src_port_off, &mut p.failure);
                check_range(self, dst_port_off, &mut p.failure);
            }
            Dir::SrcOrDst => {
                let mut src_fails = Vec::new();
                check_range(self, src_port_off, &mut src_fails);
                let ja_idx = self.push(Insn::ja(0));
                let dst_start = self.insns.len();
                for fp in src_fails {
                    self.resolve(fp, dst_start);
                }
                check_range(self, dst_port_off, &mut p.failure);
                p.success.push(Patch::Ja(ja_idx));
            }
        }
        Ok(p)
    }

    /// Emit the prerequisites for a port filter: IP guard + optional proto
    /// check + MSH to load IP header length into X.
    fn emit_port_prereqs(&mut self, proto: Option<Proto>) -> Result<Patches> {
        let mut p = self.ip4_guard()?;
        let proto_off = self.link.net_offset() + 9;

        match proto {
            Some(Proto::Tcp) => {
                let q = self.check_byte(proto_off, 6);
                p.failure.extend(q.failure);
            }
            Some(Proto::Udp) => {
                let q = self.check_byte(proto_off, 17);
                p.failure.extend(q.failure);
            }
            Some(Proto::Sctp) => {
                let q = self.check_byte(proto_off, 132);
                p.failure.extend(q.failure);
            }
            None => {
                // Accept TCP (6) or UDP (17).
                self.push(Insn::ldb_abs(proto_off));
                let i_tcp = self.push(Insn::jeq_k(6, 0xff, 0)); // jt skips UDP check
                let i_udp = self.push(Insn::jeq_k(17, 0, 0xff));
                p.failure.push(Patch::Jf(i_udp));
                // Resolve TCP jt now so it jumps to MSH (not to ACCEPT).
                // Without this, the jt patch would leak into p.success and bypass
                // the port number check entirely.
                let msh_idx = self.insns.len();
                self.push(Insn::ldx_msh(self.link.net_offset()));
                self.resolve(Patch::Jt(i_tcp), msh_idx);
                return Ok(p);
            }
            Some(pr) => {
                return Err(Error::CodegenError {
                    message: format!("port filter with proto {:?} is not supported", pr),
                });
            }
        }

        // Load IP IHL into X via BPF_MSH.
        self.push(Insn::ldx_msh(self.link.net_offset()));
        Ok(p)
    }

    // ── Ethernet host ─────────────────────────────────────────────────────────

    fn emit_ether_host(&mut self, addr: &MacAddr, dir: Dir) -> Result<Patches> {
        if self.link == LinkType::RawIp {
            return Err(Error::CodegenError {
                message: "ether host cannot be used with RawIp link type".into(),
            });
        }
        let check_mac = |cg: &mut Codegen, offset: u32, fail: &mut Vec<Patch>| {
            let word = u32::from_be_bytes([addr.0[0], addr.0[1], addr.0[2], addr.0[3]]);
            cg.push(Insn::ldw_abs(offset));
            let i1 = cg.push(Insn::jeq_k(word, 0, 0xff));
            fail.push(Patch::Jf(i1));
            let half = u32::from_be_bytes([0, 0, addr.0[4], addr.0[5]]);
            cg.push(Insn::ldh_abs(offset + 4));
            let i2 = cg.push(Insn::jeq_k(half, 0, 0xff));
            fail.push(Patch::Jf(i2));
        };

        let mut p = Patches::default();
        match dir {
            Dir::Src => check_mac(self, 6, &mut p.failure),
            Dir::Dst => check_mac(self, 0, &mut p.failure),
            Dir::SrcAndDst => {
                check_mac(self, 0, &mut p.failure);
                check_mac(self, 6, &mut p.failure);
            }
            Dir::SrcOrDst => {
                let mut src_fails = Vec::new();
                check_mac(self, 0, &mut src_fails); // dst MAC at offset 0
                let ja_idx = self.push(Insn::ja(0));
                let src_start = self.insns.len();
                for fp in src_fails {
                    self.resolve(fp, src_start);
                }
                check_mac(self, 6, &mut p.failure); // src MAC at offset 6
                p.success.push(Patch::Ja(ja_idx));
            }
        }
        Ok(p)
    }

    // ── Ethernet multicast ────────────────────────────────────────────────────

    fn emit_ether_multicast(&mut self) -> Result<Patches> {
        if self.link == LinkType::RawIp {
            return Err(Error::CodegenError {
                message: "ether multicast cannot be used with RawIp link type".into(),
            });
        }
        // Destination MAC is at offset 0; check bit 0 of its first byte.
        self.push(Insn::ldb_abs(0));
        let idx = self.push(Insn::jset_k(0x01, 0, 0xff)); // bit set → fall through; else fail
        Ok(Patches {
            success: vec![],
            failure: vec![Patch::Jf(idx)],
        })
    }

    // ── IP broadcast / multicast ──────────────────────────────────────────────

    fn emit_ip_broadcast(&mut self) -> Result<Patches> {
        let mut p = self.ip4_guard()?;
        // Check destination IP == 255.255.255.255 (limited broadcast).
        let dst_off = self.link.net_offset() + 16;
        let q = self.check_word(dst_off, 0xffffffff);
        p.failure.extend(q.failure);
        Ok(p)
    }

    fn emit_ip_multicast(&mut self) -> Result<Patches> {
        let mut p = self.ip4_guard()?;
        // Destination IP & 0xf0000000 == 0xe0000000 (224.0.0.0/4).
        let dst_off = self.link.net_offset() + 16;
        self.push(Insn::ldw_abs(dst_off));
        self.push(Insn::and_k(0xf000_0000));
        let idx = self.push(Insn::jeq_k(0xe000_0000, 0, 0xff));
        p.failure.push(Patch::Jf(idx));
        Ok(p)
    }

    fn emit_ip6_multicast(&mut self) -> Result<Patches> {
        let mut p = self.emit_ethertype(0x86dd)?;
        // First byte of destination IPv6 address == 0xff.
        // IPv6 dst starts at net_offset + 24.
        let dst_off = self.link.net_offset() + 24;
        let q = self.check_byte(dst_off, 0xff);
        p.failure.extend(q.failure);
        Ok(p)
    }

    // ── VLAN ──────────────────────────────────────────────────────────────────

    fn emit_vlan(&mut self, id: Option<u16>) -> Result<Patches> {
        // VLAN tag uses ethertype 0x8100 (802.1Q).
        let mut p = self.emit_ethertype(0x8100)?;
        if let Some(vid) = id {
            // VLAN TCI is the next 16-bit field after the ethertype.
            // On Ethernet: offset 14; on LinuxSll: offset 16.
            let tci_off = self.link.ether_proto_offset().unwrap_or(14) + 2;
            self.push(Insn::ldh_abs(tci_off));
            self.push(Insn::and_k(0x0fff)); // VLAN ID is lower 12 bits
            let idx = self.push(Insn::jeq_k(vid as u32, 0, 0xff));
            p.failure.push(Patch::Jf(idx));
        }
        Ok(p)
    }

    // ── MPLS ──────────────────────────────────────────────────────────────────

    fn emit_mpls(&mut self, label: Option<u32>) -> Result<Patches> {
        // MPLS unicast ethertype is 0x8847; multicast is 0x8848.
        // Emit: ethertype == 0x8847 OR ethertype == 0x8848.
        if let Some(off) = self.link.ether_proto_offset() {
            self.push(Insn::ldh_abs(off));
            let i_unicast = self.push(Insn::jeq_k(0x8847, 0xff, 0)); // match → success branch
            let i_mcast = self.push(Insn::jeq_k(0x8848, 0, 0xff)); // no match → fail
            let mut p = Patches {
                success: vec![Patch::Jt(i_unicast)],
                failure: vec![Patch::Jf(i_mcast)],
            };
            if let Some(lbl) = label {
                // MPLS label stack entry is at ether_proto_offset + 2.
                // Label is the top 20 bits of the 32-bit label stack entry.
                let lse_off = off + 2;
                self.push(Insn::ldw_abs(lse_off));
                self.push(Insn::rsh_k(12));
                let idx = self.push(Insn::jeq_k(lbl, 0, 0xff));
                p.failure.push(Patch::Jf(idx));
            }
            Ok(p)
        } else {
            Err(Error::CodegenError {
                message: "mpls cannot be matched on RawIp captures".into(),
            })
        }
    }

    // ── length predicates ─────────────────────────────────────────────────────

    fn emit_len(&mut self, op: CmpOp, value: u32) -> Result<Patches> {
        self.push(Insn {
            code: BPF_LD | BPF_LEN,
            jt: 0,
            jf: 0,
            k: 0,
        });
        self.emit_cmp(op, value)
    }

    // ── raw byte access ───────────────────────────────────────────────────────

    fn emit_byte_access(&mut self, ba: &ByteAccess) -> Result<Patches> {
        // Calculate the absolute packet offset for non-transport layers.
        match ba.layer {
            Layer::Raw => {
                let off = ba.offset as u32;
                self.load_sized(off, ba.size, false);
            }
            Layer::Net => {
                let off = self.link.net_offset() + ba.offset as u32;
                self.load_sized(off, ba.size, false);
            }
            Layer::Trans => {
                // Must emit MSH first to populate X with the IP header length.
                self.push(Insn::ldx_msh(self.link.net_offset()));
                let off = self.link.net_offset() + ba.offset as u32;
                self.load_sized(off, ba.size, true); // indirect
            }
        }

        if let Some(mask) = ba.mask {
            self.push(Insn::and_k(mask));
        }

        let p = self.emit_cmp(ba.op, ba.value)?;
        Ok(p)
    }

    fn load_sized(&mut self, off: u32, size: AccessSize, indirect: bool) {
        let insn = match (size, indirect) {
            (AccessSize::Byte, false) => Insn::ldb_abs(off),
            (AccessSize::Half, false) => Insn::ldh_abs(off),
            (AccessSize::Word, false) => Insn::ldw_abs(off),
            (AccessSize::Byte, true) => Insn::ldb_abs(off), // BPF_IND byte is non-standard; use ABS
            (AccessSize::Half, true) => Insn::ldh_ind(off),
            (AccessSize::Word, true) => Insn::ldw_ind(off),
        };
        self.push(insn);
    }

    fn emit_cmp(&mut self, op: CmpOp, value: u32) -> Result<Patches> {
        let (insn, fail_field) = match op {
            CmpOp::Eq => (Insn::jeq_k(value, 0, 0xff), PatchField::Jf),
            CmpOp::Ne => (Insn::jeq_k(value, 0xff, 0), PatchField::Jt), // equal → fail
            CmpOp::Gt => (Insn::jgt_k(value, 0, 0xff), PatchField::Jf),
            CmpOp::Ge => (Insn::jge_k(value, 0, 0xff), PatchField::Jf),
            CmpOp::Lt => (Insn::jge_k(value, 0xff, 0), PatchField::Jt), // ge → fail → lt succeeds
            CmpOp::Le => (Insn::jgt_k(value, 0xff, 0), PatchField::Jt), // gt → fail → le succeeds
            CmpOp::BitAnd => (Insn::jset_k(value, 0, 0xff), PatchField::Jf), // not set → fail
        };
        let idx = self.push(insn);
        let patch = match fail_field {
            PatchField::Jt => Patch::Jt(idx),
            PatchField::Jf => Patch::Jf(idx),
        };
        Ok(Patches {
            success: vec![],
            failure: vec![patch],
        })
    }
}

enum PatchField {
    Jt,
    Jf,
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Compile a filter expression into a cBPF [`Program`] for the given link type.
///
/// This is the low-level entry point used by [`pktbaffle::compile`][crate::compile]
/// when [`Target::Classic`][crate::Target::Classic] is selected.
/// Most callers should use [`pktbaffle::compile`][crate::compile] instead.
///
/// # Errors
///
/// Returns [`Error::CodegenError`][crate::Error::CodegenError] for filter
/// constructs that are valid syntax but cannot be represented in classic BPF
/// for the requested link type (e.g. `inbound`/`outbound` direction primitives).
pub fn compile(expr: &Expr, link: LinkType) -> Result<Program> {
    let mut cg = Codegen::new(link);
    let patches = cg.emit_expr(expr)?;

    // Run peephole optimizations before emitting terminals so that jump
    // offsets inserted below reflect the final instruction count.
    dedup_loads(&mut cg.insns);

    // Emit terminal instructions.
    let accept_idx = cg.insns.len();
    cg.push(Insn::ret_k(BPF_ACCEPT));
    let drop_idx = cg.insns.len();
    cg.push(Insn::ret_k(BPF_DROP));

    // Resolve all pending patches.
    cg.resolve_all(patches.success, accept_idx);
    cg.resolve_all(patches.failure, drop_idx);

    Ok(Program::new(cg.insns))
}
