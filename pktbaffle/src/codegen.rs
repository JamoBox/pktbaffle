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
//!
//! # Path facts
//!
//! The emitter tracks [`Facts`] — predicates already proven true on the
//! current fall-through path, such as "the ethertype check for 0x0800 has
//! passed" or "X holds the transport-header offset". Because AND chains fall
//! through on success, a fact established by one conjunct dominates all later
//! conjuncts, which can then skip re-emitting the same guard. This is what
//! turns `tcp and port 80` into a single linear check sequence instead of two
//! back-to-back ones.
//!
//! Facts are control-flow sensitive:
//! - **AND** accumulates facts left to right.
//! - **OR** restores the entry facts before emitting the right arm (the right
//!   arm is reached from the left arm's failure points), and keeps only facts
//!   established by *both* arms after the join. Guards required by every arm
//!   (per [`required_guards`]) are hoisted in front of the OR so each arm can
//!   elide them.
//! - **NOT** restores the entry facts afterwards: its success path is the
//!   inner failure path, which proves nothing new.
//! - Any instruction that writes the X register invalidates the
//!   "X holds the transport-header offset" fact.

use std::net::{IpAddr, Ipv4Addr};

use crate::ast::*;
use crate::bpf::{
    Insn, Program, BPF_ACCEPT, BPF_DROP, BPF_LD, BPF_LDX, BPF_LEN, BPF_MISC, BPF_TAX,
};
use crate::error::{Error, Result};
use crate::optimizer::optimize;

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

// ── L4 protocol sets ──────────────────────────────────────────────────────────

/// The set of L4 protocol numbers a port prologue admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum L4Set {
    /// Exactly one protocol number.
    One(u8),
    /// TCP (6) or UDP (17) — the unqualified `port` / `portrange` set.
    TcpOrUdp,
}

impl L4Set {
    fn contains(self, p: u8) -> bool {
        match self {
            L4Set::One(x) => x == p,
            L4Set::TcpOrUdp => p == 6 || p == 17,
        }
    }

    fn subset_of(self, other: L4Set) -> bool {
        match (self, other) {
            (L4Set::One(a), o) => o.contains(a),
            (L4Set::TcpOrUdp, L4Set::TcpOrUdp) => true,
            (L4Set::TcpOrUdp, L4Set::One(_)) => false,
        }
    }

    /// Smallest representable set containing both, if one exists.
    fn join(a: L4Set, b: L4Set) -> Option<L4Set> {
        if a == b {
            Some(a)
        } else if a.subset_of(L4Set::TcpOrUdp) && b.subset_of(L4Set::TcpOrUdp) {
            Some(L4Set::TcpOrUdp)
        } else {
            None
        }
    }
}

/// Map a port-filter protocol qualifier to its L4 protocol set.
fn l4set_for(proto: Option<Proto>) -> Result<L4Set> {
    match proto {
        None => Ok(L4Set::TcpOrUdp),
        Some(Proto::Tcp) => Ok(L4Set::One(6)),
        Some(Proto::Udp) => Ok(L4Set::One(17)),
        Some(Proto::Sctp) => Ok(L4Set::One(132)),
        Some(pr) => Err(Error::CodegenError {
            message: format!("port filter with proto {:?} is not supported", pr),
        }),
    }
}

// ── Path facts ────────────────────────────────────────────────────────────────

/// Predicates proven true on the current fall-through emission path.
///
/// The first three are pure packet facts (the packet does not change, so once
/// a check has passed on this path it stays true). `ports_ready` additionally
/// asserts machine state — X holds the transport-header offset and the IPv4
/// fragment guard has passed — and is invalidated whenever X is written.
#[derive(Debug, Default, Clone, PartialEq)]
struct Facts {
    /// The link-layer protocol field equals this value.
    ethertype: Option<u32>,
    /// The byte at `net_offset + 9` (IPv4 protocol) equals this value.
    ip4_proto: Option<u8>,
    /// The byte at `net_offset + 6` (IPv6 next header) equals this value.
    ip6_nh: Option<u8>,
    /// A port prologue admitting this protocol set has fully passed:
    /// X = transport-header offset relative to `net_offset`, and the packet
    /// is not a non-initial IPv4 fragment.
    ports_ready: Option<L4Set>,
}

impl Facts {
    /// Facts valid where two paths join: only what holds on both.
    fn meet(a: &Facts, b: &Facts) -> Facts {
        fn both<T: Copy + PartialEq>(x: Option<T>, y: Option<T>) -> Option<T> {
            match (x, y) {
                (Some(p), Some(q)) if p == q => Some(p),
                _ => None,
            }
        }
        Facts {
            ethertype: both(a.ethertype, b.ethertype),
            ip4_proto: both(a.ip4_proto, b.ip4_proto),
            ip6_nh: both(a.ip6_nh, b.ip6_nh),
            // The proven protocol set at a join is the union of the two
            // paths' sets, when that union is representable.
            ports_ready: match (a.ports_ready, b.ports_ready) {
                (Some(x), Some(y)) => L4Set::join(x, y),
                _ => None,
            },
        }
    }
}

// ── Required-guard analysis ───────────────────────────────────────────────────

/// Guards an expression requires on every accepting path.
///
/// Used to hoist checks shared by all arms of an OR: if every arm can only
/// accept packets satisfying guard `g`, then `l or r ≡ g and (l or r)`, and
/// emitting `g` once up front lets each arm elide it via [`Facts`].
#[derive(Debug, Default, Clone, PartialEq)]
struct GuardSet {
    ethertype: Option<u32>,
    ip4_proto: Option<u8>,
    ip6_nh: Option<u8>,
    port_prereqs: Option<L4Set>,
}

impl GuardSet {
    /// Guards required by a conjunction: anything either side requires.
    ///
    /// On a conflict (each side pins a different value) the conjunction can
    /// never accept, so either value is vacuously required; keep the left.
    fn union(mut self, other: GuardSet) -> GuardSet {
        self.ethertype = self.ethertype.or(other.ethertype);
        self.ip4_proto = self.ip4_proto.or(other.ip4_proto);
        self.ip6_nh = self.ip6_nh.or(other.ip6_nh);
        self.port_prereqs = self.port_prereqs.or(other.port_prereqs);
        self
    }

    /// Guards required by a disjunction: only what both sides require.
    fn intersect(self, other: GuardSet) -> GuardSet {
        fn both<T: Copy + PartialEq>(x: Option<T>, y: Option<T>) -> Option<T> {
            match (x, y) {
                (Some(p), Some(q)) if p == q => Some(p),
                _ => None,
            }
        }
        GuardSet {
            ethertype: both(self.ethertype, other.ethertype),
            ip4_proto: both(self.ip4_proto, other.ip4_proto),
            ip6_nh: both(self.ip6_nh, other.ip6_nh),
            port_prereqs: both(self.port_prereqs, other.port_prereqs),
        }
    }
}

fn required_guards(expr: &Expr) -> GuardSet {
    match expr {
        Expr::And(l, r) => required_guards(l).union(required_guards(r)),
        Expr::Or(l, r) => required_guards(l).intersect(required_guards(r)),
        // A negated check proves nothing about what its parent requires.
        Expr::Not(_) => GuardSet::default(),
        Expr::Primitive(p) => primitive_guards(p),
    }
}

fn primitive_guards(prim: &Primitive) -> GuardSet {
    let mut g = GuardSet::default();
    match prim {
        Primitive::Proto(p) => match p {
            Proto::Ip => g.ethertype = Some(0x0800),
            Proto::Ip6 => g.ethertype = Some(0x86dd),
            Proto::Arp => g.ethertype = Some(0x0806),
            Proto::Rarp => g.ethertype = Some(0x8035),
            Proto::Tcp => {
                g.ethertype = Some(0x0800);
                g.ip4_proto = Some(6);
            }
            Proto::Udp => {
                g.ethertype = Some(0x0800);
                g.ip4_proto = Some(17);
            }
            Proto::Icmp => {
                g.ethertype = Some(0x0800);
                g.ip4_proto = Some(1);
            }
            Proto::Igmp => {
                g.ethertype = Some(0x0800);
                g.ip4_proto = Some(2);
            }
            Proto::Sctp => {
                g.ethertype = Some(0x0800);
                g.ip4_proto = Some(132);
            }
            Proto::Num(n) => {
                g.ethertype = Some(0x0800);
                g.ip4_proto = Some(*n);
            }
            Proto::Icmp6 => {
                g.ethertype = Some(0x86dd);
                g.ip6_nh = Some(58);
            }
            Proto::Ip6Proto(n) => {
                g.ethertype = Some(0x86dd);
                g.ip6_nh = Some(*n);
            }
        },
        Primitive::Host { addr, .. } => {
            g.ethertype = Some(match addr {
                IpAddr::V4(_) => 0x0800,
                IpAddr::V6(_) => 0x86dd,
            });
        }
        Primitive::Net { .. } | Primitive::IpBroadcast | Primitive::IpMulticast => {
            g.ethertype = Some(0x0800);
        }
        Primitive::Net6 { .. } | Primitive::Ip6Multicast => {
            g.ethertype = Some(0x86dd);
        }
        Primitive::Port { proto, .. } | Primitive::PortRange { proto, .. } => {
            g.port_prereqs = l4set_for(*proto).ok();
        }
        Primitive::EtherProto(et) => g.ethertype = Some(*et as u32),
        Primitive::Vlan { .. } => g.ethertype = Some(0x8100),
        Primitive::PppoeDiscovery => g.ethertype = Some(0x8863),
        Primitive::PppoeSession { .. } => g.ethertype = Some(0x8864),
        Primitive::IpProtoChain(n) => {
            g.ethertype = Some(0x0800);
            g.ip4_proto = Some(*n);
        }
        Primitive::Ip6ProtoChain(n) => {
            g.ethertype = Some(0x86dd);
            g.ip6_nh = Some(*n);
        }
        // MPLS matches two ethertypes; the rest imply no hoistable guard.
        Primitive::Mpls { .. }
        | Primitive::EtherHost { .. }
        | Primitive::EtherMulticast
        | Primitive::Len { .. }
        | Primitive::ByteAccess(_)
        | Primitive::Inbound
        | Primitive::Outbound => {}
    }
    g
}

// ── Compiler state ────────────────────────────────────────────────────────────

struct Codegen {
    insns: Vec<Insn>,
    link: LinkType,
    /// Predicates proven on the current fall-through path.
    facts: Facts,
    /// Counts instructions that write X; used to detect clobbers across an
    /// OR arm or NOT body whose entry facts are later restored.
    x_writes: u64,
}

impl Codegen {
    fn new(link: LinkType) -> Self {
        Self {
            insns: Vec::new(),
            link,
            facts: Facts {
                // RawIp frames have no link-layer header: IPv4 is implicit.
                ethertype: (link == LinkType::RawIp).then_some(0x0800),
                ..Facts::default()
            },
            x_writes: 0,
        }
    }

    fn push(&mut self, insn: Insn) -> usize {
        // Writing X invalidates the "X holds the transport offset" fact.
        let class = insn.code & 0x07;
        if class == BPF_LDX || insn.code == (BPF_MISC | BPF_TAX) {
            self.x_writes += 1;
            self.facts.ports_ready = None;
        }
        let idx = self.insns.len();
        self.insns.push(insn);
        idx
    }

    // Resolve a patch to point to `target_idx`.
    fn resolve(&mut self, patch: Patch, target_idx: usize) -> Result<()> {
        match patch {
            Patch::Jt(i) => {
                self.insns[i].jt = Self::offset(i, target_idx)?;
            }
            Patch::Jf(i) => {
                self.insns[i].jf = Self::offset(i, target_idx)?;
            }
            Patch::Ja(i) => {
                let off = Self::offset(i, target_idx)? as u32;
                self.insns[i].k = off;
            }
        }
        Ok(())
    }

    fn resolve_all(&mut self, patches: Vec<Patch>, target_idx: usize) -> Result<()> {
        for p in patches {
            self.resolve(p, target_idx)?;
        }
        Ok(())
    }

    fn offset(from: usize, to: usize) -> Result<u8> {
        debug_assert!(to > from, "BPF jump target must be forward");
        let diff = to - from - 1;
        if diff > 255 {
            return Err(Error::CodegenError {
                message:
                    "filter expression is too complex: BPF jump offset exceeds 255 instructions"
                        .into(),
            });
        }
        Ok(diff as u8)
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
        self.resolve_all(left_p.success, right_start)?;
        let right_p = self.emit_expr(right)?;
        Ok(Patches {
            success: right_p.success,
            failure: left_p.failure.into_iter().chain(right_p.failure).collect(),
        })
    }

    /// OR: left's failures redirect to right; left's implicit fall-through
    /// (success) jumps past right via an inserted JA.
    ///
    /// Guards required by *every* arm are emitted once in front of the OR,
    /// so each arm can elide them; their failure patches join the OR's
    /// failure list.
    fn emit_or(&mut self, left: &Expr, right: &Expr) -> Result<Patches> {
        let mut hoist_failure = Vec::new();
        let common = required_guards(left).intersect(required_guards(right));
        if let Some(et) = common.ethertype {
            // RawIp rejects non-IPv4 ethertypes with an error; the arms
            // themselves would raise it, so don't pre-empt them here.
            if self.link.ether_proto_offset().is_some() {
                hoist_failure.extend(self.emit_ethertype(et)?.failure);
            }
        }
        if let Some(n) = common.ip4_proto {
            hoist_failure.extend(self.emit_ip4_l4(n)?.failure);
        }
        if let Some(n) = common.ip6_nh {
            hoist_failure.extend(self.emit_ip6_l4(n)?.failure);
        }
        if let Some(set) = common.port_prereqs {
            hoist_failure.extend(self.emit_port_prereqs_set(set)?.failure);
        }

        // Each arm starts from the post-hoist facts: the right arm is reached
        // from failure points inside the left arm, where only those hold.
        let branch_facts = self.facts.clone();
        let x_writes_before = self.x_writes;

        let left_p = self.emit_expr(left)?;
        let left_facts = std::mem::replace(&mut self.facts, branch_facts);
        if self.x_writes != x_writes_before {
            // The left arm may have clobbered X before any of its failure
            // edges, so the right arm cannot trust a pre-established
            // transport offset.
            self.facts.ports_ready = None;
        }

        // Unconditional jump inserted after left's fall-through success path.
        let ja_idx = self.push(Insn::ja(0));
        let right_start = self.insns.len();
        // Left's failures now try the right branch.
        self.resolve_all(left_p.failure, right_start)?;
        let right_p = self.emit_expr(right)?;

        // After the join, keep only facts both arms established.
        self.facts = Facts::meet(&left_facts, &self.facts);

        // Collect all success patches: left's explicit success jumps +
        // the JA we just inserted + right's success patches.
        let mut success = left_p.success;
        success.push(Patch::Ja(ja_idx));
        success.extend(right_p.success);
        let mut failure = right_p.failure;
        failure.extend(hoist_failure);
        Ok(Patches { success, failure })
    }

    /// NOT: swap success ↔ failure, insert a JA to handle the fall-through
    /// success path of the inner expression (which becomes NOT's failure).
    fn emit_not(&mut self, inner: &Expr) -> Result<Patches> {
        let entry_facts = self.facts.clone();
        let x_writes_before = self.x_writes;
        let inner_p = self.emit_expr(inner)?;
        // NOT's success path is the inner *failure* path: only facts already
        // proven at entry still hold there.
        self.facts = entry_facts;
        if self.x_writes != x_writes_before {
            self.facts.ports_ready = None;
        }
        // Insert a JA that the inner fall-through (success) hits → NOT's failure.
        let ja_idx = self.push(Insn::ja(0));
        // inner_p.failure patches now point to NOT's success (fall-through past JA).
        // inner_p.success patches and the new JA become NOT's failure.
        let not_succ_start = self.insns.len();
        self.resolve_all(inner_p.failure, not_succ_start)?;
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
            Primitive::Net6 { net, dir } => self.emit_net6(net, *dir),
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
            Primitive::PppoeSession { session_id } => self.emit_pppoe_session(*session_id),
            Primitive::IpProtoChain(n) => self.emit_ip4_l4(*n),
            Primitive::Ip6ProtoChain(n) => self.emit_ip6_l4(*n),
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
            if self.facts.ethertype == Some(et) {
                // Already proven on this path.
                return Ok(Patches::default());
            }
            let p = self.check_halfword(off, et);
            // Record the fact unless the path already pins a different
            // ethertype, in which case the fall-through is unreachable at
            // runtime and the original fact stays.
            if self.facts.ethertype.is_none() {
                self.facts.ethertype = Some(et);
            }
            Ok(p)
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
        if self.facts.ip4_proto == Some(proto_num) {
            return Ok(p);
        }
        let off = self.link.net_offset() + 9; // IP protocol byte
        let q = self.check_byte(off, proto_num as u32);
        p.failure.extend(q.failure);
        p.success.extend(q.success);
        if self.facts.ip4_proto.is_none() {
            self.facts.ip4_proto = Some(proto_num);
        }
        Ok(p)
    }

    fn emit_ip6_l4(&mut self, next_hdr: u8) -> Result<Patches> {
        let mut p = self.emit_ethertype(0x86dd)?;
        if self.facts.ip6_nh == Some(next_hdr) {
            return Ok(p);
        }
        let off = self.link.net_offset() + 6; // IPv6 Next Header
        let q = self.check_byte(off, next_hdr as u32);
        p.failure.extend(q.failure);
        if self.facts.ip6_nh.is_none() {
            self.facts.ip6_nh = Some(next_hdr);
        }
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
                    self.resolve(fp, dst_start)?;
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

    fn emit_net6(&mut self, net: &Ipv6Net, dir: Dir) -> Result<Patches> {
        let mut p = self.emit_ethertype(0x86dd)?;
        let base = self.link.net_offset();
        let src_off = base + 8;
        let dst_off = base + 24;
        let segs = net.addr.segments();
        let prefix_len = net.prefix_len;

        let check_net6 = |cg: &mut Codegen, addr_off: u32, fail: &mut Vec<Patch>| {
            for (i, &seg) in segs.iter().enumerate() {
                let start_bit = i as u32 * 16;
                if start_bit >= prefix_len as u32 {
                    break;
                }
                let end_bit = start_bit + 16;
                let off = addr_off + i as u32 * 2;
                cg.push(Insn::ldh_abs(off));
                if end_bit <= prefix_len as u32 {
                    let idx = cg.push(Insn::jeq_k(seg as u32, 0, 0xff));
                    fail.push(Patch::Jf(idx));
                } else {
                    let bits = prefix_len as u32 - start_bit;
                    let mask = (0xffffu32 << (16 - bits)) & 0xffff;
                    let expected = (seg as u32) & mask;
                    cg.push(Insn::and_k(mask));
                    let idx = cg.push(Insn::jeq_k(expected, 0, 0xff));
                    fail.push(Patch::Jf(idx));
                }
            }
        };

        match dir {
            Dir::Src => check_net6(self, src_off, &mut p.failure),
            Dir::Dst => check_net6(self, dst_off, &mut p.failure),
            Dir::SrcAndDst => {
                check_net6(self, src_off, &mut p.failure);
                check_net6(self, dst_off, &mut p.failure);
            }
            Dir::SrcOrDst => {
                let mut src_fails = Vec::new();
                check_net6(self, src_off, &mut src_fails);
                let ja_idx = self.push(Insn::ja(0));
                let dst_start = self.insns.len();
                for fp in src_fails {
                    self.resolve(fp, dst_start)?;
                }
                check_net6(self, dst_off, &mut p.failure);
                p.success.push(Patch::Ja(ja_idx));
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
                    self.resolve(fp, dst_start)?;
                }
                check_range(self, dst_port_off, &mut p.failure);
                p.success.push(Patch::Ja(ja_idx));
            }
        }
        Ok(p)
    }

    /// Emit prerequisites for a port/portrange filter.
    ///
    /// On return X holds the L4 header offset relative to `net_offset`:
    /// IHL*4 for IPv4 packets, 40 for IPv6 packets. The fall-through path
    /// leads directly into the port-number check. Failure patches are set for
    /// wrong ethertype, wrong protocol, or a non-first IPv4 fragment.
    fn emit_port_prereqs(&mut self, proto: Option<Proto>) -> Result<Patches> {
        let want = l4set_for(proto)?;
        self.emit_port_prereqs_set(want)
    }

    /// Emit the port prologue for the protocol set `want`, eliding whatever
    /// the current [`Facts`] already prove.
    ///
    /// When the ethertype is undetermined, the full dual-path layout is
    /// emitted:
    ///   [ldh ethertype] [jeq 0x86dd → ipv6] [jeq 0x0800 jf→FAIL]
    ///   — IPv4 path: ldb proto, proto check, ldh frag, jset 0x1fff→FAIL, ldxb MSH, ja→port
    ///   — IPv6 path: ldb next-header, nh check, ldx #40
    ///   — port check (fall-through from both paths)
    ///
    /// When the path already proves IPv4 (or IPv6), only that single path is
    /// emitted, and the protocol check is skipped too when the protocol is
    /// already pinned to a member of `want`.
    fn emit_port_prereqs_set(&mut self, want: L4Set) -> Result<Patches> {
        if let Some(have) = self.facts.ports_ready {
            if have.subset_of(want) {
                // An earlier, at-least-as-strict prologue already passed.
                return Ok(Patches::default());
            }
        }

        let mut p = Patches::default();
        let net_off = self.link.net_offset();
        let ip4_proto_off = net_off + 9; // IP protocol byte
        let ip4_frag_off = net_off + 6; // IP flags + fragment offset (ip[6:2])
        let ip6_nh_off = net_off + 6; // IPv6 next-header (byte 6 of IPv6 header)

        // RawIp has no link-layer header, so IPv4 is implicit (and the facts
        // are initialised accordingly).
        let known_v4 = self.facts.ethertype == Some(0x0800);
        let known_v6 = self.facts.ethertype == Some(0x86dd);

        if known_v4 {
            let established = if self.facts.ports_ready.is_some() {
                // X and the fragment guard are already in place from a
                // broader prologue; only narrow the protocol.
                self.push(Insn::ldb_abs(ip4_proto_off));
                self.emit_l4_set_check(want, &mut p.failure)?;
                want
            } else {
                let established = match self.facts.ip4_proto {
                    Some(n) if want.contains(n) => L4Set::One(n),
                    _ => {
                        self.push(Insn::ldb_abs(ip4_proto_off));
                        self.emit_l4_set_check(want, &mut p.failure)?;
                        want
                    }
                };
                // Non-first fragments lack the L4 header at the expected offset.
                self.push(Insn::ldh_abs(ip4_frag_off));
                let i_frag = self.push(Insn::jset_k(0x1fff, 0xff, 0)); // jt → FAIL
                p.failure.push(Patch::Jt(i_frag));
                self.push(Insn::ldx_msh(net_off)); // X = IHL * 4
                established
            };
            if let L4Set::One(n) = established {
                if self.facts.ip4_proto.is_none() {
                    self.facts.ip4_proto = Some(n);
                }
            }
            self.facts.ports_ready = Some(established);
        } else if known_v6 {
            let established = if self.facts.ports_ready.is_some() {
                self.push(Insn::ldb_abs(ip6_nh_off));
                self.emit_l4_set_check(want, &mut p.failure)?;
                want
            } else {
                let established = match self.facts.ip6_nh {
                    Some(n) if want.contains(n) => L4Set::One(n),
                    _ => {
                        self.push(Insn::ldb_abs(ip6_nh_off));
                        self.emit_l4_set_check(want, &mut p.failure)?;
                        want
                    }
                };
                self.push(Insn::ldx_imm(40)); // IPv6 header is always 40 bytes
                established
            };
            if let L4Set::One(n) = established {
                if self.facts.ip6_nh.is_none() {
                    self.facts.ip6_nh = Some(n);
                }
            }
            self.facts.ports_ready = Some(established);
        } else {
            // Ethertype unknown — or pinned to something that is neither IP
            // version, in which case this code is unreachable at runtime and
            // merely preserves the program's shape. Emit the dual path.
            let ether_off = self
                .link
                .ether_proto_offset()
                .expect("RawIp implies a known-IPv4 path");
            // Load ethertype once; IPv6 branches away, IPv4 check falls through.
            self.push(Insn::ldh_abs(ether_off));
            let i_is_ip6 = self.push(Insn::jeq_k(0x86dd, 0xff, 0)); // jt → IPv6 (patched below)
            let i_is_ip4 = self.push(Insn::jeq_k(0x0800, 0, 0xff)); // jf → FAIL
            p.failure.push(Patch::Jf(i_is_ip4));

            // ── IPv4 path ──────────────────────────────────────────────────────
            self.push(Insn::ldb_abs(ip4_proto_off));
            self.emit_l4_set_check(want, &mut p.failure)?;

            self.push(Insn::ldh_abs(ip4_frag_off));
            let i_frag = self.push(Insn::jset_k(0x1fff, 0xff, 0)); // jt → FAIL
            p.failure.push(Patch::Jt(i_frag));

            self.push(Insn::ldx_msh(net_off)); // X = IHL * 4
            let ja_skip_ip6 = self.push(Insn::ja(0)); // jump over IPv6 section (patched below)

            // ── IPv6 path ──────────────────────────────────────────────────────
            let ip6_start = self.insns.len();
            self.resolve(Patch::Jt(i_is_ip6), ip6_start)?;

            self.push(Insn::ldb_abs(ip6_nh_off));
            self.emit_l4_set_check(want, &mut p.failure)?;
            self.push(Insn::ldx_imm(40)); // IPv6 header is always 40 bytes

            // Both paths converge here; resolve IPv4 JA to this position.
            let port_check_start = self.insns.len();
            self.resolve(Patch::Ja(ja_skip_ip6), port_check_start)?;
            self.facts.ports_ready = Some(want);
        }

        Ok(p)
    }

    /// Emit an L4 protocol match against A (which must already hold the
    /// protocol / next-header byte).
    /// For [`L4Set::TcpOrUdp`], the TCP jeq's jt is resolved immediately to
    /// jump past the UDP check so it doesn't leak into the success patches.
    fn emit_l4_set_check(&mut self, want: L4Set, failure: &mut Vec<Patch>) -> Result<()> {
        match want {
            L4Set::One(n) => {
                let i = self.push(Insn::jeq_k(n as u32, 0, 0xff));
                failure.push(Patch::Jf(i));
            }
            L4Set::TcpOrUdp => {
                // Accept TCP (6) or UDP (17): jt on TCP shortcut jumps past UDP check.
                let i_tcp = self.push(Insn::jeq_k(6, 0xff, 0));
                let i_udp = self.push(Insn::jeq_k(17, 0, 0xff));
                failure.push(Patch::Jf(i_udp));
                let after = self.insns.len();
                self.resolve(Patch::Jt(i_tcp), after)?;
            }
        }
        Ok(())
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
                    self.resolve(fp, src_start)?;
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

    // ── PPPoE session ─────────────────────────────────────────────────────────

    fn emit_pppoe_session(&mut self, session_id: Option<u16>) -> Result<Patches> {
        let mut p = self.emit_ethertype(0x8864)?;
        if let Some(id) = session_id {
            // PPPoE session ID is at bytes 2–3 of the PPPoE header, which
            // immediately follows the 2-byte ethertype field.
            // Absolute offset: ether_proto_offset + 4.
            let sid_off = self.link.ether_proto_offset().unwrap_or(12) + 4;
            self.push(Insn::ldh_abs(sid_off));
            let idx = self.push(Insn::jeq_k(id as u32, 0, 0xff));
            p.failure.push(Patch::Jf(idx));
        }
        Ok(p)
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
        match &ba.rhs {
            CmpRhs::Const(value) => self.emit_byte_access_const(ba, *value),
            CmpRhs::Load(rhs_load) => self.emit_byte_access_load(ba, rhs_load),
        }
    }

    fn emit_byte_access_const(&mut self, ba: &ByteAccess, value: u32) -> Result<Patches> {
        match ba.layer {
            Layer::Raw => {
                if self.link == LinkType::RawIp {
                    return Err(Error::CodegenError {
                        message: "raw link-layer byte access cannot be used with RawIp link type"
                            .into(),
                    });
                }
                let off = ba.offset as u32;
                self.load_sized(off, ba.size, false);
            }
            Layer::Net => {
                let off = self.link.net_offset() + ba.offset as u32;
                self.load_sized(off, ba.size, false);
            }
            Layer::Trans => {
                self.push(Insn::ldx_msh(self.link.net_offset()));
                let off = self.link.net_offset() + ba.offset as u32;
                self.load_sized(off, ba.size, true);
            }
        }

        self.emit_alu_ops(&ba.alu_ops)?;
        self.emit_cmp(ba.op, value)
    }

    fn emit_alu_ops(&mut self, ops: &[(ArithOp, u32)]) -> Result<()> {
        for &(aop, operand) in ops {
            match aop {
                ArithOp::And => {
                    self.push(Insn::and_k(operand));
                }
                ArithOp::Or => {
                    self.push(Insn::or_k(operand));
                }
                ArithOp::Xor => {
                    self.push(Insn::xor_k(operand));
                }
                ArithOp::Add => {
                    self.push(Insn::add_k(operand));
                }
                ArithOp::Sub => {
                    self.push(Insn::sub_k(operand));
                }
                ArithOp::Mul => {
                    self.push(Insn::mul_k(operand));
                }
                ArithOp::Div => {
                    if operand == 0 {
                        return Err(Error::CodegenError {
                            message: "division by zero in byte-access expression".into(),
                        });
                    }
                    self.push(Insn::div_k(operand));
                }
                ArithOp::Mod => {
                    return Err(Error::CodegenError {
                        message:
                            "modulo (%) is not supported in classic BPF byte-access expressions"
                                .into(),
                    });
                }
                ArithOp::Shl => {
                    self.push(Insn::lsh_k(operand));
                }
                ArithOp::Shr => {
                    self.push(Insn::rsh_k(operand));
                }
            }
        }
        Ok(())
    }

    /// Emit code for an expr-vs-expr byte-access comparison (`lhs op rhs_load`).
    ///
    /// Strategy:
    /// - If neither side is transport-layer, use TAX to shuttle the LHS value
    ///   into X (no scratch memory needed since MSH is not required).
    /// - If either side is transport-layer, use scratch memory slot 0 to
    ///   preserve the LHS value across the MSH + indirect load of the RHS.
    fn emit_byte_access_load(&mut self, ba: &ByteAccess, rhs: &ByteLoad) -> Result<Patches> {
        let net = self.link.net_offset();
        let lhs_trans = ba.layer == Layer::Trans;
        let rhs_trans = rhs.layer == Layer::Trans;

        if lhs_trans || rhs_trans {
            // At least one side needs MSH; use scratch memory for LHS.

            // Load LHS into A.
            if lhs_trans {
                self.push(Insn::ldx_msh(net));
                let off = net + ba.offset as u32;
                self.load_sized(off, ba.size, true);
            } else {
                let off = self.layer_offset(ba.layer, ba.offset as u32);
                self.load_sized(off, ba.size, false);
            }
            self.emit_alu_ops(&ba.alu_ops)?;
            // Save LHS to scratch M[0].
            self.push(Insn::st(0));

            // Load RHS into A.  If LHS was Trans, X still holds IHL*4 from the
            // MSH above — no need to reload it.
            if rhs_trans {
                if !lhs_trans {
                    self.push(Insn::ldx_msh(net));
                }
                let off = net + rhs.offset as u32;
                self.load_sized(off, rhs.size, true);
            } else {
                let off = self.layer_offset(rhs.layer, rhs.offset as u32);
                self.load_sized(off, rhs.size, false);
            }

            // Restore LHS from scratch into X, then compare A (RHS) vs X (LHS).
            self.push(Insn::ldx_mem(0));
        } else {
            // Neither side needs MSH; use TAX for a shorter sequence.
            let lhs_off = self.layer_offset(ba.layer, ba.offset as u32);
            self.load_sized(lhs_off, ba.size, false);
            self.emit_alu_ops(&ba.alu_ops)?;
            self.push(Insn::tax());
            let rhs_off = self.layer_offset(rhs.layer, rhs.offset as u32);
            self.load_sized(rhs_off, rhs.size, false);
            // A = RHS, X = LHS — fall through to emit_cmp_x below.
        }

        self.emit_cmp_x(ba.op)
    }

    /// Compute the absolute packet byte offset for `layer` + `offset`.
    fn layer_offset(&self, layer: Layer, offset: u32) -> u32 {
        match layer {
            Layer::Raw => offset,
            Layer::Net | Layer::Trans => self.link.net_offset() + offset,
        }
    }

    fn load_sized(&mut self, off: u32, size: AccessSize, indirect: bool) {
        let insn = match (size, indirect) {
            (AccessSize::Byte, false) => Insn::ldb_abs(off),
            (AccessSize::Half, false) => Insn::ldh_abs(off),
            (AccessSize::Word, false) => Insn::ldw_abs(off),
            (AccessSize::Byte, true) => Insn::ldb_ind(off),
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

    /// Emit an X-register comparison for an expr-vs-expr test.
    ///
    /// At the call site: A = RHS value, X = LHS value.
    /// We want to test `LHS op RHS`, i.e. `X op A`.
    fn emit_cmp_x(&mut self, op: CmpOp) -> Result<Patches> {
        // A=RHS, X=LHS. Rewrite `X op A` in terms of BPF's `A op X`:
        //   X == A  ↔  A == X     → jeq_x, fail=jf
        //   X != A  ↔  A != X     → jeq_x (inverted), fail=jt
        //   X <  A  ↔  A >  X     → jgt_x, fail=jf
        //   X <= A  ↔  A >= X     → jge_x, fail=jf
        //   X >  A  ↔  NOT(A>=X)  → jge_x (inverted), fail=jt
        //   X >= A  ↔  NOT(A>X)   → jgt_x (inverted), fail=jt
        //   X &  A  ↔  A &  X     → jset_x, fail=jf
        let (insn, fail_field) = match op {
            CmpOp::Eq => (Insn::jeq_x(0, 0xff), PatchField::Jf),
            CmpOp::Ne => (Insn::jeq_x(0xff, 0), PatchField::Jt),
            CmpOp::Lt => (Insn::jgt_x(0, 0xff), PatchField::Jf),
            CmpOp::Le => (Insn::jge_x(0, 0xff), PatchField::Jf),
            CmpOp::Gt => (Insn::jge_x(0xff, 0), PatchField::Jt),
            CmpOp::Ge => (Insn::jgt_x(0xff, 0), PatchField::Jt),
            CmpOp::BitAnd => (Insn::jset_x(0, 0xff), PatchField::Jf),
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
/// Returns [`Error::CodegenError`] for filter
/// constructs that are valid syntax but cannot be represented in classic BPF
/// for the requested link type (e.g. `inbound`/`outbound` direction primitives).
pub fn compile(expr: &Expr, link: LinkType) -> Result<Program> {
    let mut cg = Codegen::new(link);
    let patches = cg.emit_expr(expr)?;

    // Emit terminal instructions.
    let accept_idx = cg.insns.len();
    cg.push(Insn::ret_k(BPF_ACCEPT));
    let drop_idx = cg.insns.len();
    cg.push(Insn::ret_k(BPF_DROP));

    // Resolve all pending patches.
    cg.resolve_all(patches.success, accept_idx)?;
    cg.resolve_all(patches.failure, drop_idx)?;

    // Peephole passes run last: they rewrite and renumber concrete jump
    // offsets, so every patch must already be resolved.
    let mut insns = cg.insns;
    optimize(&mut insns);

    Ok(Program::new(insns))
}
