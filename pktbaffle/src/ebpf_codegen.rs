//! eBPF code generator.
//!
//! Translates an `ast::Expr` into an eBPF program targeting the XDP hook.
//!
//! # Register conventions
//!
//! | Reg | Role |
//! |-----|------|
//! | R0  | Return value (XDP_PASS / XDP_DROP) |
//! | R1  | XDP context pointer (`xdp_md *`), preserved |
//! | R2  | Packet data start, set in prologue, preserved |
//! | R3  | Packet data end, set in prologue, preserved |
//! | R4  | Primary scratch: loaded packet values, computed results |
//! | R5  | Address scratch: bounds-check end pointer, computed base |
//! | R6  | Transport scratch: transport header pointer (port checks) |
//!
//! # Program layout
//!
//! ```text
//! prologue:   r2 = data; r3 = data_end
//! [filter]    fall-through → accept; jump-on-fail → drop
//! accept:     r0 = XDP_PASS; exit
//! drop:       r0 = XDP_DROP; exit
//! ```
//!
//! # Bounds checking
//!
//! Before every packet read of `size` bytes at `offset`, the codegen emits:
//! ```text
//! r5 = r2; r5 += offset + size;
//! if r5 > r3: goto drop
//! ```
//! The `jgt_reg` at the end of this sequence is a failure patch.

use std::net::{IpAddr, Ipv4Addr};

use crate::ast::*;
use crate::codegen::LinkType;
use crate::ebpf::{self, Insn, Program, R2, R3, R4, R5, R6, XDP_DROP, XDP_PASS};
use crate::error::{Error, Result};

// ── Patch bookkeeping ─────────────────────────────────────────────────────────

/// A slot whose `off` field must be filled with a forward jump offset.
#[derive(Debug, Clone, Copy)]
struct Patch(usize);

#[derive(Default)]
struct Patches {
    /// Jump to the ACCEPT epilogue when resolved.
    success: Vec<Patch>,
    /// Jump to the DROP epilogue when resolved.
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

    /// Resolve `patch` to jump forward to `target_idx`.
    fn resolve(&mut self, patch: Patch, target_idx: usize) -> Result<()> {
        let from = patch.0;
        debug_assert!(target_idx > from, "eBPF jump target must be forward");
        let diff = target_idx - from - 1;
        if diff > i16::MAX as usize {
            return Err(Error::CodegenError {
                message: "filter expression is too complex: eBPF jump offset overflow".into(),
            });
        }
        self.insns[from].off = diff as i16;
        Ok(())
    }

    fn resolve_all(&mut self, patches: Vec<Patch>, target_idx: usize) -> Result<()> {
        for p in patches {
            self.resolve(p, target_idx)?;
        }
        Ok(())
    }

    // ── Prologue ─────────────────────────────────────────────────────────────

    /// Emit the XDP prologue: load `data` into R2, `data_end` into R3.
    fn emit_prologue(&mut self) {
        // r2 = *(u32 *)(r1 + 0)   — xdp_md->data
        self.push(Insn::ldx_w(R2, ebpf::R1, 0));
        // r3 = *(u32 *)(r1 + 4)   — xdp_md->data_end
        self.push(Insn::ldx_w(R3, ebpf::R1, 4));
    }

    // ── Bounds check + packet load ────────────────────────────────────────────

    /// Emit a bounds check for `size` bytes at `offset`, then load into R4.
    /// Returns a failure patch for the bounds-check jump.
    fn emit_load_byte(&mut self, offset: u32) -> Patch {
        self.push(Insn::mov64_reg(R5, R2));
        self.push(Insn::add64_imm(R5, (offset + 1) as i32));
        let bc = self.push(Insn::jgt_reg(R5, R3, 0));
        self.push(Insn::ldx_b(R4, R2, offset as i16));
        Patch(bc)
    }

    fn emit_load_half(&mut self, offset: u32) -> Patch {
        self.push(Insn::mov64_reg(R5, R2));
        self.push(Insn::add64_imm(R5, (offset + 2) as i32));
        let bc = self.push(Insn::jgt_reg(R5, R3, 0));
        self.push(Insn::ldx_h(R4, R2, offset as i16));
        Patch(bc)
    }

    fn emit_load_word(&mut self, offset: u32) -> Patch {
        self.push(Insn::mov64_reg(R5, R2));
        self.push(Insn::add64_imm(R5, (offset + 4) as i32));
        let bc = self.push(Insn::jgt_reg(R5, R3, 0));
        self.push(Insn::ldx_w(R4, R2, offset as i16));
        Patch(bc)
    }

    // ── Helper: halfword check (ethertype guard style) ────────────────────────

    /// Load a halfword at `offset`, compare to `expected`.
    /// Returns patches: failure on mismatch, no explicit success.
    fn check_half(&mut self, offset: u32, expected: u32) -> Patches {
        let bc = self.emit_load_half(offset);
        let cmp = Patch(self.push(Insn::jne_imm(R4, expected as i32, 0)));
        Patches {
            success: vec![],
            failure: vec![bc, cmp],
        }
    }

    fn check_byte(&mut self, offset: u32, expected: u32) -> Patches {
        let bc = self.emit_load_byte(offset);
        let cmp = Patch(self.push(Insn::jne_imm(R4, expected as i32, 0)));
        Patches {
            success: vec![],
            failure: vec![bc, cmp],
        }
    }

    fn check_word(&mut self, offset: u32, expected: u32) -> Patches {
        let bc = self.emit_load_word(offset);
        let cmp = Patch(self.push(Insn::jne_imm(R4, expected as i32, 0)));
        Patches {
            success: vec![],
            failure: vec![bc, cmp],
        }
    }

    // ── Ethertype guard ───────────────────────────────────────────────────────

    fn emit_ethertype(&mut self, et: u32) -> Result<Patches> {
        if let Some(off) = self.link.ether_proto_offset() {
            Ok(self.check_half(off, et))
        } else if et == 0x0800 {
            Ok(Patches::default()) // RawIp: IPv4 is implicit
        } else {
            Err(Error::CodegenError {
                message: format!("ethertype 0x{et:04x} cannot be matched on RawIp captures"),
            })
        }
    }

    fn ip4_guard(&mut self) -> Result<Patches> {
        self.emit_ethertype(0x0800)
    }

    fn emit_ip4_l4(&mut self, proto_num: u8) -> Result<Patches> {
        let mut p = self.ip4_guard()?;
        let q = self.check_byte(self.link.net_offset() + 9, proto_num as u32);
        p.failure.extend(q.failure);
        Ok(p)
    }

    fn emit_ip6_l4(&mut self, next_hdr: u8) -> Result<Patches> {
        let mut p = self.emit_ethertype(0x86dd)?;
        let q = self.check_byte(self.link.net_offset() + 6, next_hdr as u32);
        p.failure.extend(q.failure);
        Ok(p)
    }

    /// Dual-stack L4 protocol check: accepts packets that are either IPv4 with
    /// `proto_num` in the protocol byte, or IPv6 with `proto_num` as next-header.
    ///
    /// For `RawIp` captures (no ethertype field) this falls back to IPv4-only.
    fn emit_dual_l4(&mut self, proto_num: u8) -> Result<Patches> {
        let Some(ether_off) = self.link.ether_proto_offset() else {
            return self.emit_ip4_l4(proto_num);
        };
        let net_off = self.link.net_offset();
        let mut p = Patches::default();

        // Load ethertype (bounds-check + half into R4).
        let bc_et = self.emit_load_half(ether_off);
        p.failure.push(bc_et);

        // jeq 0x0800 → ipv4_path
        let jmp_to_ipv4 = self.push(Insn::jeq_imm(R4, 0x0800, 0));

        // jne 0x86dd → drop (not IPv4, not IPv6)
        let not_ipv6 = Patch(self.push(Insn::jne_imm(R4, 0x86dd, 0)));
        p.failure.push(not_ipv6);

        // IPv6: check next-header at net_off + 6.
        let q6 = self.check_byte(net_off + 6, proto_num as u32);
        p.failure.extend(q6.failure);

        // JA past IPv4 block.
        let ja = self.push(Insn::ja(0));

        // IPv4 path.
        let ipv4_start = self.insns.len();
        self.resolve(Patch(jmp_to_ipv4), ipv4_start)?;

        // IPv4: check protocol byte at net_off + 9.
        let q4 = self.check_byte(net_off + 9, proto_num as u32);
        p.failure.extend(q4.failure);

        let after = self.insns.len();
        self.resolve(Patch(ja), after)?;

        Ok(p)
    }

    // ── Expression dispatch ───────────────────────────────────────────────────

    fn emit_expr(&mut self, expr: &Expr) -> Result<Patches> {
        match expr {
            Expr::And(l, r) => self.emit_and(l, r),
            Expr::Or(l, r) => self.emit_or(l, r),
            Expr::Not(e) => self.emit_not(e),
            Expr::Primitive(p) => self.emit_primitive(p),
        }
    }

    fn emit_and(&mut self, left: &Expr, right: &Expr) -> Result<Patches> {
        let left_p = self.emit_expr(left)?;
        let right_start = self.insns.len();
        self.resolve_all(left_p.success, right_start)?;
        let right_p = self.emit_expr(right)?;
        Ok(Patches {
            success: right_p.success,
            failure: left_p.failure.into_iter().chain(right_p.failure).collect(),
        })
    }

    fn emit_or(&mut self, left: &Expr, right: &Expr) -> Result<Patches> {
        let left_p = self.emit_expr(left)?;
        let ja_idx = self.push(Insn::ja(0));
        let right_start = self.insns.len();
        self.resolve_all(left_p.failure, right_start)?;
        let right_p = self.emit_expr(right)?;
        let mut success = left_p.success;
        success.push(Patch(ja_idx));
        success.extend(right_p.success);
        Ok(Patches {
            success,
            failure: right_p.failure,
        })
    }

    fn emit_not(&mut self, inner: &Expr) -> Result<Patches> {
        let inner_p = self.emit_expr(inner)?;
        let ja_idx = self.push(Insn::ja(0));
        let not_succ_start = self.insns.len();
        self.resolve_all(inner_p.failure, not_succ_start)?;
        Ok(Patches {
            success: vec![],
            failure: inner_p
                .success
                .into_iter()
                .chain(std::iter::once(Patch(ja_idx)))
                .collect(),
        })
    }

    // ── Primitives ────────────────────────────────────────────────────────────

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
            Primitive::ByteAccess(ba) => self.emit_byte_access(ba),
            Primitive::Inbound | Primitive::Outbound => Err(Error::CodegenError {
                message: "inbound/outbound direction cannot be expressed in eBPF".into(),
            }),
        }
    }

    // ── Protocol ─────────────────────────────────────────────────────────────

    fn emit_proto(&mut self, proto: &Proto) -> Result<Patches> {
        match proto {
            Proto::Ip => self.emit_ethertype(0x0800),
            Proto::Ip6 => self.emit_ethertype(0x86dd),
            Proto::Arp => self.emit_ethertype(0x0806),
            Proto::Rarp => self.emit_ethertype(0x8035),
            // TCP, UDP, and SCTP run over both IPv4 and IPv6 — use dual-stack.
            Proto::Tcp => self.emit_dual_l4(6),
            Proto::Udp => self.emit_dual_l4(17),
            Proto::Sctp => self.emit_dual_l4(132),
            // ICMP and IGMP are IPv4-only; ICMPv6 and ip6proto are IPv6-only.
            Proto::Icmp => self.emit_ip4_l4(1),
            Proto::Igmp => self.emit_ip4_l4(2),
            Proto::Icmp6 => self.emit_ip6_l4(58),
            Proto::Num(n) => self.emit_ip4_l4(*n),
            Proto::Ip6Proto(n) => self.emit_ip6_l4(*n),
        }
    }

    // ── Host ─────────────────────────────────────────────────────────────────

    fn emit_host(&mut self, addr: IpAddr, dir: Dir) -> Result<Patches> {
        match addr {
            IpAddr::V4(a) => self.emit_host4(a, dir),
            IpAddr::V6(a) => self.emit_host6(a, dir),
        }
    }

    fn emit_host4(&mut self, addr: Ipv4Addr, dir: Dir) -> Result<Patches> {
        let mut p = self.ip4_guard()?;
        let base = self.link.net_offset();
        let src_off = base + 12;
        let dst_off = base + 16;
        let k = u32::from(addr) as i32;
        let q = self.check_addr4(k, src_off, dst_off, dir);
        p.failure.extend(q.failure);
        p.success.extend(q.success);
        Ok(p)
    }

    fn check_addr4(&mut self, k: i32, src_off: u32, dst_off: u32, dir: Dir) -> Patches {
        match dir {
            Dir::Src => {
                let bc = self.emit_load_word(src_off);
                let cmp = Patch(self.push(Insn::jne_imm(R4, k, 0)));
                Patches {
                    success: vec![],
                    failure: vec![bc, cmp],
                }
            }
            Dir::Dst => {
                let bc = self.emit_load_word(dst_off);
                let cmp = Patch(self.push(Insn::jne_imm(R4, k, 0)));
                Patches {
                    success: vec![],
                    failure: vec![bc, cmp],
                }
            }
            Dir::SrcAndDst => {
                let bc1 = self.emit_load_word(src_off);
                let cmp1 = Patch(self.push(Insn::jne_imm(R4, k, 0)));
                let bc2 = self.emit_load_word(dst_off);
                let cmp2 = Patch(self.push(Insn::jne_imm(R4, k, 0)));
                Patches {
                    success: vec![],
                    failure: vec![bc1, cmp1, bc2, cmp2],
                }
            }
            Dir::SrcOrDst => {
                let bc1 = self.emit_load_word(src_off);
                let eq_src = Patch(self.push(Insn::jeq_imm(R4, k, 0)));
                let bc2 = self.emit_load_word(dst_off);
                let cmp2 = Patch(self.push(Insn::jne_imm(R4, k, 0)));
                Patches {
                    success: vec![eq_src],
                    failure: vec![bc1, bc2, cmp2],
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

        let check_ip6 = |cg: &mut Codegen, off: u32, fail: &mut Vec<Patch>| {
            for (i, &seg) in segs.iter().enumerate() {
                let bc = cg.emit_load_half(off + i as u32 * 2);
                let cmp = Patch(cg.push(Insn::jne_imm(R4, seg as i32, 0)));
                fail.push(bc);
                fail.push(cmp);
            }
        };

        match dir {
            Dir::Src => check_ip6(self, src_off, &mut p.failure),
            Dir::Dst => check_ip6(self, dst_off, &mut p.failure),
            Dir::SrcAndDst => {
                check_ip6(self, src_off, &mut p.failure);
                check_ip6(self, dst_off, &mut p.failure);
            }
            Dir::SrcOrDst => {
                let mut src_fails = Vec::new();
                check_ip6(self, src_off, &mut src_fails);
                let ja_idx = Patch(self.push(Insn::ja(0)));
                let dst_start = self.insns.len();
                for fp in src_fails {
                    self.resolve(fp, dst_start)?;
                }
                check_ip6(self, dst_off, &mut p.failure);
                p.success.push(ja_idx);
            }
        }
        Ok(p)
    }

    // ── Network ───────────────────────────────────────────────────────────────

    fn emit_net(&mut self, net: &IpNet, dir: Dir) -> Result<Patches> {
        let mut p = self.ip4_guard()?;
        let base = self.link.net_offset();
        let src_off = base + 12;
        let dst_off = base + 16;
        let mask = net.mask as i32;
        let masked = (u32::from(net.addr) & net.mask) as i32;

        let check = |cg: &mut Codegen, off: u32, fail: &mut Vec<Patch>| {
            let bc = cg.emit_load_word(off);
            cg.push(Insn::and32_imm(R4, mask));
            let cmp = Patch(cg.push(Insn::jne_imm(R4, masked, 0)));
            fail.push(bc);
            fail.push(cmp);
        };

        match dir {
            Dir::Src => check(self, src_off, &mut p.failure),
            Dir::Dst => check(self, dst_off, &mut p.failure),
            Dir::SrcAndDst => {
                check(self, src_off, &mut p.failure);
                check(self, dst_off, &mut p.failure);
            }
            Dir::SrcOrDst => {
                let bc = self.emit_load_word(src_off);
                self.push(Insn::and32_imm(R4, mask));
                let eq_src = Patch(self.push(Insn::jeq_imm(R4, masked, 0)));
                let bc2 = self.emit_load_word(dst_off);
                self.push(Insn::and32_imm(R4, mask));
                let cmp2 = Patch(self.push(Insn::jne_imm(R4, masked, 0)));
                p.success.push(eq_src);
                p.failure.extend([bc, bc2, cmp2]);
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
                let bc = cg.emit_load_half(off);
                fail.push(bc);
                if end_bit <= prefix_len as u32 {
                    let cmp = Patch(cg.push(Insn::jne_imm(R4, seg as i32, 0)));
                    fail.push(cmp);
                } else {
                    let bits = prefix_len as u32 - start_bit;
                    let mask = (0xffffu32 << (16 - bits)) & 0xffff;
                    let expected = (seg as u32) & mask;
                    cg.push(Insn::and32_imm(R4, mask as i32));
                    let cmp = Patch(cg.push(Insn::jne_imm(R4, expected as i32, 0)));
                    fail.push(cmp);
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
                let ja_idx = Patch(self.push(Insn::ja(0)));
                let dst_start = self.insns.len();
                for fp in src_fails {
                    self.resolve(fp, dst_start)?;
                }
                check_net6(self, dst_off, &mut p.failure);
                p.success.push(ja_idx);
            }
        }
        Ok(p)
    }

    // ── Port ─────────────────────────────────────────────────────────────────

    /// Emit protocol prereqs + transport header pointer setup for eBPF.
    ///
    /// For link types with an ethertype field (Ethernet, LinuxSll) this emits a
    /// dual-stack IPv4/IPv6 OR path so that both `tcp port 80` and
    /// `ip6 and tcp port 80` work correctly.  For `RawIp` (no ethertype) the
    /// IPv4-only path is used unchanged.
    ///
    /// On return R6 points to the start of the transport header.
    fn emit_port_prereqs(&mut self, proto: Option<Proto>) -> Result<Patches> {
        // RawIp carries no ethertype; IPv4 is implicit — keep old path.
        let Some(ether_off) = self.link.ether_proto_offset() else {
            return self.emit_port_prereqs_ipv4_only(proto);
        };

        let net_off = self.link.net_offset();
        let mut p = Patches::default();

        // Load ethertype (bounds-check + halfword load into R4).
        let bc_et = self.emit_load_half(ether_off);
        p.failure.push(bc_et);

        // jeq R4, 0x0800 → ipv4_path  (if IPv4, jump forward to IPv4 block)
        let jmp_to_ipv4 = self.push(Insn::jeq_imm(R4, 0x0800, 0));

        // jne R4, 0x86dd → drop  (neither IPv4 nor IPv6)
        let not_ipv6 = Patch(self.push(Insn::jne_imm(R4, 0x86dd, 0)));
        p.failure.push(not_ipv6);

        // ── IPv6 path (fall-through) ──────────────────────────────────────────
        // Check next-header field at net_off + 6.
        self.emit_l4_proto_check(net_off + 6, proto, &mut p)?;

        // R6 = R2 + net_off + 40  (fixed IPv6 header size)
        self.push(Insn::mov64_reg(R6, R2));
        self.push(Insn::add64_imm(R6, (net_off + 40) as i32));

        // Bounds-check: transport header needs ≥4 bytes for port fields.
        self.push(Insn::mov64_reg(R5, R6));
        self.push(Insn::add64_imm(R5, 4));
        let bc_v6 = Patch(self.push(Insn::jgt_reg(R5, R3, 0)));
        p.failure.push(bc_v6);

        // Unconditional jump past IPv4 block → port comparison.
        let ja_skip_v4 = self.push(Insn::ja(0));

        // ── IPv4 path ─────────────────────────────────────────────────────────
        let ipv4_start = self.insns.len();
        self.resolve(Patch(jmp_to_ipv4), ipv4_start)?;

        // Check protocol byte at net_off + 9.
        self.emit_l4_proto_check(net_off + 9, proto, &mut p)?;

        // Compute R6 = R2 + net_off + IHL*4.
        let bc_ihl = self.emit_load_byte(net_off);
        p.failure.push(bc_ihl);
        self.push(Insn::and32_imm(R4, 0x0f));
        self.push(Insn::lsh32_imm(R4, 2));
        self.push(Insn::mov64_reg(R6, R2));
        self.push(Insn::add64_imm(R6, net_off as i32));
        self.push(Insn::add64_reg(R6, R4));

        // Bounds-check: transport header needs ≥4 bytes for port fields.
        self.push(Insn::mov64_reg(R5, R6));
        self.push(Insn::add64_imm(R5, 4));
        let bc_v4 = Patch(self.push(Insn::jgt_reg(R5, R3, 0)));
        p.failure.push(bc_v4);

        // Resolve the IPv6-path JA to the port-comparison start.
        let port_check_start = self.insns.len();
        self.resolve(Patch(ja_skip_v4), port_check_start)?;

        Ok(p)
    }

    /// IPv4-only prereqs used for `RawIp` captures (no ethertype field).
    fn emit_port_prereqs_ipv4_only(&mut self, proto: Option<Proto>) -> Result<Patches> {
        let mut p = self.ip4_guard()?;
        let net_off = self.link.net_offset();
        self.emit_l4_proto_check(net_off + 9, proto, &mut p)?;

        // Compute transport header pointer into R6 via IHL.
        let bc_ihl = self.emit_load_byte(net_off);
        p.failure.push(bc_ihl);
        self.push(Insn::and32_imm(R4, 0x0f));
        self.push(Insn::lsh32_imm(R4, 2));
        self.push(Insn::mov64_reg(R6, R2));
        self.push(Insn::add64_imm(R6, net_off as i32));
        self.push(Insn::add64_reg(R6, R4));

        self.push(Insn::mov64_reg(R5, R6));
        self.push(Insn::add64_imm(R5, 4));
        let bc_trans = Patch(self.push(Insn::jgt_reg(R5, R3, 0)));
        p.failure.push(bc_trans);

        Ok(p)
    }

    /// Emit an L4 protocol check at `proto_off`.
    ///
    /// For a specific proto: emit a single-byte equality check.
    /// For `None`: accept TCP (6) or UDP (17).
    fn emit_l4_proto_check(
        &mut self,
        proto_off: u32,
        proto: Option<Proto>,
        p: &mut Patches,
    ) -> Result<()> {
        match proto {
            Some(Proto::Tcp) => {
                p.failure.extend(self.check_byte(proto_off, 6).failure);
            }
            Some(Proto::Udp) => {
                p.failure.extend(self.check_byte(proto_off, 17).failure);
            }
            Some(Proto::Sctp) => {
                p.failure.extend(self.check_byte(proto_off, 132).failure);
            }
            None => {
                // TCP (6) or UDP (17): jeq 6 skips the UDP check on match.
                let bc = self.emit_load_byte(proto_off);
                let eq_tcp = Patch(self.push(Insn::jeq_imm(R4, 6, 0)));
                let cmp_udp = Patch(self.push(Insn::jne_imm(R4, 17, 0)));
                p.failure.extend([bc, cmp_udp]);
                let after_udp = self.insns.len();
                self.resolve(eq_tcp, after_udp)?;
            }
            Some(pr) => {
                return Err(Error::CodegenError {
                    message: format!("port filter with proto {:?} is not supported", pr),
                });
            }
        }
        Ok(())
    }

    fn emit_port(&mut self, port: u16, dir: Dir, proto: Option<Proto>) -> Result<Patches> {
        let mut p = self.emit_port_prereqs(proto)?;
        let k = port as i32;

        // Load port from R6 (transport header pointer).
        // src port at R6+0, dst port at R6+2.
        match dir {
            Dir::Src => {
                self.push(Insn::ldx_h(R4, R6, 0));
                let cmp = self.push(Insn::jne_imm(R4, k, 0));
                p.failure.push(Patch(cmp));
            }
            Dir::Dst => {
                self.push(Insn::ldx_h(R4, R6, 2));
                let cmp = self.push(Insn::jne_imm(R4, k, 0));
                p.failure.push(Patch(cmp));
            }
            Dir::SrcAndDst => {
                self.push(Insn::ldx_h(R4, R6, 0));
                let cmp1 = self.push(Insn::jne_imm(R4, k, 0));
                self.push(Insn::ldx_h(R4, R6, 2));
                let cmp2 = self.push(Insn::jne_imm(R4, k, 0));
                p.failure.extend([Patch(cmp1), Patch(cmp2)]);
            }
            Dir::SrcOrDst => {
                self.push(Insn::ldx_h(R4, R6, 0));
                let eq_src = self.push(Insn::jeq_imm(R4, k, 0));
                self.push(Insn::ldx_h(R4, R6, 2));
                let cmp_dst = self.push(Insn::jne_imm(R4, k, 0));
                p.success.push(Patch(eq_src));
                p.failure.push(Patch(cmp_dst));
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
        let lo = lo as i32;
        let hi = hi as i32;

        let check_range = |cg: &mut Codegen, src_reg: u8, off: i16, fail: &mut Vec<Patch>| {
            cg.push(Insn::ldx_h(R4, src_reg, off));
            // A < lo → drop
            let i_lo = cg.push(Insn::jlt_imm(R4, lo, 0));
            fail.push(Patch(i_lo));
            // A > hi → drop
            let i_hi = cg.push(Insn::jgt_imm(R4, hi, 0));
            fail.push(Patch(i_hi));
        };

        match dir {
            Dir::Src => check_range(self, R6, 0, &mut p.failure),
            Dir::Dst => check_range(self, R6, 2, &mut p.failure),
            Dir::SrcAndDst => {
                check_range(self, R6, 0, &mut p.failure);
                check_range(self, R6, 2, &mut p.failure);
            }
            Dir::SrcOrDst => {
                let mut src_fails = Vec::new();
                check_range(self, R6, 0, &mut src_fails);
                let ja_idx = self.push(Insn::ja(0));
                let dst_start = self.insns.len();
                for fp in src_fails {
                    self.resolve(fp, dst_start)?;
                }
                check_range(self, R6, 2, &mut p.failure);
                p.success.push(Patch(ja_idx));
            }
        }
        Ok(p)
    }

    // ── Ethernet host ─────────────────────────────────────────────────────────

    fn emit_ether_host(&mut self, addr: &MacAddr, dir: Dir) -> Result<Patches> {
        if self.link == LinkType::RawIp {
            return Err(Error::CodegenError {
                message: "ether host cannot be used with RawIp link type".into(),
            });
        }
        let word = u32::from_be_bytes([addr.0[0], addr.0[1], addr.0[2], addr.0[3]]) as i32;
        let half = u32::from_be_bytes([0, 0, addr.0[4], addr.0[5]]) as i32;

        let check_mac = |cg: &mut Codegen, offset: u32, fail: &mut Vec<Patch>| {
            let bc1 = cg.emit_load_word(offset);
            let cmp1 = Patch(cg.push(Insn::jne_imm(R4, word, 0)));
            fail.extend([bc1, cmp1]);
            let bc2 = cg.emit_load_half(offset + 4);
            let cmp2 = Patch(cg.push(Insn::jne_imm(R4, half, 0)));
            fail.extend([bc2, cmp2]);
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
                let ja_idx = Patch(self.push(Insn::ja(0)));
                let src_start = self.insns.len();
                for fp in src_fails {
                    self.resolve(fp, src_start)?;
                }
                check_mac(self, 6, &mut p.failure); // src MAC at offset 6
                p.success.push(ja_idx);
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
        let bc = self.emit_load_byte(0);
        // Bit 0 not set → not multicast → drop
        let cmp = Patch(self.push(Insn::jset_imm(R4, 0x01, 0)));
        // Fall-through means bit not set → failure
        let ja_fail = Patch(self.push(Insn::ja(0)));
        let after = self.insns.len();
        // Resolve jset shortcut past ja_fail to the success fall-through.
        self.resolve(cmp, after)?;
        Ok(Patches {
            success: vec![],
            failure: vec![bc, ja_fail],
        })
    }

    // ── IP broadcast / multicast ──────────────────────────────────────────────

    fn emit_ip_broadcast(&mut self) -> Result<Patches> {
        let mut p = self.ip4_guard()?;
        let dst_off = self.link.net_offset() + 16;
        let q = self.check_word(dst_off, 0xffff_ffff);
        p.failure.extend(q.failure);
        Ok(p)
    }

    fn emit_ip_multicast(&mut self) -> Result<Patches> {
        let mut p = self.ip4_guard()?;
        let dst_off = self.link.net_offset() + 16;
        let bc = self.emit_load_word(dst_off);
        self.push(Insn::and32_imm(R4, 0xf000_0000u32 as i32));
        let cmp = Patch(self.push(Insn::jne_imm(R4, 0xe000_0000u32 as i32, 0)));
        p.failure.extend([bc, cmp]);
        Ok(p)
    }

    fn emit_ip6_multicast(&mut self) -> Result<Patches> {
        let mut p = self.emit_ethertype(0x86dd)?;
        let dst_off = self.link.net_offset() + 24;
        let q = self.check_byte(dst_off, 0xff);
        p.failure.extend(q.failure);
        Ok(p)
    }

    // ── VLAN ──────────────────────────────────────────────────────────────────

    fn emit_vlan(&mut self, id: Option<u16>) -> Result<Patches> {
        let mut p = self.emit_ethertype(0x8100)?;
        if let Some(vid) = id {
            let tci_off = self.link.ether_proto_offset().unwrap_or(14) + 2;
            let bc = self.emit_load_half(tci_off);
            self.push(Insn::and32_imm(R4, 0x0fff));
            let cmp = Patch(self.push(Insn::jne_imm(R4, vid as i32, 0)));
            p.failure.extend([bc, cmp]);
        }
        Ok(p)
    }

    // ── MPLS ──────────────────────────────────────────────────────────────────

    fn emit_mpls(&mut self, label: Option<u32>) -> Result<Patches> {
        let off = self
            .link
            .ether_proto_offset()
            .ok_or_else(|| Error::CodegenError {
                message: "mpls cannot be matched on RawIp captures".into(),
            })?;

        let bc = self.emit_load_half(off);
        let eq_uni = Patch(self.push(Insn::jeq_imm(R4, 0x8847, 0)));
        let cmp_mc = Patch(self.push(Insn::jne_imm(R4, 0x8848, 0)));
        let after_et = self.insns.len();
        self.resolve(eq_uni, after_et)?;

        let mut p = Patches {
            success: vec![],
            failure: vec![bc, cmp_mc],
        };

        if let Some(lbl) = label {
            let lse_off = off + 2;
            let bc2 = self.emit_load_word(lse_off);
            self.push(Insn::rsh32_imm(R4, 12));
            let cmp2 = Patch(self.push(Insn::jne_imm(R4, lbl as i32, 0)));
            p.failure.extend([bc2, cmp2]);
        }
        Ok(p)
    }

    // ── PPPoE session ─────────────────────────────────────────────────────────

    fn emit_pppoe_session(&mut self, session_id: Option<u16>) -> Result<Patches> {
        let mut p = self.emit_ethertype(0x8864)?;
        if let Some(id) = session_id {
            // PPPoE session ID is at bytes 2–3 of the PPPoE header, which
            // immediately follows the 2-byte ethertype field.
            // Absolute offset: ether_proto_offset + 4.
            let sid_off = self.link.ether_proto_offset().unwrap_or(12) + 4;
            let bc = self.emit_load_half(sid_off);
            let cmp = Patch(self.push(Insn::jne_imm(R4, id as i32, 0)));
            p.failure.extend([bc, cmp]);
        }
        Ok(p)
    }

    // ── Length predicates ─────────────────────────────────────────────────────

    fn emit_len(&mut self, op: CmpOp, value: u32) -> Result<Patches> {
        // packet length = data_end - data
        self.push(Insn::mov64_reg(R4, R3));
        self.push(Insn::new(
            ebpf::BPF_ALU64 | ebpf::BPF_SUB | ebpf::BPF_X,
            R4,
            R2,
            0,
            0,
        ));
        self.emit_cmp(op, value)
    }

    // ── Raw byte access ───────────────────────────────────────────────────────

    fn emit_byte_access(&mut self, ba: &ByteAccess) -> Result<Patches> {
        let value =
            match &ba.rhs {
                CmpRhs::Const(v) => *v,
                CmpRhs::Load(_) => return Err(Error::CodegenError {
                    message:
                        "expr-vs-expr byte-access comparison is not yet supported for eBPF targets"
                            .into(),
                }),
            };

        let base_off = match ba.layer {
            Layer::Raw => 0u32,
            Layer::Net => self.link.net_offset(),
            Layer::Trans => {
                return self.emit_trans_byte_access(ba, value);
            }
        };
        let off = base_off + ba.offset as u32;
        let bc = match ba.size {
            AccessSize::Byte => self.emit_load_byte(off),
            AccessSize::Half => self.emit_load_half(off),
            AccessSize::Word => self.emit_load_word(off),
        };
        for &(aop, operand) in &ba.alu_ops {
            self.push(ebpf_alu32(aop, R4, operand as i32)?);
        }
        let mut p = self.emit_cmp(ba.op, value)?;
        p.failure.insert(0, bc);
        Ok(p)
    }

    fn emit_trans_byte_access(&mut self, ba: &ByteAccess, value: u32) -> Result<Patches> {
        let net_off = self.link.net_offset();
        let bc_ihl = self.emit_load_byte(net_off);
        self.push(Insn::and32_imm(R4, 0x0f));
        self.push(Insn::lsh32_imm(R4, 2));
        self.push(Insn::mov64_reg(R6, R2));
        self.push(Insn::add64_imm(R6, net_off as i32));
        self.push(Insn::add64_reg(R6, R4));
        let size_bytes = match ba.size {
            AccessSize::Byte => 1i32,
            AccessSize::Half => 2,
            AccessSize::Word => 4,
        };
        let end_off = ba.offset + size_bytes;
        self.push(Insn::mov64_reg(R5, R6));
        self.push(Insn::add64_imm(R5, end_off));
        let bc_trans = Patch(self.push(Insn::jgt_reg(R5, R3, 0)));

        let insn = match ba.size {
            AccessSize::Byte => Insn::ldx_b(R4, R6, ba.offset as i16),
            AccessSize::Half => Insn::ldx_h(R4, R6, ba.offset as i16),
            AccessSize::Word => Insn::ldx_w(R4, R6, ba.offset as i16),
        };
        self.push(insn);
        for &(aop, operand) in &ba.alu_ops {
            self.push(ebpf_alu32(aop, R4, operand as i32)?);
        }
        let mut p = self.emit_cmp(ba.op, value)?;
        p.failure.extend([bc_ihl, bc_trans]);
        Ok(p)
    }

    fn emit_cmp(&mut self, op: CmpOp, value: u32) -> Result<Patches> {
        let v = value as i32;
        let idx = match op {
            CmpOp::Eq => self.push(Insn::jne_imm(R4, v, 0)),
            CmpOp::Ne => self.push(Insn::jeq_imm(R4, v, 0)),
            CmpOp::Gt => self.push(Insn::jle_imm(R4, v, 0)),
            CmpOp::Ge => self.push(Insn::jlt_imm(R4, v, 0)),
            CmpOp::Lt => self.push(Insn::jge_imm(R4, v, 0)),
            CmpOp::Le => self.push(Insn::jgt_imm(R4, v, 0)),
            CmpOp::BitAnd => {
                let jset = Patch(self.push(Insn::jset_imm(R4, v, 0)));
                let ja_fail = Patch(self.push(Insn::ja(0)));
                let after = self.insns.len();
                self.resolve(jset, after)?;
                return Ok(Patches {
                    success: vec![],
                    failure: vec![ja_fail],
                });
            }
        };
        Ok(Patches {
            success: vec![],
            failure: vec![Patch(idx)],
        })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn ebpf_alu32(op: ArithOp, dst: u8, imm: i32) -> Result<Insn> {
    Ok(match op {
        ArithOp::And => Insn::and32_imm(dst, imm),
        ArithOp::Or => Insn::or32_imm(dst, imm),
        ArithOp::Xor => Insn::xor32_imm(dst, imm),
        ArithOp::Add => Insn::add32_imm(dst, imm),
        ArithOp::Sub => Insn::sub32_imm(dst, imm),
        ArithOp::Mul => Insn::mul32_imm(dst, imm),
        ArithOp::Div => {
            if imm == 0 {
                return Err(Error::CodegenError {
                    message: "division by zero in byte-access expression".into(),
                });
            }
            Insn::div32_imm(dst, imm)
        }
        ArithOp::Mod => {
            return Err(Error::CodegenError {
                message: "modulo (%) is not supported in eBPF byte-access expressions".into(),
            });
        }
        ArithOp::Shl => Insn::lsh32_imm(dst, imm),
        ArithOp::Shr => Insn::rsh32_imm(dst, imm),
    })
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Compile a filter expression into an eBPF [`Program`] for the given link type.
///
/// The generated program targets the XDP hook and returns `XDP_PASS` (2) for
/// matching packets and `XDP_DROP` (1) for non-matching packets.
pub fn compile(expr: &Expr, link: LinkType) -> Result<Program> {
    let mut cg = Codegen::new(link);
    cg.emit_prologue();
    let patches = cg.emit_expr(expr)?;

    // Epilogue: accept path.
    let accept_idx = cg.insns.len();
    cg.push(Insn::mov64_imm(ebpf::R0, XDP_PASS));
    cg.push(Insn::exit());

    // Drop path.
    let drop_idx = cg.insns.len();
    cg.push(Insn::mov64_imm(ebpf::R0, XDP_DROP));
    cg.push(Insn::exit());

    cg.resolve_all(patches.success, accept_idx)?;
    cg.resolve_all(patches.failure, drop_idx)?;

    Ok(Program::new(cg.insns))
}
