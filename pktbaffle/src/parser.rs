//! Recursive-descent parser for libpcap-style filter expressions.
//!
//! Grammar (lowest to highest precedence):
//!
//! ```text
//! expr      ::= or_expr
//! or_expr   ::= and_expr ('or' and_expr)*
//! and_expr  ::= not_expr ('and' not_expr | not_expr)*   // juxtaposition = AND
//! not_expr  ::= ('not' | '!') not_expr | atom
//! atom      ::= '(' expr ')' | primitive
//! ```

use std::net::IpAddr;

use crate::ast::*;
use crate::error::{Error, Result};
use crate::lexer::{Spanned, Token};

/// Parse a slice of [`Spanned`] tokens into a filter expression tree.
///
/// This is the low-level entry point. Most callers should use
/// [`pktbaffle::parse`][crate::parse], which handles lexing automatically.
///
/// # Errors
///
/// Returns [`Error::ParseError`] if the token
/// stream does not match the filter grammar.
///
/// # Example
///
/// ```rust
/// use pktbaffle::{lexer, parser};
///
/// let tokens = lexer::lex("tcp port 80").unwrap();
/// let expr = parser::parse(&tokens).unwrap();
/// println!("{expr:#?}");
/// ```
pub fn parse(tokens: &[Spanned]) -> Result<Expr> {
    let mut p = Parser { tokens, pos: 0 };
    let expr = p.parse_expr()?;
    if p.pos < p.tokens.len() {
        return Err(p.err(format!(
            "unexpected token {:?} — trailing input",
            p.cur_tok()
        )));
    }
    Ok(expr)
}

struct Parser<'a> {
    tokens: &'a [Spanned],
    pos: usize,
}

impl Parser<'_> {
    fn cur_tok(&self) -> Option<&Token> {
        self.tokens.get(self.pos).map(|s| &s.token)
    }

    fn advance(&mut self) -> Option<&Token> {
        let t = self.tokens.get(self.pos).map(|s| &s.token);
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn eat(&mut self, expected: &Token) -> bool {
        if self.cur_tok() == Some(expected) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, expected: &Token) -> Result<()> {
        if self.eat(expected) {
            Ok(())
        } else {
            Err(self.err(format!("expected {:?}, got {:?}", expected, self.cur_tok())))
        }
    }

    fn err(&self, msg: impl Into<String>) -> Error {
        Error::ParseError {
            message: msg.into(),
        }
    }

    // ── expression levels ────────────────────────────────────────────────────

    fn parse_expr(&mut self) -> Result<Expr> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<Expr> {
        let mut left = self.parse_and()?;
        while self.eat(&Token::Or) {
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr> {
        let mut left = self.parse_not()?;
        loop {
            let explicit = self.eat(&Token::And);
            if !explicit {
                // Implicit AND: next token can start a primitive, and it's not
                // an `or` or `)` or end of input.
                match self.cur_tok() {
                    None | Some(Token::Or) | Some(Token::RParen) => break,
                    _ => {}
                }
                // But only if the current position actually looks like the
                // start of a primitive (not some dangling token).
                if !self.looks_like_primitive_start() {
                    break;
                }
            }
            let right = self.parse_not()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn looks_like_primitive_start(&self) -> bool {
        matches!(
            self.cur_tok(),
            Some(
                Token::Not
                    | Token::Bang
                    | Token::LParen
                    | Token::Src
                    | Token::Dst
                    | Token::Host
                    | Token::Net
                    | Token::Port
                    | Token::PortRange
                    | Token::Ether
                    | Token::Broadcast
                    | Token::Multicast
                    | Token::Ip
                    | Token::Ip6
                    | Token::Arp
                    | Token::Rarp
                    | Token::Tcp
                    | Token::Udp
                    | Token::Icmp
                    | Token::Icmp6
                    | Token::Igmp
                    | Token::Sctp
                    | Token::Proto
                    | Token::Ah
                    | Token::Esp
                    | Token::Pim
                    | Token::Igrp
                    | Token::Vrrp
                    | Token::Vlan
                    | Token::Mpls
                    | Token::Pppoed
                    | Token::Pppoes
                    | Token::Inbound
                    | Token::Outbound
                    | Token::Len
                    | Token::Less
                    | Token::Greater
                    | Token::Gateway
                    | Token::Ipv4(_)
                    | Token::Ipv6(_)
                    | Token::Num(_)
                    | Token::LBracket
            )
        )
    }

    fn parse_not(&mut self) -> Result<Expr> {
        if self.eat(&Token::Not) || self.eat(&Token::Bang) {
            let inner = self.parse_not()?;
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.parse_atom()
    }

    fn parse_atom(&mut self) -> Result<Expr> {
        if self.eat(&Token::LParen) {
            let inner = self.parse_expr()?;
            self.expect(&Token::RParen)?;
            return Ok(inner);
        }
        self.parse_primitive().map(Expr::Primitive)
    }

    // ── primitives ───────────────────────────────────────────────────────────

    fn parse_primitive(&mut self) -> Result<Primitive> {
        match self.cur_tok() {
            // ── length comparisons ───────────────────────────────────────────
            Some(Token::Less) => {
                self.advance();
                Ok(Primitive::Len {
                    op: CmpOp::Le,
                    value: self.parse_u32()?,
                })
            }
            Some(Token::Greater) => {
                self.advance();
                Ok(Primitive::Len {
                    op: CmpOp::Ge,
                    value: self.parse_u32()?,
                })
            }
            Some(Token::Len) => {
                self.advance();
                let op = self.parse_cmpop()?;
                let value = self.parse_u32()?;
                Ok(Primitive::Len { op, value })
            }

            // ── bare link-layer keywords ─────────────────────────────────────
            Some(Token::Broadcast) => {
                self.advance();
                // bare `broadcast` = ether broadcast = dst MAC ff:ff:ff:ff:ff:ff
                Ok(Primitive::EtherHost {
                    addr: MacAddr([0xff; 6]),
                    dir: Dir::Dst,
                })
            }
            Some(Token::Multicast) => {
                self.advance();
                // bare `multicast` = ether multicast
                Ok(Primitive::EtherMulticast)
            }

            // ── bare protocol keywords ───────────────────────────────────────
            Some(Token::Ip) => {
                self.advance();
                if self.cur_tok() == Some(&Token::LBracket) {
                    return self.parse_byte_access(Layer::Net);
                }
                if self.eat(&Token::Proto) {
                    let n = self.parse_proto_num()?;
                    return Ok(Primitive::Proto(Proto::Num(n)));
                }
                if self.eat(&Token::Protochain) {
                    let n = self.parse_proto_num()?;
                    return Ok(Primitive::IpProtoChain(n));
                }
                if self.eat(&Token::Broadcast) {
                    return Ok(Primitive::IpBroadcast);
                }
                if self.eat(&Token::Multicast) {
                    return Ok(Primitive::IpMulticast);
                }
                Ok(Primitive::Proto(Proto::Ip))
            }
            Some(Token::Ip6) => {
                self.advance();
                if self.cur_tok() == Some(&Token::LBracket) {
                    return self.parse_byte_access(Layer::Net);
                }
                if self.eat(&Token::Proto) {
                    let n = self.parse_proto_num()?;
                    return Ok(Primitive::Proto(Proto::Ip6Proto(n)));
                }
                if self.eat(&Token::Protochain) {
                    let n = self.parse_proto_num()?;
                    return Ok(Primitive::Ip6ProtoChain(n));
                }
                if self.eat(&Token::Multicast) {
                    return Ok(Primitive::Ip6Multicast);
                }
                Ok(Primitive::Proto(Proto::Ip6))
            }
            Some(Token::Arp) => {
                self.advance();
                Ok(Primitive::Proto(Proto::Arp))
            }
            Some(Token::Rarp) => {
                self.advance();
                Ok(Primitive::Proto(Proto::Rarp))
            }
            Some(Token::Icmp) => {
                self.advance();
                if self.cur_tok() == Some(&Token::LBracket) {
                    return self.parse_byte_access(Layer::Trans);
                }
                Ok(Primitive::Proto(Proto::Icmp))
            }
            Some(Token::Icmp6) => {
                self.advance();
                if self.cur_tok() == Some(&Token::LBracket) {
                    return self.parse_byte_access(Layer::Trans);
                }
                Ok(Primitive::Proto(Proto::Icmp6))
            }
            Some(Token::Igmp) => {
                self.advance();
                Ok(Primitive::Proto(Proto::Igmp))
            }
            Some(Token::Sctp) => {
                self.advance();
                if self.eat(&Token::Port) {
                    return self.parse_port(Dir::SrcOrDst, Some(Proto::Sctp));
                }
                if self.eat(&Token::PortRange) {
                    return self.parse_portrange(Dir::SrcOrDst, Some(Proto::Sctp));
                }
                Ok(Primitive::Proto(Proto::Sctp))
            }

            Some(Token::Tcp) => {
                self.advance();
                if self.cur_tok() == Some(&Token::LBracket) {
                    return self.parse_byte_access(Layer::Trans);
                }
                if self.eat(&Token::Port) {
                    return self.parse_port(Dir::SrcOrDst, Some(Proto::Tcp));
                }
                if self.eat(&Token::PortRange) {
                    return self.parse_portrange(Dir::SrcOrDst, Some(Proto::Tcp));
                }
                Ok(Primitive::Proto(Proto::Tcp))
            }
            Some(Token::Udp) => {
                self.advance();
                if self.cur_tok() == Some(&Token::LBracket) {
                    return self.parse_byte_access(Layer::Trans);
                }
                if self.eat(&Token::Port) {
                    return self.parse_port(Dir::SrcOrDst, Some(Proto::Udp));
                }
                if self.eat(&Token::PortRange) {
                    return self.parse_portrange(Dir::SrcOrDst, Some(Proto::Udp));
                }
                Ok(Primitive::Proto(Proto::Udp))
            }

            Some(Token::Proto) => {
                self.advance();
                let n = self.parse_u32()?;
                Ok(Primitive::Proto(Proto::Num(n as u8)))
            }

            // ── additional IP protocol keywords ──────────────────────────────
            Some(Token::Ah) => {
                self.advance();
                Ok(Primitive::Proto(Proto::Num(51)))
            }
            Some(Token::Esp) => {
                self.advance();
                Ok(Primitive::Proto(Proto::Num(50)))
            }
            Some(Token::Pim) => {
                self.advance();
                Ok(Primitive::Proto(Proto::Num(103)))
            }
            Some(Token::Igrp) => {
                self.advance();
                Ok(Primitive::Proto(Proto::Num(9)))
            }
            Some(Token::Vrrp) => {
                self.advance();
                Ok(Primitive::Proto(Proto::Num(112)))
            }

            // ── encapsulation primitives ─────────────────────────────────────
            Some(Token::Vlan) => {
                self.advance();
                let id = if let Some(&Token::Num(n)) = self.cur_tok() {
                    self.advance();
                    Some(n as u16)
                } else {
                    None
                };
                Ok(Primitive::Vlan { id })
            }
            Some(Token::Mpls) => {
                self.advance();
                let label = if let Some(&Token::Num(n)) = self.cur_tok() {
                    self.advance();
                    Some(n as u32)
                } else {
                    None
                };
                Ok(Primitive::Mpls { label })
            }
            Some(Token::Pppoed) => {
                self.advance();
                Ok(Primitive::PppoeDiscovery)
            }
            Some(Token::Pppoes) => {
                self.advance();
                let session_id = if let Some(&Token::Num(n)) = self.cur_tok() {
                    if n > 0xffff {
                        return Err(
                            self.err(format!("pppoes session ID {n} out of range (max 65535)"))
                        );
                    }
                    self.advance();
                    Some(n as u16)
                } else {
                    None
                };
                Ok(Primitive::PppoeSession { session_id })
            }

            // ── direction primitives ─────────────────────────────────────────
            Some(Token::Inbound) => {
                self.advance();
                Ok(Primitive::Inbound)
            }
            Some(Token::Outbound) => {
                self.advance();
                Ok(Primitive::Outbound)
            }

            // ── gateway ─────────────────────────────────────────────────────
            Some(Token::Gateway) => {
                self.advance();
                // Consume the hostname/address argument even though we can't compile it.
                self.advance();
                Err(self.err("'gateway' requires DNS resolution and is not supported"))
            }

            Some(Token::Ether) => self.parse_ether_prim(),

            Some(Token::Src) | Some(Token::Dst) => {
                let dir = self.parse_dir();
                self.parse_after_dir(dir)
            }

            Some(Token::Host) => {
                self.advance();
                self.parse_host(Dir::SrcOrDst)
            }
            Some(Token::Net) => {
                self.advance();
                self.parse_net(Dir::SrcOrDst)
            }
            Some(Token::Port) => {
                self.advance();
                self.parse_port(Dir::SrcOrDst, None)
            }
            Some(Token::PortRange) => {
                self.advance();
                self.parse_portrange(Dir::SrcOrDst, None)
            }

            Some(Token::Ipv4(_)) | Some(Token::Ipv6(_)) => {
                let addr = self.parse_ip()?;
                Ok(Primitive::Host {
                    addr,
                    dir: Dir::SrcOrDst,
                })
            }

            // ── raw link-layer byte access: [offset:size] op value ───────────
            Some(Token::LBracket) => self.parse_byte_access(Layer::Raw),

            tok => Err(self.err(format!(
                "unexpected token {:?} — expected a filter primitive",
                tok
            ))),
        }
    }

    fn parse_ether_prim(&mut self) -> Result<Primitive> {
        self.advance(); // consume `ether`
        if self.cur_tok() == Some(&Token::LBracket) {
            return self.parse_byte_access(Layer::Raw);
        }
        let dir = self.parse_dir();
        match self.cur_tok() {
            Some(Token::Host) => {
                self.advance();
                let mac = self.parse_mac()?;
                Ok(Primitive::EtherHost { addr: mac, dir })
            }
            // `ether src <mac>` / `ether dst <mac>` — host keyword optional
            Some(Token::Mac(_)) => {
                let mac = self.parse_mac()?;
                Ok(Primitive::EtherHost { addr: mac, dir })
            }
            Some(Token::Broadcast) => {
                self.advance();
                Ok(Primitive::EtherHost { addr: MacAddr([0xff; 6]), dir: Dir::Dst })
            }
            Some(Token::Multicast) => {
                self.advance();
                Ok(Primitive::EtherMulticast)
            }
            Some(Token::Proto) => {
                self.advance();
                let ethertype = match self.cur_tok() {
                    Some(Token::Ip)   => { self.advance(); 0x0800 }
                    Some(Token::Ip6)  => { self.advance(); 0x86dd }
                    Some(Token::Arp)  => { self.advance(); 0x0806 }
                    Some(Token::Rarp) => { self.advance(); 0x8035 }
                    _ => self.parse_u32()? as u16,
                };
                Ok(Primitive::EtherProto(ethertype))
            }
            Some(Token::Ip)   => { self.advance(); Ok(Primitive::EtherProto(0x0800)) }
            Some(Token::Ip6)  => { self.advance(); Ok(Primitive::EtherProto(0x86dd)) }
            Some(Token::Arp)  => { self.advance(); Ok(Primitive::EtherProto(0x0806)) }
            Some(Token::Rarp) => { self.advance(); Ok(Primitive::EtherProto(0x8035)) }
            tok => Err(self.err(format!(
                "expected 'host', 'broadcast', 'multicast', 'proto', 'ip', 'ip6', 'arp', 'rarp', or a MAC address after 'ether', got {:?}",
                tok
            ))),
        }
    }

    // ── direction qualifier ──────────────────────────────────────────────────

    fn parse_dir(&mut self) -> Dir {
        match self.cur_tok() {
            Some(Token::Src) => {
                self.advance();
                if self.eat(&Token::And) && self.cur_tok() == Some(&Token::Dst) {
                    self.advance();
                    Dir::SrcAndDst
                } else if self.eat(&Token::Or) && self.cur_tok() == Some(&Token::Dst) {
                    self.advance();
                    Dir::SrcOrDst
                } else {
                    Dir::Src
                }
            }
            Some(Token::Dst) => {
                self.advance();
                Dir::Dst
            }
            _ => Dir::SrcOrDst,
        }
    }

    fn parse_after_dir(&mut self, dir: Dir) -> Result<Primitive> {
        match self.cur_tok() {
            Some(Token::Host)      => { self.advance(); self.parse_host(dir) }
            Some(Token::Net)       => { self.advance(); self.parse_net(dir) }
            Some(Token::Port)      => { self.advance(); self.parse_port(dir, None) }
            Some(Token::PortRange) => { self.advance(); self.parse_portrange(dir, None) }
            Some(Token::Tcp) => {
                self.advance();
                if self.eat(&Token::Port) {
                    self.parse_port(dir, Some(Proto::Tcp))
                } else if self.eat(&Token::PortRange) {
                    self.parse_portrange(dir, Some(Proto::Tcp))
                } else {
                    Err(self.err(format!(
                        "expected 'port' or 'portrange' after 'tcp', got {:?}",
                        self.cur_tok()
                    )))
                }
            }
            Some(Token::Udp) => {
                self.advance();
                if self.eat(&Token::Port) {
                    self.parse_port(dir, Some(Proto::Udp))
                } else if self.eat(&Token::PortRange) {
                    self.parse_portrange(dir, Some(Proto::Udp))
                } else {
                    Err(self.err(format!(
                        "expected 'port' or 'portrange' after 'udp', got {:?}",
                        self.cur_tok()
                    )))
                }
            }
            Some(Token::Sctp) => {
                self.advance();
                if self.eat(&Token::Port) {
                    self.parse_port(dir, Some(Proto::Sctp))
                } else if self.eat(&Token::PortRange) {
                    self.parse_portrange(dir, Some(Proto::Sctp))
                } else {
                    Err(self.err(format!(
                        "expected 'port' or 'portrange' after 'sctp', got {:?}",
                        self.cur_tok()
                    )))
                }
            }
            Some(Token::Ipv4(_)) | Some(Token::Ipv6(_)) => {
                let addr = self.parse_ip()?;
                Ok(Primitive::Host { addr, dir })
            }
            tok => Err(self.err(format!(
                "expected 'host', 'net', 'port', 'portrange', or an IP address after direction qualifier, got {:?}",
                tok
            ))),
        }
    }

    // ── concrete primitive parsers ────────────────────────────────────────────

    fn parse_host(&mut self, dir: Dir) -> Result<Primitive> {
        Ok(Primitive::Host {
            addr: self.parse_ip()?,
            dir,
        })
    }

    fn parse_net(&mut self, dir: Dir) -> Result<Primitive> {
        let tok_desc = format!("{:?}", self.cur_tok());
        let octs = match self.advance() {
            Some(Token::Ipv4(octs)) => *octs,
            // Single-octet classful shorthand: `net 10` → `net 10.0.0.0/8`.
            Some(Token::Num(n)) => {
                let n = *n;
                if n > 0xff {
                    return Err(self.err(format!(
                        "expected IPv4 network after 'net', got {}",
                        tok_desc
                    )));
                }
                [n as u8, 0, 0, 0]
            }
            Some(Token::Ipv6(addr)) => {
                let addr = *addr;
                let prefix_len = match self.cur_tok() {
                    Some(Token::Num(n)) => {
                        let n = *n;
                        self.advance();
                        if n > 128 {
                            return Err(self.err(format!(
                                "IPv6 prefix length {n} out of range (0\u{2013}128)"
                            )));
                        }
                        n as u8
                    }
                    _ => {
                        return Err(self.err(
                            "IPv6 net requires a CIDR prefix length (e.g. net 2001:db8::/32)",
                        ))
                    }
                };
                return Ok(Primitive::Net6 {
                    net: Ipv6Net { addr, prefix_len },
                    dir,
                });
            }
            _ => {
                return Err(self.err(format!(
                    "expected IPv4 or IPv6 network after 'net', got {}",
                    tok_desc
                )))
            }
        };
        let addr = std::net::Ipv4Addr::from(octs);
        if self.eat(&Token::Minus) {
            return Err(self.err("net range syntax not supported; use CIDR or mask notation"));
        }
        // CIDR prefix length immediately after the address (lexer splits on '/').
        let mask = if let Some(Token::Num(n)) = self.cur_tok() {
            let n = *n as u8;
            self.advance();
            if n == 0 {
                0u32
            } else {
                !0u32 << (32 - n)
            }
        } else if self.eat(&Token::Mask) {
            // `net <addr> mask <netmask>` syntax
            match self.advance() {
                Some(Token::Ipv4(m)) => u32::from_be_bytes(*m),
                _ => return Err(self.err("expected IPv4 netmask after 'mask'")),
            }
        } else {
            // Classful inference from address bytes
            let m = if octs[3] != 0 {
                32u8
            } else if octs[2] != 0 {
                24
            } else if octs[1] != 0 {
                16
            } else {
                8
            };
            if m == 0 {
                0
            } else {
                !0u32 << (32 - m)
            }
        };
        Ok(Primitive::Net {
            net: IpNet { addr, mask },
            dir,
        })
    }

    fn parse_port(&mut self, dir: Dir, proto: Option<Proto>) -> Result<Primitive> {
        Ok(Primitive::Port {
            port: self.parse_u16()?,
            dir,
            proto,
        })
    }

    fn parse_portrange(&mut self, dir: Dir, proto: Option<Proto>) -> Result<Primitive> {
        let lo = self.parse_u16()?;
        self.expect(&Token::Minus)?;
        let hi = self.parse_u16()?;
        Ok(Primitive::PortRange { lo, hi, dir, proto })
    }

    // ── byte-access: layer[offset:size] op value ─────────────────────────────

    fn parse_byte_access(&mut self, layer: Layer) -> Result<Primitive> {
        self.expect(&Token::LBracket)?;
        let offset = self.parse_i32()?;
        if offset < 0 {
            return Err(self.err(format!(
                "byte-access offset must be non-negative, got {}",
                offset
            )));
        }
        let size = if self.eat(&Token::Colon) {
            match self.cur_tok() {
                Some(Token::Num(1)) => {
                    self.advance();
                    AccessSize::Byte
                }
                Some(Token::Num(2)) => {
                    self.advance();
                    AccessSize::Half
                }
                Some(Token::Num(4)) => {
                    self.advance();
                    AccessSize::Word
                }
                tok => {
                    return Err(self.err(format!(
                        "invalid byte-access size {:?} (must be 1, 2, or 4)",
                        tok
                    )))
                }
            }
        } else {
            AccessSize::Byte
        };
        self.expect(&Token::RBracket)?;

        // Zero or more arithmetic/bitwise ops applied to the loaded value.
        let mut alu_ops: Vec<(ArithOp, u32)> = Vec::new();
        loop {
            let aop = match self.cur_tok() {
                Some(Token::Amp) => ArithOp::And,
                Some(Token::Pipe) => ArithOp::Or,
                Some(Token::Caret) => ArithOp::Xor,
                Some(Token::Plus) => ArithOp::Add,
                Some(Token::Minus) => ArithOp::Sub,
                Some(Token::Star) => ArithOp::Mul,
                Some(Token::Slash) => ArithOp::Div,
                Some(Token::Percent) => ArithOp::Mod,
                Some(Token::Shl) => ArithOp::Shl,
                Some(Token::Shr) => ArithOp::Shr,
                _ => break,
            };
            self.advance();
            let operand = self.parse_u32()?;
            alu_ops.push((aop, operand));
        }

        let op = self.parse_cmpop()?;
        let value = self.parse_u32()?;

        Ok(Primitive::ByteAccess(ByteAccess {
            layer,
            offset,
            size,
            alu_ops,
            op,
            value,
        }))
    }

    fn parse_cmpop(&mut self) -> Result<CmpOp> {
        let tok_desc = format!("{:?}", self.cur_tok());
        match self.advance() {
            Some(Token::Eq) => Ok(CmpOp::Eq),
            Some(Token::Ne) => Ok(CmpOp::Ne),
            Some(Token::Lt) => Ok(CmpOp::Lt),
            Some(Token::Le) => Ok(CmpOp::Le),
            Some(Token::Gt) => Ok(CmpOp::Gt),
            Some(Token::Ge) => Ok(CmpOp::Ge),
            Some(Token::Amp) => Ok(CmpOp::BitAnd),
            _ => Err(self.err(format!(
                "expected comparison operator (=, !=, <, <=, >, >=, &), got {}",
                tok_desc
            ))),
        }
    }

    // ── token helpers ────────────────────────────────────────────────────────

    fn parse_ip(&mut self) -> Result<IpAddr> {
        let tok_desc = format!("{:?}", self.cur_tok());
        match self.advance() {
            Some(Token::Ipv4(octs)) => Ok(IpAddr::V4(std::net::Ipv4Addr::from(*octs))),
            Some(Token::Ipv6(a)) => Ok(IpAddr::V6(*a)),
            _ => Err(self.err(format!("expected IP address, got {}", tok_desc))),
        }
    }

    fn parse_mac(&mut self) -> Result<MacAddr> {
        let tok_desc = format!("{:?}", self.cur_tok());
        match self.advance() {
            Some(Token::Mac(m)) => Ok(MacAddr(*m)),
            _ => Err(self.err(format!(
                "expected MAC address (xx:xx:xx:xx:xx:xx), got {}",
                tok_desc
            ))),
        }
    }

    fn parse_proto_num(&mut self) -> Result<u8> {
        let n = match self.cur_tok() {
            Some(Token::Tcp) => {
                self.advance();
                6
            }
            Some(Token::Udp) => {
                self.advance();
                17
            }
            Some(Token::Icmp) => {
                self.advance();
                1
            }
            Some(Token::Icmp6) => {
                self.advance();
                58
            }
            Some(Token::Igmp) => {
                self.advance();
                2
            }
            Some(Token::Sctp) => {
                self.advance();
                132
            }
            Some(Token::Ah) => {
                self.advance();
                51
            }
            Some(Token::Esp) => {
                self.advance();
                50
            }
            Some(Token::Pim) => {
                self.advance();
                103
            }
            Some(Token::Igrp) => {
                self.advance();
                9
            }
            Some(Token::Vrrp) => {
                self.advance();
                112
            }
            _ => {
                let n = self.parse_u32()?;
                if n > 0xff {
                    return Err(self.err("IP protocol number out of range (0–255)"));
                }
                n as u8
            }
        };
        Ok(n)
    }

    fn parse_u32(&mut self) -> Result<u32> {
        let tok_desc = format!("{:?}", self.cur_tok());
        match self.advance() {
            Some(Token::Num(n)) => {
                let n = *n;
                if n > u32::MAX as u64 {
                    Err(self.err("integer literal too large (max u32)"))
                } else {
                    Ok(n as u32)
                }
            }
            _ => Err(self.err(format!("expected integer literal, got {}", tok_desc))),
        }
    }

    fn parse_u16(&mut self) -> Result<u16> {
        let n = self.parse_u32()?;
        if n > 0xffff {
            Err(self.err("value out of range for a port number (0–65535)"))
        } else {
            Ok(n as u16)
        }
    }

    fn parse_i32(&mut self) -> Result<i32> {
        let neg = self.eat(&Token::Minus);
        let n = self.parse_u32()? as i32;
        Ok(if neg { -n } else { n })
    }
}
