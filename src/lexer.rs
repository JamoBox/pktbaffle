//! Tokenizer for libpcap-style filter expressions.

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    // ── logical operators ────────────────────────────────────────────────────
    And,
    Or,
    Not,

    // ── direction qualifiers ─────────────────────────────────────────────────
    Src,
    Dst,

    // ── address-type qualifiers ──────────────────────────────────────────────
    Host,
    Net,
    Port,
    PortRange,

    // ── link-layer keywords ──────────────────────────────────────────────────
    Ether,
    Broadcast,
    Multicast,

    // ── protocol primitives ──────────────────────────────────────────────────
    Ip,
    Ip6,
    Arp,
    Rarp,
    Tcp,
    Udp,
    Icmp,
    Icmp6,
    Igmp,
    Sctp,
    Proto,

    // ── additional IP protocol keywords ─────────────────────────────────────
    Ah,   // Authentication Header (proto 51)
    Esp,  // Encapsulating Security Payload (proto 50)
    Pim,  // Protocol Independent Multicast (proto 103)
    Igrp, // IGRP (proto 9)
    Vrrp, // VRRP (proto 112)

    // ── encapsulation primitives ─────────────────────────────────────────────
    Vlan,
    Mpls,
    Pppoed,
    Pppoes,

    // ── direction primitives ─────────────────────────────────────────────────
    Inbound,
    Outbound,

    // ── length keyword ────────────────────────────────────────────────────────
    Len,

    // ── net mask keyword ─────────────────────────────────────────────────────
    Mask,

    // ── gateway ──────────────────────────────────────────────────────────────
    Gateway,

    // ── size comparisons ─────────────────────────────────────────────────────
    Less,
    Greater,

    // ── punctuation ──────────────────────────────────────────────────────────
    LParen,
    RParen,
    LBracket,
    RBracket,
    Colon,
    Minus,

    // ── comparison operators ─────────────────────────────────────────────────
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Amp,
    Bang,

    // ── literals ─────────────────────────────────────────────────────────────
    Num(u64),
    Ipv4([u8; 4]),
    Ipv6(std::net::Ipv6Addr),
    Mac([u8; 6]),
    Ident(String),
}

#[derive(Debug, Clone)]
pub struct Spanned {
    pub token: Token,
    pub offset: usize,
}

pub fn lex(src: &str) -> Result<Vec<Spanned>> {
    let bytes = src.as_bytes();
    let len = bytes.len();
    let mut pos = 0;
    let mut tokens: Vec<Spanned> = Vec::new();

    macro_rules! push {
        ($tok:expr) => {
            tokens.push(Spanned {
                token: $tok,
                offset: pos,
            })
        };
    }

    while pos < len {
        if bytes[pos].is_ascii_whitespace() {
            pos += 1;
            continue;
        }

        // ── two-character operators first ────────────────────────────────────
        if pos + 1 < len {
            match (bytes[pos], bytes[pos + 1]) {
                (b'!', b'=') => {
                    push!(Token::Ne);
                    pos += 2;
                    continue;
                }
                (b'<', b'=') => {
                    push!(Token::Le);
                    pos += 2;
                    continue;
                }
                (b'>', b'=') => {
                    push!(Token::Ge);
                    pos += 2;
                    continue;
                }
                (b'&', b'&') => {
                    push!(Token::And);
                    pos += 2;
                    continue;
                }
                (b'|', b'|') => {
                    push!(Token::Or);
                    pos += 2;
                    continue;
                }
                _ => {}
            }
        }

        // ── single-character tokens ──────────────────────────────────────────
        match bytes[pos] {
            b'(' => {
                push!(Token::LParen);
                pos += 1;
                continue;
            }
            b')' => {
                push!(Token::RParen);
                pos += 1;
                continue;
            }
            b'[' => {
                push!(Token::LBracket);
                pos += 1;
                continue;
            }
            b']' => {
                push!(Token::RBracket);
                pos += 1;
                continue;
            }
            b':' => {
                push!(Token::Colon);
                pos += 1;
                continue;
            }
            b'-' => {
                push!(Token::Minus);
                pos += 1;
                continue;
            }
            b'&' => {
                push!(Token::Amp);
                pos += 1;
                continue;
            }
            b'!' => {
                push!(Token::Bang);
                pos += 1;
                continue;
            }
            b'=' => {
                push!(Token::Eq);
                pos += 1;
                continue;
            }
            b'<' => {
                push!(Token::Lt);
                pos += 1;
                continue;
            }
            b'>' => {
                push!(Token::Gt);
                pos += 1;
                continue;
            }
            _ => {}
        }

        // ── hex literals 0x… ─────────────────────────────────────────────────
        if bytes[pos] == b'0' && pos + 1 < len && (bytes[pos + 1] == b'x' || bytes[pos + 1] == b'X')
        {
            let start = pos;
            pos += 2;
            while pos < len && bytes[pos].is_ascii_hexdigit() {
                pos += 1;
            }
            let n = u64::from_str_radix(&src[start + 2..pos], 16).map_err(|_| Error::LexError {
                offset: start,
                ch: '0',
            })?;
            tokens.push(Spanned {
                token: Token::Num(n),
                offset: start,
            });
            continue;
        }

        // ── numeric / IPv4 / MAC starts with a digit ─────────────────────────
        if bytes[pos].is_ascii_digit() {
            let start = pos;
            // Consume digits, dots, and colons (for MACs).
            while pos < len
                && (bytes[pos].is_ascii_alphanumeric() || bytes[pos] == b'.' || bytes[pos] == b':')
            {
                pos += 1;
            }
            let raw = &src[start..pos];
            let tok = parse_numlike(raw, start)?;
            tokens.push(Spanned {
                token: tok,
                offset: start,
            });
            // If this was an IPv4 address and the next char is '/', consume
            // the prefix length as a separate Num token (CIDR notation).
            if matches!(tokens.last(), Some(s) if matches!(s.token, Token::Ipv4(_)))
                && pos < len
                && bytes[pos] == b'/'
            {
                pos += 1; // consume '/'
                let pl_start = pos;
                while pos < len && bytes[pos].is_ascii_digit() {
                    pos += 1;
                }
                let n: u64 = src[pl_start..pos].parse().map_err(|_| Error::LexError {
                    offset: pl_start,
                    ch: '/',
                })?;
                tokens.push(Spanned {
                    token: Token::Num(n),
                    offset: pl_start,
                });
            }
            continue;
        }

        // ── identifiers / keywords / IPv6 ────────────────────────────────────
        if bytes[pos].is_ascii_alphabetic() || bytes[pos] == b'_' {
            let start = pos;
            while pos < len
                && (bytes[pos].is_ascii_alphanumeric()
                    || bytes[pos] == b'_'
                    || bytes[pos] == b':'   // IPv6 and MACs
                    || bytes[pos] == b'.'   // IPv4-mapped
                    // Hyphen followed by alpha: allows tcp-syn, icmp-echo, etc.
                    || (bytes[pos] == b'-'
                        && pos + 1 < len
                        && bytes[pos + 1].is_ascii_alphabetic()))
            {
                pos += 1;
            }
            let word = &src[start..pos];

            // IPv6 contains "::" or 2+ colons.
            if word.contains("::") || word.chars().filter(|&c| c == ':').count() >= 2 {
                if let Ok(addr) = word.parse::<std::net::Ipv6Addr>() {
                    tokens.push(Spanned {
                        token: Token::Ipv6(addr),
                        offset: start,
                    });
                    continue;
                }
            }
            // MAC: exactly five colons, all hex digits between them.
            if word.chars().filter(|&c| c == ':').count() == 5 {
                if let Some(mac) = parse_mac(word) {
                    tokens.push(Spanned {
                        token: Token::Mac(mac),
                        offset: start,
                    });
                    continue;
                }
            }

            tokens.push(Spanned {
                token: keyword_or_ident(word),
                offset: start,
            });
            continue;
        }

        return Err(Error::LexError {
            offset: pos,
            ch: src[pos..].chars().next().unwrap_or('?'),
        });
    }

    Ok(tokens)
}

fn parse_numlike(raw: &str, offset: usize) -> Result<Token> {
    // IPv4 (contains a dot)
    if raw.contains('.') {
        let addr_part = raw.split('/').next().unwrap();
        if let Ok(addr) = addr_part.parse::<std::net::Ipv4Addr>() {
            return Ok(Token::Ipv4(addr.octets()));
        }
    }
    // MAC (five colons)
    if raw.chars().filter(|&c| c == ':').count() == 5 {
        if let Some(mac) = parse_mac(raw) {
            return Ok(Token::Mac(mac));
        }
    }
    // Plain decimal integer
    if let Ok(n) = raw.parse::<u64>() {
        return Ok(Token::Num(n));
    }
    Err(Error::LexError {
        offset,
        ch: raw.chars().next().unwrap_or('?'),
    })
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(mac)
}

fn keyword_or_ident(s: &str) -> Token {
    match s {
        "and" => Token::And,
        "or" => Token::Or,
        "not" => Token::Not,
        "src" => Token::Src,
        "dst" => Token::Dst,
        "host" => Token::Host,
        "net" => Token::Net,
        "port" => Token::Port,
        "portrange" => Token::PortRange,
        "ether" => Token::Ether,
        "broadcast" => Token::Broadcast,
        "multicast" => Token::Multicast,
        "ip" => Token::Ip,
        "ip6" => Token::Ip6,
        "arp" => Token::Arp,
        "rarp" => Token::Rarp,
        "tcp" => Token::Tcp,
        "udp" => Token::Udp,
        "icmp" => Token::Icmp,
        "icmp6" => Token::Icmp6,
        "igmp" => Token::Igmp,
        "sctp" => Token::Sctp,
        "proto" => Token::Proto,
        "less" => Token::Less,
        "greater" => Token::Greater,
        // Additional IP protocol keywords
        "ah" => Token::Ah,
        "esp" => Token::Esp,
        "pim" => Token::Pim,
        "igrp" => Token::Igrp,
        "vrrp" => Token::Vrrp,
        // Encapsulation
        "vlan" => Token::Vlan,
        "mpls" => Token::Mpls,
        "pppoed" => Token::Pppoed,
        "pppoes" => Token::Pppoes,
        // Direction
        "inbound" => Token::Inbound,
        "outbound" => Token::Outbound,
        // Length
        "len" => Token::Len,
        // Net mask
        "mask" => Token::Mask,
        // Gateway
        "gateway" => Token::Gateway,
        // ── Named integer constants (used as offsets or mask values) ─────────
        // TCP header field offsets
        "tcpflags" => Token::Num(13),
        // ICMP/ICMPv6 header field offsets
        "icmptype" => Token::Num(0),
        "icmpcode" => Token::Num(1),
        "icmp6type" => Token::Num(0),
        "icmp6code" => Token::Num(1),
        // TCP flag bit values
        "tcp-fin" => Token::Num(0x01),
        "tcp-syn" => Token::Num(0x02),
        "tcp-rst" => Token::Num(0x04),
        "tcp-push" => Token::Num(0x08),
        "tcp-ack" => Token::Num(0x10),
        "tcp-urg" => Token::Num(0x20),
        "tcp-ece" => Token::Num(0x40),
        "tcp-cwr" => Token::Num(0x80),
        // ICMP type values
        "icmp-echoreply" => Token::Num(0),
        "icmp-unreach" => Token::Num(3),
        "icmp-sourcequench" => Token::Num(4),
        "icmp-redirect" => Token::Num(5),
        "icmp-echo" => Token::Num(8),
        "icmp-routeradvert" => Token::Num(9),
        "icmp-routersolicit" => Token::Num(10),
        "icmp-timxceed" => Token::Num(11),
        "icmp-paramprob" => Token::Num(12),
        "icmp-tstamp" => Token::Num(13),
        "icmp-tstampreply" => Token::Num(14),
        "icmp-ireq" => Token::Num(15),
        "icmp-ireqreply" => Token::Num(16),
        "icmp-maskreq" => Token::Num(17),
        "icmp-maskreply" => Token::Num(18),
        s => Token::Ident(s.to_string()),
    }
}
