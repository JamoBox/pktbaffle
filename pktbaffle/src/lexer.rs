//! Tokenizer for libpcap-style filter expressions.

use crate::error::{Error, Result};

/// A single token produced by [`lex`].
///
/// Variants map directly to keywords, operators, punctuation, and literals in
/// the libpcap filter grammar. The grouping comments below match the grammar
/// sections where each token appears.
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

    // ── protocol chain traversal ─────────────────────────────────────────────
    Protochain,

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

    // ── arithmetic / bitwise operators ──────────────────────────────────────
    Plus,
    Star,
    Slash,
    Percent,
    Pipe,
    Caret,
    Shl,
    Shr,

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

/// A [`Token`] together with its byte offset in the source string.
#[derive(Debug, Clone)]
pub struct Spanned {
    /// The token value.
    pub token: Token,
    /// Byte offset of this token's first character in the original input.
    /// Retained for future diagnostic spans; not read internally yet (the
    /// lexer is a private module since 0.2.0, so the field is not public API).
    #[allow(dead_code)]
    pub offset: usize,
}

/// Tokenise a libpcap filter expression string.
///
/// Returns a vector of [`Spanned`] tokens on success. The tokens can be
/// passed directly to [`crate::parser::parse`] to build an AST.
///
/// # Errors
///
/// Returns [`crate::Error::LexError`] if the input contains a character that
/// is not part of the filter grammar.
///
/// # Example
///
/// ```ignore
/// // Internal module (private since 0.2.0); illustrative only.
/// let tokens = lex("tcp port 80").unwrap();
/// assert_eq!(tokens[0].token, Token::Tcp);
/// assert_eq!(tokens[0].offset, 0);
/// assert_eq!(tokens[1].token, Token::Port);
/// ```
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
                (b'<', b'<') => {
                    push!(Token::Shl);
                    pos += 2;
                    continue;
                }
                (b'>', b'>') => {
                    push!(Token::Shr);
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
                // A leading `::` may begin an IPv6 address (e.g. `::1`, `::ffff:192.0.2.1`).
                if pos + 1 < len && bytes[pos + 1] == b':' {
                    let start = pos;
                    let mut tmp = pos;
                    while tmp < len
                        && (bytes[tmp].is_ascii_hexdigit()
                            || bytes[tmp] == b':'
                            || bytes[tmp] == b'.')
                    {
                        tmp += 1;
                    }
                    let candidate = &src[start..tmp];
                    if let Ok(addr) = candidate.parse::<std::net::Ipv6Addr>() {
                        tokens.push(Spanned {
                            token: Token::Ipv6(addr),
                            offset: start,
                        });
                        pos = tmp;
                        continue;
                    }
                }
                push!(Token::Colon);
                pos += 1;
                continue;
            }
            b'-' => {
                push!(Token::Minus);
                pos += 1;
                continue;
            }
            b'+' => {
                push!(Token::Plus);
                pos += 1;
                continue;
            }
            b'*' => {
                push!(Token::Star);
                pos += 1;
                continue;
            }
            b'/' => {
                push!(Token::Slash);
                pos += 1;
                continue;
            }
            b'%' => {
                push!(Token::Percent);
                pos += 1;
                continue;
            }
            b'|' => {
                push!(Token::Pipe);
                pos += 1;
                continue;
            }
            b'^' => {
                push!(Token::Caret);
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
            // Consume alphanumeric and dots, but NOT colons.  A colon after a
            // number is usually the range separator in byte-access syntax
            // (e.g. tcp[0:2]) and must not be greedily consumed here.
            while pos < len && (bytes[pos].is_ascii_alphanumeric() || bytes[pos] == b'.') {
                pos += 1;
            }
            // Digit-starting MACs (e.g. 00:11:22:33:44:55) still need colon
            // support.  Speculatively extend when followed by exactly five
            // ":XX" segments and the whole thing parses as a MAC.
            if pos < len && bytes[pos] == b':' {
                let mut tmp = pos;
                let mut ok = true;
                for _ in 0..5 {
                    if tmp >= len || bytes[tmp] != b':' {
                        ok = false;
                        break;
                    }
                    tmp += 1;
                    let seg_start = tmp;
                    while tmp < len && bytes[tmp].is_ascii_hexdigit() {
                        tmp += 1;
                    }
                    if tmp == seg_start || tmp - seg_start > 2 {
                        ok = false;
                        break;
                    }
                }
                // If another ':' follows the 6th group, there are more segments —
                // this is a full-form IPv6 address, not a MAC.
                if ok && tmp < len && bytes[tmp] == b':' {
                    ok = false;
                }
                if ok {
                    if let Some(mac) = parse_mac(&src[start..tmp]) {
                        tokens.push(Spanned {
                            token: Token::Mac(mac),
                            offset: start,
                        });
                        pos = tmp;
                        continue;
                    }
                }
            }
            // Digit-first IPv6 (e.g. 2001:db8::1): MAC detection above didn't
            // match, but a trailing ':' may still begin an IPv6 address.
            // Speculatively extend through hex digits and colons; commit only
            // when the candidate contains '::' or two or more colons.
            if pos < len && bytes[pos] == b':' {
                let mut tmp = pos;
                while tmp < len && (bytes[tmp].is_ascii_hexdigit() || bytes[tmp] == b':') {
                    tmp += 1;
                }
                let candidate = &src[start..tmp];
                if looks_like_ipv6(candidate) {
                    if let Ok(addr) = candidate.parse::<std::net::Ipv6Addr>() {
                        tokens.push(Spanned {
                            token: Token::Ipv6(addr),
                            offset: start,
                        });
                        pos = tmp;
                        if pos < len && bytes[pos] == b'/' {
                            pos += 1;
                            let pl_start = pos;
                            while pos < len && bytes[pos].is_ascii_digit() {
                                pos += 1;
                            }
                            let n: u64 =
                                src[pl_start..pos].parse().map_err(|_| Error::LexError {
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
                }
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
            if looks_like_ipv6(word) {
                if let Ok(addr) = word.parse::<std::net::Ipv6Addr>() {
                    tokens.push(Spanned {
                        token: Token::Ipv6(addr),
                        offset: start,
                    });
                    if pos < len && bytes[pos] == b'/' {
                        pos += 1;
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
            }
            // MAC: exactly five colons, all hex digits between them.
            if looks_like_mac(word) {
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

fn looks_like_ipv6(s: &str) -> bool {
    s.contains("::") || s.bytes().filter(|&b| b == b':').take(2).count() >= 2
}

fn looks_like_mac(s: &str) -> bool {
    s.bytes().filter(|&b| b == b':').take(6).count() == 5
}

fn parse_numlike(raw: &str, offset: usize) -> Result<Token> {
    // IPv4 (contains a dot)
    if raw.contains('.') {
        let addr_part = raw.split('/').next().unwrap();
        if let Ok(addr) = addr_part.parse::<std::net::Ipv4Addr>() {
            return Ok(Token::Ipv4(addr.octets()));
        }
        // Partial IPv4 (1–3 octets): zero-pad and emit as Ipv4 for classful net shorthand.
        let parts: Vec<&str> = addr_part.split('.').collect();
        if !parts.is_empty() && parts.len() <= 3 {
            let mut octets = [0u8; 4];
            let mut valid = true;
            for (i, p) in parts.iter().enumerate() {
                if let Ok(n) = p.parse::<u8>() {
                    octets[i] = n;
                } else {
                    valid = false;
                    break;
                }
            }
            if valid {
                return Ok(Token::Ipv4(octets));
            }
        }
    }
    // IPv6 (contains "::" or two or more colons)
    if looks_like_ipv6(raw) {
        if let Ok(addr) = raw.parse::<std::net::Ipv6Addr>() {
            return Ok(Token::Ipv6(addr));
        }
    }
    // MAC (five colons)
    if looks_like_mac(raw) {
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
        "protochain" => Token::Protochain,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_digit_first_double_colon() {
        // 2001:db8::1 starts with a digit — the bug caused a LexError here.
        let tokens = lex("2001:db8::1").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token, Token::Ipv6("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn ipv6_digit_first_full_address() {
        let tokens = lex("2001:0db8:0000:0000:0000:0000:0000:0001").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token, Token::Ipv6("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn ipv6_letter_first_still_works() {
        // fe80::1 starts with a letter; this path already worked before the fix.
        let tokens = lex("fe80::1").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token, Token::Ipv6("fe80::1".parse().unwrap()));
    }

    #[test]
    fn ipv6_in_host_filter() {
        // Digit-first IPv6 used inside a filter expression.
        let tokens = lex("host 2001:db8::1").unwrap();
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[0].token, Token::Host);
        assert_eq!(tokens[1].token, Token::Ipv6("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn ipv6_all_zero_groups_not_confused_with_mac() {
        // 0:0:0:0:0:0:0:1 — first six groups look like a MAC but there are 8.
        let tokens = lex("0:0:0:0:0:0:0:1").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token, Token::Ipv6("::1".parse().unwrap()));
    }

    #[test]
    fn ipv6_all_zero_address_not_confused_with_mac() {
        // 0:0:0:0:0:0:0:0 — all eight groups are zero.
        let tokens = lex("0:0:0:0:0:0:0:0").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token, Token::Ipv6("::".parse().unwrap()));
    }

    #[test]
    fn mac_address_still_lexes_correctly() {
        // A genuine 6-octet MAC must not be affected by the IPv6 fix.
        let tokens = lex("00:11:22:33:44:55").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(
            tokens[0].token,
            Token::Mac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
    }

    #[test]
    fn ipv6_leading_double_colon_loopback() {
        let tokens = lex("::1").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token, Token::Ipv6("::1".parse().unwrap()));
    }

    #[test]
    fn ipv6_leading_double_colon_all_zeros() {
        let tokens = lex("::").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token, Token::Ipv6("::".parse().unwrap()));
    }

    #[test]
    fn ipv6_leading_double_colon_ipv4_mapped() {
        let tokens = lex("::ffff:192.0.2.1").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(
            tokens[0].token,
            Token::Ipv6("::ffff:192.0.2.1".parse().unwrap())
        );
    }

    #[test]
    fn ipv6_leading_double_colon_in_host_filter() {
        let tokens = lex("host ::1").unwrap();
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[0].token, Token::Host);
        assert_eq!(tokens[1].token, Token::Ipv6("::1".parse().unwrap()));
    }

    #[test]
    fn single_colon_still_lexes_as_colon_token() {
        // A bare `:` (not `::`) must still produce Token::Colon.
        let tokens = lex(":").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token, Token::Colon);
    }

    // ── Arithmetic / bitwise tokens (#32) ─────────────────────────────────────

    #[test]
    fn plus_token() {
        let tokens = lex("+").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token, Token::Plus);
    }

    #[test]
    fn star_token() {
        let tokens = lex("*").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token, Token::Star);
    }

    #[test]
    fn slash_token() {
        let tokens = lex("/").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token, Token::Slash);
    }

    #[test]
    fn percent_token() {
        let tokens = lex("%").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token, Token::Percent);
    }

    #[test]
    fn pipe_token() {
        let tokens = lex("|").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token, Token::Pipe);
    }

    #[test]
    fn caret_token() {
        let tokens = lex("^").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token, Token::Caret);
    }

    #[test]
    fn shl_token() {
        let tokens = lex("<<").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token, Token::Shl);
    }

    #[test]
    fn shr_token() {
        let tokens = lex(">>").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token, Token::Shr);
    }

    #[test]
    fn pipe_pipe_is_or_not_two_pipes() {
        // `||` must still lex as Token::Or, not two Pipe tokens.
        let tokens = lex("||").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token, Token::Or);
    }

    #[test]
    fn lt_still_lexes_after_shl_addition() {
        // bare `<` must still produce Token::Lt
        let tokens = lex("<").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token, Token::Lt);
    }

    #[test]
    fn gt_still_lexes_after_shr_addition() {
        // bare `>` must still produce Token::Gt
        let tokens = lex(">").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token, Token::Gt);
    }

    #[test]
    fn byte_access_subtract_lexes() {
        // ip[8]-1 < 64 must tokenise without a LexError
        let tokens = lex("ip[8]-1 < 64").unwrap();
        assert!(tokens.iter().any(|s| s.token == Token::Minus));
        assert!(tokens.iter().any(|s| s.token == Token::Lt));
    }

    #[test]
    fn byte_access_shl_lexes() {
        // tcp[0]<<2 = 8 must produce a Shl token
        let tokens = lex("tcp[0]<<2 = 8").unwrap();
        assert!(tokens.iter().any(|s| s.token == Token::Shl));
    }

    #[test]
    fn byte_access_or_lexes() {
        // tcp[13]|0x02 = 0x02 must produce a Pipe token
        let tokens = lex("tcp[13]|0x02 = 0x02").unwrap();
        assert!(tokens.iter().any(|s| s.token == Token::Pipe));
    }

    // ── looks_like_ipv6 / looks_like_mac helpers (#97) ───────────────────────

    #[test]
    fn looks_like_ipv6_basic() {
        assert!(looks_like_ipv6("2001:db8::1"));
        assert!(looks_like_ipv6("::1"));
        assert!(looks_like_ipv6("::"));
        assert!(looks_like_ipv6("a:b:c"));
        assert!(!looks_like_ipv6("a:b"));
        assert!(!looks_like_ipv6("abc"));
        assert!(!looks_like_ipv6(""));
    }

    #[test]
    fn looks_like_mac_basic() {
        assert!(looks_like_mac("aa:bb:cc:dd:ee:ff"));
        assert!(looks_like_mac("00:00:00:00:00:00"));
        assert!(!looks_like_mac("aa:bb:cc:dd:ee")); // only 4 colons
        assert!(!looks_like_mac("aa:bb:cc:dd:ee:ff:00")); // 6 colons
        assert!(!looks_like_mac(""));
        assert!(!looks_like_mac("no colons here"));
    }
}
