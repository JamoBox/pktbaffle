//! Abstract syntax tree for libpcap-style filter expressions.

use std::net::IpAddr;

/// Direction qualifier: which address(es) to test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// Match either source or destination (default).
    SrcOrDst,
    /// Match only the source.
    Src,
    /// Match only the destination.
    Dst,
    /// Match both source AND destination simultaneously.
    SrcAndDst,
}

/// Protocol/address-type qualifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrType {
    /// Default — inferred from the address literal.
    Unspecified,
    /// IP-level host address.
    Host,
    /// IP network address (with optional prefix length or netmask).
    Net,
    /// Transport-layer port.
    Port,
    /// Port range.
    PortRange,
    /// Link-layer (Ethernet) address.
    Ether,
}

/// An IPv4 network: address + 32-bit mask (may be non-contiguous for explicit `mask` syntax).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpNet {
    pub addr: std::net::Ipv4Addr,
    /// 32-bit network mask.
    pub mask: u32,
}

/// An IPv6 network: address + prefix length (0–128).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Net {
    pub addr: std::net::Ipv6Addr,
    pub prefix_len: u8,
}

impl IpNet {
    /// Construct from a CIDR prefix length (0–32).
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::net::Ipv4Addr;
    /// use pktbaffle::ast::IpNet;
    ///
    /// let net = IpNet::from_prefix(Ipv4Addr::new(10, 0, 0, 0), 8);
    /// assert_eq!(net.mask, 0xff00_0000);
    ///
    /// let host = IpNet::from_prefix(Ipv4Addr::new(192, 168, 1, 1), 32);
    /// assert_eq!(host.mask, 0xffff_ffff);
    /// ```
    pub fn from_prefix(addr: std::net::Ipv4Addr, prefix_len: u8) -> Self {
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };
        Self { addr, mask }
    }
}

/// A 48-bit Ethernet (MAC) address stored as six octets in network byte order.
///
/// # Example
///
/// ```rust
/// use pktbaffle::ast::MacAddr;
/// let addr = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
/// assert_eq!(addr.0[0], 0xaa);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddr(pub [u8; 6]);

/// Known L4 / L3 protocol identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
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
    /// Raw IPv4 IP-protocol number (0–255).
    Num(u8),
    /// IPv6 next-header protocol number.
    Ip6Proto(u8),
}

/// A leaf predicate in the filter tree.
#[derive(Debug, Clone, PartialEq)]
pub enum Primitive {
    /// Match a host IP address.
    Host { addr: IpAddr, dir: Dir },
    /// Match packets on a transport-layer port.
    Port {
        port: u16,
        dir: Dir,
        proto: Option<Proto>,
    },
    /// Match packets in a port range (inclusive).
    PortRange {
        lo: u16,
        hi: u16,
        dir: Dir,
        proto: Option<Proto>,
    },
    /// Match an IPv4 network.
    Net { net: IpNet, dir: Dir },
    /// Match an IPv6 network prefix.
    Net6 { net: Ipv6Net, dir: Dir },
    /// Match on L4 / L3 protocol.
    Proto(Proto),
    /// Match on Ethernet MAC address.
    EtherHost { addr: MacAddr, dir: Dir },
    /// Match on Ethernet type field (e.g. 0x0800 for IP).
    EtherProto(u16),
    /// Match Ethernet multicast (bit 0 of destination MAC first byte is set).
    EtherMulticast,
    /// Match IP broadcast (destination IP == 255.255.255.255).
    IpBroadcast,
    /// Match IP multicast (destination IP in 224.0.0.0/4).
    IpMulticast,
    /// Match IPv6 multicast (first byte of destination IPv6 address == 0xff).
    Ip6Multicast,
    /// Match VLAN-tagged packets (ethertype 0x8100), optionally with a specific VLAN ID.
    Vlan { id: Option<u16> },
    /// Match MPLS-labeled packets (ethertype 0x8847/0x8848), optionally with a specific label.
    Mpls { label: Option<u32> },
    /// PPPoE Discovery (ethertype 0x8863).
    PppoeDiscovery,
    /// PPPoE Session (ethertype 0x8864), optionally with a specific session ID.
    PppoeSession { session_id: Option<u16> },
    /// IPv4 protocol-chain traversal: `ip protochain N`.
    IpProtoChain(u8),
    /// IPv6 protocol-chain traversal: `ip6 protochain N`.
    Ip6ProtoChain(u8),
    /// Packet length comparison: `len relop value`; also used for `less` and `greater`.
    Len { op: CmpOp, value: u32 },
    /// Inbound direction — not expressible in standard BPF; codegen returns an error.
    Inbound,
    /// Outbound direction — not expressible in standard BPF; codegen returns an error.
    Outbound,
    /// Raw byte access comparison: `expr[offset:size] op value`.
    ByteAccess(ByteAccess),
}

/// Arithmetic / bitwise operator applied to a loaded byte-access value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    And,
    Or,
    Xor,
    Shl,
    Shr,
}

/// Comparison operator used in raw byte-access expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    BitAnd,
}

/// Load size (bytes) for a raw byte-access test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessSize {
    Byte,
    Half,
    Word,
}

/// Packet layer offset origin for a raw accessor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// Offset from the start of the packet (link-layer frame).
    Raw,
    /// Offset from the start of the network-layer (IP) header.
    Net,
    /// Offset from the start of the transport-layer header.
    Trans,
}

/// A raw byte load from a packet field, used as the RHS of an expr-vs-expr
/// byte-access comparison.
#[derive(Debug, Clone, PartialEq)]
pub struct ByteLoad {
    pub layer: Layer,
    pub offset: i32,
    pub size: AccessSize,
}

/// The right-hand side of a byte-access comparison.
#[derive(Debug, Clone, PartialEq)]
pub enum CmpRhs {
    /// Compare against a constant integer.
    Const(u32),
    /// Compare against another packet field load.
    Load(ByteLoad),
}

/// A raw byte-access test, e.g. `tcp[13] & 0x02 != 0` (SYN flag) or
/// `tcp[0] = tcp[4]` (expr-vs-expr).
///
/// The full semantics are: load the value at `(layer, offset, size)`, apply
/// each `(ArithOp, operand)` in `alu_ops` in sequence to the accumulator,
/// then compare the result with `op` and `rhs` (a constant or a second load).
#[derive(Debug, Clone, PartialEq)]
pub struct ByteAccess {
    pub layer: Layer,
    pub offset: i32,
    pub size: AccessSize,
    /// ALU operations applied to the loaded value before comparison.
    pub alu_ops: Vec<(ArithOp, u32)>,
    pub op: CmpOp,
    pub rhs: CmpRhs,
}

/// A node in the filter expression tree.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// Logical AND (short-circuiting).
    And(Box<Expr>, Box<Expr>),
    /// Logical OR (short-circuiting).
    Or(Box<Expr>, Box<Expr>),
    /// Logical NOT.
    Not(Box<Expr>),
    /// A leaf predicate.
    Primitive(Primitive),
}
