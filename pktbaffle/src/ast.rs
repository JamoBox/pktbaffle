//! Abstract syntax tree for libpcap-style filter expressions.

use std::fmt;
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
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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
///
/// `a or b or c` parses left-deep (`Or(Or(a, b), c)`), so a long chain is a
/// deep tree. Dropping, cloning, comparing (`==`) and compiling one all run in
/// constant stack, at any depth.
///
/// `Debug` output matches what `#[derive(Debug)]` would print (both `{:?}`
/// and `{:#?}`) for a tree up to 128 levels deep. Anything nested deeper is
/// printed as `..`, so formatting a very long chain returns a short string
/// instead of overflowing the stack (or producing hundreds of megabytes).
///
/// `Expr` implements [`Drop`], so its fields cannot be moved out by
/// destructuring a value; match on a reference instead (and clone what you
/// keep), or use [`std::mem::replace`].
#[non_exhaustive]
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

/// Drops the tree with an explicit stack: `a or b or ...` and `!!!...x` nest
/// one level per term, so the default recursive drop would overflow the
/// stack on long chains (#149).
impl Drop for Expr {
    fn drop(&mut self) {
        fn take_children(e: &mut Expr, stack: &mut Vec<Expr>) {
            // A unit-like leaf: replacing a child with it allocates nothing.
            let mut take = |b: &mut Box<Expr>| {
                stack.push(std::mem::replace(
                    &mut **b,
                    Expr::Primitive(Primitive::IpBroadcast),
                ))
            };
            match e {
                Expr::And(l, r) | Expr::Or(l, r) => {
                    take(l);
                    take(r);
                }
                Expr::Not(inner) => take(inner),
                Expr::Primitive(_) => {}
            }
        }
        let mut stack = Vec::new();
        take_children(self, &mut stack);
        // Each popped node's children are detached before it drops, so its
        // own `drop` sees only leaves and never recurses further.
        while let Some(mut e) = stack.pop() {
            take_children(&mut e, &mut stack);
        }
    }
}

/// A unit-like leaf: building or replacing a node with it allocates nothing.
fn placeholder() -> Expr {
    Expr::Primitive(Primitive::IpBroadcast)
}

/// Clones with an explicit stack (#229): each entry pairs a source node with
/// the empty slot in the new tree that it is copied into.
impl Clone for Expr {
    fn clone(&self) -> Self {
        let mut root = placeholder();
        let mut stack = vec![(self, &mut root)];
        while let Some((src, dst)) = stack.pop() {
            *dst = match src {
                Expr::And(..) => Expr::And(Box::new(placeholder()), Box::new(placeholder())),
                Expr::Or(..) => Expr::Or(Box::new(placeholder()), Box::new(placeholder())),
                Expr::Not(_) => Expr::Not(Box::new(placeholder())),
                Expr::Primitive(p) => Expr::Primitive(p.clone()),
            };
            match (src, dst) {
                (Expr::And(sl, sr), Expr::And(dl, dr)) | (Expr::Or(sl, sr), Expr::Or(dl, dr)) => {
                    stack.push((&**sr, &mut **dr));
                    stack.push((&**sl, &mut **dl));
                }
                (Expr::Not(s), Expr::Not(d)) => stack.push((&**s, &mut **d)),
                _ => {}
            }
        }
        root
    }
}

/// Compares with an explicit stack of node pairs (#229); same result as the
/// derived impl: same variant, equal children, equal leaf payloads.
impl PartialEq for Expr {
    fn eq(&self, other: &Self) -> bool {
        let mut stack = vec![(self, other)];
        while let Some(pair) = stack.pop() {
            match pair {
                (Expr::And(al, ar), Expr::And(bl, br)) | (Expr::Or(al, ar), Expr::Or(bl, br)) => {
                    stack.push((&**ar, &**br));
                    stack.push((&**al, &**bl));
                }
                (Expr::Not(a), Expr::Not(b)) => stack.push((&**a, &**b)),
                (Expr::Primitive(a), Expr::Primitive(b)) if a == b => {}
                _ => return false,
            }
        }
        true
    }
}

/// Deepest nesting level `Debug` prints in full; anything below it is `..`
/// (#229). Each level costs a few hundred bytes of stack in a debug build.
const DEBUG_MAX_DEPTH: usize = 128;

/// An `Expr` at a known nesting depth. Its `Debug` is what `derive` generates
/// for `Expr`, except that it stops at [`DEBUG_MAX_DEPTH`].
struct AtDepth<'a>(&'a Expr, usize);

impl fmt::Debug for AtDepth<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let AtDepth(e, depth) = *self;
        if depth > DEBUG_MAX_DEPTH {
            return f.write_str("..");
        }
        let d = depth + 1;
        match e {
            Expr::And(l, r) => f
                .debug_tuple("And")
                .field(&AtDepth(l, d))
                .field(&AtDepth(r, d))
                .finish(),
            Expr::Or(l, r) => f
                .debug_tuple("Or")
                .field(&AtDepth(l, d))
                .field(&AtDepth(r, d))
                .finish(),
            Expr::Not(x) => f.debug_tuple("Not").field(&AtDepth(x, d)).finish(),
            Expr::Primitive(p) => f.debug_tuple("Primitive").field(p).finish(),
        }
    }
}

impl fmt::Debug for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&AtDepth(self, 0), f)
    }
}
