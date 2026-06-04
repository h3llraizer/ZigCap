const std = @import("std");
const activeTag = std.meta.activeTag;
const print = std.debug.print;

pub const IPProtocol = enum(u8) {
    ICMP = 1,
    IGMP = 2,
    TCP = 6,
    UDP = 17,
    ICMPv6 = 58,
    Unknown = 0,
};

pub const IPVersions = enum(u4) {
    IPv4 = 4,
    IPv6 = 6,
};

pub const EthType = enum(u16) {
    IP = 0x0800,
    ARP = 0x0806,
    //   ETHBRIDGE = 0x6558,
    //   REVARP = 0x8035,
    //   AT = 0x809B,
    //   AARP = 0x80F3,
    VLAN = 0x8100,
    //    IPX = 0x8137,
    IPV6 = 0x86DD,
    LOOPBACK = 0x9000,
    //  PPPOED = 0x8863,
    //  PPPOES = 0x8864,
    //  MPLS = 0x8847,
    //  PPP = 0x880B,
    //  ROCEV1 = 0x8915,
    //  IEEE_802_1AD = 0x88A8,
    //  WAKE_ON_LAN = 0x0842,
};

pub const link_layer_type = enum(u16) { // these should be renamed to LinkLayerTypes
    NULL = 0, // Loopback (BSD/macOS)
    ETHERNET = 1, // Ethernet (most common)
    RAW = 101, // Raw IP (no link header)
    //PPP = 9,
    //PPP_ETHER = 51, // PPPoE
    //IEEE802_11 = 105, // WiFi
    //IEEE802_11_RADIOTAP = 127, // WiFi + metadata (monitor mode)
    //LINUX_SLL = 113, // "cooked" capture (tcpdump on Linux)
    //LINUX_SLL2 = 276, // newer version
    LOOP = 108, // Loopback (OpenBSD)
    //SLIP = 8, // legacy serial IP
    INVALID = 0xFFFF,
};

pub const NullLinkType = enum(u8) {
    IPv4 = 0x02,
    OSI = 0x07,
    IPX = 0x23,
};

// TODO: Rename to LayerParseError
// TODO: Also move out of ProtocolEnums
pub const LayerError = error{
    OutOfMemory,
    BufferTooSmall,
    MisalignedBuffer,
    EmptyPayload,
    InvalidOperation,
    LayerInvalid,
};
