const std = @import("std");
const print = std.debug.print;
const allocPrint = std.fmt.allocPrint;

pub const LinkLayerType = enum(u16) {
    /// BSD loopback encapsulation
    NULL = 0,
    /// IEEE 802.3 Ethernet
    ETHERNET = 1,
    /// AX.25 packet
    AX25 = 3,
    /// IEEE 802.5 Token Ring
    IEEE802_5 = 6,
    /// ARCNET Data Packets
    ARCNET_BSD = 7,
    /// SLIP, encapsulated with a LINKTYPE_SLIP header
    SLIP = 8,
    /// PPP, as per RFC 1661 and RFC 1662
    PPP = 9,
    /// FDDI, as specified by ANSI INCITS 239-1994
    FDDI = 10,
    /// Raw IP
    DLT_RAW1 = 12,
    /// Raw IP (OpenBSD)
    DLT_RAW2 = 14,
    /// PPP in HDLC-like framing, or Cisco PPP with HDLC framing
    PPP_HDLC = 50,
    /// PPPoE
    PPP_ETHER = 51,
    /// RFC 1483 LLC/SNAP-encapsulated ATM
    ATM_RFC1483 = 100,
    /// Raw IP
    RAW = 101,
    /// Cisco PPP with HDLC framing
    C_HDLC = 104,
    /// IEEE 802.11 wireless LAN
    IEEE802_11 = 105,
    /// Frame Relay
    FRELAY = 107,
    /// OpenBSD loopback encapsulation
    LOOP = 108,
    /// Linux "cooked" capture encapsulation
    LINUX_SLL = 113,
    /// Apple LocalTalk
    LTALK = 114,
    /// OpenBSD pflog
    PFLOG = 117,
    /// Prism monitor mode info followed by 802.11 header
    IEEE802_11_PRISM = 119,
    /// RFC 2625 IP-over-Fibre Channel
    IP_OVER_FC = 122,
    /// ATM traffic as used by SunATM devices
    SUNATM = 123,
    /// Radiotap link-layer info followed by 802.11 header
    IEEE802_11_RADIOTAP = 127,
    /// ARCNET Data Packets (Linux)
    ARCNET_LINUX = 129,
    /// Apple IP-over-IEEE 1394 cooked header
    APPLE_IP_OVER_IEEE1394 = 138,
    /// Signaling System 7 MTP2 with pseudo-header
    MTP2_WITH_PHDR = 139,
    MTP2 = 140,
    MTP3 = 141,
    SCCP = 142,
    DOCSIS = 143,
    LINUX_IRDA = 144,
    USER0 = 147,
    USER1 = 148,
    USER2 = 149,
    USER3 = 150,
    USER4 = 151,
    USER5 = 152,
    USER6 = 153,
    USER7 = 154,
    USER8 = 155,
    USER9 = 156,
    USER10 = 157,
    USER11 = 158,
    USER12 = 159,
    USER13 = 160,
    USER14 = 161,
    USER15 = 162,
    IEEE802_11_AVS = 163,
    BACNET_MS_TP = 165,
    PPP_PPPD = 166,
    GPRS_LLC = 169,
    GPF_T = 170,
    GPF_F = 171,
    LINUX_LAPD = 177,
    BLUETOOTH_HCI_H4 = 187,
    USB_LINUX = 189,
    PPI = 192,
    IEEE802_15_4 = 195,
    SITA = 196,
    ERF = 197,
    BLUETOOTH_HCI_H4_WITH_PHDR = 201,
    AX25_KISS = 202,
    LAPD = 203,
    PPP_WITH_DIR = 204,
    C_HDLC_WITH_DIR = 205,
    FRELAY_WITH_DIR = 206,
    IPMB_LINUX = 209,
    IEEE802_15_4_NONASK_PHY = 215,
    USB_LINUX_MMAPPED = 220,
    FC_2 = 224,
    FC_2_WITH_FRAME_DELIMS = 225,
    IPNET = 226,
    CAN_SOCKETCAN = 227,
    IPV4 = 228,
    IPV6 = 229,
    IEEE802_15_4_NOFCS = 230,
    DBUS = 231,
    DVB_CI = 235,
    MUX27010 = 236,
    STANAG_5066_D_PDU = 237,
    NFLOG = 239,
    NETANALYZER = 240,
    NETANALYZER_TRANSPARENT = 241,
    IPOIB = 242,
    MPEG_2_TS = 243,
    NG40 = 244,
    NFC_LLCP = 245,
    INFINIBAND = 247,
    SCTP = 248,
    USBPCAP = 249,
    RTAC_SERIAL = 250,
    BLUETOOTH_LE_LL = 251,
    NETLINK = 253,
    BLUETOOTH_LINUX_MONITOR = 254,
    BLUETOOTH_BREDR_BB = 255,
    BLUETOOTH_LE_LL_WITH_PHDR = 256,
    PROFIBUS_DL = 257,
    PKTAP = 258,
    EPON = 259,
    IPMI_HPM_2 = 260,
    ZWAVE_R1_R2 = 261,
    ZWAVE_R3 = 262,
    WATTSTOPPER_DLM = 263,
    ISO_14443 = 264,
    LINUX_SLL2 = 276,
    /// Set if interface ID for a packet of a pcapng file is too high
    INVALID = 0xFFFF,
};

pub const TcpIpLayer = enum {
    Application, // HTTP, DNS, SMTP, etc.
    Transport, // TCP, UDP, QUIC
    Network, // IPv4, IPv6, ICMP
    NetworkAccess, // Ethernet, Wi-Fi, ARP
};

pub const EthType = enum(u16) {
    IP = 0x0800,
    ARP = 0x0806,
    ETHBRIDGE = 0x6558,
    REVARP = 0x8035,
    AT = 0x809B,
    AARP = 0x80F3,
    VLAN = 0x8100,
    IPX = 0x8137,
    IPV6 = 0x86DD,
    LOOPBACK = 0x9000,
    PPPOED = 0x8863,
    PPPOES = 0x8864,
    MPLS = 0x8847,
    PPP = 0x880B,
    ROCEV1 = 0x8915,
    IEEE_802_1AD = 0x88A8,
    WAKE_ON_LAN = 0x0842,
};

pub const IPv4Proto = enum(u8) {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    GRE = 47,
    ESP = 50,
    AH = 51,
};

pub const ProtoType = enum(u8) {
    UnknownProtocol = 0,
    Ethernet = 1,
    IPv4 = 2,
    IPv6 = 3,
    TCP = 4,
    UDP = 5,
    HTTPRequest = 6,
    HTTPResponse = 7,
    ARP = 8,
    VLAN = 9,
    ICMP = 10,
    PPPoESession = 11,
    PPPoEDiscovery = 12,
    DNS = 13,
    MPLS = 14,
    GREv0 = 15,
    GREv1 = 16,
    PPP_PPTP = 17,
    SSL = 18,
    SLL = 19,
    DHCP = 20,
    NULL_LOOPBACK = 21,
    IGMPv1 = 22,
    IGMPv2 = 23,
    IGMPv3 = 24,
    GenericPayload = 25,
    VXLAN = 26,
    SIPRequest = 27,
    SIPResponse = 28,
    SDP = 29,
    PacketTrailer = 30,
    Radius = 31,
    GTPv1 = 32,
    EthernetDot3 = 33,
    BGP = 34,
    SSH = 35,
    AuthenticationHeader = 36,
    ESP = 37,
    DHCPv6 = 38,
    NTP = 39,
    Telnet = 40,
    FTPControl = 41,
    ICMPv6 = 42,
    STP = 43,
    LLC = 44,
    SomeIP = 45,
    WakeOnLan = 46,
    NFLOG = 47,
    TPKT = 48,
    VRRPv2 = 49,
    VRRPv3 = 50,
    COTP = 51,
    SLL2 = 52,
    S7COMM = 53,
    SMTP = 54,
    LDAP = 55,
    WireGuard = 56,
    GTPv2 = 57,
    CiscoHDLC = 58,
    DOIP = 59,
    FTPData = 60,
    Modbus = 61,
};

pub const RawPacket = struct {
    timestamp_s: u32,
    timestamp_ms: u32,
    raw_data: []u8,
    raw_len: u32,
    link_type: c_int,

    pub fn init(ts_usec: c_long, ts_sec: c_long, raw: []const u8, len: c_uint, link_type: c_int, allocator: *std.mem.Allocator) !*RawPacket {
        var p: *RawPacket = try allocator.create(RawPacket);

        p.timestamp_ms = @intCast(ts_usec);

        p.timestamp_s = @intCast(ts_sec);

        p.raw_len = @intCast(len);

        p.raw_data = try allocator.alloc(u8, p.raw_len);

        p.link_type = link_type;

        @memmove(p.raw_data, raw[0..p.raw_len]);

        return p;
    }

    pub fn slice(self: *RawPacket, offset: usize, len: usize) ![]const u8 {
        if (offset > self.raw_len or offset > len or len > self.raw_len) {
            return error.InvalidBounds;
        }

        return self.raw_data[offset..len];
    }

    pub fn to_string(self: RawPacket) void {
        print("Timestamp_s: {any} Timestamp_ms: {any} Raw_data (ptr): {any} raw_len: {any}\n", .{ self.timestamp_s, self.timestamp_ms, self.raw_data.ptr, self.raw_len });
    }

    pub fn print_bytes(self: RawPacket, len: u32) void {
        const bytes: []const u8 = @ptrCast(self.raw_data[0..len]);
        for (bytes) |b| {
            std.debug.print("{x} ", .{b});
        }
        std.debug.print("\n", .{});
    }

    pub fn deinit(self: *RawPacket, allocator: *std.mem.Allocator) void {
        allocator.free(self.raw_data);
        allocator.destroy(self);
    }
};

pub const MacHdr = struct {
    dst: [6]u8,
    src: [6]u8,
};

pub const EthHdr = struct {
    mac_header: *MacHeader,
    eth_type: EtherType,
};

pub const EthLayer = struct {
    eth_header: EthHeader,

    pub fn init(raw_packet: *RawPacket) ?EthLayer {
        if (raw_packet.raw_len < 12) return null;

        const eth_slice = raw_packet.slice(0, 14) catch |err| {
            print("Error: {s}\n", .{@errorName(err)});
            return null;
        };

        const mac_hdr: *MacHeader = @ptrCast(@constCast(eth_slice.ptr));

        const eth_type: EtherType = @enumFromInt(std.mem.readInt(u16, eth_slice[12..14], .big));

        const eth_hdr = EthHeader{ .mac_header = mac_hdr, .eth_type = eth_type };

        return EthLayer{ .eth_header = eth_hdr };
    }

    pub fn to_string(self: EthLayer, allocator: *std.mem.Allocator) ![]u8 {
        const dst = self.eth_header.mac_header.dst;
        const src = self.eth_header.mac_header.src;

        // Allocate strings for MAC addresses
        const dest_str = try std.fmt.allocPrint(allocator.*, "{x}:{x}:{x}:{x}:{x}:{x}", .{ dst[0], dst[1], dst[2], dst[3], dst[4], dst[5] });

        const src_str = try std.fmt.allocPrint(allocator.*, "{x}:{x}:{x}:{x}:{x}:{x}", .{ src[0], src[1], src[2], src[3], src[4], src[5] });

        // Allocate final string
        const ret_str = try std.fmt.allocPrint(allocator.*, "Type: 0x{X} ({s}) Src: {s} Dst: {s}", .{
            self.eth_header.eth_type,
            @tagName(self.eth_header.eth_type),
            src_str,
            dest_str,
        });

        // Free intermediate strings to avoid leaks
        allocator.free(src_str);
        allocator.free(dest_str);

        return ret_str;
    }
};

pub const IPv4Hdr = struct {
    version: u8,
    header_length: u8, // in bytes
    total_length: u16,
    protocol: u8,
    src_ip: []const u8, // mutable slice pointing into the raw packet
    dst_ip: []const u8, // mutable slice pointing into the raw packet

    /// Initialize from raw IPv4 packet slice
    pub fn init(raw_packet: *RawPacket) !IPv4Header {
        const raw_slice = try raw_packet.slice(14, raw_packet.raw_len); // or appropriate offset

        if (raw_slice.len < 20)
            return error.InvalidPacket;

        const version_ihl = raw_slice[0];
        const version = version_ihl >> 4;

        std.debug.print("Version: {d}\n", .{version});

        if (version != 4)
            return error.NotIPv4;

        const ihl = version_ihl & 0x0F;
        const header_length: u8 = ihl * 4;

        if (raw_slice.len < header_length)
            return error.InvalidPacket;

        const total_length = std.mem.readInt(u16, raw_slice[2..4], .big);

        return .{
            .version = version,
            .header_length = header_length,
            .total_length = total_length,
            .protocol = raw_slice[9],
            .src_ip = raw_slice[12..16],
            .dst_ip = raw_slice[16..20],
        };
    }

    /// Print the header nicely
    pub fn print(self: IPv4Header) void {
        std.debug.print("IPv4 Header:\n", .{});
        std.debug.print("Version: {d}, Header Length: {d} bytes\n", .{ self.version, self.header_length });
        std.debug.print("Total Length: {d}\n", .{self.total_length});
        std.debug.print("Protocol: {d}\n", .{self.protocol});
        std.debug.print("Source IP: {d}.{d}.{d}.{d}\n", .{ self.src_ip[0], self.src_ip[1], self.src_ip[2], self.src_ip[3] });
        std.debug.print("Destination IP: {d}.{d}.{d}.{d}\n", .{ self.dst_ip[0], self.dst_ip[1], self.dst_ip[2], self.dst_ip[3] });
    }
};

pub const ProtocolType = enum(u8) {
    UnknownProtocol = 0,
    Ethernet = 1,
    IPv4 = 2,
    TCP = 3,
    UDP = 4,
    GenericPayload = 5,
};

pub const EtherType = enum(u16) {
    IP = 0x0800,
    IPV6 = 0x86DD,
    ARP = 0x0806,
    VLAN = 0x8100,
};

pub const IPv4Protocol = enum(u8) {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
};

pub const MacHeader = struct {
    dst: [6]u8,
    src: [6]u8,
};

pub const EthHeader = struct {
    mac: MacHeader,
    eth_type: u16, // big-endian
};

pub const EthHd = packed struct {
    dst0: u8,
    dst1: u8,
    dst2: u8,
    dst3: u8,
    dst4: u8,
    dst5: u8,

    src0: u8,
    src1: u8,
    src2: u8,
    src3: u8,
    src4: u8,
    src5: u8,

    eth_type: u16, // BigEndian
};

pub const IPv4Header = packed struct {
    version_ihl: u8,
    dscp_ecn: u8,
    total_length: u16,
    identification: u16,
    flags_fragment: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src_ip0: u8,
    src_ip1: u8,
    src_ip2: u8,
    src_ip3: u8,

    dst_ip0: u8,
    dst_ip1: u8,
    dst_ip2: u8,
    dst_ip3: u8,
};

pub const TCPHeader = packed struct {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    data_offset_reserved_flags: u16,
    window: u16,
    checksum: u16,
    urgent_ptr: u16,
};

pub const UDPHeader = packed struct {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
};

pub const DNSHeader = packed struct {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
};

pub const Layer = struct {
    raw: []const u8,
    len: usize,
    protocol: ProtocolType,
    prev: ?*Layer,
    next: ?*Layer,
};

pub const Packet = struct {
    raw_packet: *RawPacket,
    offset: usize,
    first_layer: ?*Layer,
    last_layer: ?*Layer,

    pub fn init(raw_packet: *RawPacket) Packet {
        return .{
            .raw_packet = raw_packet,
            .offset = 0,
            .first_layer = null,
            .last_layer = null,
        };
    }

    pub fn parse_layers(self: *Packet, allocator: *std.mem.Allocator) !void {
        var current_layer: ?*Layer = null;

        // --- Ethernet ---
        if (self.raw_packet.raw_data.len < 14) return error.InvalidPacket;
        const eth_ptr: *align(1) const EthHd = @ptrCast(self.raw_packet.raw_data.ptr);

        const eth_layer = try allocator.create(Layer);
        eth_layer.raw = self.raw_packet.raw_data[0..14];
        eth_layer.len = 14;
        eth_layer.protocol = ProtocolType.Ethernet;
        eth_layer.prev = null;
        eth_layer.next = null;

        self.first_layer = eth_layer;
        self.last_layer = eth_layer;
        current_layer = eth_layer;
        self.offset += 14;

        // --- IPv4 (if EtherType is IP) --
        if (std.mem.bigToNative(u16, eth_ptr.*.eth_type) == @intFromEnum(EtherType.IP)) {
            if (self.raw_packet.raw_data.len < self.offset + 20) return error.InvalidPacket;
            const ipv4_ptr: *align(1) const IPv4Header = @ptrCast(&self.raw_packet.raw_data[self.offset]);
            const ihl = (ipv4_ptr.*.version_ihl & 0x0F) * 4;

            const ip_layer = try allocator.create(Layer);
            ip_layer.raw = self.raw_packet.raw_data[self.offset .. self.offset + ihl];
            ip_layer.len = ihl;
            ip_layer.protocol = ProtocolType.IPv4;
            ip_layer.prev = current_layer;
            ip_layer.next = null;

            current_layer.?.next = ip_layer;
            current_layer = ip_layer;
            self.last_layer = ip_layer;
            self.offset += ihl;

            const ip_proto = std.enums.fromInt(IPv4Protocol, ipv4_ptr.protocol).?;

            // --- TCP / UDP ---
            switch (ip_proto) {
                IPv4Protocol.TCP => {
                    if (self.raw_packet.raw_data.len < self.offset + 20) return error.InvalidPacket;
                    const tcp_layer = try allocator.create(Layer);
                    tcp_layer.raw = self.raw_packet.raw_data[self.offset .. self.offset + 20]; // min TCP header
                    tcp_layer.len = 20;
                    tcp_layer.protocol = ProtocolType.TCP;
                    tcp_layer.prev = current_layer;
                    tcp_layer.next = null;

                    current_layer.?.next = tcp_layer;
                    current_layer = tcp_layer;
                    self.last_layer = tcp_layer;
                    self.offset += 20;
                },
                IPv4Protocol.UDP => {
                    if (self.raw_packet.raw_data.len < self.offset + 8) return error.InvalidPacket;
                    const udp_layer = try allocator.create(Layer);
                    udp_layer.raw = self.raw_packet.raw_data[self.offset .. self.offset + 8];
                    udp_layer.len = 8;
                    udp_layer.protocol = ProtocolType.UDP;
                    udp_layer.prev = current_layer;
                    udp_layer.next = null;

                    current_layer.?.next = udp_layer;
                    current_layer = udp_layer;
                    self.last_layer = udp_layer;
                    self.offset += 8;
                },
                else => {},
            }
        }

        // --- Payload ---
        if (self.offset < self.raw_packet.raw_data.len) {
            const payload_layer = try allocator.create(Layer);
            payload_layer.raw = self.raw_packet.raw_data[self.offset..];
            payload_layer.len = self.raw_packet.raw_data.len - self.offset;
            payload_layer.protocol = ProtocolType.GenericPayload;
            payload_layer.prev = current_layer;
            payload_layer.next = null;

            current_layer.?.next = payload_layer;
            self.last_layer = payload_layer;
        }
    }

    pub fn print_layers(self: *Packet) void {
        var layer = self.first_layer;
        while (layer) |l| {
            std.debug.print("Layer: {s}, Len: {d}\n", .{ @tagName(l.protocol), l.len });
            layer = l.next;
        }
    }
};

//pub const Packet = struct {
//    raw_packet: *RawPacket,
//    offset: usize = 0,
//    first_layer: ?*Layer,
//    last_layer: ?*Layer,
//
//    /// Initialize from a RawPacket pointer
//    pub fn init(raw_packet: *RawPacket) Packet {
//        return .{ .raw_packet = raw_packet, .offset = 0, .first_layer = null, .last_layer = null };
//    }
//
//    /// Get the packets first layer
//    pub fn get_first_layer(self: Packet) ?*Layer {
//        return self.first_layer;
//    }
//
//    //// Get the packets last layer
//    pub fn get_last_layer(self: Packet) ?*Layer {
//        return self.last_layer;
//    }
//
//    /// Returns next n bytes and advances cursor
//    pub fn next(self: *Packet, n: usize) ![]const u8 {
//        const raw = self.raw_packet.bytes;
//        if (self.offset + n > raw.len)
//            return error.InvalidPacket;
//
//        const slice = raw[self.offset .. self.offset + n];
//        self.offset += n;
//        return slice;
//    }
//
//    /// Peek n bytes without advancing
//    pub fn peek(self: *Packet, n: usize) ![]const u8 {
//        const raw = self.raw_packet.bytes;
//        if (self.offset + n > raw.len)
//            return error.InvalidPacket;
//
//        return raw[self.offset .. self.offset + n];
//    }
//
//    /// Skip n bytes
//    pub fn skip(self: *Packet, n: usize) !void {
//        const raw = self.raw_packet.bytes;
//        if (self.offset + n > raw.len)
//            return error.InvalidPacket;
//
//        self.offset += n;
//    }
//
//    /// Remaining unread bytes
//    pub fn remaining(self: *Packet) usize {
//        return self.raw_packet.bytes.len - self.offset;
//    }
//
//    /// Reset cursor
//    pub fn reset(self: *Packet) void {
//        self.offset = 0;
//    }
//};
