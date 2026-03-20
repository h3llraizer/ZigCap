const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

/// ApplicationProtocols values are defined with their well-known port number - this makes the transport layers parse_next_layer simpler
pub const ApplicationProtocols = enum(u16) {
    HTTP = 80,
    DNS = 53,
};

pub const TransportProtocols = enum(u8) {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
};

pub const NetworkProtocols = enum(u16) {
    IPv4 = 4,
    IPv6 = 6,
};

pub const LinkLayerProtocols = enum(u16) {
    NULL = 0, // BSD loopback encapsulation
    ETHERNET = 1, // IEEE 802.3 Ethernet
    AX25 = 3, // AX.25 packet
    IEEE802_5 = 6, // IEEE 802.5 Token Ring
    ARCNET_BSD = 7, // ARCNET Data Packets
    SLIP = 8, // SLIP, encapsulated with a LINKTYPE_SLIP header
    PPP = 9, // PPP, as per RFC 1661 and RFC 1662
    FDDI = 10, // FDDI, as specified by ANSI INCITS 239-1994
    DLT_RAW1 = 12, // Raw IP
    DLT_RAW2 = 14, // Raw IP (OpenBSD)
    PPP_HDLC = 50, // PPP in HDLC-like framing, or Cisco PPP with HDLC framing
    PPP_ETHER = 51, // PPPoE
    ATM_RFC1483 = 100, // RFC 1483 LLC/SNAP-encapsulated ATM
    RAW = 101, // Raw IP
    C_HDLC = 104, // Cisco PPP with HDLC framing
    IEEE802_11 = 105, // IEEE 802.11 wireless LAN
    FRELAY = 107, // Frame Relay
    LOOP = 108, // OpenBSD loopback encapsulation
    LINUX_SLL = 113, // Linux "cooked" capture encapsulation
    LTALK = 114, // Apple LocalTalk
    PFLOG = 117, // OpenBSD pflog
    IEEE802_11_PRISM = 119, // Prism monitor mode info followed by 802.11 header
    IP_OVER_FC = 122, // RFC 2625 IP-over-Fibre Channel
    SUNATM = 123, // ATM traffic as used by SunATM devices
    IEEE802_11_RADIOTAP = 127, // Radiotap link-layer info followed by 802.11 header
    ARCNET_LINUX = 129, // ARCNET Data Packets (Linux)
    APPLE_IP_OVER_IEEE1394 = 138, // Apple IP-over-IEEE 1394 cooked header
    MTP2_WITH_PHDR = 139, // Signaling System 7 MTP2 with pseudo-header
    MTP2 = 140, // MTP2
    MTP3 = 141, // MTP3
    SCCP = 142, // SCCP
    DOCSIS = 143, // DOCSIS
    LINUX_IRDA = 144, // Linux IRDA
    IEEE802_11_AVS = 163, // IEEE 802.11 AVS
    BACNET_MS_TP = 165, // BACnet MS/TP
    PPP_PPPD = 166, // PPP via PPPD
    GPRS_LLC = 169, // GPRS LLC
    GPF_T = 170, // GPF-T
    GPF_F = 171, // GPF-F
    LINUX_LAPD = 177, // Linux LAPD
    BLUETOOTH_HCI_H4 = 187, // Bluetooth HCI H4
    USB_LINUX = 189, // USB (Linux)
    PPI = 192, // Per-Packet Information
    IEEE802_15_4 = 195, // IEEE 802.15.4
    SITA = 196, // SITA
    ERF = 197, // ERF
    BLUETOOTH_HCI_H4_WITH_PHDR = 201, // Bluetooth HCI H4 with pseudo-header
    AX25_KISS = 202, // AX.25 KISS
    LAPD = 203, // LAPD
    PPP_WITH_DIR = 204, // PPP with direction
    C_HDLC_WITH_DIR = 205, // Cisco HDLC with direction
    FRELAY_WITH_DIR = 206, // Frame Relay with direction
    IPMB_LINUX = 209, // IPMB (Linux)
    IEEE802_15_4_NONASK_PHY = 215, // IEEE 802.15.4 non-ASK PHY
    USB_LINUX_MMAPPED = 220, // USB Linux mmapped
    FC_2 = 224, // Fibre Channel FC-2
    FC_2_WITH_FRAME_DELIMS = 225, // FC-2 with frame delimiters
    IPNET = 226, // IPNet
    CAN_SOCKETCAN = 227, // CAN (SocketCAN)
    IPV4 = 228, // Raw IPv4
    IPV6 = 229, // Raw IPv6
    IEEE802_15_4_NOFCS = 230, // IEEE 802.15.4 without FCS
    DBUS = 231, // DBus
    DVB_CI = 235, // DVB-CI
    MUX27010 = 236, // MUX27010
    STANAG_5066_D_PDU = 237, // STANAG 5066 D-PDU
    NFLOG = 239, // Netfilter NFLOG
    NETANALYZER = 240, // NetAnalyzer
    NETANALYZER_TRANSPARENT = 241, // NetAnalyzer Transparent
    IPOIB = 242, // IP over InfiniBand
    MPEG_2_TS = 243, // MPEG-2 Transport Stream
    NG40 = 244, // NG40
    NFC_LLCP = 245, // NFC LLCP
    INFINIBAND = 247, // InfiniBand
    SCTP = 248, // SCTP
    USBPCAP = 249, // USBPcap
    RTAC_SERIAL = 250, // RTAC Serial
    BLUETOOTH_LE_LL = 251, // Bluetooth Low Energy LL
    NETLINK = 253, // Netlink
    BLUETOOTH_LINUX_MONITOR = 254, // Bluetooth Linux monitor
    BLUETOOTH_BREDR_BB = 255, // Bluetooth BR/EDR baseband
    BLUETOOTH_LE_LL_WITH_PHDR = 256, // Bluetooth LE LL with pseudo-header
    PROFIBUS_DL = 257, // PROFIBUS Data Link
    PKTAP = 258, // PKTAP
    EPON = 259, // EPON
    IPMI_HPM_2 = 260, // IPMI HPM.2
    ZWAVE_R1_R2 = 261, // Z-Wave R1/R2
    ZWAVE_R3 = 262, // Z-Wave R3
    WATTSTOPPER_DLM = 263, // Wattstopper DLM
    ISO_14443 = 264, // ISO 14443
    LINUX_SLL2 = 276, // Linux cooked capture v2
    INVALID = 0xFFFF, // Set if interface ID for a packet of a pcapng file is too high
};

pub const LayerProtocols = union(enum) {
    LinkLayer: LinkLayerProtocols,
    Network: NetworkProtocols,
    Transport: TransportProtocols,
    Application: ApplicationProtocols,
};

pub fn from_protocol_layer(layer: *Layer, protocol_layer: LayerProtocols, layer_type: anytype) ?*layer_type {
    if (std.meta.activeTag(layer.get_protocol()) == std.meta.activeTag(protocol_layer)) {
        return TPtr(*layer_type, layer.layer_type);
    }

    return null;
}

/// Layer interface
pub const Layer = struct {
    layer_type: *anyopaque,

    next_layer: ?*Layer,
    prev_layer: ?*Layer,

    v_get_data: *const fn (*anyopaque) []u8,
    v_get_payload: *const fn (*anyopaque) []u8,
    v_to_string: *const fn (*anyopaque, Allocator) []const u8,
    v_parse_next_layer: *const fn (*anyopaque, Allocator) ?*Layer,
    v_get_protocol: *const fn (*anyopaque) LayerProtocols,
    v_deinit: *const fn (*anyopaque, Allocator) void,

    // link the protocol layer pointer to the vtable functions
    pub fn implBy(layer_type: anytype) Layer {
        const delegate = LayerDelegate(layer_type);
        return .{
            .layer_type = layer_type,
            .next_layer = null,
            .prev_layer = null,

            .v_get_data = delegate.get_data,
            .v_get_payload = delegate.get_payload,
            .v_to_string = delegate.to_string,
            .v_parse_next_layer = delegate.parse_next_layer,

            .v_get_protocol = delegate.get_protocol,
            .v_deinit = delegate.deinit,
        };
    }

    /// get slice of data (hdr+payload)
    pub fn get_data(self: *Layer) []u8 {
        return self.v_get_data(self);
    }

    /// return mutable slice of the payload
    pub fn get_payload(self: *Layer) []u8 {
        return self.v_get_payload(self);
    }

    // Public functions
    pub fn get_next_layer(self: *Layer) ?*Layer {
        return self.next_layer;
    }

    pub fn get_prev_layer(self: *Layer) ?*Layer {
        return self.prev_layer;
    }

    pub fn set_next_layer(self: *Layer, next_layer: *Layer) void {
        self.next_layer = next_layer;
        next_layer.prev_layer = self;
    }

    pub fn set_prev_layer(self: *Layer, prev_layer: *Layer) void {
        self.prev_layer = prev_layer;
    }

    pub fn to_string(self: *Layer, allocator: Allocator) []const u8 {
        return self.v_to_string(self.layer_type, allocator);
    }

    pub fn parse_next_layer(self: *Layer, allocator: Allocator) ?*Layer {
        return self.v_parse_next_layer(self.layer_type, allocator);
    }

    pub fn get_protocol(self: *Layer) LayerProtocols {
        return self.v_get_protocol(self.layer_type);
    }

    pub fn deinit(self: *Layer, allocator: Allocator) void {
        self.v_deinit(self.layer_type, allocator);
    }
};

/// Links a Layer to the implementation functions
inline fn LayerDelegate(layer_type: anytype) type { // VTable Link
    const LayerType = @TypeOf(layer_type);

    return struct {
        pub fn get_data(layer: *anyopaque) []u8 {
            return TPtr(LayerType, layer).get_data();
        }

        pub fn get_payload(layer: *anyopaque) []u8 {
            return TPtr(LayerType, layer).get_payload();
        }

        pub fn to_string(layer: *anyopaque, allocator: Allocator) []const u8 {
            return TPtr(LayerType, layer).to_string(allocator);
        }

        pub fn parse_next_layer(layer: *anyopaque, allocator: Allocator) ?*Layer {
            return TPtr(LayerType, layer).parse_next_layer(allocator);
        }

        pub fn get_protocol(layer: *anyopaque) LayerProtocols {
            return TPtr(LayerType, layer).get_protocol();
        }

        pub fn deinit(layer: *anyopaque, allocator: Allocator) void {
            TPtr(LayerType, layer).deinit(allocator);
        }
    };
}

/// Converts an opaque pointer back to the implementation
pub fn TPtr(T: type, opaque_ptr: *anyopaque) T {
    return @as(T, @ptrCast(@alignCast(opaque_ptr)));
}
