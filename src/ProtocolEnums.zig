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
