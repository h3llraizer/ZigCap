const Eth = @import("Eth.zig");
const LoopBack = @import("Loopback.zig");

const IPv4 = @import("IPv4.zig");
const IPv6 = @import("IPv6.zig");
const UDP = @import("UDP.zig");
const TCP = @import("TCP.zig");
const ARP = @import("ARP.zig");
const ICMP = @import("ICMP.zig");
const GenericLayer = @import("GenericLayer.zig");
const DNS = @import("DNS.zig");

pub const tcp_ip_protocol = enum(u32) {
    generic = 0,
    eth = 1,
    loopback = 2,
    icmp = 3,
    ipv4 = 4,
    ipv6 = 5,
    arp = 6,

    http = 7,
    dns = 8,

    tcp = 9,
    udp = 10,
};

pub fn get_layer_type_enum(value: type) !tcp_ip_protocol {
    switch (value) {
        Eth.EthLayer => return tcp_ip_protocol.eth,
        LoopBack.LoopBackLayer => return tcp_ip_protocol.loopback,
        IPv4.IPv4Layer => return tcp_ip_protocol.ipv4,
        IPv6.IPv6Layer => return tcp_ip_protocol.ipv6,
        UDP.UDPLayer => return tcp_ip_protocol.udp,
        TCP.TCPLayer => return tcp_ip_protocol.tcp,
        ARP.ARPLayer => return tcp_ip_protocol.arp,
        ICMP.ICMPLayer => return tcp_ip_protocol.icmp,
        GenericLayer.ApplicationLayer => return tcp_ip_protocol.generic,
        DNS.DNSLayer => return tcp_ip_protocol.dns,
        else => return error.LayerInvalid,
    }
}
