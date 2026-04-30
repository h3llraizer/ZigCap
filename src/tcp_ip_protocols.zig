const Eth = @import("Eth.zig");
const Loopback = @import("Loopback.zig");

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
    vlan = 2,
    loopback = 3,
    icmp = 4,
    ipv4 = 5,
    ipv6 = 6,
    arp = 7,

    http = 8,
    dns = 9,

    tcp = 10,
    udp = 11,
};

pub const TransportLayer = union(enum) {
    tcp: TCP.TCPLayer,
    udp: UDP.UDPLayer,
};

pub fn get_layer_type_enum(value: type) !tcp_ip_protocol {
    switch (value) {
        Eth.EthLayer => return tcp_ip_protocol.eth,
        Loopback.LoopbackLayer => return tcp_ip_protocol.loopback,
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
