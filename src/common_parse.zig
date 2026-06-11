const std = @import("std");

const ProtocolEnums = @import("ProtocolEnums.zig");
const IPv4 = @import("IPv4.zig");
const IPv6 = @import("IPv6.zig");
const GenericLayer = @import("GenericLayer.zig");
const tcp_ip_protocols = @import("tcp_ip_protocols.zig");

const IPVersions = ProtocolEnums.IPVersions;
const tcp_ip_protocol = tcp_ip_protocols.tcp_ip_protocol;

pub const LayerMeta = struct {
    protocol: tcp_ip_protocol,
    len: usize,
};

fn create_ip_layer(raw: []const u8) LayerMeta {
    if (raw.len < IPv4.MinHeaderLength) {
        return LayerMeta{ .protocol = .generic, .len = raw.len };
    }

    const ihl_byte = raw[0];
    const ip_version = ihl_byte >> 4;
    if (ip_version == @intFromEnum(IPVersions.IPv4)) {
        const hdr_len = (ihl_byte & 0x0F) * 4;
        if (hdr_len < IPv4.MinHeaderLength or hdr_len > IPv4.MaxHeaderLength or hdr_len < raw.len or hdr_len > raw.len) {
            return LayerMeta{ .protocol = .generic, .len = raw.len };
        }

        return LayerMeta{ .protocol = .ipv4, .len = @intCast(hdr_len) };
    }

    if (ip_version == @intFromEnum(IPVersions.IPv6)) {
        if (raw.len < IPv6.IPv6HeaderSize) {
            return LayerMeta{ .protocol = .generic, .len = raw.len };
        }

        const payload_len = std.mem.readInt(u16, raw[4..6].ptr, .big);

        _ = payload_len;

        var offset: usize = 0;

        while (offset < raw.len) {
            offset += 1;
        }

        return LayerMeta{ .protocol = .ipv6, .len = IPv6.IPv6HeaderSize };
    } else {
        return LayerMeta{ .protocol = .generic, .len = raw.len };
    }
}
