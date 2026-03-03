const std = @import("std");

pub const UDPHeader = packed struct {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
};

pub fn parseHeader(packet: []const u8) !void {
    if (packet.len < 8) {
        return error.InvalidPacket;
    }

    const src_port = std.mem.readInt(u16, packet[0..2], .big);
    const dst_port = std.mem.readInt(u16, packet[2..4], .big);
    const length = std.mem.readInt(u16, packet[4..6], .big);
    const checksum = std.mem.readInt(u16, packet[6..8], .big);

    std.debug.print("UDP Header:\n", .{});
    std.debug.print("Source Port: {d}, Destination Port: {d}\n", .{ src_port, dst_port });
    std.debug.print("Length: {d}, Checksum: {x}\n", .{ length, checksum });
}

pub fn getSrcPort(packet: []const u8) !u16 {
    if (packet.len < 8) {
        return error.InvalidPacket;
    }

    const src_port = std.mem.readInt(u16, packet[0..2], .big);

    return src_port;
}

pub fn getDstPort(packet: []const u8) !u16 {
    if (packet.len < 8) {
        return error.InvalidPacket;
    }

    const dst_port = std.mem.readInt(u16, packet[2..4], .big);

    return dst_port;
}
