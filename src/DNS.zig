const std = @import("std");

pub const DNSFlags = packed struct { QR: u16, OPCODE: u16, AA: u16, TC: u16, RD: u16, RA: u16, Z: u16, RCODE: u16 };

pub const DNSHeader = packed struct {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
};

pub fn getFlags(flags: u16) DNSFlags {
    const dns_flags: DNSFlags = .{
        .QR = (flags >> 15) & 0x1,
        .OPCODE = (flags >> 11) & 0xF,
        .AA = (flags >> 10) & 0x1,
        .TC = (flags >> 9) & 0x1,
        .RD = (flags >> 8) & 0x1,
        .RA = (flags >> 7) & 0x1,
        .Z = (flags >> 4) & 0x7, // reserved
        .RCODE = flags & 0xF,
    };

    return dns_flags;
}

pub fn parseHeader(payload: []const u8) !void {
    if (payload.len < 12) {
        return error.InvalidPacket;
    }

    // DNS fields are big-endian (network byte order)
    const transaction_id = std.mem.readInt(u16, payload[0..2], .big);
    const flags = getFlags(std.mem.readInt(u16, payload[2..4], .big));
    const qdcount = std.mem.readInt(u16, payload[4..6], .big);
    const ancount = std.mem.readInt(u16, payload[6..8], .big);
    const nscount = std.mem.readInt(u16, payload[8..10], .big);
    const arcount = std.mem.readInt(u16, payload[10..12], .big);

    std.debug.print("DNS Header:\n", .{});
    std.debug.print("Transaction ID: {d}\n", .{transaction_id});
    //std.debug.print("Flags: {x}\n", .{flags});
    std.debug.print("QR Type: {s}\n", .{if (flags.QR == 0) "query" else "response"});
    std.debug.print("Questions: {d}, Answers: {d}, Authority: {d}, Additional: {d}\n", .{ qdcount, ancount, nscount, arcount });
}
