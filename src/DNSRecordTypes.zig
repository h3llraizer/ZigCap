const std = @import("std");
const Allocator = std.mem.Allocator;

const DNS = @import("DNS.zig");
const IPv4Address = @import("IPv4.zig").IPv4Address;
const IPv6Address = @import("IPv6.zig").IPv6Address;

const QueryType = DNS.QueryType;
const DnsClass = DNS.DnsClass;
const DNSLayer = DNS.DNSLayer;
const AnswerRecord = DNS.AnswerRecord;

/// A Record - IPv4 Responses
pub const ARecord = struct {
    offset: usize,
    length: usize,
    qtype: QueryType,
    qclass: DnsClass,
    layer: *DNSLayer,
    next_answer: ?*AnswerRecord = null,
    prev_answer: ?*AnswerRecord = null,

    pub fn get_data(self: *ARecord) []const u8 {
        return self.layer.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_data_mut(self: *ARecord) []u8 {
        return self.layer.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_ip(self: *ARecord) ?IPv4Address {
        if (self.qtype == QueryType.A) {
            const data = self.get_data();
            if (data.len >= 16) {
                const ip_u32: u32 = std.mem.readInt(u32, data[12..16], .big);
                const ip = IPv4Address.init_from_u32(ip_u32);
                return ip;
            }
        }

        return null;
    }

    pub fn get_rr_type(self: ARecord) QueryType {
        return self.qtype;
    }
};

/// AAAA Record - IPv6 responses
pub const AAAARecord = struct {
    offset: usize,
    length: usize,
    qtype: QueryType,
    qclass: DnsClass,
    layer: *DNSLayer,
    next_answer: ?*AnswerRecord = null,
    prev_answer: ?*AnswerRecord = null,

    pub fn get_data(self: *AAAARecord) []const u8 {
        return self.layer.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_data_mut(self: *AAAARecord) []u8 {
        return self.layer.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_ipv6(self: *AAAARecord) ?IPv6Address {
        if (self.qtype == QueryType.AAAA) {
            const data = self.get_data();
            if (data.len >= 28) {
                //                const ip_u64: u64 = std.mem.readInt(u64, data[12..28], .big);
                var ipv6_arr: [16]u8 = undefined;
                @memmove(ipv6_arr[0..], data[12..28]);

                const ip = IPv6Address.init_from_array(ipv6_arr);
                return ip;
            }
        }

        return null;
    }

    pub fn get_rr_type(self: AAAARecord) QueryType {
        return self.qtype;
    }
};

/// CNAME Record
pub const CNAMERecord = struct {
    offset: usize,
    length: usize,
    qtype: QueryType,
    qclass: DnsClass,
    layer: *DNSLayer,
    next_answer: ?*AnswerRecord = null,
    prev_answer: ?*AnswerRecord = null,

    pub fn get_data(self: *CNAMERecord) []const u8 {
        return self.layer.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_data_mut(self: *CNAMERecord) []u8 {
        return self.layer.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_cname_raw(self: *CNAMERecord) []const u8 {
        return self.get_data()[12..];
    }

    pub fn decode_cname(self: *CNAMERecord, allocator: Allocator) ![]u8 {
        const full_packet = self.layer.get_data(); // get the entire dns layers data - this is required for pointer jumps
        const rdata = self.get_data()[12..]; // CNAME's rdata, offset 12 is used for name ptr (2bytes), rrtype (2 bytes), class (2bytes), ttl (4bytes), data length (2bytes)

        var list = try std.ArrayList(u8).initCapacity(allocator, full_packet.len);
        defer list.deinit(allocator);

        var offset: usize = 0;
        var first = true;

        while (offset < rdata.len and rdata[offset] != 0) {
            const label_len = rdata[offset];

            // Check for compression pointer (first two bits are 11)
            // 0xC0 is compresssion ptr
            if ((label_len & 0xC0) == 0xC0) {
                if (offset + 1 >= rdata.len) return error.InvalidPacket;

                // Calculate absolute jump offset in the FULL packet
                const absolute_jump = (@as(u16, label_len & 0x3F) << 8) | @as(u16, rdata[offset + 1]);

                //                std.debug.print("Pointer at rdata offset {} jumps to absolute packet offset {}\n", .{ offset, absolute_jump });

                // Decode the name at the absolute jump position
                const jumped_name = try decodeQnameFromAbsolute(allocator, full_packet, absolute_jump);
                defer allocator.free(jumped_name);

                // Append the jumped name
                if (jumped_name.len > 0) {
                    if (!first) try list.append(allocator, '.');
                    try list.appendSlice(allocator, jumped_name);
                    first = false;
                }

                // Move past the pointer (2 bytes) and continue
                offset += 2;
                continue;
            }

            // Regular label (not a pointer)
            offset += 1;

            if (offset + label_len > rdata.len) return error.InvalidPacket;

            if (!first) try list.append(allocator, '.');
            first = false;

            try list.appendSlice(allocator, rdata[offset .. offset + label_len]);
            offset += label_len;
        }

        return list.toOwnedSlice(allocator);
    }

    fn decodeQnameFromAbsolute(allocator: Allocator, full_packet: []const u8, start_offset: usize) ![]u8 {
        var list = try std.ArrayList(u8).initCapacity(allocator, full_packet.len);
        defer list.deinit(allocator);

        var offset = start_offset;
        var first = true;

        while (offset < full_packet.len and full_packet[offset] != 0) {
            const label_len = full_packet[offset];

            // Handle nested pointers (pointer pointing to another pointer)
            if ((label_len & 0xC0) == 0xC0) {
                if (offset + 1 >= full_packet.len) return error.InvalidPacket;
                const jump = (@as(u16, label_len & 0x3F) << 8) | @as(u16, full_packet[offset + 1]);
                const nested = try decodeQnameFromAbsolute(allocator, full_packet, jump);
                defer allocator.free(nested);

                if (nested.len > 0) {
                    if (!first) try list.append(allocator, '.');
                    try list.appendSlice(allocator, nested);
                    first = false;
                }

                // Move past the pointer
                offset += 2;
                continue;
            }

            // Regular label
            offset += 1;

            if (offset + label_len > full_packet.len) return error.InvalidPacket;

            if (!first) try list.append(allocator, '.');
            first = false;

            try list.appendSlice(allocator, full_packet[offset .. offset + label_len]);
            offset += label_len;
        }

        return list.toOwnedSlice(allocator);
    }

    pub fn get_rr_type(self: CNAMERecord) QueryType {
        return self.qtype;
    }
};
