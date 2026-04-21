const std = @import("std");
const Allocator = std.mem.Allocator;

const DNS = @import("DNS.zig");
const IPv4Address = @import("IPv4.zig").IPv4Address;
const IPv6Address = @import("IPv6.zig").IPv6Address;

const QueryType = DNS.QueryType;
const DnsClass = DNS.DnsClass;
const DNSLayer = DNS.DNSLayer;
const AnswerRecord = DNS.AnswerRecord;

pub const GenericRecord = struct {
    offset: usize,
    length: usize,
    qtype: QueryType,
    qclass: DnsClass,
    layer: *DNSLayer,
    next_answer: ?*AnswerRecord = null,
    prev_answer: ?*AnswerRecord = null,

    pub fn get_data(self: *GenericRecord) []const u8 {
        return self.layer.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_data_mut(self: *GenericRecord) []u8 {
        return self.layer.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_rr_type(self: GenericRecord) QueryType {
        return self.qtype;
    }
};

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

    pub fn set_ip(self: *ARecord, ipv4: IPv4Address) void {
        const data = self.get_data_mut();
        if (data.len >= 16) {
            std.mem.writeInt(u32, data[12..16], ipv4.to_u32(), .big);
        }
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

    /// returns the IPv6 address of the AAAA record by creating a copy of the IPv6 start to len bytes and init'ing the IPv6 address from it.
    /// null is retured when length of the RR data (in the DNS Layer) is not atleast 28 bytes in length
    pub fn get_ipv6(self: *AAAARecord) ?IPv6Address {
        const data = self.get_data();
        if (data.len >= 28) {
            //                const ip_u64: u64 = std.mem.readInt(u64, data[12..28], .big);
            var ipv6_arr: [16]u8 = undefined;
            @memmove(ipv6_arr[0..], data[12..28]);

            const ip = IPv6Address.init_from_array(ipv6_arr);
            return ip;
        }

        return null;
    }

    /// Sets the IPv6 address of this record.
    /// Will fail silently when length of the RR data (in the DNS Layer) is not atleast 28 bytes in length
    pub fn set_ipv6(self: *AAAARecord, ipv6: IPv6Address) void {
        const data = self.get_data_mut();
        if (data.len >= 28) {
            var ipv6_arr: [16]u8 = ipv6.array;
            @memmove(data[12..28], ipv6_arr[0..]);
        }
    }

    pub fn get_rr_type(self: AAAARecord) QueryType {
        return self.qtype;
    }
};

/// CNAME (Canonical Name) Record
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

    pub fn get_name(self: *CNAMERecord, allocator: Allocator) ![]u8 {
        const data = self.get_data();
        // the length of the name is not known so just take use the offset of this RR
        return try decode_name(self.layer.get_data(), data, allocator);
    }

    pub fn decode_cname(self: *CNAMERecord, allocator: Allocator) ![]u8 {
        // CNAME's rdata, offset 12 is used for name ptr (2bytes), rrtype (2 bytes), class (2bytes), ttl (4bytes), data length (2bytes)
        if (self.get_data().len < 12) {
            return error.InalidCnameRecord;
        }
        return try decode_name(self.layer.get_data(), self.get_data()[12..], allocator);
    }

    /// Takes a non-dns-label cname value and converts it to label format using a helper method and the allocator provided.
    /// The formatted cname value is copied over the current one with these cases:
    /// if the formatted cname value is of the same length as the current one, the DNSLayer buffer remains unchanged
    /// else if the new cname is shorter or longer, then the dns layers buffer is shortened or extended, respectively
    ///
    /// currently broken. don't use it.
    pub fn set_cname(self: *CNAMERecord, cname: []const u8, allocator: Allocator) !void {
        const data = self.get_data_mut();
        const new_cname_wire = try encodeQnameSimple(allocator, cname);
        defer allocator.free(new_cname_wire);

        const current_rdata = data[12..];
        const old_len = current_rdata.len;
        const new_len = new_cname_wire.len;

        if (new_len > old_len) {
            const extend_len = new_len - old_len;
            const cname_offset = self.offset + 12;

            // Extend the payload
            _ = try self.layer.extend_payload(cname_offset, extend_len);

            // Update this record's length
            self.length += extend_len;

            // Update all subsequent records' offsets and lengths
            var next_record: ?*AnswerRecord = self.next_answer;
            while (next_record) |next| {
                next.set_offset(next.get_offset() + extend_len);
                next.set_length(next.get_length() + extend_len);
                next_record = next.get_next_record();
            }

            // Update ALL compression pointers in the packet
            try self.updateCompressionPointers(cname_offset, @as(isize, @intCast(extend_len)));

            // Refresh data pointer and write new CNAME
            const new_data = self.get_data_mut();
            @memcpy(new_data[12..], new_cname_wire);
        } else if (new_len < old_len) {
            const shrink_len = old_len - new_len;
            const cname_offset = self.offset + 12;

            // Shrink the payload (shift everything left)
            const full_packet = self.layer.get_data();
            const after_rdata = cname_offset + old_len;
            @memmove(full_packet[cname_offset + new_len ..][0 .. full_packet.len - (cname_offset + new_len)], full_packet[after_rdata..]);

            // Update this record's length
            self.length -= shrink_len;

            // Update subsequent records' offsets and lengths
            var next_record: ?*AnswerRecord = self.next_answer;
            while (next_record) |next| {
                next.set_offset(next.get_offset() - shrink_len);
                next.set_length(next.get_length() - shrink_len);
                next_record = next.get_next_record();
            }

            // Update compression pointers
            try self.updateCompressionPointers(cname_offset, -@as(isize, @intCast(shrink_len)));

            // Write new CNAME
            const new_data = self.get_data_mut();
            @memcpy(new_data[12..], new_cname_wire);
        } else {
            // Same length, simple overwrite
            @memcpy(data[12..], new_cname_wire);
        }
    }

    fn updateCompressionPointers(self: *CNAMERecord, start_offset: usize, delta: isize) !void {
        const full_packet = self.layer.get_data();
        var offset: usize = 0;

        while (offset < full_packet.len - 1) {
            // Look for compression pointers (bytes starting with 0xC0)
            if (full_packet[offset] & 0xC0 == 0xC0) {
                const pointer: u16 = (@as(u16, full_packet[offset] & 0x3F) << 8) | @as(u16, full_packet[offset + 1]);
                std.debug.print("ptr: {} {x}\n", .{ pointer, pointer });

                // If this pointer points to or after the modified region, update it
                if (pointer >= start_offset) {
                    const new_pointer: u16 = @as(u16, @intCast(@as(isize, @intCast(pointer)) + delta));
                    std.debug.print("new ptr: {} {x}\n", .{ new_pointer, new_pointer });
                    full_packet[offset] = @as(u8, @intCast(0xC0 | ((new_pointer >> 8) & 0x3F)));
                    full_packet[offset + 1] = @as(u8, @intCast(new_pointer & 0xFF));
                    std.debug.print("updated offset: {x}\n", .{full_packet[offset .. offset + 2]});
                }

                // Skip the pointer (2 bytes)
                offset += 2;
            } else {
                // Regular label: length byte + label data
                const len = full_packet[offset];
                if (len == 0) {
                    offset += 1; // Null terminator
                    continue;
                }

                // Skip length byte + label data
                offset += 1 + len;
            }
        }
    }

    pub fn get_rr_type(self: CNAMERecord) QueryType {
        return self.qtype;
    }
};

/// TXT Record
pub const TXTRecord = struct {
    offset: usize,
    length: usize,
    qtype: QueryType,
    qclass: DnsClass,
    layer: *DNSLayer,
    next_answer: ?*AnswerRecord = null,
    prev_answer: ?*AnswerRecord = null,

    pub fn get_data(self: *TXTRecord) []const u8 {
        return self.layer.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_data_mut(self: *TXTRecord) []u8 {
        return self.layer.get_data()[self.offset .. self.offset + self.length];
    }

    /// gets the records data from offset 13 and returns the slice which is the TXT string itself.
    /// no conversion needed because it's already a string
    /// to get the domain part, use get_name
    pub fn get_record_str(self: *TXTRecord) []const u8 {
        return self.get_data()[13..];
    }

    /// retrieves the name stated in the RR.
    pub fn get_name(self: *TXTRecord, allocator: Allocator) ![]u8 {
        const data = self.get_data();
        return try decode_name(self.layer.get_data(), data, allocator);
    }

    pub fn get_rr_type(self: TXTRecord) QueryType {
        return self.qtype;
    }
};

/// MX Record
pub const MXRecord = struct {
    offset: usize,
    length: usize,
    qtype: QueryType,
    qclass: DnsClass,
    layer: *DNSLayer,
    next_answer: ?*AnswerRecord = null,
    prev_answer: ?*AnswerRecord = null,

    pub fn get_data(self: *MXRecord) []const u8 {
        return self.layer.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_data_mut(self: *MXRecord) []u8 {
        return self.layer.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_mx_domain(self: *MXRecord, allocator: Allocator) ![]const u8 {
        const domain_start = self.get_data()[14..];
        return try decode_name(self.layer.get_data(), domain_start, allocator);
    }

    pub fn get_rr_type(self: MXRecord) QueryType {
        return self.qtype;
    }
};

pub const PTRRecord = struct {
    offset: usize,
    length: usize,
    qtype: QueryType,
    qclass: DnsClass,
    layer: *DNSLayer,
    next_answer: ?*AnswerRecord = null,
    prev_answer: ?*AnswerRecord = null,

    pub fn get_data(self: *PTRRecord) []const u8 {
        return self.layer.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_data_mut(self: *PTRRecord) []u8 {
        return self.layer.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_name(self: *PTRRecord, allocator: Allocator) ![]u8 {
        return try decode_name(self.layer.get_data(), self.get_data()[12..], allocator);
    }

    pub fn get_rr_type(self: PTRRecord) QueryType {
        return self.qtype;
    }
};

pub fn encodeQname(allocator: Allocator, domain: []const u8, compression_dict: ?std.StringHashMap(u16)) ![]u8 {
    var list = try std.ArrayList(u8).initCapacity(allocator, domain.len + 2); // +2 for root and null
    defer list.deinit(allocator);

    // Split domain into labels
    var labels = std.mem.splitScalar(u8, domain, '.');
    var label_count: usize = 0;

    while (labels.next()) |label| {
        if (label.len == 0) continue; // Skip empty labels

        if (label.len > 63) return error.LabelTooLong;

        // Check if this label sequence (from this point forward) exists in compression dictionary
        if (compression_dict) |dict| {
            // Build the remaining domain string from current position
            var remaining = std.ArrayList(u8).init(allocator);
            defer remaining.deinit();

            // Reconstruct the remaining domain (current label + remaining labels)
            var remaining_labels = std.mem.splitScalar(u8, domain[label_count..], '.');
            var first = true;
            while (remaining_labels.next()) |rem_label| {
                if (rem_label.len == 0) continue;
                if (!first) try remaining.append('.');
                try remaining.appendSlice(rem_label);
                first = false;
            }

            if (dict.contains(remaining.items)) {
                const offset = dict.get(remaining.items).?;
                // Write compression pointer
                const pointer: u16 = 0xC000 | offset;
                try list.append(@as(u8, @truncate(pointer >> 8)));
                try list.append(@as(u8, @truncate(pointer & 0xFF)));
                return list.toOwnedSlice();
            }
        }

        // Write label length
        try list.append(@as(u8, @intCast(label.len)));
        // Write label bytes
        try list.appendSlice(label);

        label_count += label.len + 1; // +1 for the dot we'll skip
    }

    // Write terminating null byte
    try list.append(0);

    return list.toOwnedSlice();
}

// Simplified version without compression
pub fn encodeQnameSimple(allocator: Allocator, domain: []const u8) ![]u8 {
    var list = try std.ArrayList(u8).initCapacity(allocator, domain.len + 2);
    defer list.deinit(allocator);

    var labels = std.mem.splitScalar(u8, domain, '.');

    while (labels.next()) |label| {
        if (label.len == 0) continue;

        if (label.len > 63) return error.LabelTooLong;

        try list.append(allocator, @as(u8, @intCast(label.len)));
        try list.appendSlice(allocator, label);
    }

    // Add terminating null
    try list.append(allocator, 0);

    return list.toOwnedSlice(allocator);
}

// Version that builds compression dictionary while encoding multiple names
pub fn buildCompressionDict(allocator: Allocator, domains: []const []const u8) !std.StringHashMap(u16) {
    var dict = std.StringHashMap(u16).init(allocator);
    errdefer dict.deinit();

    var current_offset: u16 = 0;

    for (domains) |domain| {
        var labels = std.mem.splitScalar(u8, domain, '.');
        var label_list = std.ArrayList([]const u8).init(allocator);
        defer label_list.deinit();

        // Collect labels in reverse order for suffix compression
        while (labels.next()) |label| {
            try label_list.append(label);
        }

        // Add suffixes to dictionary (from TLD down to full domain)
        var i: usize = label_list.items.len;
        while (i > 0) {
            i -= 1;
            var suffix = std.ArrayList(u8).init(allocator);
            defer suffix.deinit();

            for (label_list.items[i..]) |label| {
                if (suffix.items.len > 0) try suffix.append('.');
                try suffix.appendSlice(label);
            }

            if (!dict.contains(suffix.items)) {
                try dict.put(suffix.items, current_offset);
            }
        }

        // Update offset for next domain (including null terminator)
        const encoded = try encodeQnameSimple(allocator, domain);
        defer allocator.free(encoded);
        current_offset += @as(u16, @intCast(encoded.len));
    }

    return dict;
}

pub fn decode_name(layer_data: []const u8, record_data: []const u8, allocator: Allocator) ![]u8 {
    const full_packet = layer_data; // get the entire dns layers data - this is required for pointer jumps
    const rdata = record_data;

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
            const jumped_name = try decodeNameFromAbsolute(allocator, full_packet, absolute_jump);
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

fn decodeNameFromAbsolute(allocator: Allocator, full_packet: []const u8, start_offset: usize) ![]u8 {
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
            const nested = try decodeNameFromAbsolute(allocator, full_packet, jump);
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
