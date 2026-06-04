const std = @import("std");
const DNS = @import("DNS.zig");
const IPv4Address = @import("IPv4.zig").IPv4Address;
const IPv6Address = @import("IPv6.zig").IPv6Address;

const print = std.debug.print;
const Allocator = std.mem.Allocator;
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

    pub fn get_name(self: *ARecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        const data = self.get_data(); // the length of the name is not known so just take use the offset of this RR

        return try decode_name(self.layer.get_data(), data, allocator);
    }

    pub fn get_ip(self: *ARecord) ?IPv4Address {
        const data = self.get_data();
        if (data.len >= 16) {
            var offset: usize = 0;

            _ = DNS.DNSLayer.decode_name(self.get_data(), &offset) catch {
                print("error decoding name.\n", .{});
                return null;
            };

            offset += 10; //  rrtype (2 bytes), class (2bytes), ttl (4bytes), data length (2bytes)

            const ip_u32: u32 = std.mem.bytesToValue(u32, data[offset .. offset + @sizeOf(u32)]);

            const ip = IPv4Address.init_from_u32(@byteSwap(ip_u32));
            return ip;
        }

        return null;
    }

    pub fn set_ip(self: *ARecord, ipv4: IPv4Address) void {
        const data = self.get_data_mut();
        if (data.len >= 16) {
            var offset: usize = 0;

            _ = DNS.DNSLayer.decode_name(self.get_data(), &offset) catch {
                print("error decoding name.\n", .{});
                return;
            };

            offset += 10; //  rrtype (2 bytes), class (2bytes), ttl (4bytes), data length (2bytes)

            const ip_ptr = std.mem.bytesAsValue(u32, data[offset .. offset + @sizeOf(u32)]);

            ip_ptr.* = @byteSwap(ipv4.to_u32());
        }
    }

    pub fn to_string(self: *ARecord, allocator: Allocator) Allocator.Error![]const u8 {
        var list: std.ArrayList(u8) = .empty;

        const name = try self.get_name(allocator);
        defer allocator.free(name);
        const type_s = @tagName(self.qtype);
        const class_s = @tagName(self.qclass);
        var ip: []const u8 = undefined;
        if (self.get_ip()) |ipv4| {
            ip = try ipv4.to_string(allocator);
        }
        defer allocator.free(ip);

        const space = " ";

        try list.appendSlice(allocator, name);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, type_s);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, class_s);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, ip);

        return try list.toOwnedSlice(allocator);
    }

    pub fn get_rr_type(self: ARecord) QueryType {
        _ = self;
        return QueryType.A;
    }
};

/// AAAA Record - IPv6 responses
pub const AAAARecord = struct {
    offset: usize,
    length: usize,
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
        _ = self;
        return QueryType.AAAA;
    }
};

/// NS (Name Server) Record
pub const NSRecord = struct {
    offset: usize,
    length: usize,
    qclass: DnsClass,
    layer: *DNSLayer,
    next_answer: ?*AnswerRecord = null,
    prev_answer: ?*AnswerRecord = null,

    pub fn get_data(self: *NSRecord) []const u8 {
        return self.layer.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_data_mut(self: *NSRecord) []u8 {
        return self.layer.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_name(self: *NSRecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        const data = self.get_data(); // the length of the name is not known so just take use the offset of this RR

        return try decode_name(self.layer.get_data(), data, allocator);
    }

    pub fn decode_ns_name(self: *NSRecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        // NS's rdata, offset 12 is used for name ptr (2bytes), rrtype (2 bytes), class (2bytes), ttl (4bytes), data length (2bytes)
        if (self.get_data().len < 12) {
            return DNSLayer.DNSParseError.RecordTooShort;
        }
        return try decode_name(self.layer.get_data(), self.get_data()[12..], allocator);
    }

    /// Takes a non-dns-label cname value and converts it to label format using a helper method and the allocator provided.
    /// The formatted cname value is copied over the current one with these cases:
    /// if the formatted cname value is of the same length as the current one, the DNSLayer buffer remains unchanged
    /// else if the new cname is shorter or longer, then the dns layers buffer is shortened or extended, respectively
    ///
    /// currently broken. don't use it.
    fn set_ns_name(self: *NSRecord, cname: []const u8, allocator: Allocator) Allocator.Error!void {
        // need to check if the cname being changed contains any sub label ptrs which proceeding records rely on
        // e.g. .net in a cname can be relied on proceeding records
        // in this case, find the next record that uses this ptr, edit the cname record to include that sub-label
        // and then update the proceeding records so that they use the ptr to the above
        const data = self.get_data_mut();
        const new_cname_wire = try encodeQnameSimple(allocator, cname);
        defer allocator.free(new_cname_wire);

        const current_rdata = data[12..];
        const old_len = current_rdata.len;
        const new_len = new_cname_wire.len;

        const cname_start = self.offset + 12;

        var ptr: [2]u8 = undefined; // generate compression ptr for this cname record being changed
        ptr[0] = 0xC0 | @as(u8, @truncate((cname_start >> 8) & 0x3F));
        ptr[1] = @as(u8, @truncate(cname_start & 0xFF));

        if (new_len > old_len) {
            const extend_len = new_len - old_len;
            const cname_offset = self.offset + 12;

            print("extend len: {}\n", .{extend_len});

            // Extend the payload
            _ = try self.layer.extend_layer(cname_offset, extend_len);

            // Update this record's length
            self.length += extend_len;

            // Update all subsequent records' offsets and lengths
            var next_record: ?*AnswerRecord = self.next_answer;
            while (next_record) |next| {
                next.set_offset(next.get_offset() + extend_len);
                next_record = next.get_next_record();
            }

            // Update ALL compression pointers in the packet
            self.update_proceeding_records(@intCast(extend_len));
            try self.update_rest_ptrs(ptr); // needs to be called now

            // Refresh data pointer and write new NS
            const new_data = self.get_data_mut();
            @memcpy(new_data[12..], new_cname_wire);
        } else if (new_len < old_len) {
            print("new cname len is less than current. current: {} new: {}\n", .{ old_len, new_len });
            const shrink_len: isize = @as(isize, @intCast(old_len)) - @as(isize, @intCast(new_len));
            print("shrink len: {}\n", .{shrink_len});
            const cname_offset = self.offset + 12;

            // Shrink the records RR
            _ = try self.layer.shorten_layer(cname_offset, @intCast(shrink_len));
            print("shortened.\n", .{});

            // Update this record's length
            self.length -= @intCast(shrink_len); // int cast required here because shrink_len is isize

            // Update subsequent records' offsets and lengths
            print("Update subsequent records' offsets and lengths:\n", .{});
            var next_record: ?*AnswerRecord = self.next_answer;
            while (next_record) |next| {
                const cur_offset = next.get_offset();
                print("cur record offset: {}\n", .{cur_offset});
                next.set_offset(cur_offset - @as(usize, @intCast(shrink_len)));
                print("cur record new offset: {}\n", .{next.get_offset()});
                next_record = next.get_next_record();
            }

            print("shrink len: {}\n", .{-shrink_len});

            // Update compression pointers
            self.update_proceeding_records(-shrink_len);
            print("proceeding records updated.\n", .{});
            try self.update_rest_ptrs(ptr); // needs to be called now
            print("rest of ptrs updated.\n", .{});

            // Write new NS
            const new_data = self.get_data_mut();
            @memcpy(new_data[12..], new_cname_wire);
        } else {
            // Same length, simple overwrite
            @memcpy(data[12..], new_cname_wire);
        }
    }

    pub fn to_string(self: *NSRecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]const u8 {
        var list: std.ArrayList(u8) = .empty;

        const name = try self.get_name(allocator);
        defer allocator.free(name);
        const type_s = @tagName(self.qtype);
        const class_s = @tagName(self.qclass);
        const cname = try self.decode_cname(allocator);
        defer allocator.free(cname);

        const space = " ";

        try list.appendSlice(allocator, name);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, type_s);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, class_s);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, cname);

        return try list.toOwnedSlice(allocator);
    }

    pub fn get_rr_type(self: NSRecord) QueryType {
        _ = self;
        return QueryType.NS;
    }
};

/// CNAME (Canonical Name) Record
pub const CNAMERecord = struct {
    offset: usize,
    length: usize,
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

    pub fn get_name(self: *CNAMERecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        const data = self.get_data(); // the length of the name is not known so just take use the offset of this RR

        return try decode_name(self.layer.get_data(), data, allocator);
    }

    pub fn decode_cname(self: *CNAMERecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        if (self.get_data().len < 12) {
            return DNSLayer.DNSParseError.RecordTooShort;
        }

        var offset: usize = 0;

        _ = try DNS.DNSLayer.decode_name(self.get_data(), &offset);

        offset += 10; //  rrtype (2 bytes), class (2bytes), ttl (4bytes), data length (2bytes)

        return try decode_name(self.layer.get_data(), self.get_data()[offset..], allocator);
    }

    pub fn to_string(self: *CNAMERecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]const u8 {
        var list: std.ArrayList(u8) = .empty;

        const name = try self.get_name(allocator);
        defer allocator.free(name);
        const type_s = @tagName(self.qtype);
        const class_s = @tagName(self.qclass);
        const cname = try self.decode_cname(allocator);
        defer allocator.free(cname);

        const space = " ";

        try list.appendSlice(allocator, name);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, type_s);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, class_s);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, cname);

        return try list.toOwnedSlice(allocator);
    }

    pub fn get_rr_type(self: CNAMERecord) QueryType {
        _ = self;
        return QueryType.CNAME;
    }
};

/// TXT Record
pub const TXTRecord = struct {
    offset: usize,
    length: usize,
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
    pub fn get_name(self: *TXTRecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        const data = self.get_data();
        return try decode_name(self.layer.get_data(), data, allocator);
    }

    pub fn get_rr_type(self: TXTRecord) QueryType {
        _ = self;
        return QueryType.TXT;
    }
};

/// MX Record
pub const MXRecord = struct {
    offset: usize,
    length: usize,
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

    pub fn get_mx_domain(self: *MXRecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]const u8 {
        const domain_start = self.get_data()[14..];
        return try decode_name(self.layer.get_data(), domain_start, allocator);
    }

    pub fn get_rr_type(self: MXRecord) QueryType {
        _ = self;
        return QueryType.MX;
    }
};

pub const PTRRecord = struct {
    offset: usize,
    length: usize,
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

    pub fn get_name(self: *PTRRecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        return try decode_name(self.layer.get_data(), self.get_data()[12..], allocator);
    }

    pub fn get_rr_type(self: PTRRecord) QueryType {
        _ = self;
        return QueryType.PTR;
    }
};

pub const SOARecord = struct {
    offset: usize,
    length: usize,
    qclass: DnsClass,
    layer: *DNSLayer,
    next_answer: ?*AnswerRecord = null,
    prev_answer: ?*AnswerRecord = null,

    pub fn get_data(self: *SOARecord) []const u8 {
        return self.layer.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_data_mut(self: *SOARecord) []u8 {
        return self.layer.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_name(self: *SOARecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        return try decode_name(self.layer.get_data(), self.get_data()[12..], allocator);
    }

    /// Primary Name Server
    pub fn get_mname(self: *SOARecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        var offset: usize = 0;

        _ = try DNS.DNSLayer.decode_name(self.get_data(), &offset);

        offset += 10; //  rrtype (2 bytes), class (2bytes), ttl (4bytes), data length (2bytes)

        if (self.get_data().len < offset) {
            return "";
        }

        return try decode_name(self.layer.get_data(), self.get_data()[offset..], allocator);
    }

    /// Responsible Authorities Mailbox
    pub fn get_rname(self: *SOARecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        var offset: usize = 0;

        _ = try DNS.DNSLayer.decode_name(self.get_data(), &offset);

        offset += 10; //  rrtype (2 bytes), class (2bytes), ttl (4bytes), data length (2bytes)

        _ = try DNS.DNSLayer.decode_name(self.get_data(), &offset);

        if (self.get_data().len < offset) {
            return ""; // return error instead
        }

        return try decode_name(self.layer.get_data(), self.get_data()[offset..], allocator);
    }

    pub fn get_serial(self: *SOARecord) u32 {
        const data = self.get_data();
        var offset: usize = 0;

        // advance offset past NAME
        advance_past_name(self.get_data(), &offset) catch {
            print("error decoding name.\n", .{});
            return 0;
        };

        // At this point, offset points to the byte AFTER the last label's null terminator
        // So we're now at the TYPE field

        // Skip TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)
        offset += 10;

        // adance offset past MNAME
        advance_past_name(self.get_data(), &offset) catch {
            print("error decoding mname.\n", .{});
            return 0;
        };

        // advance offset past RNAME
        advance_past_name(self.get_data(), &offset) catch {
            print("error decoding rname.\n", .{});
            print("bytes from current offset: {x}\n", .{data[offset..]});
            return 0;
        };

        if (self.get_data().len < offset + 4) {
            return 0;
        }

        const serial_be: u32 = std.mem.bytesToValue(u32, data[offset .. offset + @sizeOf(u32)]);
        return @byteSwap(serial_be);
    }

    pub fn get_refresh_interval(self: *SOARecord) u32 {
        const data = self.get_data();
        var offset: usize = 0;

        // advance offset past NAME
        advance_past_name(self.get_data(), &offset) catch {
            print("error decoding name.\n", .{});
            return 0;
        };

        // At this point, offset points to the byte AFTER the last label's null terminator
        // So we're now at the TYPE field

        // Skip TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)
        offset += 10;

        // adance offset past MNAME
        advance_past_name(self.get_data(), &offset) catch {
            print("error decoding mname.\n", .{});
            return 0;
        };

        // advance offset past RNAME
        advance_past_name(self.get_data(), &offset) catch {
            print("error decoding rname.\n", .{});
            print("bytes from current offset: {x}\n", .{data[offset..]});
            return 0;
        };

        // advance past serial
        offset += 4;

        if (self.get_data().len < offset + 4) {
            return 0;
        }

        const re_be: u32 = std.mem.bytesToValue(u32, data[offset .. offset + @sizeOf(u32)]);
        return @byteSwap(re_be);
    }

    pub fn get_retry_interval(self: *SOARecord) u32 {
        const data = self.get_data();
        var offset: usize = 0;

        // advance offset past NAME
        advance_past_name(self.get_data(), &offset) catch {
            print("error decoding name.\n", .{});
            return 0;
        };

        // At this point, offset points to the byte AFTER the last label's null terminator
        // So we're now at the TYPE field

        // Skip TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)
        offset += 10;

        // adance offset past MNAME
        advance_past_name(self.get_data(), &offset) catch {
            print("error decoding mname.\n", .{});
            return 0;
        };

        // advance offset past RNAME
        advance_past_name(self.get_data(), &offset) catch {
            print("error decoding rname.\n", .{});
            print("bytes from current offset: {x}\n", .{data[offset..]});
            return 0;
        };

        // advance past serial
        offset += 4;

        // advance past refresh interval
        offset += 4;

        if (self.get_data().len < offset + 4) {
            return 0;
        }

        const exp_limit: u32 = std.mem.bytesToValue(u32, data[offset .. offset + @sizeOf(u32)]);
        return @byteSwap(exp_limit);
    }

    pub fn get_expire_limit(self: *SOARecord) u32 {
        const data = self.get_data();
        var offset: usize = 0;

        // advance offset past NAME
        advance_past_name(self.get_data(), &offset) catch {
            print("error decoding name.\n", .{});
            return 0;
        };

        // At this point, offset points to the byte AFTER the last label's null terminator
        // So we're now at the TYPE field

        // Skip TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)
        offset += 10;

        // adance offset past MNAME
        advance_past_name(self.get_data(), &offset) catch {
            print("error decoding mname.\n", .{});
            return 0;
        };

        // advance offset past RNAME
        advance_past_name(self.get_data(), &offset) catch {
            print("error decoding rname.\n", .{});
            print("bytes from current offset: {x}\n", .{data[offset..]});
            return 0;
        };

        // advance past serial
        offset += 4;

        // advance past refresh interval
        offset += 4;

        // advance past retry interval
        offset += 4;

        if (self.get_data().len < offset + 4) {
            return 0;
        }

        const exp_limit: u32 = std.mem.bytesToValue(u32, data[offset .. offset + @sizeOf(u32)]);
        return @byteSwap(exp_limit);
    }

    pub fn get_minimum_ttl(self: *SOARecord) u32 {
        const data = self.get_data();
        var offset: usize = 0;

        // advance offset past NAME
        advance_past_name(self.get_data(), &offset) catch {
            print("error decoding name.\n", .{});
            return 0;
        };

        // At this point, offset points to the byte AFTER the last label's null terminator
        // So we're now at the TYPE field

        // Skip TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)
        offset += 10;

        // adance offset past MNAME
        advance_past_name(self.get_data(), &offset) catch {
            print("error decoding mname.\n", .{});
            return 0;
        };

        // advance offset past RNAME
        advance_past_name(self.get_data(), &offset) catch {
            print("error decoding rname.\n", .{});
            print("bytes from current offset: {x}\n", .{data[offset..]});
            return 0;
        };

        // advance past serial
        offset += 4;

        // advance past refresh interval
        offset += 4;

        // advance past retry interval
        offset += 4;

        // advance past expire limit
        offset += 4;

        if (self.get_data().len < offset + 4) {
            return 0;
        }

        const min_ttl: u32 = std.mem.bytesToValue(u32, data[offset .. offset + @sizeOf(u32)]);
        return @byteSwap(min_ttl);
    }

    pub fn get_rr_type(self: SOARecord) QueryType {
        _ = self;
        return QueryType.SOA;
    }
};

pub fn advance_past_name(slice: []const u8, offset: *usize) (DNSLayer.DNSParseError)!void {
    while (offset.* < slice.len) {
        const byte = slice[offset.*];
        if (byte == 0) {
            offset.* += 1;
            return;
        }
        if ((byte & 0xC0) == 0xC0) {
            offset.* += 2;
            return;
        }
        offset.* += 1 + byte; // Skip length byte and label
    }
    return error.InvalidPacket;
}

// MNAME - variable len

// RNAME - variable len

// SERIAL - 4 bytes / u32

// REFRESH INTERVAL - 4 bytes / u32

// RETRY INTERVAL - 4 bytes / u32

// EXPIRE LIMIT - 4 bytes / u32

// MIN TTL - 4 bytes / u32

pub fn decode_name(layer_data: []const u8, record_data: []const u8, allocator: Allocator) (DNS.DNSLayer.DNSParseError || Allocator.Error)![]u8 {
    const full_packet = layer_data; // get the entire dns layers data - this is required for pointer jumps
    const rdata = record_data;

    var list = try std.ArrayList(u8).initCapacity(allocator, full_packet.len);
    defer list.deinit(allocator);

    var offset: usize = 0;
    var first = true;

    while (offset < rdata.len and rdata[offset] != 0) {
        const label_len = rdata[offset];

        //print("label len: {}\n", .{label_len});

        // Check for compression pointer (first two bits are 11)
        // 0xC0 is compresssion ptr
        if ((label_len & 0xC0) == 0xC0) {
            if (offset + 1 >= rdata.len) return error.InvalidPacket;

            // Calculate absolute jump offset in the FULL packet
            const absolute_jump = (@as(u16, label_len & 0x3F) << 8) | @as(u16, rdata[offset + 1]);

            //std.debug.print("Pointer at rdata offset {} jumps to absolute packet offset {}\n", .{ offset, absolute_jump });

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
            //offset += 2;
            //continue;
            break;
        }

        // Regular label (not a pointer)
        offset += 1;

        if (offset + label_len > rdata.len) return error.LabelOOB;

        if (!first) try list.append(allocator, '.');
        first = false;

        try list.appendSlice(allocator, rdata[offset .. offset + label_len]);
        offset += label_len;
    }

    return list.toOwnedSlice(allocator);
}

fn decodeNameFromAbsolute(allocator: Allocator, full_packet: []const u8, start_offset: usize) (DNS.DNSLayer.DNSParseError || Allocator.Error)![]u8 {
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
            //offset += 2;
            //continue;
            break;
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

pub fn encodeQname(allocator: Allocator, domain: []const u8, compression_dict: ?std.StringHashMap(u16)) (DNS.DNSLayer.DNSParseError || Allocator.Error)![]u8 {
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
pub fn encodeQnameSimple(allocator: Allocator, domain: []const u8) (DNS.DNSLayer.DNSParseError || Allocator.Error)![]u8 {
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
pub fn buildCompressionDict(allocator: Allocator, domains: []const []const u8) (DNSLayer.DNSParseError || Allocator.Error)!std.StringHashMap(u16) {
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

//   fn update_proceeding_records(self: *CNAMERecord, delta: isize) void {
//       const pos = self.offset + 12;
//       const ptr0: [1]u8 = .{0xC0};
//
//       var cur = self.next_answer;
//       while (cur) |ans| {
//           var next_data = ans.get_data_mut();
//           var off: usize = 0;
//
//           while (off < next_data.len - 1) {
//               const ptr_in_ans = next_data[off .. off + 2];
//               if (ptr_in_ans[0] == ptr0[0]) {
//                   var pointer: u16 = (@as(u16, ptr_in_ans[0] & 0x3F) << 8) | @as(u16, ptr_in_ans[1]);
//                   print("original ptr: {}\n", .{pointer});
//
//                   if (pointer > pos) {
//                       // Convert to signed to handle negative delta, then back to unsigned
//                       const new_pointer = @as(i32, pointer) + delta;
//                       if (new_pointer < 0) {
//                           // Handle error case - pointer would become negative
//                           @panic("pointer would become negative");
//                       }
//                       pointer = @as(u16, @intCast(new_pointer));
//                       print("changed ptr: {}\n", .{pointer});
//
//                       ptr_in_ans[0] = @as(u8, 0xC0 | @as(u8, @truncate((pointer >> 8) & 0x3F)));
//                       ptr_in_ans[1] = @as(u8, @truncate(pointer & 0xFF));
//                   }
//               }
//               off += 2;
//           }
//           cur = ans.get_next_record();
//       }
//   }
//
//   fn update_rest_ptrs(self: *CNAMERecord, ignore: [2]u8) !void {
//       print("ignoring offset: {x}\n", .{ignore});
//       const end = self.offset + self.length;
//
//       var first: bool = true;
//       var new_ptr_loc: [2]u8 = undefined;
//       var difference: isize = 0;
//
//       var cur = self.next_answer;
//       while (cur) |ans| {
//           var answers_data: []u8 = undefined;
//
//           switch (ans.get_rr_type()) {
//               .A => {
//                   answers_data = ans.get_data_mut()[0..2];
//               },
//               .CNAME => {
//                   answers_data = ans.get_data_mut();
//               },
//               else => {
//                   cur = ans.get_next_record();
//                   continue;
//               },
//           }
//
//           const total_len = answers_data.len;
//           var i: usize = 0;
//
//           while (i < total_len - 1) {
//               if (answers_data[i] & 0xC0 == 0xC0) {
//                   const pointer: u16 = @as(u16, answers_data[i] & 0x3F) << 8 | @as(u16, answers_data[i + 1]);
//
//                   print("found ptr: {}.\n", .{pointer});
//
//                   if (pointer >= self.offset and pointer < end) {
//                       if (!(answers_data[i] == ignore[0] and answers_data[i + 1] == ignore[1])) {
//                           var ptr_begin = self.layer.get_data()[pointer..];
//
//                           // Find the end of the label
//                           var idx: usize = 0;
//                           var label_end: bool = false;
//                           var zero_count: usize = 0;
//                           while (!label_end) {
//                               if (ptr_begin[idx] == 0) {
//                                   zero_count += 1;
//                               }
//                               if (zero_count == 1) {
//                                   label_end = true;
//                               }
//                               idx += 1;
//                           }
//
//                           ptr_begin = ptr_begin[0..idx];
//                           const label_len: isize = @intCast(ptr_begin.len);
//
//                           if (first) {
//                               const extend_start = ans.get_offset() + i;
//                               const begin = self.layer.get_data()[extend_start .. extend_start + 2];
//                               difference = label_len - @as(isize, @intCast(begin.len));
//
//                               // Handle both positive and negative differences
//                               if (difference > 0) {
//                                   // Extend the payload
//                                   _ = try self.layer.extend_layer(extend_start, @as(usize, @intCast(difference)));
//                               } else if (difference < 0) {
//                                   // Shrink the payload
//                                   _ = try self.layer.shorten_layer(extend_start, @as(usize, @intCast(-difference)));
//                               }
//                               // difference == 0: no change needed
//
//                               // Copy the label
//                               const src = self.layer.get_data()[pointer .. pointer + idx];
//                               var tmp: [512]u8 = undefined;
//                               @memcpy(tmp[0..src.len], src);
//                               const label: []u8 = tmp[0..src.len];
//                               @memcpy(self.layer.get_data()[extend_start .. extend_start + label.len], label);
//
//                               // Update the pointer location
//                               new_ptr_loc[0] = 0xC0 | @as(u8, @truncate((extend_start >> 8) & 0x3F));
//                               new_ptr_loc[1] = @as(u8, @truncate(extend_start & 0xFF));
//
//                               // Update answer record length
//                               ans.set_length(ans.get_length() + @as(usize, @intCast(difference)));
//
//                               // Update subsequent record offsets
//                               print("Update subsequent record offsets:\n", .{});
//                               var next = ans.get_next_record();
//                               while (next) |next_record| {
//                                   const cur_offset = next_record.get_offset();
//                                   print("cur_offset: {}\n", .{cur_offset});
//                                   next_record.set_offset(cur_offset + @as(usize, @intCast(difference)));
//                                   print("new offset: {}\n", .{next_record.get_offset()});
//                                   next = next_record.get_next_record();
//                               }
//
//                               first = false;
//                           } else {
//                               // Replace pointer with new location
//                               answers_data[i] = new_ptr_loc[0];
//                               answers_data[i + 1] = new_ptr_loc[1];
//                           }
//                       }
//                   } else if (!first) {
//                       const new_ptr: u16 = (@as(u16, new_ptr_loc[0] & 0x3F) << 8) | @as(u16, new_ptr_loc[1]);
//                       if (pointer > new_ptr) {
//                           print("pointer {} greater than new_ptr.\n", .{pointer});
//                           // Use signed arithmetic for pointer adjustment
//                           const ext_pointer = @as(i32, pointer) + difference;
//                           if (ext_pointer < 0) {
//                               @panic("pointer would become negative");
//                           }
//                           print("ext_pointer: {}\n", .{ext_pointer});
//
//                           answers_data[i] = 0xC0 | @as(u8, @truncate((@as(u16, @intCast(ext_pointer)) >> 8) & 0x3F));
//                           answers_data[i + 1] = @as(u8, @truncate(@as(u16, @intCast(ext_pointer)) & 0xFF));
//                       } else {
//                           print("pointer {} not greater than new_ptr.\n", .{pointer});
//                       }
//                   }
//
//                   i += 2;
//                   continue;
//               }
//               i += 1;
//           }
//           cur = ans.get_next_record();
//       }
//   }
//
//   /// Takes a non-dns-label cname value and converts it to label format using a helper method and the allocator provided.
//   /// The formatted cname value is copied over the current one with these cases:
//   /// if the formatted cname value is of the same length as the current one, the DNSLayer buffer remains unchanged
//   /// else if the new cname is shorter or longer, then the dns layers buffer is shortened or extended, respectively
//   ///
//   /// currently broken. don't use it.
//   fn set_cname(self: *CNAMERecord, cname: []const u8, allocator: Allocator) !void {
//       // need to check if the cname being changed contains any sub label ptrs which proceeding records rely on
//       // e.g. .net in a cname can be relied on proceeding records
//       // in this case, find the next record that uses this ptr, edit the cname record to include that sub-label
//       // and then update the proceeding records so that they use the ptr to the above
//       const data = self.get_data_mut();
//       const new_cname_wire = try encodeQnameSimple(allocator, cname);
//       defer allocator.free(new_cname_wire);
//
//       const current_rdata = data[12..];
//       const old_len = current_rdata.len;
//       const new_len = new_cname_wire.len;
//
//       const cname_start = self.offset + 12;
//
//       var ptr: [2]u8 = undefined; // generate compression ptr for this cname record being changed
//       ptr[0] = 0xC0 | @as(u8, @truncate((cname_start >> 8) & 0x3F));
//       ptr[1] = @as(u8, @truncate(cname_start & 0xFF));
//
//       if (new_len > old_len) {
//           const extend_len = new_len - old_len;
//           const cname_offset = self.offset + 12;
//
//           print("extend len: {}\n", .{extend_len});
//
//           // Extend the payload
//           _ = try self.layer.extend_layer(cname_offset, extend_len);
//
//           // Update this record's length
//           self.length += extend_len;
//
//           // Update all subsequent records' offsets and lengths
//           var next_record: ?*AnswerRecord = self.next_answer;
//           while (next_record) |next| {
//               next.set_offset(next.get_offset() + extend_len);
//               next_record = next.get_next_record();
//           }
//
//           // Update ALL compression pointers in the packet
//           self.update_proceeding_records(@intCast(extend_len));
//           try self.update_rest_ptrs(ptr); // needs to be called now
//
//           // Refresh data pointer and write new CNAME
//           const new_data = self.get_data_mut();
//           @memcpy(new_data[12..], new_cname_wire);
//       } else if (new_len < old_len) {
//           print("new cname len is less than current. current: {} new: {}\n", .{ old_len, new_len });
//           const shrink_len: isize = @as(isize, @intCast(old_len)) - @as(isize, @intCast(new_len));
//           print("shrink len: {}\n", .{shrink_len});
//           const cname_offset = self.offset + 12;
//
//           // Shrink the records RR
//           _ = try self.layer.shorten_layer(cname_offset, @intCast(shrink_len));
//           print("shortened.\n", .{});
//
//           // Update this record's length
//           self.length -= @intCast(shrink_len); // int cast required here because shrink_len is isize
//
//           // Update subsequent records' offsets and lengths
//           print("Update subsequent records' offsets and lengths:\n", .{});
//           var next_record: ?*AnswerRecord = self.next_answer;
//           while (next_record) |next| {
//               const cur_offset = next.get_offset();
//               print("cur record offset: {}\n", .{cur_offset});
//               next.set_offset(cur_offset - @as(usize, @intCast(shrink_len)));
//               print("cur record new offset: {}\n", .{next.get_offset()});
//               next_record = next.get_next_record();
//           }
//
//           print("shrink len: {}\n", .{-shrink_len});
//
//           // Update compression pointers
//           self.update_proceeding_records(-shrink_len);
//           print("proceeding records updated.\n", .{});
//           try self.update_rest_ptrs(ptr); // needs to be called now
//           print("rest of ptrs updated.\n", .{});
//
//           // Write new CNAME
//           const new_data = self.get_data_mut();
//           @memcpy(new_data[12..], new_cname_wire);
//       } else {
//           // Same length, simple overwrite
//           @memcpy(data[12..], new_cname_wire);
//       }
//   }
