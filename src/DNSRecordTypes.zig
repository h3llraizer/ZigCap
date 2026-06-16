const std = @import("std");
const DNS = @import("DNS.zig");
const IPv4Address = @import("IPv4.zig").IPv4Address;
const IPv6Address = @import("IPv6.zig").IPv6Address;
const TLVOwner = @import("Owner.zig").TLVOwner;
const LayerError = @import("ProtocolEnums.zig").LayerError;

const print = std.debug.print;
const Allocator = std.mem.Allocator;
const QueryType = DNS.QueryType;
const DnsClass = DNS.DnsClass;
const DNSLayer = DNS.DNSLayer;

pub const Query = DNS.Query;
pub const Queries = DNS.Queries;

const advance_past_name = DNSLayer.advance_past_name;

pub const QUERY_TYPE_LENGTH = DNS.QUERY_TYPE_LENGTH;
pub const CLASS_TYPE_LENGTH = DNS.CLASS_TYPE_LENGTH;
pub const TTL_LENGTH = DNS.TTL_LENGTH;
pub const RD_LENGTH = DNS.RD_LENGTH;

const TXT_LENGTH = @sizeOf(u8);
const MX_PREFERENCE_VALUE_LENGTH = @sizeOf(u16);

/// This tagged union is an interface over the concrete Answer Record Types.
/// currently implemented record types are:
///     A,
///     AAAA,
///     CNAME,
///     TXT,
///     MX,
///     PTR,
///     NS,
///     SOA,
///     Generic,
pub const AnswerRecord = union(enum) {
    a: ARecord,
    aaaa: AAAARecord,
    cname: CNAMERecord,
    txt: TXTRecord,
    mx: MXRecord,
    ptr: PTRRecord,
    ns: NSRecord,
    soa: SOARecord,
    generic: GenericRecord,

    pub fn init(offset: usize, length: usize, qtype: QueryType, qclass: DnsClass, owner: TLVOwner) AnswerRecord {
        switch (qtype) {
            // TODO: reduce repeating code
            .A => {
                return .{ .a = .{
                    .offset = offset,
                    .length = length,
                    .qclass = qclass,
                    .owner = owner,
                } };
            },

            .AAAA => {
                return .{ .aaaa = .{
                    .offset = offset,
                    .length = length,
                    .qclass = qclass,
                    .owner = owner,
                } };
            },

            .CNAME => {
                return .{ .cname = .{
                    .offset = offset,
                    .length = length,
                    .qclass = qclass,
                    .owner = owner,
                } };
            },

            .TXT => {
                return .{ .txt = .{
                    .offset = offset,
                    .length = length,
                    .qclass = qclass,
                    .owner = owner,
                } };
            },

            .MX => {
                return .{ .mx = .{
                    .offset = offset,
                    .length = length,
                    .qclass = qclass,
                    .owner = owner,
                } };
            },

            .PTR => {
                return .{ .ptr = .{
                    .offset = offset,
                    .length = length,
                    .qclass = qclass,
                    .owner = owner,
                } };
            },

            .NS => {
                return .{ .ns = .{
                    .offset = offset,
                    .length = length,
                    .qclass = qclass,
                    .owner = owner,
                } };
            },

            .SOA => {
                return .{ .soa = .{
                    .offset = offset,
                    .length = length,
                    .qclass = qclass,
                    .owner = owner,
                } };
            },

            .GENERIC => {
                return .{ .generic = .{
                    .offset = offset,
                    .length = length,
                    .qtype = qtype,
                    .qclass = qclass,
                    .owner = owner,
                } };
            },

            else => return .{ .generic = .{
                .offset = offset,
                .length = length,
                .qtype = qtype,
                .qclass = qclass,
                .owner = owner,
            } },
        }
    }

    // experimental
    fn change_rec_type(self: *AnswerRecord, qtype: QueryType, qclass: QueryType) void {
        self.* = AnswerRecord.init(
            self.get_offset(),
            self.get_length(),
            qtype,
            qclass,
            self.get_owner().*,
        );
    }

    pub fn get_name(self: *AnswerRecord, allocator: Allocator) ![]u8 {
        const data = self.get_data();
        // the length of the name is not known so just take use the offset of this RR
        const owner = self.get_owner();
        return try decode_name(owner.get_data(), data, allocator);
    }

    pub fn get_name_raw(self: *AnswerRecord) []const u8 {
        const data = self.get_data();

        var offset: usize = 0;

        advance_past_name(data, &offset);

        return data[0..offset];
    }

    pub fn get_owner(self: *AnswerRecord) *TLVOwner {
        return switch (self.*) {
            inline else => |*rr| &rr.owner,
        };
    }

    pub fn get_offset(self: *AnswerRecord) usize {
        return switch (self.*) {
            inline else => |*rr| rr.offset,
        };
    }

    pub fn get_length(self: *AnswerRecord) usize {
        return switch (self.*) {
            inline else => |*rr| rr.length,
        };
    }

    pub fn set_offset(self: *AnswerRecord, offset: usize) void {
        return switch (self.*) {
            inline else => |*rr| rr.offset = offset,
        };
    }

    pub fn set_length(self: *AnswerRecord, length: usize) void {
        return switch (self.*) {
            inline else => |*rr| rr.length = length,
        };
    }

    pub fn get_data(self: *AnswerRecord) []const u8 {
        return switch (self.*) {
            inline else => |*rr| rr.get_data(),
        };
    }

    pub fn get_data_mut(self: *AnswerRecord) []u8 {
        return switch (self.*) {
            inline else => |*rr| rr.get_data_mut(),
        };
    }

    pub fn set_next_record(self: *AnswerRecord, next: *AnswerRecord) void {
        return switch (self.*) {
            inline else => |*rr| rr.next_answer = next,
        };
    }

    pub fn set_prev_record(self: *AnswerRecord, prev: *AnswerRecord) void {
        return switch (self.*) {
            inline else => |*rr| rr.prev_answer = prev,
        };
    }

    pub fn get_next_record(self: *AnswerRecord) ?*AnswerRecord {
        return switch (self.*) {
            inline else => |*rr| rr.next_answer,
        };
    }

    pub fn get_prev_record(self: *AnswerRecord) ?*AnswerRecord {
        return switch (self.*) {
            inline else => |*rr| rr.prev_answer,
        };
    }

    pub fn get_ttl(self: *AnswerRecord) u32 {
        const data = self.get_data();

        var offset: usize = 0;

        advance_past_name(self.get_data(), &offset);

        offset += QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH; //  rrtype (2 bytes), class (2bytes)

        const ttl: u32 = std.mem.bytesToValue(u32, data[offset .. offset + TTL_LENGTH]);

        return @byteSwap(ttl);
    }

    pub fn set_ttl(self: *AnswerRecord, ttl: u32) void {
        const data = self.get_data_mut();

        var offset: usize = 0;

        advance_past_name(self.get_data(), &offset);

        offset += QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH; //  rrtype (2 bytes), class (2bytes)

        const ttl_ptr = std.mem.bytesAsValue(u32, data[offset .. offset + TTL_LENGTH]);

        ttl_ptr.* = @byteSwap(ttl);
    }

    pub fn get_rr_type(self: *AnswerRecord) QueryType {
        return get_q_type(self.get_data());
    }

    pub fn get_class_type(self: *AnswerRecord) DnsClass {
        return get_dns_class(self.get_data());
    }
};

/// A doubly linked list containing RR-Records
pub const AnswerRecords = struct {
    owner: TLVOwner,
    first: ?*AnswerRecord = null,
    last: ?*AnswerRecord = null,
    answer_count: usize = 0,

    /// Do not use
    pub fn add_answer( // TODO: add compress bool arg - use compression ptr for name or rdata
        self: *AnswerRecords,
        qname_record: ?*Query,
        answer_record: *AnswerRecord,
        allocator: Allocator,
    ) (LayerError || Allocator.Error)!void {
        _ = qname_record;

        const extend_len = answer_record.get_data().len;

        var extend_offset = if (self.owner.is_layer_owned()) DNS.DNSHeaderSize else 0; // need to find offset of last ans instead

        var cur: ?*AnswerRecord = self.first;
        var last: ?*AnswerRecord = null;

        while (cur) |a| {
            if (a.get_next_record() == null) {
                extend_offset = a.get_offset() + a.get_length();
                last = a;
                break;
            } else {
                last = a.get_next_record();
            }

            cur = a.get_next_record();
        }

        const answer_buf = try self.owner.extend_buffer(extend_offset, extend_len);

        @memmove(answer_buf, answer_record.get_data());

        const added_answer = try allocator.create(AnswerRecord);

        added_answer.* = AnswerRecord.init(
            extend_offset,
            extend_len,
            answer_record.get_rr_type(),
            answer_record.get_class_type(),
            self.owner,
        );

        if (last) |last_answer| {
            last_answer.next_answer = added_answer;
            added_answer.prev_answer = last_answer;
        } else {
            self.first = added_answer;
        }

        self.answer_count += 1;

        if (self.owner.is_layer_owned()) {
            var hdr: *DNS.DNSHeader = @ptrCast(self.owner.get_data()[0..DNS.DNSHeaderSize]);
            var ancount = hdr.get_ancount();

            ancount += 1;
            hdr.set_ancount(ancount);
        }
    }

    /// Do not use
    pub fn remove_answer(self: *AnswerRecords, answer: *AnswerRecord, allocator: Allocator) !void {
        var cur: ?*AnswerRecord = if (self.first != null) self.first else return error.AnswerRecordListEmpty;

        while (cur) |a| {
            if (a == answer) {
                const shorten_offset = answer.offset;

                try self.owner.shorten_buffer(shorten_offset, answer.length);

                var next_answer = answer.get_next_record();
                while (next_answer) |next| {
                    next.offset -= answer.get_length();
                    next_answer = next.get_next_record();
                }

                self.answer_count -= 1;

                if (self.owner.is_layer_owned()) {
                    const hdr: *DNS.DNSHeader = @ptrCast(self.owner.get_data()[0..DNS.DNSHeaderSize]);
                    var ancount = hdr.get_ancount();
                    ancount -= 1;
                    hdr.set_ancount(ancount);
                }

                // Update the list pointers BEFORE destroying
                // Update first pointer if necessary
                if (self.first == a) {
                    self.first = a.get_next_record();
                }

                if (a.get_next_record()) |next| {
                    next.set_prev_record(a.get_prev_record());
                }

                if (a.get_prev_record()) |prev| {
                    prev.set_next_record(a.get_next_record());
                }

                allocator.destroy(answer);
                return;
            }
            cur = a.get_next_record();
        }

        return error.AnswerRecordNotFound;
    }

    pub fn deinit(self: *AnswerRecords, allocator: Allocator) void {
        var cur = self.last;

        while (cur) |ansrec| {
            if (!ansrec.get_owner().is_layer_owned()) {
                ansrec.get_owner().deinit();
            }

            cur = ansrec.get_prev_record();
        }

        cur = self.last;

        while (cur) |ansrec| {
            const prev = ansrec.get_prev_record();
            allocator.destroy(ansrec);
            cur = prev;
        }

        self.first = null;
        self.last = null;
        self.answer_count = 0;
    }
};

// Answer Records
// Answer RR(s):
// NAME
// TYPE
// CLASS
// TTL
// RDLENGTH
// RDATA

fn get_dns_class(data: []const u8) DnsClass {
    var offset: usize = 0;

    advance_past_name(data, &offset);

    offset += QUERY_TYPE_LENGTH;

    return @enumFromInt(std.mem.readInt(u16, @ptrCast(data[offset .. offset + RD_LENGTH].ptr), .big));
}

fn set_dns_class(data: []u8, class: DnsClass) void {
    var offset: usize = 0;

    advance_past_name(data, &offset);

    offset += QUERY_TYPE_LENGTH;

    return std.mem.writeInt(u16, @ptrCast(data[offset .. offset + RD_LENGTH].ptr), @intFromEnum(class), .big);
}

fn get_q_type(data: []const u8) QueryType {
    var offset: usize = 0;

    advance_past_name(data, &offset);

    return @enumFromInt(std.mem.readInt(u16, @ptrCast(data[offset .. offset + RD_LENGTH].ptr), .big));
}

fn set_q_type(data: []u8, qtype: QueryType) void {
    var offset: usize = 0;

    advance_past_name(data, &offset);

    return std.mem.writeInt(u16, @ptrCast(data[offset .. offset + RD_LENGTH].ptr), @intFromEnum(qtype), .big);
}

fn init_buffer(owner: *TLVOwner, qtype: QueryType, class: DnsClass) !void {
    if (owner.get_data().len < (@sizeOf(u8) * 2 + QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH + TTL_LENGTH)) {
        const buf = try owner.extend_buffer();

        std.mem.writeInt(u16, buf[2..4], @intFromEnum(qtype), .big);
        std.mem.writeInt(u16, buf[4..6], @intFromEnum(class), .big);

        std.mem.writeInt(u16, buf[6..10], 64, .big);
    }
}

pub const GenericRecord = struct {
    offset: usize,
    length: usize,
    qtype: QueryType,
    qclass: DnsClass,
    owner: TLVOwner,
    next_answer: ?*AnswerRecord = null,
    prev_answer: ?*AnswerRecord = null,

    /// init a new generic record.
    /// Name provided must be an encoded name (use DNS.encode_name method).
    /// qtype and class are set to value 0 (not valid)
    /// allocated name length + 12 bytes (qtype, qclass, ttl, rd len, 2 byte rdata)
    pub fn init(name: []const u8, allocator: Allocator) Allocator.Error!GenericRecord {
        const initial_len = (name.len + QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH + TTL_LENGTH + RD_LENGTH + (@sizeOf(u8) * 2));

        var rec = GenericRecord{
            .offset = 0,
            .length = initial_len,
            .qtype = @enumFromInt(0),
            .qclass = @enumFromInt(0),
            .owner = TLVOwner{ .owned_buffer = .init_empty(allocator) },
        };

        _ = try rec.owner.extend_buffer(0, initial_len);

        @memmove(rec.owner.get_data()[0..name.len], name);

        return rec;
    }

    pub fn get_data(self: *GenericRecord) []const u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_data_mut(self: *GenericRecord) []u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_name(self: *GenericRecord, allocator: Allocator) ![]u8 {
        const data = self.get_data();
        // the length of the name is not known so just take use the offset of this RR

        return try decode_name(data, data, allocator);
    }

    pub fn set_name(self: *GenericRecord, qname: []const u8) Allocator.Error!void {
        const data = self.get_data();

        var offset: usize = 0;

        advance_past_name(data, &offset);

        const cur_name_len = offset;

        if (cur_name_len < qname.len) {
            const diff = qname.len - cur_name_len;
            _ = try self.owner.extend_buffer(cur_name_len, diff);
        }

        if (cur_name_len > qname.len) {
            const diff = cur_name_len - qname.len;

            try self.owner.shorten_buffer(cur_name_len, diff);
        }

        @memmove(self.get_data_mut()[0..qname.len], qname);
    }

    pub fn set_rr_type(self: *GenericRecord, qtype: QueryType) void {
        const data = self.get_data_mut();
        var offset: usize = 0;

        advance_past_name(data, &offset);

        std.mem.writeInt(
            u16,
            @ptrCast(data[offset .. offset + QUERY_TYPE_LENGTH].ptr),
            @intFromEnum(qtype),
            .big,
        );
    }

    pub fn get_rr_type(self: *GenericRecord) QueryType {
        return get_q_type(self.get_data());
    }

    pub fn set_class(self: *GenericRecord, qclass: DnsClass) void {
        const data = self.get_data_mut();

        var offset: usize = 0;

        advance_past_name(data, &offset);

        offset += QUERY_TYPE_LENGTH;

        std.mem.writeInt(
            u16,
            @ptrCast(data[offset .. offset + CLASS_TYPE_LENGTH].ptr),
            @intFromEnum(qclass),
            .big,
        );
    }

    pub fn get_class(self: *GenericRecord) DnsClass {
        return get_dns_class(self.get_data());
    }

    pub fn set_ttl(self: *GenericRecord, ttl: u32) void {
        const data = self.get_data_mut();

        var offset: usize = 0;

        advance_past_name(data, &offset);

        offset += QUERY_TYPE_LENGTH;
        offset += CLASS_TYPE_LENGTH;

        std.mem.writeInt(
            u32,
            @ptrCast(data[offset .. offset + TTL_LENGTH].ptr),
            ttl,
            .big,
        );
    }

    pub fn get_ttl(self: *GenericRecord) u32 {
        const data = self.get_data();

        var offset: usize = 0;

        advance_past_name(data, &offset);

        offset += QUERY_TYPE_LENGTH;
        offset += CLASS_TYPE_LENGTH;

        return std.mem.readInt(
            u32,
            @ptrCast(data[offset .. offset + TTL_LENGTH].ptr),
            .big,
        );
    }

    pub fn get_rd_len(self: *GenericRecord) u16 {
        const data = self.get_data();

        var offset: usize = 0;

        advance_past_name(data, &offset);

        offset += QUERY_TYPE_LENGTH;
        offset += CLASS_TYPE_LENGTH;
        offset += TTL_LENGTH;

        return std.mem.readInt(
            u16,
            @ptrCast(data[offset .. offset + RD_LENGTH].ptr),
            .big,
        );
    }

    pub fn set_rdata(self: *GenericRecord, rdata: []const u8) Allocator.Error!void {
        const data = self.get_data();

        var offset: usize = 0;

        advance_past_name(data, &offset);

        offset += QUERY_TYPE_LENGTH;
        offset += CLASS_TYPE_LENGTH;
        offset += TTL_LENGTH;

        const rd_offset = offset;

        offset += RD_LENGTH;

        const cur_rdata_len: usize = data.len - offset;

        if (cur_rdata_len < rdata.len) {
            const diff = rdata.len - cur_rdata_len;
            const slice = try self.owner.extend_buffer(offset, diff);
            self.length += slice.len;

            var next_rec = self.next_answer;
            while (next_rec) |rr| {
                rr.set_offset(rr.get_offset() + diff);
                next_rec = rr.get_next_record();
            }
        }
        if (cur_rdata_len > rdata.len) {
            const diff = cur_rdata_len - rdata.len;

            try self.owner.shorten_buffer(offset + rdata.len, diff);

            self.length -= diff;

            var next_rec = self.next_answer;
            while (next_rec) |rr| {
                rr.set_offset(rr.get_offset() - diff);
                next_rec = rr.get_next_record();
            }
        }

        @memmove(self.get_data_mut()[offset..], rdata);

        std.mem.writeInt(
            u16,
            @ptrCast(self.get_data_mut()[rd_offset .. rd_offset + RD_LENGTH].ptr),
            @intCast(rdata.len),
            .big,
        );
    }

    pub fn get_rdata(self: *GenericRecord) []const u8 {
        const data = self.get_data();

        var offset: usize = 0;

        advance_past_name(data, &offset);

        offset += QUERY_TYPE_LENGTH;
        offset += CLASS_TYPE_LENGTH;
        offset += TTL_LENGTH;
        offset += RD_LENGTH;

        return data[offset..self.length];
    }

    pub fn deinit(self: *GenericRecord) void {
        self.owner.deinit();
    }
};

/// A Record - IPv4 Responses
pub const ARecord = struct {
    offset: usize,
    length: usize,
    qclass: DnsClass,
    owner: TLVOwner,
    next_answer: ?*AnswerRecord = null,
    prev_answer: ?*AnswerRecord = null,

    pub fn get_data(self: *ARecord) []const u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_data_mut(self: *ARecord) []u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_name(self: *ARecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        const data = self.get_data(); // the length of the name is not known so just take use the offset of this RR

        return try decode_name(self.owner.get_data(), data, allocator);
    }

    pub fn get_class(self: *ARecord) DnsClass {
        return get_dns_class(self.get_data());
    }

    pub fn set_class(self: *ARecord, class: DnsClass) void {
        return set_dns_class(self.get_data_mut(), class);
    }

    pub fn get_ip(self: *ARecord) ?IPv4Address {
        const data = self.get_data();
        if (data.len >= 16) {
            var offset: usize = 0;

            advance_past_name(self.get_data(), &offset);

            //         rrtype (2 bytes),   class (2bytes),    ttl (4bytes), data length (2bytes)
            offset += (QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH + TTL_LENGTH + RD_LENGTH);

            const ip_u32: u32 = std.mem.bytesToValue(u32, data[offset .. offset + TTL_LENGTH]);

            const ip = IPv4Address.init_from_u32(@byteSwap(ip_u32));
            return ip;
        }

        return null;
    }

    pub fn set_ip(self: *ARecord, ipv4: IPv4Address) void {
        const data = self.get_data_mut();
        if (data.len >= 16) {
            var offset: usize = 0;

            advance_past_name(self.get_data(), &offset);

            //         rrtype (2 bytes),   class (2bytes),     ttl (4bytes), data length (2bytes)
            offset += (QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH + TTL_LENGTH + RD_LENGTH);

            const ip_ptr = std.mem.bytesAsValue(u32, data[offset .. offset + TTL_LENGTH]);

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
        return get_q_type(self.get_data());
    }
};

/// AAAA Record - IPv6 responses
pub const AAAARecord = struct {
    offset: usize,
    length: usize,
    qclass: DnsClass,
    owner: TLVOwner,
    next_answer: ?*AnswerRecord = null,
    prev_answer: ?*AnswerRecord = null,

    pub fn get_data(self: *AAAARecord) []const u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_data_mut(self: *AAAARecord) []u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    /// returns the IPv6 address of the AAAA record by creating a copy of the IPv6 start to len bytes and init'ing the IPv6 address from it.
    /// null is retured when length of the RR data (in the DNS Layer) is not atleast 28 bytes in length
    pub fn get_ipv6(self: *AAAARecord) ?IPv6Address {
        const data = self.get_data();
        if (data.len >= 28) {
            var offset: usize = 0;

            advance_past_name(data, &offset);

            offset += (QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH + TTL_LENGTH + RD_LENGTH);

            var ipv6_arr: [16]u8 = undefined;
            @memmove(ipv6_arr[0..], data[offset .. offset + @sizeOf(IPv6Address)]);

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
            var offset: usize = 0;

            advance_past_name(data, &offset);

            offset += (QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH + TTL_LENGTH + RD_LENGTH);

            var ipv6_arr: [16]u8 = ipv6.array;
            @memmove(data[offset .. offset + @sizeOf(IPv6Address)], ipv6_arr[0..]);
        }
    }

    pub fn get_rr_type(self: AAAARecord) QueryType {
        return get_q_type(self.get_data());
    }
};

/// NS (Name Server) Record
pub const NSRecord = struct { //TODO: remove magic numbers
    offset: usize,
    length: usize,
    qclass: DnsClass,
    owner: TLVOwner,
    next_answer: ?*AnswerRecord = null,
    prev_answer: ?*AnswerRecord = null,

    pub fn get_data(self: *NSRecord) []const u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_data_mut(self: *NSRecord) []u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_name(self: *NSRecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        const data = self.get_data(); // the length of the name is not known so just take use the offset of this RR

        return try decode_name(self.owner.get_data(), data, allocator);
    }

    pub fn decode_ns_name(self: *NSRecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        // NS's rdata, offset 12 is used for name ptr (2bytes), rrtype (2 bytes), class (2bytes), ttl (4bytes), data length (2bytes)
        if (self.get_data().len < 12) {
            return DNSLayer.DNSParseError.RecordTooShort;
        }
        return try decode_name(self.owner.get_data(), self.get_data()[12..], allocator);
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

        var offset: usize = 0;

        advance_past_name(data, &offset);

        offset += (QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH + TTL_LENGTH + RD_LENGTH);

        const current_rdata = data[offset..];
        const old_len = current_rdata.len;
        const new_len = new_cname_wire.len;

        const cname_start = self.offset + offset;

        var ptr: [2]u8 = undefined; // generate compression ptr for this cname record being changed
        ptr[0] = 0xC0 | @as(u8, @truncate((cname_start >> 8) & 0x3F));
        ptr[1] = @as(u8, @truncate(cname_start & 0xFF));

        if (new_len > old_len) {
            const extend_len = new_len - old_len;
            const cname_offset = self.offset + offset;

            //print("extend len: {}\n", .{extend_len});

            // Extend the payload
            _ = try self.owner.extend_layer(cname_offset, extend_len);

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
            @memcpy(new_data[offset..], new_cname_wire);
        } else if (new_len < old_len) {
            //print("new cname len is less than current. current: {} new: {}\n", .{ old_len, new_len });
            const shrink_len: isize = @as(isize, @intCast(old_len)) - @as(isize, @intCast(new_len));
            //print("shrink len: {}\n", .{shrink_len});
            const cname_offset = self.offset + offset; // remove temp magic number

            // Shrink the records RR
            try self.owner.shorten_layer(cname_offset, @intCast(shrink_len));
            //print("shortened.\n", .{});

            // Update this record's length
            self.length -= @intCast(shrink_len); // int cast required here because shrink_len is isize

            // Update subsequent records' offsets and lengths
            //print("Update subsequent records' offsets and lengths:\n", .{});
            var next_record: ?*AnswerRecord = self.next_answer;
            while (next_record) |next| {
                const cur_offset = next.get_offset();
                //print("cur record offset: {}\n", .{cur_offset});
                next.set_offset(cur_offset - @as(usize, @intCast(shrink_len)));
                //print("cur record new offset: {}\n", .{next.get_offset()});
                next_record = next.get_next_record();
            }

            //print("shrink len: {}\n", .{-shrink_len});

            // Update compression pointers
            self.update_proceeding_records(-shrink_len);
            //print("proceeding records updated.\n", .{});
            try self.update_rest_ptrs(ptr); // needs to be called now
            //print("rest of ptrs updated.\n", .{});

            // Write new NS
            const new_data = self.get_data_mut();
            @memcpy(new_data[offset..], new_cname_wire); // remove temp magic number
        } else {
            // Same length, simple overwrite
            @memcpy(data[offset..], new_cname_wire); // remove temp magic number
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
        return get_q_type(self.get_data());
    }
};

/// CNAME (Canonical Name) Record
pub const CNAMERecord = struct {
    offset: usize,
    length: usize,
    qclass: DnsClass,
    owner: TLVOwner,
    next_answer: ?*AnswerRecord = null,
    prev_answer: ?*AnswerRecord = null,

    pub fn get_data(self: *CNAMERecord) []const u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_data_mut(self: *CNAMERecord) []u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_name(self: *CNAMERecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        const data = self.get_data(); // the length of the name is not known so just take use the offset of this RR

        return try decode_name(self.owner.get_data(), data, allocator);
    }

    pub fn decode_cname(self: *CNAMERecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        if (self.get_data().len < 12) { // TODO: remove temp magic number
            return DNSLayer.DNSParseError.RecordTooShort;
        }

        var offset: usize = 0;

        advance_past_name(self.get_data(), &offset);

        //  rrtype (2 bytes), class (2bytes), ttl (4bytes), data length (2bytes)
        offset += (QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH + TTL_LENGTH + RD_LENGTH);

        return try decode_name(self.owner.get_data(), self.get_data()[offset..], allocator);
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
        return get_q_type(self.get_data());
    }
};

/// TXT Record
pub const TXTRecord = struct {
    offset: usize,
    length: usize,
    qclass: DnsClass,
    owner: TLVOwner,
    next_answer: ?*AnswerRecord = null,
    prev_answer: ?*AnswerRecord = null,

    pub fn get_data(self: *TXTRecord) []const u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_data_mut(self: *TXTRecord) []u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    /// retrieves the name stated in the RR.
    pub fn get_name(self: *TXTRecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        const data = self.get_data();
        return try decode_name(self.owner.get_data(), data, allocator);
    }

    /// gets the records data from offset 13 and returns the slice which is the TXT string itself.
    /// no conversion needed because it's already a string
    /// to get the domain part, use get_name
    pub fn get_record_str(self: *TXTRecord) []const u8 {
        const data = self.get_data();

        var offset: usize = 0;

        advance_past_name(data, &offset);

        offset += (QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH + TTL_LENGTH + RD_LENGTH + TXT_LENGTH);

        return self.get_data()[offset..];
    }

    pub fn get_rr_type(self: TXTRecord) QueryType {
        return get_q_type(self.get_data());
    }
};

/// MX Record
pub const MXRecord = struct {
    offset: usize,
    length: usize,
    qclass: DnsClass,
    owner: TLVOwner,
    next_answer: ?*AnswerRecord = null,
    prev_answer: ?*AnswerRecord = null,

    pub fn get_data(self: *MXRecord) []const u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_data_mut(self: *MXRecord) []u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_mx_domain(self: *MXRecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]const u8 {
        var offset: usize = 0;

        const data = self.get_data();

        advance_past_name(data, &offset);

        offset += (QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH + TTL_LENGTH + RD_LENGTH + MX_PREFERENCE_VALUE_LENGTH);

        const domain_start = self.get_data()[offset..];

        return try decode_name(self.owner.get_data(), domain_start, allocator);
    }

    pub fn get_rr_type(self: MXRecord) QueryType {
        return get_q_type(self.get_data());
    }
};

pub const PTRRecord = struct {
    offset: usize,
    length: usize,
    qclass: DnsClass,
    owner: TLVOwner,
    next_answer: ?*AnswerRecord = null,
    prev_answer: ?*AnswerRecord = null,

    pub fn get_data(self: *PTRRecord) []const u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_data_mut(self: *PTRRecord) []u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_name(self: *PTRRecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        return try decode_name(self.owner.get_data(), self.get_data()[12..], allocator);
    }

    pub fn get_rr_type(self: PTRRecord) QueryType {
        return get_q_type(self.get_data());
    }
};

pub const SOARecord = struct {
    offset: usize,
    length: usize,
    qclass: DnsClass,
    owner: TLVOwner,
    next_answer: ?*AnswerRecord = null,
    prev_answer: ?*AnswerRecord = null,

    pub fn get_data(self: *SOARecord) []const u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_data_mut(self: *SOARecord) []u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_name(self: *SOARecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        return try decode_name(self.owner.get_data(), self.get_data()[0..], allocator);
    }

    /// Primary Name Server
    pub fn get_mname(self: *SOARecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        var offset: usize = 0;

        advance_past_name(self.get_data(), &offset);

        offset += (QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH + TTL_LENGTH + RD_LENGTH);

        if (self.get_data().len < offset) {
            return "";
        }

        return try decode_name(self.owner.get_data(), self.get_data()[offset..], allocator);
    }

    /// Responsible Authorities Mailbox
    pub fn get_rname(self: *SOARecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        var offset: usize = 0;

        advance_past_name(self.get_data(), &offset);

        offset += (QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH + TTL_LENGTH + RD_LENGTH);

        advance_past_name(self.get_data(), &offset);

        if (self.get_data().len < offset) {
            return ""; // return error instead
        }

        return try decode_name(self.owner.get_data(), self.get_data()[offset..], allocator);
    }

    pub fn get_serial(self: *SOARecord) u32 {
        const data = self.get_data();
        var offset: usize = 0;

        // advance offset past NAME
        advance_past_name(self.get_data(), &offset);

        // At this point, offset points to the byte AFTER the last label's null terminator
        // So we're now at the TYPE field

        // Skip TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)

        offset += (QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH + TTL_LENGTH + RD_LENGTH);

        // adance offset past MNAME
        advance_past_name(self.get_data(), &offset);

        // advance offset past RNAME
        advance_past_name(self.get_data(), &offset);

        if (self.get_data().len < offset + TTL_LENGTH) {
            return 0;
        }

        const serial_be: u32 = std.mem.bytesToValue(u32, data[offset .. offset + TTL_LENGTH]);
        return @byteSwap(serial_be);
    }

    pub fn get_refresh_interval(self: *SOARecord) u32 {
        const data = self.get_data();
        var offset: usize = 0;

        // advance offset past NAME
        advance_past_name(self.get_data(), &offset);

        // At this point, offset points to the byte AFTER the last label's null terminator
        // So we're now at the TYPE field

        // Skip TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)

        offset += (QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH + TTL_LENGTH + RD_LENGTH);

        // adance offset past MNAME
        advance_past_name(self.get_data(), &offset);
        // advance offset past RNAME
        advance_past_name(self.get_data(), &offset);

        // advance past serial
        offset += TTL_LENGTH;

        if (self.get_data().len < offset + TTL_LENGTH) {
            return 0;
        }

        const re_be: u32 = std.mem.bytesToValue(u32, data[offset .. offset + TTL_LENGTH]);
        return @byteSwap(re_be);
    }

    pub fn get_retry_interval(self: *SOARecord) u32 {
        const data = self.get_data();
        var offset: usize = 0;

        // advance offset past NAME
        advance_past_name(self.get_data(), &offset);

        // At this point, offset points to the byte AFTER the last label's null terminator
        // So we're now at the TYPE field

        // Skip TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)

        offset += (QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH + TTL_LENGTH + RD_LENGTH);

        // adance offset past MNAME
        advance_past_name(self.get_data(), &offset);

        // advance offset past RNAME
        advance_past_name(self.get_data(), &offset);

        // advance past serial
        offset += TTL_LENGTH;

        // advance past refresh interval
        offset += TTL_LENGTH;

        if (self.get_data().len < offset + TTL_LENGTH) {
            return 0;
        }

        const exp_limit: u32 = std.mem.bytesToValue(u32, data[offset .. offset + TTL_LENGTH]);
        return @byteSwap(exp_limit);
    }

    pub fn get_expire_limit(self: *SOARecord) u32 {
        const data = self.get_data();
        var offset: usize = 0;

        // advance offset past NAME
        advance_past_name(self.get_data(), &offset);

        // Skip TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)

        offset += (QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH + TTL_LENGTH + RD_LENGTH);

        // adance offset past MNAME
        advance_past_name(self.get_data(), &offset);

        // advance offset past RNAME
        advance_past_name(self.get_data(), &offset);

        // advance past serial
        offset += TTL_LENGTH;

        // advance past refresh interval
        offset += TTL_LENGTH;

        // advance past retry interval
        offset += TTL_LENGTH;

        if (self.get_data().len < offset + TTL_LENGTH) {
            return 0;
        }

        const exp_limit: u32 = std.mem.bytesToValue(u32, data[offset .. offset + TTL_LENGTH]);
        return @byteSwap(exp_limit);
    }

    pub fn get_minimum_ttl(self: *SOARecord) u32 {
        const data = self.get_data();
        var offset: usize = 0;

        // advance offset past NAME
        advance_past_name(self.get_data(), &offset);

        //  Skip  TYPE (2),             CLASS (2),          TTL (4),        RDLENGTH (2)
        offset += (QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH + TTL_LENGTH + RD_LENGTH);

        // adance offset past MNAME
        advance_past_name(self.get_data(), &offset);

        // advance offset past RNAME
        advance_past_name(self.get_data(), &offset);

        // advance past serial
        offset += TTL_LENGTH;

        // advance past refresh interval
        offset += TTL_LENGTH;

        // advance past retry interval
        offset += TTL_LENGTH;

        // advance past expire limit
        offset += TTL_LENGTH;

        if (self.get_data().len < offset + TTL_LENGTH) {
            return 0;
        }

        const min_ttl: u32 = std.mem.bytesToValue(u32, data[offset .. offset + TTL_LENGTH]);
        return @byteSwap(min_ttl);
    }

    pub fn get_rr_type(self: SOARecord) QueryType {
        return get_q_type(self.get_data());
    }
};

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
