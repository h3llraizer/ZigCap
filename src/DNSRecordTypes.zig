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

const COMPRESSION_PTR_LENGTH = @sizeOf(u8) * 2;

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

    pub fn init(offset: usize, length: usize, qtype: QueryType, owner: TLVOwner) AnswerRecord {
        switch (qtype) {
            // TODO: reduce repeating code
            .A => {
                return .{ .a = .{
                    .offset = offset,
                    .length = length,

                    .owner = owner,
                } };
            },

            .AAAA => {
                return .{ .aaaa = .{
                    .offset = offset,
                    .length = length,

                    .owner = owner,
                } };
            },

            .CNAME => {
                return .{ .cname = .{
                    .offset = offset,
                    .length = length,

                    .owner = owner,
                } };
            },

            .TXT => {
                return .{ .txt = .{
                    .offset = offset,
                    .length = length,

                    .owner = owner,
                } };
            },

            .MX => {
                return .{ .mx = .{
                    .offset = offset,
                    .length = length,

                    .owner = owner,
                } };
            },

            .PTR => {
                return .{ .ptr = .{
                    .offset = offset,
                    .length = length,

                    .owner = owner,
                } };
            },

            .NS => {
                return .{ .ns = .{
                    .offset = offset,
                    .length = length,

                    .owner = owner,
                } };
            },

            .SOA => {
                return .{ .soa = .{
                    .offset = offset,
                    .length = length,

                    .owner = owner,
                } };
            },

            .GENERIC => {
                return .{ .generic = .{
                    .offset = offset,
                    .length = length,

                    .owner = owner,
                } };
            },

            else => return .{ .generic = .{
                .offset = offset,
                .length = length,

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

    pub fn next(self: *AnswerRecord) ?*AnswerRecord {
        return switch (self.*) {
            inline else => |*rr| rr.next_answer,
        };
    }

    pub fn set_next(self: *AnswerRecord, rec: *AnswerRecord) void {
        return switch (self.*) {
            inline else => |*rr| rr.next_answer = rec,
        };
    }

    pub fn prev(self: *AnswerRecord) ?*AnswerRecord {
        return switch (self.*) {
            inline else => |*rr| rr.prev_answer,
        };
    }

    pub fn set_prev(self: *AnswerRecord, rec: *AnswerRecord) void {
        return switch (self.*) {
            inline else => |*rr| rr.prev_answer = rec,
        };
    }

    pub fn get_ttl(self: *AnswerRecord) u32 {
        return switch (self.*) {
            inline else => |*rr| rr.get_ttl(),
        };
    }

    pub fn set_ttl(self: *AnswerRecord, ttl: u32) void {
        return switch (self.*) {
            inline else => |*rr| rr.set_ttl(ttl),
        };
    }

    pub fn get_rr_type(self: *AnswerRecord) QueryType {
        return switch (self.*) {
            inline else => |*rr| rr.get_rr_type(),
        };
    }

    pub fn get_class_type(self: *AnswerRecord) DnsClass {
        return switch (self.*) {
            inline else => |*rr| rr.get_class(),
        };
    }

    pub fn to_string(self: *AnswerRecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]const u8 {
        return switch (self.*) {
            inline else => |*rr| try rr.to_string(allocator),
        };
    }

    pub fn deinit(self: *AnswerRecord) void {
        return switch (self.*) {
            inline else => |*rr| rr.deinit(),
        };
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

        // need to find offset of last ans instead

        var extend_offset = if (self.owner.is_layer_owned()) DNS.DNSHeaderSize else 0;
        var cur: ?*AnswerRecord = self.first;
        var last: ?*AnswerRecord = null;

        while (cur) |a| {
            if (a.next() == null) {
                extend_offset = a.get_offset() + a.get_length();
                last = a;
                break;
            } else {
                last = a.next();
            }

            cur = a.next();
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

                var next_answer = answer.next();
                while (next_answer) |next| {
                    next.offset -= answer.get_length();
                    next_answer = next.next();
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
                    self.first = a.next();
                }

                if (a.next()) |next| {
                    next.set_prev_record(a.prev());
                }

                if (a.prev()) |prev| {
                    prev.set_next(a.next());
                }

                allocator.destroy(answer);
                return;
            }
            cur = a.next();
        }

        return error.AnswerRecordNotFound;
    }

    pub fn deinit(self: *AnswerRecords, allocator: Allocator) void {
        var cur = self.last;

        while (cur) |ansrec| {
            if (!ansrec.get_owner().is_layer_owned()) {
                ansrec.get_owner().deinit();
            }

            cur = ansrec.prev();
        }

        cur = self.last;

        while (cur) |ansrec| {
            const prev = ansrec.prev();
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

    return @enumFromInt(std.mem.readInt(
        u16,
        @ptrCast(data[offset .. offset + CLASS_TYPE_LENGTH].ptr),
        .big,
    ));
}

fn set_dns_class(data: []u8, class: DnsClass) void {
    var offset: usize = 0;

    advance_past_name(data, &offset);

    offset += QUERY_TYPE_LENGTH;

    return std.mem.writeInt(
        u16,
        @ptrCast(data[offset .. offset + CLASS_TYPE_LENGTH].ptr),
        @intFromEnum(class),
        .big,
    );
}

fn get_q_type(data: []const u8) QueryType {
    var offset: usize = 0;

    advance_past_name(data, &offset);

    return @enumFromInt(std.mem.readInt(
        u16,
        @ptrCast(data[offset .. offset + QUERY_TYPE_LENGTH].ptr),
        .big,
    ));
}

fn set_q_type(data: []u8, qtype: QueryType) void {
    var offset: usize = 0;

    advance_past_name(data, &offset);

    return std.mem.writeInt(
        u16,
        @ptrCast(data[offset .. offset + QUERY_TYPE_LENGTH].ptr),
        @intFromEnum(qtype),
        .big,
    );
}

fn init_record(name: []const u8, qtype: QueryType, class: DnsClass, allocator: Allocator) (LayerError || Allocator.Error)!TLVOwner {
    var initial_len: usize = name.len +
        QUERY_TYPE_LENGTH + // 2 bytes
        CLASS_TYPE_LENGTH + // 2 bytes
        TTL_LENGTH + // 4 bytes
        RD_LENGTH; // 2 bytes

    var rd_len: u16 = 0;

    switch (qtype) {
        .MX => {
            rd_len += MXRecord.MX_PREFERENCE_VALUE_LENGTH; // 2 bytes

            //rd_len += COMPRESSION_PTR_LENGTH; // include at least 2 bytes for the rdata (compression ptr length) and extend when required

        },
        .TXT => {
            rd_len += TXTRecord.TXT_LENGTH; // 1 byte
        },
        .A => rd_len += @sizeOf(IPv4Address), // 4 bytes
        .AAAA => rd_len += @sizeOf(IPv6Address), // 16 bytes
        else => {
            rd_len += COMPRESSION_PTR_LENGTH; // 2 bytes
        },
    }

    initial_len += rd_len;

    var owner = TLVOwner{ .owned_buffer = .init_empty(allocator) };

    const buf = try owner.extend_buffer(0, initial_len);

    @memmove(buf[0..name.len], name);

    const qtype_offset = name.len;

    std.mem.writeInt(
        u16,
        @ptrCast(buf[qtype_offset .. qtype_offset + QUERY_TYPE_LENGTH].ptr),
        @intFromEnum(qtype),
        .big,
    );

    const qclass_offset = qtype_offset + QUERY_TYPE_LENGTH;

    std.mem.writeInt(
        u16,
        @ptrCast(buf[qclass_offset .. qclass_offset + CLASS_TYPE_LENGTH].ptr),
        @intFromEnum(class),
        .big,
    );

    const rd_len_offset = qclass_offset + CLASS_TYPE_LENGTH + TTL_LENGTH;

    std.mem.writeInt(
        u16,
        @ptrCast(buf[rd_len_offset .. rd_len_offset + RD_LENGTH].ptr),
        rd_len,
        .big,
    );

    return owner;
}

pub const GenericRecord = struct {
    offset: usize,
    length: usize,
    owner: TLVOwner,
    next_answer: ?*AnswerRecord = null,
    prev_answer: ?*AnswerRecord = null,

    const CLASS_TYPE_OFFSET_FROM_NAME = QUERY_TYPE_LENGTH;
    const TTL_OFFSET_FROM_NAME = QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH;
    const RD_LENGTH_OFFSET_FROM_NAME = QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH + TTL_LENGTH;
    const RDATA_OFFSET_FROM_NAME = QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH + TTL_LENGTH + RD_LENGTH;

    /// Init a new generic record.
    /// Name provided must be an encoded name (use DNS.encode_name method).
    /// qtype and class are set to value 0 (not valid), rd length is set to 2.
    /// Allocates name length + 12 bytes (qtype, qclass, ttl, rd len, 2 byte rdata).
    pub fn init(name: []const u8, allocator: Allocator) (LayerError || Allocator.Error)!GenericRecord {
        var owner: TLVOwner = try init_record(
            name,
            @enumFromInt(0),
            @enumFromInt(0),
            allocator,
        );

        const len = owner.get_data().len;

        const rec = GenericRecord{
            .offset = 0,
            .length = len,
            .owner = owner,
        };

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
        return try decode_name(self.owner.get_data(), data, allocator);
    }

    /// Name provided must be an encoded name (use DNS.encode_name method).
    pub fn set_name(self: *GenericRecord, name: []const u8) (LayerError || Allocator.Error)!void {
        const data = self.get_data();

        var offset: usize = 0;

        advance_past_name(data, &offset);

        const cur_name_len = offset;

        if (cur_name_len < name.len) {
            const extend_len = name.len - cur_name_len;
            _ = try self.owner.extend_buffer(cur_name_len, extend_len);

            self.length += extend_len;

            // increase the proceeding records offsets by the extend_len
            var next_rec = self.next_answer;
            while (next_rec) |rr| {
                rr.set_offset(rr.get_offset() + extend_len);
                next_rec = rr.next();
            }
        }

        if (cur_name_len > name.len) {
            const shorten_len = cur_name_len - name.len;

            //print("shortening at {} by {}\n", .{ cur_name_len, shorten_len });

            try self.owner.shorten_buffer(name.len, shorten_len);

            self.length -= shorten_len;

            // decrease the proceeding records offsets by the shorten_len
            var next_rec = self.next_answer;
            while (next_rec) |rr| {
                rr.set_offset(rr.get_offset() - shorten_len);
                next_rec = rr.next();
            }
        }

        // if name is same length as current it can just be copied over
        @memmove(self.get_data_mut()[0..name.len], name);
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
        const data = self.get_data();

        var offset: usize = 0;

        advance_past_name(data, &offset);

        return @enumFromInt(std.mem.readInt(
            u16,
            @ptrCast(data[offset .. offset + QUERY_TYPE_LENGTH].ptr),
            .big,
        ));
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
        const data = self.get_data();

        var offset: usize = 0;

        advance_past_name(data, &offset);

        offset += QUERY_TYPE_LENGTH;

        return @enumFromInt(std.mem.readInt(
            u16,
            @ptrCast(data[offset .. offset + RD_LENGTH].ptr),
            .big,
        ));
    }

    pub fn set_ttl(self: *GenericRecord, ttl: u32) void {
        const data = self.get_data_mut();

        var offset: usize = 0;

        advance_past_name(data, &offset);

        offset += TTL_OFFSET_FROM_NAME;

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

        offset += TTL_OFFSET_FROM_NAME;

        return std.mem.readInt(
            u32,
            @ptrCast(data[offset .. offset + TTL_LENGTH].ptr),
            .big,
        );
    }

    /// Returns the RDATA-Length value
    pub fn get_rd_len(self: *GenericRecord) u16 {
        const data = self.get_data();

        var offset: usize = 0;

        advance_past_name(data, &offset);

        offset += RD_LENGTH_OFFSET_FROM_NAME;

        return std.mem.readInt(
            u16,
            @ptrCast(data[offset .. offset + RD_LENGTH].ptr),
            .big,
        );
    }

    /// Sets raw rdata bytes.
    /// Caller needs to handle endiannes, name encoding, compression ptrs before calling the method.
    /// RD_LENGTH value is handled in the method
    /// If any proceeding layers, their offsets are adjusted
    pub fn set_rdata(self: *GenericRecord, rdata: []const u8) (LayerError || Allocator.Error)!void {
        const data = self.get_data();

        var offset: usize = 0;

        advance_past_name(data, &offset);

        offset += RD_LENGTH_OFFSET_FROM_NAME;

        const rd_len_offset = offset; // assign rd length offset

        offset += RD_LENGTH;

        const cur_rdata_len: usize = data.len - offset;

        if (cur_rdata_len < rdata.len) {
            const extend_len = rdata.len - cur_rdata_len;
            const slice = try self.owner.extend_buffer(offset, extend_len);
            self.length += slice.len;

            // increase the proceeding layers offset by the shorten_len
            var next_rec = self.next_answer;
            while (next_rec) |rr| {
                rr.set_offset(rr.get_offset() + extend_len);
                next_rec = rr.next();
            }
        }
        if (cur_rdata_len > rdata.len) {
            const shorten_len = cur_rdata_len - rdata.len;

            try self.owner.shorten_buffer(offset + rdata.len, shorten_len);

            self.length -= shorten_len;

            // decrease the proceeding layers offset by the shorten_len
            var next_rec = self.next_answer;
            while (next_rec) |rr| {
                rr.set_offset(rr.get_offset() - shorten_len);
                next_rec = rr.next();
            }
        }

        @memmove(self.get_data_mut()[offset..], rdata);

        // set the RD_LEN value the len of the rdata provided/written as big endian
        std.mem.writeInt(
            u16,
            @ptrCast(self.get_data_mut()[rd_len_offset .. rd_len_offset + RD_LENGTH].ptr),
            @intCast(rdata.len),
            .big,
        );
    }

    pub fn get_rdata(self: *GenericRecord) []const u8 {
        const data = self.get_data();

        var offset: usize = 0;

        advance_past_name(data, &offset);

        offset += RDATA_OFFSET_FROM_NAME;

        return data[offset..self.length];
    }

    pub fn to_string(self: *GenericRecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]const u8 {
        var list: std.ArrayList(u8) = .empty;

        const name = try self.get_name(allocator);
        defer allocator.free(name);
        const ttl = try std.fmt.allocPrint(allocator, "{d}", .{self.get_ttl()});
        defer allocator.free(ttl);

        const type_s = @tagName(self.get_rr_type());
        const class_s = @tagName(self.get_class());
        const rdata = self.get_rdata();

        const space = ". ";
        const dot = '.';

        try list.appendSlice(allocator, name);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, ttl);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, type_s);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, class_s);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, rdata);
        try list.append(allocator, dot);

        return try list.toOwnedSlice(allocator);
    }

    /// experimental
    pub fn as(self: *GenericRecord, rr_type: anytype) *rr_type {
        return @ptrCast(self);
    }

    pub fn deinit(self: *GenericRecord) void {
        self.owner.deinit();
    }
};

/// A Record - IPv4 Responses
pub const ARecord = struct {
    offset: usize,
    length: usize,
    owner: TLVOwner,
    next_answer: ?*AnswerRecord = null,
    prev_answer: ?*AnswerRecord = null,

    /// Init a new A record.
    /// Name provided must be an encoded name (use DNS.encode_name method).
    /// qtype is set to A
    /// Allocates name length + 16 bytes (qtype, qclass, ttl, rd len, 4 bytes for ipv4 address).
    /// copies all provided values into correct places
    pub fn init(
        name: []const u8,
        class: DnsClass,
        ttl: u32,
        ip: IPv4Address,
        allocator: Allocator,
    ) (LayerError || Allocator.Error)!ARecord {
        var owner: TLVOwner = try init_record(
            name,
            .A,
            class,
            allocator,
        );

        const len = owner.get_data().len;

        const rec = ARecord{
            .offset = 0,
            .length = len,

            .owner = owner,
        };

        const ttl_offset = name.len + GenericRecord.TTL_OFFSET_FROM_NAME;

        std.mem.writeInt(
            u32,
            @ptrCast(owner.get_data()[ttl_offset .. ttl_offset + TTL_LENGTH].ptr),
            ttl,
            .big,
        );

        const rd_len_offset = name.len + GenericRecord.RD_LENGTH_OFFSET_FROM_NAME;

        std.mem.writeInt(
            u16,
            @ptrCast(owner.get_data()[rd_len_offset .. rd_len_offset + @sizeOf(IPv4Address)].ptr),
            @sizeOf(IPv4Address),
            .big,
        );

        const ip_offset = name.len + GenericRecord.RDATA_OFFSET_FROM_NAME;

        @memmove(
            owner.get_data()[ip_offset .. ip_offset + @sizeOf(IPv4Address)],
            &ip.array,
        );

        return rec;
    }

    pub fn get_data(self: *ARecord) []const u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_data_mut(self: *ARecord) []u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn set_name(self: *ARecord, name: []const u8) Allocator.Error!void {
        var grec: *GenericRecord = @ptrCast(self);
        return try grec.set_name(name);
    }

    pub fn get_name(self: *ARecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        var grec: *GenericRecord = @ptrCast(self);
        return try grec.get_name(allocator);
    }

    pub fn get_rr_type(self: *ARecord) QueryType {
        return get_q_type(self.get_data());
    }

    pub fn get_class(self: *ARecord) DnsClass {
        return get_dns_class(self.get_data());
    }

    pub fn set_class(self: *ARecord, class: DnsClass) void {
        return set_dns_class(self.get_data_mut(), class);
    }

    pub fn get_ttl(self: *ARecord) u32 {
        var grec: *GenericRecord = @ptrCast(self);
        return grec.get_ttl();
    }

    pub fn set_ttl(self: *ARecord, ttl: u32) void {
        var grec: *GenericRecord = @ptrCast(self);

        return grec.set_ttl(ttl);
    }

    pub fn get_ip(self: *ARecord) IPv4Address {
        const data = self.get_data();
        std.debug.assert(data.len >= 16);

        var offset: usize = 0;

        advance_past_name(self.get_data(), &offset);

        offset += GenericRecord.RDATA_OFFSET_FROM_NAME;

        const ip_u32: u32 = std.mem.bytesToValue(u32, data[offset .. offset + @sizeOf(IPv4Address)]);

        const ip = IPv4Address.init_from_u32(@byteSwap(ip_u32));
        return ip;
    }

    pub fn set_ip(self: *ARecord, ipv4: IPv4Address) void {
        const data = self.get_data_mut();

        std.debug.assert(data.len >= 16);

        var offset: usize = 0;

        advance_past_name(self.get_data(), &offset);

        offset += GenericRecord.RDATA_OFFSET_FROM_NAME;

        const ip_ptr = std.mem.bytesAsValue(u32, data[offset .. offset + @sizeOf(IPv4Address)]);

        ip_ptr.* = @byteSwap(ipv4.to_u32());
    }

    pub fn to_string(self: *ARecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]const u8 {
        var list: std.ArrayList(u8) = .empty;

        const name = try self.get_name(allocator);
        defer allocator.free(name);
        const ttl = try std.fmt.allocPrint(allocator, "{d}", .{self.get_ttl()});
        defer allocator.free(ttl);
        const type_s = @tagName(self.get_rr_type());
        const class_s = @tagName(self.get_class());
        const ip = try self.get_ip().to_string(allocator);
        defer allocator.free(ip);

        const space = ". ";
        const dot = '.';

        try list.appendSlice(allocator, name);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, ttl);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, type_s);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, class_s);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, ip);
        try list.append(allocator, dot);

        return try list.toOwnedSlice(allocator);
    }

    pub fn deinit(self: *ARecord) void {
        self.owner.deinit();
    }
};

/// AAAA Record - IPv6 responses
pub const AAAARecord = struct {
    offset: usize,
    length: usize,
    owner: TLVOwner,
    next_answer: ?*AnswerRecord = null,
    prev_answer: ?*AnswerRecord = null,

    pub fn init(
        name: []const u8,
        class: DnsClass,
        ttl: u32,
        ip: IPv6Address,
        allocator: Allocator,
    ) (LayerError || Allocator.Error)!AAAARecord {
        var owner: TLVOwner = try init_record(
            name,
            .AAAA,
            class,
            allocator,
        );

        const len = owner.get_data().len;

        const rec = AAAARecord{
            .offset = 0,
            .length = len,

            .owner = owner,
        };

        var offset: usize = 0;

        advance_past_name(owner.get_data(), &offset);

        offset += GenericRecord.TTL_OFFSET_FROM_NAME;

        std.mem.writeInt(
            u32,
            @ptrCast(owner.get_data()[offset .. offset + TTL_LENGTH].ptr),
            ttl,
            .big,
        );

        offset += (TTL_LENGTH + RD_LENGTH);

        @memmove(owner.get_data()[offset .. offset + ip.array.len], &ip.array);

        return rec;
    }

    pub fn get_data(self: *AAAARecord) []const u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_data_mut(self: *AAAARecord) []u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn set_name(self: *AAAARecord, name: []const u8) Allocator.Error!void {
        var grec: *GenericRecord = @ptrCast(self);
        return try grec.set_name(name);
    }

    pub fn get_name(self: *AAAARecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        var grec: *GenericRecord = @ptrCast(self);
        return try grec.get_name(allocator);
    }

    pub fn get_rr_type(self: *AAAARecord) QueryType {
        return get_q_type(self.get_data());
    }

    pub fn get_class(self: *AAAARecord) DnsClass {
        return get_dns_class(self.get_data());
    }

    pub fn set_class(self: *AAAARecord, class: DnsClass) void {
        return set_dns_class(self.get_data_mut(), class);
    }

    pub fn get_ttl(self: *AAAARecord) u32 {
        var grec: *GenericRecord = @ptrCast(self);
        return grec.get_ttl();
    }

    pub fn set_ttl(self: *AAAARecord, ttl: u32) void {
        var grec: *GenericRecord = @ptrCast(self);

        return grec.set_ttl(ttl);
    }

    /// returns the IPv6 address of the AAAA record by creating a copy of the IPv6 start to len bytes and init'ing the IPv6 address from it.
    /// null is retured when length of the RR data (in the DNS Layer) is not atleast 28 bytes in length
    pub fn get_ipv6(self: *AAAARecord) IPv6Address {
        const data = self.get_data();
        std.debug.assert(data.len >= 28);
        var offset: usize = 0;

        advance_past_name(data, &offset);

        offset += GenericRecord.RDATA_OFFSET_FROM_NAME;

        var ipv6_arr: [16]u8 = undefined;
        @memmove(ipv6_arr[0..], data[offset .. offset + @sizeOf(IPv6Address)]);

        const ip = IPv6Address.init_from_array(ipv6_arr);
        return ip;
    }

    /// Sets the IPv6 address of this record.
    /// Will fail silently when length of the RR data (in the DNS Layer) is not atleast 28 bytes in length
    pub fn set_ipv6(self: *AAAARecord, ipv6: IPv6Address) void {
        const data = self.get_data_mut();

        std.debug.assert(data.len >= 28);

        var offset: usize = 0;

        advance_past_name(data, &offset);

        offset += GenericRecord.RDATA_OFFSET_FROM_NAME;

        var ipv6_arr: [16]u8 = ipv6.array;
        @memmove(data[offset .. offset + @sizeOf(IPv6Address)], ipv6_arr[0..]);
    }

    pub fn to_string(self: *AAAARecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]const u8 {
        var list: std.ArrayList(u8) = .empty;

        const name = try self.get_name(allocator);
        defer allocator.free(name);
        const ttl = try std.fmt.allocPrint(allocator, "{d}", .{self.get_ttl()});
        defer allocator.free(ttl);

        const type_s = @tagName(self.get_rr_type());
        const class_s = @tagName(self.get_class());
        const ip = try self.get_ipv6().to_string(allocator);
        defer allocator.free(ip);

        const space = ". ";
        const dot = '.';

        try list.appendSlice(allocator, name);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, ttl);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, type_s);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, class_s);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, ip);
        try list.append(allocator, dot);

        return try list.toOwnedSlice(allocator);
    }

    pub fn deinit(self: *AAAARecord) void {
        self.owner.deinit();
    }
};

/// NS (Name Server) Record
pub const NSRecord = struct {
    offset: usize,
    length: usize,
    owner: TLVOwner,
    next_answer: ?*AnswerRecord = null,
    prev_answer: ?*AnswerRecord = null,

    pub fn init(
        name: []const u8,
        class: DnsClass,
        ttl: u32,
        ns_name: []const u8,
        allocator: Allocator,
    ) (LayerError || Allocator.Error)!NSRecord {
        var owner: TLVOwner = try init_record(
            name,
            .NS,
            class,
            allocator,
        );

        if (ns_name.len > COMPRESSION_PTR_LENGTH) {
            const diff = ns_name.len - COMPRESSION_PTR_LENGTH;
            const current_len = owner.get_data().len;
            _ = try owner.extend_buffer(current_len, diff);
        }

        const len = owner.get_data().len;

        const rec = NSRecord{
            .offset = 0,
            .length = len,

            .owner = owner,
        };

        const ttl_offset = name.len + GenericRecord.TTL_OFFSET_FROM_NAME;

        std.mem.writeInt(
            u32,
            @ptrCast(owner.get_data()[ttl_offset .. ttl_offset + TTL_LENGTH].ptr),
            ttl,
            .big,
        );

        const rd_len_offset = name.len + GenericRecord.RD_LENGTH_OFFSET_FROM_NAME;

        std.mem.writeInt(
            u16,
            @ptrCast(owner.get_data()[rd_len_offset .. rd_len_offset + RD_LENGTH].ptr),
            @intCast(ns_name.len),
            .big,
        );

        const ns_offset = name.len + GenericRecord.RDATA_OFFSET_FROM_NAME;

        @memmove(
            owner.get_data()[ns_offset .. ns_offset + ns_name.len],
            ns_name,
        );

        return rec;
    }

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

    pub fn set_name(self: *NSRecord, name: []const u8) (LayerError || Allocator.Error)!void {
        var grec: *GenericRecord = @ptrCast(self);
        return grec.set_name(name);
    }

    pub fn get_rr_type(self: *NSRecord) QueryType {
        return get_q_type(self.get_data());
    }

    pub fn set_class(self: *NSRecord, qclass: DnsClass) void {
        var grec: *GenericRecord = @ptrCast(self);
        grec.set_class(qclass);
    }

    pub fn get_class(self: *NSRecord) DnsClass {
        return get_dns_class(self.get_data());
    }

    pub fn get_ttl(self: *NSRecord) u32 {
        var grec: *GenericRecord = @ptrCast(self);
        return grec.get_ttl();
    }

    pub fn set_ttl(self: *NSRecord, ttl: u32) void {
        var grec: *GenericRecord = @ptrCast(self);
        return grec.set_ttl(ttl);
    }

    pub fn get_rd_len(self: *NSRecord) u16 {
        var grec: *GenericRecord = @ptrCast(self);
        return grec.get_rd_len();
    }

    pub fn decode_ns_name(self: *NSRecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        var offset: usize = 0;

        advance_past_name(self.get_data(), &offset);

        offset += GenericRecord.RDATA_OFFSET_FROM_NAME;

        return try decode_name(self.owner.get_data(), self.get_data()[offset..], allocator);
    }

    pub fn set_ns_name(self: *NSRecord, server_name: []const u8) (LayerError || Allocator.Error)!void {
        var grec: *GenericRecord = @ptrCast(self);
        try grec.set_rdata(server_name);
    }

    pub fn to_string(self: *NSRecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]const u8 {
        var list: std.ArrayList(u8) = .empty;

        const name = try self.get_name(allocator);
        defer allocator.free(name);
        const ttl = try std.fmt.allocPrint(allocator, "{d}", .{self.get_ttl()});
        defer allocator.free(ttl);

        const type_s = @tagName(self.get_rr_type());
        const class_s = @tagName(self.get_class());
        const cname = try self.decode_ns_name(allocator);
        defer allocator.free(cname);

        const space = " ";

        try list.appendSlice(allocator, name);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, ttl);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, type_s);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, class_s);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, cname);

        return try list.toOwnedSlice(allocator);
    }

    pub fn deinit(self: *NSRecord) void {
        self.owner.deinit();
    }
};

/// CNAME (Canonical Name) Record
pub const CNAMERecord = struct {
    offset: usize,
    length: usize,
    owner: TLVOwner,
    next_answer: ?*AnswerRecord = null,
    prev_answer: ?*AnswerRecord = null,

    pub fn init(
        name: []const u8,
        class: DnsClass,
        ttl: u32,
        cname: []const u8,
        allocator: Allocator,
    ) (LayerError || Allocator.Error)!CNAMERecord {
        var owner: TLVOwner = try init_record(name, .CNAME, class, allocator);

        const cur_len = owner.get_data().len;

        const extend_len = cname.len - COMPRESSION_PTR_LENGTH;

        _ = owner.extend_buffer(cur_len, extend_len) catch |err| {
            owner.deinit();
            return err;
        };

        var offset: usize = 0;

        advance_past_name(owner.get_data(), &offset);

        offset += GenericRecord.TTL_OFFSET_FROM_NAME;

        std.mem.writeInt(
            u32,
            @ptrCast(owner.get_data()[offset .. offset + TTL_LENGTH].ptr),
            ttl,
            .big,
        );

        offset += TTL_LENGTH;

        std.mem.writeInt(
            u16,
            @ptrCast(owner.get_data()[offset .. offset + RD_LENGTH].ptr),
            @intCast(cname.len),
            .big,
        );

        offset += RD_LENGTH;

        @memmove(owner.get_data()[offset .. offset + cname.len], cname);

        return .{
            .offset = 0,
            .length = owner.get_data().len,

            .owner = owner,
        };
    }

    pub fn get_data(self: *CNAMERecord) []const u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_data_mut(self: *CNAMERecord) []u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn set_name(self: *CNAMERecord, name: []const u8) (LayerError || Allocator.Error)!void {
        var grec: *GenericRecord = @ptrCast(self);
        return try grec.set_name(name);
    }

    pub fn get_name(self: *CNAMERecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        var grec: *GenericRecord = @ptrCast(self);
        return try grec.get_name(allocator);
    }

    pub fn get_rr_type(self: *CNAMERecord) QueryType {
        return get_q_type(self.get_data());
    }

    pub fn get_class(self: *CNAMERecord) DnsClass {
        return get_dns_class(self.get_data());
    }

    pub fn set_class(self: *CNAMERecord, class: DnsClass) void {
        return set_dns_class(self.get_data_mut(), class);
    }

    pub fn get_ttl(self: *CNAMERecord) u32 {
        var grec: *GenericRecord = @ptrCast(self);
        return grec.get_ttl();
    }

    pub fn set_ttl(self: *CNAMERecord, ttl: u32) void {
        var grec: *GenericRecord = @ptrCast(self);

        return grec.set_ttl(ttl);
    }

    pub fn get_rd_len(self: *CNAMERecord) u16 {
        var grec: *GenericRecord = @ptrCast(self);
        return grec.get_rd_len();
    }

    pub fn get_cname(self: *CNAMERecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        if (self.get_data().len < 12) { // TODO: remove temp magic number
            return DNSLayer.DNSParseError.RecordTooShort;
        }

        var offset: usize = 0;

        advance_past_name(self.get_data(), &offset);

        //  rrtype (2 bytes), class (2bytes), ttl (4bytes), data length (2bytes)
        offset += GenericRecord.RDATA_OFFSET_FROM_NAME;

        return try decode_name(self.owner.get_data(), self.get_data()[offset..], allocator);
    }

    pub fn set_cname(self: *CNAMERecord, cname: []const u8) (LayerError || Allocator.Error)!void {
        var grec: *GenericRecord = @ptrCast(self);
        try grec.set_rdata(cname);
    }

    pub fn to_string(self: *CNAMERecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]const u8 {
        var list: std.ArrayList(u8) = .empty;

        const name = try self.get_name(allocator);
        defer allocator.free(name);
        const ttl = try std.fmt.allocPrint(allocator, "{d}", .{self.get_ttl()});
        defer allocator.free(ttl);

        const type_s = @tagName(self.get_rr_type());
        const class_s = @tagName(self.get_class());
        const cname = try self.get_cname(allocator);
        defer allocator.free(cname);

        const space = ". ";
        const dot = '.';

        try list.appendSlice(allocator, name);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, ttl);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, type_s);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, class_s);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, cname);
        try list.append(allocator, dot);

        return try list.toOwnedSlice(allocator);
    }

    pub fn deinit(self: *CNAMERecord) void {
        self.owner.deinit();
    }
};

/// TXT Record
pub const TXTRecord = struct {
    offset: usize,
    length: usize,
    owner: TLVOwner,
    next_answer: ?*AnswerRecord = null,
    prev_answer: ?*AnswerRecord = null,

    const TXT_LENGTH = @sizeOf(u8);

    const TXT_STRING_OFFSET_FROM_NAME = QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH + TTL_LENGTH + RD_LENGTH + TXT_LENGTH;

    pub fn init(
        name: []const u8,
        class: DnsClass,
        ttl: u32,
        txt_str: []const u8,
        allocator: Allocator,
    ) (LayerError || Allocator.Error)!TXTRecord {
        var owner: TLVOwner = try init_record(
            name,
            .TXT,
            class,
            allocator,
        );

        _ = try owner.extend_buffer(owner.get_data().len, txt_str.len);

        const len = owner.get_data().len;

        var rec = TXTRecord{
            .offset = 0,
            .length = len,

            .owner = owner,
        };

        var offset: usize = 0;

        advance_past_name(owner.get_data(), &offset);

        offset += QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH + TTL_LENGTH;

        const rd_len_offset = offset;
        offset += RD_LENGTH;

        owner.get_data()[offset] = @intCast(txt_str.len);
        @memmove(owner.get_data()[offset + 1 .. offset + 1 + txt_str.len], txt_str);

        std.mem.writeInt(
            u16,
            @ptrCast(owner.get_data()[rd_len_offset .. rd_len_offset + RD_LENGTH].ptr),
            @intCast(1 + txt_str.len),
            .big,
        );

        var grec: *GenericRecord = @ptrCast(&rec);
        grec.set_ttl(ttl);

        return rec;
    }

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

    pub fn set_name(self: *TXTRecord, name: []const u8) (LayerError || Allocator.Error)!void {
        var grec: *GenericRecord = @ptrCast(self);
        return grec.set_name(name);
    }

    pub fn get_rr_type(self: *TXTRecord) QueryType {
        var grec: *GenericRecord = @ptrCast(self);
        return grec.get_rr_type();
    }

    pub fn set_class(self: *TXTRecord, qclass: DnsClass) void {
        var grec: *GenericRecord = @ptrCast(self);
        grec.set_class(qclass);
    }

    pub fn get_class(self: *TXTRecord) DnsClass {
        var grec: *GenericRecord = @ptrCast(self);
        return grec.get_class();
    }

    pub fn get_ttl(self: *TXTRecord) u32 {
        var grec: *GenericRecord = @ptrCast(self);
        return grec.get_ttl();
    }

    pub fn set_ttl(self: *TXTRecord, ttl: u32) void {
        var grec: *GenericRecord = @ptrCast(self);
        return grec.set_ttl(ttl);
    }

    pub fn get_rd_len(self: *TXTRecord) u16 {
        var grec: *GenericRecord = @ptrCast(self);
        return grec.get_rd_len();
    }

    pub fn get_txt_len(self: *TXTRecord) u8 {
        var offset: usize = 0;

        advance_past_name(self.get_data(), &offset);

        offset += TXT_STRING_OFFSET_FROM_NAME - @sizeOf(u8);

        return self.get_data()[offset];
    }

    pub fn get_txt(self: *TXTRecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]const u8 {
        const data = self.get_data();

        var offset: usize = 0;

        advance_past_name(data, &offset);

        offset += TXT_STRING_OFFSET_FROM_NAME;

        return try decode_name(self.owner.get_data(), self.get_data()[offset..], allocator);
    }

    pub fn set_txt(self: *TXTRecord, str: []const u8) Allocator.Error!void {
        const data = self.get_data();

        var offset: usize = 0;

        advance_past_name(data, &offset);

        offset += TXT_STRING_OFFSET_FROM_NAME;

        const cur_len: usize = offset + self.length;

        if (str.len > cur_len) {
            const extend_len: usize = str.len - cur_len;

            _ = try self.owner.extend_buffer(offset, extend_len);

            self.length += extend_len;

            var next_rec = self.next_answer;
            while (next_rec) |rr| {
                rr.set_offset(rr.get_offse() + extend_len);
                next_rec = rr.next();
            }
        }

        if (str.len < cur_len) {
            const shorten_len: usize = cur_len - str.len;

            try self.owner.shorten_buffer(offset + str.len, shorten_len);

            self.length -= shorten_len;

            var next_rec = self.next_answer;

            while (next_rec) |rr| {
                rr.set_offset(rr.get_offset() - shorten_len);
                next_rec = rr.next();
            }
        }

        offset -= TXT_STRING_OFFSET_FROM_NAME;

        self.get_data_mut()[offset] = @intCast(str.len - 1);

        offset -= RD_LENGTH;

        std.mem.writeInt(
            u16,
            @ptrCast(self.get_data_mut[offset .. offset + RD_LENGTH].ptr),
            @intCast(str.len),
            .big,
        );

        @memmove(self.get_data_mut()[offset..str.len], str);
    }

    pub fn to_string(self: *TXTRecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]const u8 {
        var list: std.ArrayList(u8) = .empty;

        const name = try self.get_name(allocator);
        defer allocator.free(name);

        const ttl = try std.fmt.allocPrint(allocator, "{d}", .{self.get_ttl()});
        defer allocator.free(ttl);

        const type_s = @tagName(self.get_rr_type());
        const class_s = @tagName(self.get_class());
        const txt = try self.get_txt(allocator);
        defer allocator.free(txt);

        const space = ". ";
        const dot = '.';

        try list.appendSlice(allocator, name);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, ttl);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, type_s);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, class_s);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, txt);
        try list.append(allocator, dot);

        return try list.toOwnedSlice(allocator);
    }

    pub fn deinit(self: *TXTRecord) void {
        self.owner.deinit();
    }
};

pub const MXRecord = struct {
    offset: usize,
    length: usize,
    owner: TLVOwner,
    next_answer: ?*AnswerRecord = null,
    prev_answer: ?*AnswerRecord = null,

    pub const MX_PREFERENCE_VALUE_LENGTH = @sizeOf(u16);

    const MX_PREF_OFFSET_FROM_RD_LENGTH = GenericRecord.RD_LENGTH_OFFSET_FROM_NAME + RD_LENGTH;

    const MX_DOMAIN_OFFSET_FROM_NAME = MX_PREF_OFFSET_FROM_RD_LENGTH + MX_PREFERENCE_VALUE_LENGTH;

    pub fn init(
        name: []const u8,
        class: DnsClass,
        ttl: u32,
        preference: u16,
        mx_domain: []const u8,
        allocator: Allocator,
    ) (LayerError || Allocator.Error)!MXRecord {
        var owner: TLVOwner = .{ .owned_buffer = .init_empty(allocator) };

        const initial_len = name.len +
            QUERY_TYPE_LENGTH +
            CLASS_TYPE_LENGTH +
            TTL_LENGTH +
            RD_LENGTH +
            MX_PREFERENCE_VALUE_LENGTH +
            mx_domain.len;

        var offset: usize = 0;

        const buf = try owner.extend_buffer(offset, initial_len);

        @memmove(buf[offset..name.len], name);

        offset += name.len;

        std.mem.writeInt(
            u16,
            @ptrCast(buf[offset .. offset + QUERY_TYPE_LENGTH].ptr),
            @intFromEnum(QueryType.MX),
            .big,
        );

        offset += QUERY_TYPE_LENGTH;

        std.mem.writeInt(
            u16,
            @ptrCast(buf[offset .. offset + CLASS_TYPE_LENGTH].ptr),
            @intFromEnum(class),
            .big,
        );

        offset += CLASS_TYPE_LENGTH;

        std.mem.writeInt(
            u32,
            @ptrCast(buf[offset .. offset + TTL_LENGTH].ptr),
            ttl,
            .big,
        );

        offset += TTL_LENGTH;

        std.mem.writeInt(
            u16,
            @ptrCast(buf[offset .. offset + RD_LENGTH].ptr),
            @intCast(mx_domain.len + MX_PREFERENCE_VALUE_LENGTH),
            .big,
        );

        offset += RD_LENGTH;

        std.mem.writeInt(
            u16,
            @ptrCast(buf[offset .. offset + MX_PREFERENCE_VALUE_LENGTH].ptr),
            preference,
            .big,
        );

        offset += MX_PREFERENCE_VALUE_LENGTH;

        @memmove(buf[offset .. offset + mx_domain.len], mx_domain);

        const mxrecord = MXRecord{
            .offset = 0,
            .length = owner.get_data().len,

            .owner = owner,
        };

        return mxrecord;
    }

    pub fn get_data(self: *MXRecord) []const u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_data_mut(self: *MXRecord) []u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    /// retrieves the name stated in the RR.
    pub fn get_name(self: *MXRecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        //const data = self.get_data();
        //return try decode_name(self.owner.get_data(), data, allocator);
        var grec: *GenericRecord = @ptrCast(self);
        return try grec.get_name(allocator);
    }

    pub fn set_name(self: *MXRecord, name: []const u8) (LayerError || Allocator.Error)!void {
        var grec: *GenericRecord = @ptrCast(self);
        return try grec.set_name(name);
    }

    pub fn get_rr_type(self: *MXRecord) QueryType {
        var grec: *GenericRecord = @ptrCast(self);
        return grec.get_rr_type();
    }

    pub fn set_class(self: *MXRecord, qclass: DnsClass) void {
        var grec: *GenericRecord = @ptrCast(self);
        grec.set_class(qclass);
    }

    pub fn get_class(self: *MXRecord) DnsClass {
        var grec: *GenericRecord = @ptrCast(self);
        return grec.get_class();
    }

    pub fn get_ttl(self: *MXRecord) u32 {
        var grec: *GenericRecord = @ptrCast(self);
        return grec.get_ttl();
    }

    pub fn set_ttl(self: *MXRecord, ttl: u32) void {
        var grec: *GenericRecord = @ptrCast(self);
        return grec.set_ttl(ttl);
    }

    pub fn get_rd_len(self: *MXRecord) u16 {
        var grec: *GenericRecord = @ptrCast(self);
        return grec.get_rd_len();
    }

    pub fn get_preference(self: *MXRecord) u16 {
        var offset: usize = 0;

        advance_past_name(self.get_data(), &offset);

        offset += MX_PREF_OFFSET_FROM_RD_LENGTH;

        return std.mem.readInt(
            u16,
            @ptrCast(self.get_data()[offset .. offset + MX_PREFERENCE_VALUE_LENGTH].ptr),
            .big,
        );
    }

    pub fn set_preference(self: *MXRecord, pref: u16) void {
        var offset: usize = 0;

        advance_past_name(self.get_data(), &offset);

        offset += MX_PREF_OFFSET_FROM_RD_LENGTH;

        std.mem.writeInt(
            u16,
            @ptrCast(self.get_data_mut()[offset .. offset + MX_PREFERENCE_VALUE_LENGTH].ptr),
            pref,
            .big,
        );
    }

    pub fn get_mx_domain(self: *MXRecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]const u8 {
        var offset: usize = 0;

        const data = self.get_data();

        advance_past_name(data, &offset);

        offset += (QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH + TTL_LENGTH + RD_LENGTH + MX_PREFERENCE_VALUE_LENGTH);

        const domain_start = self.get_data()[offset..];

        return try decode_name(self.owner.get_data(), domain_start, allocator);
    }

    pub fn set_mx_domain(self: *MXRecord, mx_domain: []const u8) (DNSLayer.DNSParseError || LayerError || Allocator.Error)!void {
        const data = self.get_data();

        var offset: usize = 0;

        advance_past_name(data, &offset);

        const rd_len_offset = offset + QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH + TTL_LENGTH;

        offset += (QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH + TTL_LENGTH + RD_LENGTH + MX_PREFERENCE_VALUE_LENGTH);

        var cur_len: usize = 0;

        advance_past_name(self.get_data()[offset..self.length], &cur_len);

        if (mx_domain.len > cur_len) {
            const extend_len: usize = mx_domain.len - cur_len;

            _ = try self.owner.extend_buffer(offset, extend_len);

            self.length += extend_len;

            var next_rec = self.next_answer;
            while (next_rec) |rr| {
                rr.set_offset(rr.get_offset() + extend_len);
                next_rec = rr.next();
            }
        }

        if (mx_domain.len < cur_len) {
            const shorten_len: usize = cur_len - mx_domain.len;

            const end = offset + mx_domain.len;

            try self.owner.shorten_buffer(end, shorten_len);

            self.length -= shorten_len;

            var next_rec = self.next_answer;

            while (next_rec) |rr| {
                rr.set_offset(rr.get_offset() - shorten_len);
                next_rec = rr.next();
            }
        }

        std.mem.writeInt(
            u16,
            @ptrCast(self.get_data_mut()[rd_len_offset .. rd_len_offset + RD_LENGTH].ptr),
            @intCast(mx_domain.len),
            .big,
        );

        @memmove(self.get_data_mut()[offset .. offset + mx_domain.len], mx_domain);
    }

    pub fn to_string(self: *MXRecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]const u8 {
        var list: std.ArrayList(u8) = .empty;

        const name = try self.get_name(allocator);
        defer allocator.free(name);
        const ttl = try std.fmt.allocPrint(allocator, "{d}", .{self.get_ttl()});
        defer allocator.free(ttl);

        const type_s = @tagName(self.get_rr_type());
        const class_s = @tagName(self.get_class());
        const mx = try self.get_mx_domain(allocator);
        defer allocator.free(mx);

        const space = ". ";
        const dot = '.';

        try list.appendSlice(allocator, name);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, ttl);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, type_s);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, class_s);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, mx);
        try list.append(allocator, dot);

        return try list.toOwnedSlice(allocator);
    }

    pub fn deinit(self: *MXRecord) void {
        self.owner.deinit();
    }
};

pub const PTRRecord = struct {
    offset: usize,
    length: usize,
    owner: TLVOwner,
    next_answer: ?*AnswerRecord = null,
    prev_answer: ?*AnswerRecord = null,

    pub fn init(
        name: []const u8,
        class: DnsClass,
        ttl: u32,
        domain_name: []const u8,
        allocator: Allocator,
    ) (LayerError || Allocator.Error)!PTRRecord {
        var owner = try init_record(name, .PTR, class, allocator);

        _ = try owner.extend_buffer(owner.get_data().len, domain_name.len - COMPRESSION_PTR_LENGTH);

        var offset: usize = 0;

        advance_past_name(owner.get_data(), &offset);

        offset += GenericRecord.TTL_OFFSET_FROM_NAME;

        std.mem.writeInt(
            u32,
            @ptrCast(owner.get_data()[offset .. offset + TTL_LENGTH].ptr),
            ttl,
            .big,
        );

        offset += TTL_LENGTH;

        std.mem.writeInt(u16, @ptrCast(owner.get_data()[offset .. offset + RD_LENGTH].ptr), @intCast(domain_name.len), .big);

        offset += RD_LENGTH;

        @memmove(owner.get_data()[offset .. offset + domain_name.len], domain_name);

        const rec = PTRRecord{
            .offset = 0,
            .length = owner.get_data().len,

            .owner = owner,
        };

        return rec;
    }

    pub fn get_data(self: *PTRRecord) []const u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_data_mut(self: *PTRRecord) []u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    /// returns the PTR Name. e.g. "113.30.251.142.in-addr.arpa"
    pub fn get_name(self: *PTRRecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        var offset: usize = 0;

        advance_past_name(self.get_data(), &offset);

        return try decode_name(self.owner.get_data(), self.get_data()[0..offset], allocator);
    }

    /// sets the PTR Name. e.g. name="113.30.251.142.in-addr.arpa"
    pub fn set_name(self: *PTRRecord, name: []const u8) (LayerError || Allocator.Error)!void {
        var grec: *GenericRecord = @ptrCast(self);
        try grec.set_name(name);
    }

    pub fn get_rr_type(self: *PTRRecord) QueryType {
        return get_q_type(self.get_data());
    }

    pub fn get_class(self: *PTRRecord) DnsClass {
        return get_dns_class(self.get_data());
    }

    pub fn set_class(self: *PTRRecord, class: DnsClass) void {
        return set_dns_class(self.get_data_mut(), class);
    }

    pub fn get_ttl(self: *PTRRecord) u32 {
        var grec: *GenericRecord = @ptrCast(self);
        return grec.get_ttl();
    }

    pub fn set_ttl(self: *PTRRecord, ttl: u32) void {
        var grec: *GenericRecord = @ptrCast(self);
        return grec.set_ttl(ttl);
    }

    pub fn get_rd_len(self: *PTRRecord) u16 {
        var grec: *GenericRecord = @ptrCast(self);
        return grec.get_rd_len();
    }

    pub fn get_domain(self: *PTRRecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        var grec: *GenericRecord = @ptrCast(self);
        const rdata = grec.get_rdata();
        return try decode_name(self.owner.get_data(), rdata, allocator);
    }

    /// set the rdata (domain part) of the record to the domain provided
    pub fn set_domain(self: *PTRRecord, domain: []const u8) (LayerError || Allocator.Error)!void {
        var grec: *GenericRecord = @ptrCast(self);
        try grec.set_rdata(domain);
    }

    pub fn to_string(self: *PTRRecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]const u8 {
        var list: std.ArrayList(u8) = .empty;

        const name = try self.get_name(allocator);
        defer allocator.free(name);
        const ttl = try std.fmt.allocPrint(allocator, "{d}", .{self.get_ttl()});
        defer allocator.free(ttl);

        const type_s = @tagName(self.get_rr_type());
        const class_s = @tagName(self.get_class());
        const domain = try self.get_domain(allocator);
        defer allocator.free(domain);

        const space = ". ";
        const dot = '.';

        try list.appendSlice(allocator, name);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, ttl);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, type_s);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, class_s);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, domain);
        try list.append(allocator, dot);

        return try list.toOwnedSlice(allocator);
    }

    pub fn deinit(self: *PTRRecord) void {
        self.owner.deinit();
    }
};

pub const SOARecord = struct {
    offset: usize,
    length: usize,
    owner: TLVOwner,
    next_answer: ?*AnswerRecord = null,
    prev_answer: ?*AnswerRecord = null,

    pub const SERIAL_NUMBER_LENGTH = @sizeOf(u32);
    pub const REFRESH_INTERVAL_LENGTH = @sizeOf(u32);
    pub const RETRY_INTERVAL_LENGTH = @sizeOf(u32);
    pub const EXPIRE_LIMIT_LENGTH = @sizeOf(u32);
    pub const MIN_TTL_LENGTH = TTL_LENGTH;

    const MNAME_OFFSET_FROM_NAME = GenericRecord.RDATA_OFFSET_FROM_NAME;

    const RETRY_INTERVAL_OFFSET_FROM_RNAME = SERIAL_NUMBER_LENGTH + REFRESH_INTERVAL_LENGTH;
    const EXPIRE_LIMIT_OFFSET_FROM_RNAME = RETRY_INTERVAL_OFFSET_FROM_RNAME + RETRY_INTERVAL_LENGTH;
    const MIN_TTL_OFFSET_FROM_RNAME = EXPIRE_LIMIT_OFFSET_FROM_RNAME + EXPIRE_LIMIT_LENGTH;

    pub fn init(
        name: []const u8,
        class: DnsClass,
        ttl: u32,
        primary_ns: []const u8,
        responsible_mbox: []const u8,
        serial: u32,
        refresh_interval: u32,
        retry_interval: u32,
        expire_limit: u32,
        min_ttl: u32,
        allocator: Allocator,
    ) (LayerError || Allocator.Error)!SOARecord {
        const initial_len = name.len +
            QUERY_TYPE_LENGTH +
            CLASS_TYPE_LENGTH +
            TTL_LENGTH +
            RD_LENGTH +
            primary_ns.len +
            responsible_mbox.len +
            SERIAL_NUMBER_LENGTH +
            REFRESH_INTERVAL_LENGTH +
            RETRY_INTERVAL_LENGTH +
            EXPIRE_LIMIT_LENGTH +
            MIN_TTL_LENGTH;

        var owner = TLVOwner{ .owned_buffer = .init_empty(allocator) };

        const buf = try owner.extend_buffer(0, initial_len);

        @memmove(buf[0..name.len], name);

        var offset = name.len;

        std.mem.writeInt(
            u16,
            @ptrCast(buf[offset .. offset + QUERY_TYPE_LENGTH].ptr),
            @intFromEnum(QueryType.SOA),
            .big,
        );

        offset += QUERY_TYPE_LENGTH;

        std.mem.writeInt(
            u16,
            @ptrCast(buf[offset .. offset + CLASS_TYPE_LENGTH].ptr),
            @intFromEnum(class),
            .big,
        );

        offset += CLASS_TYPE_LENGTH;

        std.mem.writeInt(
            u32,
            @ptrCast(buf[offset .. offset + TTL_LENGTH].ptr),
            ttl,
            .big,
        );

        offset += TTL_LENGTH;

        std.mem.writeInt(
            u16,
            @ptrCast(buf[offset .. offset + RD_LENGTH].ptr),
            @intCast(initial_len - (name.len + QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH + TTL_LENGTH + RD_LENGTH)),
            .big,
        );

        offset += RD_LENGTH;

        @memmove(buf[offset .. offset + primary_ns.len], primary_ns);

        offset += primary_ns.len;

        @memmove(buf[offset .. offset + responsible_mbox.len], responsible_mbox);

        offset += responsible_mbox.len;

        std.mem.writeInt(
            u32,
            @ptrCast(buf[offset .. offset + SERIAL_NUMBER_LENGTH].ptr),
            serial,
            .big,
        );

        offset += SERIAL_NUMBER_LENGTH;

        std.mem.writeInt(
            u32,
            @ptrCast(buf[offset .. offset + REFRESH_INTERVAL_LENGTH].ptr),
            refresh_interval,
            .big,
        );

        offset += REFRESH_INTERVAL_LENGTH;

        std.mem.writeInt(
            u32,
            @ptrCast(buf[offset .. offset + RETRY_INTERVAL_LENGTH].ptr),
            retry_interval,
            .big,
        );

        offset += RETRY_INTERVAL_LENGTH;

        std.mem.writeInt(
            u32,
            @ptrCast(buf[offset .. offset + EXPIRE_LIMIT_LENGTH].ptr),
            expire_limit,
            .big,
        );

        offset += EXPIRE_LIMIT_LENGTH;

        std.mem.writeInt(
            u32,
            @ptrCast(buf[offset .. offset + MIN_TTL_LENGTH].ptr),
            min_ttl,
            .big,
        );

        offset += MIN_TTL_LENGTH;

        return SOARecord{
            .offset = 0,
            .length = initial_len,

            .owner = owner,
        };
    }

    pub fn get_data(self: *SOARecord) []const u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_data_mut(self: *SOARecord) []u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn get_name(self: *SOARecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        return try decode_name(self.owner.get_data(), self.get_data()[0..], allocator);
    }

    pub fn set_name(self: *SOARecord, name: []const u8) (LayerError || Allocator.Error)!void {
        var grec: *GenericRecord = @ptrCast(self);
        return grec.set_name(name);
    }

    pub fn get_rr_type(self: *SOARecord) QueryType {
        return get_q_type(self.get_data());
    }

    pub fn set_class(self: *SOARecord, qclass: DnsClass) void {
        var grec: *GenericRecord = @ptrCast(self);
        grec.set_class(qclass);
    }

    pub fn get_class(self: *SOARecord) DnsClass {
        return get_dns_class(self.get_data());
    }

    pub fn get_ttl(self: *SOARecord) u32 {
        var grec: *GenericRecord = @ptrCast(self);
        return grec.get_ttl();
    }

    pub fn set_ttl(self: *SOARecord, ttl: u32) void {
        var grec: *GenericRecord = @ptrCast(self);
        return grec.set_ttl(ttl);
    }

    pub fn get_rd_len(self: *SOARecord) u16 {
        var grec: *GenericRecord = @ptrCast(self);
        return grec.get_rd_len();
    }

    fn set_soa_name(self: *SOARecord, offset: usize, rdata: []const u8) (LayerError || Allocator.Error)!void {
        const initial_offset: usize = offset;
        var length: usize = 0;

        const data = self.get_data();

        advance_past_name(data[initial_offset..], &length);

        const cur_rdata_len: usize = length;

        var diff: isize = 0;

        if (cur_rdata_len < rdata.len) {
            const extend_len = rdata.len - cur_rdata_len;

            diff = @intCast(extend_len);

            const slice = try self.owner.extend_buffer(initial_offset + cur_rdata_len, extend_len);
            self.length += slice.len;

            // increase the proceeding layers offset by the shorten_len
            var next_rec = self.next_answer;
            while (next_rec) |rr| {
                rr.set_offset(rr.get_offset() + extend_len);
                next_rec = rr.next();
            }
        }
        if (cur_rdata_len > rdata.len) {
            const shorten_len = cur_rdata_len - rdata.len;

            diff = -@as(isize, @intCast(shorten_len));

            try self.owner.shorten_buffer(initial_offset + rdata.len, shorten_len);

            self.length -= shorten_len;

            // decrease the proceeding layers offset by the shorten_len
            var next_rec = self.next_answer;
            while (next_rec) |rr| {
                rr.set_offset(rr.get_offset() - shorten_len);
                next_rec = rr.next();
            }
        }

        @memmove(self.get_data_mut()[initial_offset .. initial_offset + rdata.len], rdata);

        var rd_len_offset: usize = 0;

        advance_past_name(self.get_data(), &rd_len_offset);

        rd_len_offset += GenericRecord.RD_LENGTH_OFFSET_FROM_NAME;

        const current_rd_len = std.mem.readInt(
            u16,
            @ptrCast(self.get_data()[rd_len_offset .. rd_len_offset + RD_LENGTH].ptr),
            .big,
        );

        const new_rd_len = @as(isize, @intCast(current_rd_len)) + diff;

        // set the RD_LEN value the len of the rdata provided/written as big endian
        std.mem.writeInt(
            u16,
            @ptrCast(self.get_data_mut()[rd_len_offset .. rd_len_offset + RD_LENGTH].ptr),
            @intCast(new_rd_len),
            .big,
        );
    }

    pub fn set_mname(self: *SOARecord, mname: []const u8) (LayerError || Allocator.Error)!void {
        var offset: usize = 0;

        advance_past_name(self.get_data(), &offset);

        offset += MNAME_OFFSET_FROM_NAME;

        try self.set_soa_name(offset, mname);
    }

    /// Primary Name Server
    pub fn get_mname(self: *SOARecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        var offset: usize = 0;

        advance_past_name(self.get_data(), &offset);

        offset += MNAME_OFFSET_FROM_NAME;

        if (self.get_data().len < offset) {
            return "";
        }

        return try decode_name(self.owner.get_data(), self.get_data()[offset..], allocator);
    }

    pub fn set_rname(self: *SOARecord, rname: []const u8) (LayerError || Allocator.Error)!void {
        var offset: usize = 0;

        advance_past_name(self.get_data(), &offset);

        offset += MNAME_OFFSET_FROM_NAME;

        advance_past_name(self.get_data(), &offset);

        try self.set_soa_name(offset, rname);
    }

    /// Responsible Authorities Mailbox
    pub fn get_rname(self: *SOARecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
        var offset: usize = 0;

        // advance past query name
        advance_past_name(self.get_data(), &offset);

        // advance past
        offset += MNAME_OFFSET_FROM_NAME;

        // advance past mname
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

        // Skip TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)
        offset += MNAME_OFFSET_FROM_NAME;

        // advance offset past MNAME
        advance_past_name(self.get_data(), &offset);

        // advance offset past RNAME
        advance_past_name(self.get_data(), &offset);

        if (self.get_data().len < offset + TTL_LENGTH) {
            return 0;
        }

        return std.mem.readInt(
            u32,
            @ptrCast(data[offset .. offset + TTL_LENGTH].ptr),
            .big,
        );
    }

    pub fn get_refresh_interval(self: *SOARecord) u32 {
        const data = self.get_data();
        var offset: usize = 0;

        // advance offset past NAME
        advance_past_name(self.get_data(), &offset);

        // At this point, offset points to the byte AFTER the last label's null terminator
        // So we're now at the TYPE field

        // Skip TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)

        offset += MNAME_OFFSET_FROM_NAME;

        // adance offset past MNAME
        advance_past_name(self.get_data(), &offset);
        // advance offset past RNAME
        advance_past_name(self.get_data(), &offset);

        // advance past serial
        offset += SERIAL_NUMBER_LENGTH;

        if (self.get_data().len < offset + TTL_LENGTH) {
            return 0;
        }

        return std.mem.readInt(
            u32,
            @ptrCast(data[offset .. offset + TTL_LENGTH].ptr),
            .big,
        );
    }

    pub fn get_retry_interval(self: *SOARecord) u32 {
        const data = self.get_data();
        var offset: usize = 0;

        // advance offset past NAME
        advance_past_name(self.get_data(), &offset);

        offset += MNAME_OFFSET_FROM_NAME;

        // adance offset past MNAME
        advance_past_name(self.get_data(), &offset);

        // advance offset past RNAME
        advance_past_name(self.get_data(), &offset);

        // advance past serial
        offset += RETRY_INTERVAL_OFFSET_FROM_RNAME;

        if (self.get_data().len < offset + TTL_LENGTH) {
            return 0;
        }

        return std.mem.readInt(
            u32,
            @ptrCast(data[offset .. offset + TTL_LENGTH].ptr),
            .big,
        );
    }

    pub fn get_expire_limit(self: *SOARecord) u32 {
        const data = self.get_data();
        var offset: usize = 0;

        // advance offset past NAME
        advance_past_name(self.get_data(), &offset);

        // Skip TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)

        offset += MNAME_OFFSET_FROM_NAME;

        // adance offset past MNAME
        advance_past_name(self.get_data(), &offset);

        // advance offset past RNAME
        advance_past_name(self.get_data(), &offset);

        // advance past serial
        offset += EXPIRE_LIMIT_OFFSET_FROM_RNAME;

        if (self.get_data().len < offset + TTL_LENGTH) {
            return 0;
        }

        return std.mem.readInt(
            u32,
            @ptrCast(data[offset .. offset + TTL_LENGTH].ptr),
            .big,
        );
    }

    pub fn get_minimum_ttl(self: *SOARecord) u32 {
        const data = self.get_data();
        var offset: usize = 0;

        // advance offset past NAME
        advance_past_name(self.get_data(), &offset);

        //  Skip  TYPE (2),             CLASS (2),          TTL (4),        RDLENGTH (2)
        offset += MNAME_OFFSET_FROM_NAME;

        // adance offset past MNAME
        advance_past_name(self.get_data(), &offset);

        // advance offset past RNAME
        advance_past_name(self.get_data(), &offset);

        // advance past serial
        offset += MIN_TTL_OFFSET_FROM_RNAME;

        if (self.get_data().len < offset + MIN_TTL_LENGTH) {
            return 0;
        }

        return std.mem.readInt(
            u32,
            @ptrCast(data[offset .. offset + MIN_TTL_LENGTH].ptr),
            .big,
        );
    }

    pub fn to_string(self: *SOARecord, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]const u8 {
        var list: std.ArrayList(u8) = .empty;

        const name = try self.get_name(allocator);
        defer allocator.free(name);
        const ttl = try std.fmt.allocPrint(allocator, "{d}", .{self.get_ttl()});
        defer allocator.free(ttl);
        const type_s = @tagName(self.get_rr_type());
        const class_s = @tagName(self.get_class());
        const rname = try self.get_rname(allocator);
        defer allocator.free(rname);
        const mname = try self.get_mname(allocator);
        defer allocator.free(mname);

        const space = ". ";
        const dot = '.';

        try list.appendSlice(allocator, name);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, ttl);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, type_s);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, class_s);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, mname);
        try list.appendSlice(allocator, space);
        try list.appendSlice(allocator, rname);
        try list.append(allocator, dot);

        return try list.toOwnedSlice(allocator);
    }

    pub fn deinit(self: *SOARecord) void {
        self.owner.deinit();
    }
};

const SVC_PARAM_KEY = enum(u16) {
    mandatory = 0,
    alpn = 1,
    no_default_alpn = 2,
    port = 3,
    ipv4hint = 4,
    ech = 5,
    ipv6hint = 6,
    dohpath = 7,
    ohttp = 8,
    tls_supported_groups = 9,
    docpath = 10,
    _,
};

//    Extended Reference for All SvcParamKey Types
//    KeyName Value Format Fixed Length? Notes
//    0 mandatory List of u16 keys  No variable length list of SvcParamKey values that must be understood
//    1 alpn Length-prefixed strings   No  Variable number of ALPN IDs (e.g., h3, h2, http/1.1)
//    2 no-default-alpn  Empty   Yes (0 bytes)  No value; presence alone is meaningful
//    3 port  u16 (2 bytes)   Yes (2 bytes)  Exactly one port number
//    4 ipv4hint  List of IPv4 (4 bytes each)   No  Variable number of IPv4 addresses
//    5 ech  Binary ECHConfigList   No  Variable length ECH configuration
//    6 ipv6hint  List of IPv6 (16 bytes each)   No  Variable number of IPv6 addresses
//    7 dohpath  Length-prefixed string   No  DNS over HTTPS URI template
//    8 ohttp  Binary OHTTP configuration   No  Oblivious HTTP configuration
//    9 tls-supported-groups  List of u16 (2 bytes each)   No  Variable number of TLS group IDs
//    10 docpath  Length-prefixed string   No  DNS over DNS-over-QUIC path

// TODO: Rename to indicate compression ptr handling
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
