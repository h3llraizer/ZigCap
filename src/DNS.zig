const std = @import("std");
const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;
const LayerError = @import("ProtocolEnums.zig").LayerError;
const LayerOwner = @import("Layer.zig").LayerOwner;
const Layer = @import("Packet.zig").Layer;
const LayerIface = @import("LayerIface.zig").LayerIface;
const Buffer = @import("Buffer.zig").Buffer;
const IPv4 = @import("IPv4.zig");
const IPv6 = @import("IPv6.zig");
const DNSEnums = @import("DNSEnums.zig");
const DNSRecordTypes = @import("DNSRecordTypes.zig");

const print = std.debug.print;
const Allocator = std.mem.Allocator;

pub const QueryType = DNSEnums.QueryType;
pub const DnsClass = DNSEnums.DnsClass;

const GenericRecord = DNSRecordTypes.GenericRecord;
const ARecord = DNSRecordTypes.ARecord;
const AAAARecord = DNSRecordTypes.AAAARecord;
const CNAMERecord = DNSRecordTypes.CNAMERecord;
const TXTRecord = DNSRecordTypes.TXTRecord;
const MXRecord = DNSRecordTypes.MXRecord;
const PTRRecord = DNSRecordTypes.PTRRecord;

/// Use to build a DNSQuery.
/// Buffer struct is created using the allocator which you provide
pub const DNSQuery = struct {
    qtype: QueryType,
    qclass: DnsClass,
    buffer: Buffer,

    pub fn init(qname: []const u8, qtype: QueryType, qclass: DnsClass, allocator: Allocator) !DNSQuery {
        var self = DNSQuery{ .qtype = undefined, .qclass = undefined, .buffer = .init_empty(allocator) };
        const extend_len = qname.len + 6;

        var query_buf = try self.extend_query_buf(extend_len);

        // Slice buffer starting at offset
        var qbuffer = query_buf[0..];

        // Write QNAME (labels)
        var buf_offset: usize = 0;
        var it = std.mem.splitScalar(u8, qname, '.');
        while (it.next()) |label| {
            qbuffer[buf_offset] = @intCast(label.len);
            buf_offset += 1;
            std.mem.copyForwards(u8, qbuffer[buf_offset .. buf_offset + label.len], label);
            buf_offset += label.len;
        }
        qbuffer[buf_offset] = 0; // null terminator
        buf_offset += 1;

        // Write QTYPE
        std.mem.writeInt(u16, @ptrCast(qbuffer[buf_offset .. buf_offset + 2]), @intCast(@intFromEnum(qtype)), .big);
        buf_offset += 2;

        // Write QCLASS
        std.mem.writeInt(u16, @ptrCast(qbuffer[buf_offset .. buf_offset + 2]), @intCast(@intFromEnum(qclass)), .big);
        buf_offset += 2;

        self.qtype = qtype;
        self.qclass = qclass;

        return self;
    }

    pub fn get_data(self: *DNSQuery) []u8 {
        return self.buffer.buffer.items;
    }

    /// doesn't work yet
    /// TODO: fix
    pub fn decode_name(self: *DNSQuery) ![]const u8 {
        var offset: usize = 0;
        const raw = self.get_data();
        const start = offset;
        var end = start;

        // Single-byte pointer compression support
        if (end >= raw.len)
            return error.InvalidPacket;

        if ((raw[end] & 0xC0) == 0xC0) {
            // pointer: 2 bytes
            if (end + 1 >= raw.len)
                return error.InvalidPacket;
            offset += 2;
            return raw[end .. end + 2]; // just return the pointer slice for now
        } else {
            // label sequence
            while (end < raw.len and raw[end] != 0) : (end += raw[end] + 1) {}
            if (end >= raw.len)
                return error.InvalidPacket;
            offset = end + 1; // move past null terminator
            return raw[start..offset];
        }
    }

    pub fn extend_query_buf(self: *DNSQuery, length: usize) ![]u8 {
        return try self.buffer.extend(0, length);
    }

    pub fn deinit(self: *DNSQuery) void {
        self.buffer.deinit();
    }

    pub const QError = error{
        LabelTooLong, // A label length exceeds the remaining buffer
        MemoryAllocationFailed, // Allocator failed to create a node
    };
};

// TODO: incorperate with AnswerRecord
pub const DNSAnswer = struct {
    qtype: QueryType,
    qclass: DnsClass,
    ttl: u32,
    rdlength: u16,
    buffer: Buffer,

    pub fn init(qtype: QueryType, qclass: DnsClass, ttl: u32, rdlength: u16, allocator: Allocator) DNSAnswer {
        const self = DNSAnswer{ .qtype = qtype, .qclass = qclass, .ttl = ttl, .rdlength = rdlength, .buffer = .init_empty(allocator) };
        return self;
    }
};

pub const DNSHeaderFlags = packed struct {
    /// Response Code
    rcode: u4 = 0,
    /// Reserved (must be 0)
    z: u3 = 0,
    /// Recursion Available
    ra: u1 = 0,
    /// Recursion Desired
    rd: u1 = 0,
    /// Truncation
    tc: u1 = 0,
    /// Authoritative Answer
    aa: u1 = 0,
    /// Operaiton Code
    opcode: u4 = 0,
    // Query/Response
    qr: u1 = 0,

    /// Set the Response Code of the DNSHeader
    /// Common resonse codes can be found in DNS.DNSRcode
    /// the enum isn't explicitly required here but @intFromEnum can be used for convenience
    pub fn set_rcode(self: *DNSHeaderFlags, rcode: u4) void {
        self.rcode = rcode;
    }

    /// Set Recursion Available
    /// can be either 1 for "true"/yes and 0 for "false"/no
    pub fn set_ra(self: *DNSHeaderFlags, ra: u1) void {
        self.ra = ra;
    }

    /// Set Recursion Desired
    /// can be either 1 for "true"/yes and 0 for "false"/no
    pub fn set_rd(self: *DNSHeaderFlags, rd: u1) void {
        self.rd = rd;
    }

    /// Set Truncation
    /// can be either 1 for "true"/yes and 0 for "false"/no
    pub fn set_tc(self: *DNSHeaderFlags, rc: u1) void {
        self.rc = rc;
    }

    /// Set Authoritative Answer
    /// can be either 1 for "true"/yes and 0 for "false"/no
    pub fn set_aa(self: *DNSHeaderFlags, aa: u1) void {
        self.aa = aa;
    }

    /// Set Operation Code
    /// Common operation codes can be found in DNS.DNSOpcode
    /// the enum isn't explicitly required here but @intFromEnum can be used for convenience
    pub fn set_opcode(self: *DNSHeaderFlags, opcode: u4) void {
        self.opcode = opcode;
    }
};

pub const DNSHeaderSize: usize = 12;

/// Standard DNS Header.
/// Setters take native values and byteswap before set
/// Getters return byteswapped values
pub const DNSHeader = extern struct {
    /// Identification / Transaction ID
    id: u16,
    /// QR, Opcode, AA, TC, RD, RA, Z, RCODE packed - see DNSHeaderFlags
    flags: u16,
    /// Number of questions
    qdcount: u16,
    /// Number of answer ResponseRecords
    ancount: u16,
    /// Number of authority ResponseRecords
    nscount: u16,
    /// Number of additional ResponseRecords
    arcount: u16,

    pub fn set_id(self: *DNSHeader, id: u16) void {
        self.id = @byteSwap(id);
    }

    pub fn get_id(self: *const DNSHeader) u16 {
        return @byteSwap(self.id);
    }

    /// sets qdcount to the value provided as BE
    pub fn set_qdcount(self: *DNSHeader, qdcount: u16) void {
        self.qdcount = @byteSwap(qdcount);
    }

    /// returns the qdcount as LE
    pub fn get_qdcount(self: *const DNSHeader) u16 {
        return @byteSwap(self.qdcount);
    }

    pub fn set_ancount(self: *DNSHeader, ancount: u16) void {
        self.ancount = @byteSwap(ancount);
    }

    pub fn get_ancount(self: *const DNSHeader) u16 {
        return @byteSwap(self.ancount);
    }

    pub fn set_nscount(self: *DNSHeader, nscount: u16) void {
        self.nscount = @byteSwap(nscount);
    }

    pub fn get_nscount(self: *const DNSHeader) u16 {
        return @byteSwap(self.nscount);
    }

    pub fn set_arcount(self: *DNSHeader, arcount: u16) void {
        self.arcount = @byteSwap(arcount);
    }

    pub fn get_arcount(self: *const DNSHeader) u16 {
        return @byteSwap(self.arcount);
    }

    //TODO: implement get_flags_mutable
    pub fn get_flags(self: *DNSHeader) *DNSHeaderFlags {
        self.flags = @byteSwap(self.flags);
        return @ptrCast(&self.flags);
    }

    pub fn get_flags_immutable(self: *DNSHeader) *const DNSHeaderFlags {
        self.flags = @byteSwap(self.flags);
        const flags: *const DNSHeaderFlags = @ptrCast(&self.flags);
        return flags;
    }
};

/// Different to the DNSQuery struct which you create a query from scratch with (see DNSQuery)
/// Query struct stores offset and length of the raw query so the DNSLayer can manage it (similar to Packet.Layer)
pub const Query = struct {
    offset: usize,
    length: usize,
    qtype: QueryType,
    qclass: DnsClass,
    layer: *DNSLayer,
    next_query: ?*Query = null,

    pub fn init(offset: usize, length: usize, qtype: QueryType, qclass: DnsClass, layer: *DNSLayer) Query {
        return Query{ .offset = offset, .length = length, .qtype = qtype, .qclass = qclass, .layer = layer };
    }

    pub fn get_data(self: *Query) []const u8 {
        return self.layer.get_data()[self.offset .. self.offset + self.length];
    }

    pub fn decode_qname(self: *Query, allocator: Allocator) ![]const u8 {
        return try decodeQname(allocator, self.get_data());
    }
};

/// This tagged union is an interface over the concrete Answer Record Types.
/// currently implemented record types are:
///     A,
///     AAAA,
///     CNAME,
///     TXT,
///     MX,
///     PTR,
///     Generic,
pub const AnswerRecord = union(enum) {
    a: ARecord,
    aaaa: AAAARecord,
    cname: CNAMERecord,
    txt: TXTRecord,
    mx: MXRecord,
    ptr: PTRRecord,
    generic: GenericRecord,

    pub fn init(offset: usize, length: usize, qtype: QueryType, qclass: DnsClass, layer: *DNSLayer) AnswerRecord {
        switch (qtype) {
            // TODO: reduce repeating code
            .A => {
                return AnswerRecord{ .a = .{ .offset = offset, .length = length, .qtype = qtype, .qclass = qclass, .layer = layer } };
            },

            .AAAA => {
                return AnswerRecord{ .aaaa = .{ .offset = offset, .length = length, .qtype = qtype, .qclass = qclass, .layer = layer } };
            },

            .CNAME => {
                return AnswerRecord{ .cname = .{ .offset = offset, .length = length, .qtype = qtype, .qclass = qclass, .layer = layer } };
            },

            .TXT => {
                return AnswerRecord{ .txt = .{ .offset = offset, .length = length, .qtype = qtype, .qclass = qclass, .layer = layer } };
            },

            .MX => {
                return AnswerRecord{ .mx = .{ .offset = offset, .length = length, .qtype = qtype, .qclass = qclass, .layer = layer } };
            },

            .PTR => {
                return AnswerRecord{ .ptr = .{ .offset = offset, .length = length, .qtype = qtype, .qclass = qclass, .layer = layer } };
            },

            .GENERIC => {
                return AnswerRecord{ .generic = .{ .offset = offset, .length = length, .qtype = qtype, .qclass = qclass, .layer = layer } };
            },

            else => return AnswerRecord{ .generic = .{ .offset = offset, .length = length, .qtype = qtype, .qclass = qclass, .layer = layer } },
        }
    }

    pub fn get_name(self: *AnswerRecord, allocator: Allocator) ![]u8 {
        const data = self.get_data();
        // the length of the name is not known so just take use the offset of this RR
        const layer = self.get_layer();
        return try DNSRecordTypes.decode_name(layer.get_data(), data, allocator);
    }

    pub fn get_name_raw(self: *AnswerRecord) []const u8 {
        const data = self.get_data();
        return data;
    }

    pub fn get_layer(self: *AnswerRecord) *DNSLayer {
        return switch (self.*) {
            inline else => |*rr| rr.layer,
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
        const ttl: u32 = std.mem.readInt(u32, data[6..10], .big);
        return ttl;
    }

    pub fn set_ttl(self: *AnswerRecord, ttl: u32) void {
        const data = self.get_data_mut();
        std.mem.writeInt(u32, data[6..10], ttl, .big);
    }

    pub fn get_rr_type(self: *AnswerRecord) QueryType {
        return switch (self.*) {
            inline else => |*rr| rr.qtype,
        };
    }

    pub fn get_class_type(self: *AnswerRecord) DnsClass {
        return switch (self.*) {
            inline else => |*rr| rr.qclass,
        };
    }
};

/// DNSLayer represents the DNSHeader and it's queries and answers (if there are any)
/// Queries are stored as a singly linked list as most DNS packets usually contain only one query
/// Answers are stored as a doubly linked list as there is commonly more than one answer
pub const DNSLayer = struct {
    owner: LayerOwner,
    first_query: ?*Query = null,
    first_answer: ?*AnswerRecord = null,
    last_answer: ?*AnswerRecord = null,

    const Protocol = tcp_ip_protocol.dns;

    pub fn init(owner: LayerOwner) LayerError!DNSLayer {
        switch (owner) {
            .packet_layer => {
                const self = DNSLayer{
                    .owner = owner,
                };

                return self;
            },
            .owned_buffer => {
                var self = DNSLayer{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < DNSHeaderSize) {
                    const dns_data = try self.owner.owned_buffer.extend(buffer_len, DNSHeaderSize);

                    @memset(dns_data, 0);
                }

                return self;
            },
        }
    }

    fn get_allocator(self: *DNSLayer) Allocator {
        return self.owner.get_allocator();
    }

    pub fn get_data(self: *const DNSLayer) []u8 {
        return self.owner.get_data();
    }

    /// Get the payload (data after DNS header)
    pub fn get_payload(self: *DNSLayer) []const u8 {
        const data = self.get_data();

        if (data.len > DNSHeaderSize) {
            return data[DNSHeaderSize..]; // return remaining bytes after the header
        } else {
            return "";
        }
    }

    pub fn get_mutable_header(self: *const DNSLayer) *DNSHeader {
        const data = self.get_data();

        if (data.len < DNSHeaderSize) {
            std.debug.panic("DNS data len ({}) less than DNSHeaderSize", .{data.len});
        }

        const aligned_ptr: [*]align(@alignOf(DNSHeader)) u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    pub fn get_immutable_header(self: *const DNSLayer) *const DNSHeader {
        const data: []const u8 = self.get_data();

        if (data.len < DNSHeaderSize) {
            std.debug.panic("DNS data len ({}) less than DNSHeaderSize", .{data.len});
        }

        const aligned_ptr: [*]align(@alignOf(DNSHeader)) const u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    pub fn is_response(self: *DNSLayer) bool {
        const hdr = self.get_mutable_header();
        return hdr.get_flags().rcode == 1;
    }

    pub fn print_queries_meta(self: *DNSLayer) void {
        var count: usize = 0;
        var cur = self.first_query;
        while (cur) |query| {
            count += 1;
            print("count: {} offset: {} length: {}\n", .{ count, query.offset, query.length });
            cur = query.next_query;
        }
    }

    pub fn get_query_count(self: *DNSLayer) usize {
        var count: usize = 0;
        var cur = self.first_query;
        while (cur) |query| {
            count += 1;
            cur = query.next_query;
        }

        return count;
    }

    /// Sets DNS Header values to reflect Query and Answer count and perform byte swap for NBE order.
    /// Call this if you intend to send dns packet over the network or you need to undertake further analysis of the DNSHeader post modification
    pub fn validate_layer(self: *DNSLayer) void {
        var hdr = self.get_mutable_header();
        hdr.flags = @byteSwap(hdr.flags);
    }

    pub fn add_query(self: *DNSLayer, query: *DNSQuery) !void {
        var allocator = self.get_allocator();
        const q = try allocator.create(Query);
        const last_query = self.get_last_query();

        var start_offset = DNSHeaderSize;

        if (last_query) |last| {
            last.next_query = q;
            start_offset += last.length;
        } else {
            self.first_query = q;
        }

        const length = query.get_data().len;
        const offset = self.get_data().len;

        q.* = Query.init(offset, length, query.qtype, query.qclass, self);

        const qbuf = try self.extend_payload(start_offset, q.length);
        @memmove(qbuf, query.get_data());

        var hdr = self.get_mutable_header();
        var qdcount = hdr.get_qdcount();

        qdcount += 1;
        hdr.set_qdcount(qdcount);
    }

    fn decode_name(raw: []const u8, offset: *usize) ![]const u8 {
        const start = offset.*;
        var end = start;

        // Single-byte pointer compression support
        if (end >= raw.len)
            return error.InvalidPacket;

        if ((raw[end] & 0xC0) == 0xC0) {
            // pointer: 2 bytes
            if (end + 1 >= raw.len)
                return error.InvalidPacket;
            offset.* += 2;
            return raw[end .. end + 2]; // just return the pointer slice for now
        } else {
            // label sequence
            while (end < raw.len and raw[end] != 0) : (end += raw[end] + 1) {}
            if (end >= raw.len)
                return error.InvalidPacket;
            offset.* = end + 1; // move past null terminator
            return raw[start..offset.*];
        }
    }

    fn extend_payload(self: *DNSLayer, offset: usize, extend_len: usize) ![]u8 {
        var buf: []u8 = undefined;
        switch (self.owner) {
            .packet_layer => |layer| {
                buf = try layer.packet.extend_layer(layer, offset, extend_len); // TODO: extend at offset instead
            },
            .owned_buffer => |*buffer| {
                buf = try buffer.extend(offset, extend_len);
            },
        }

        return buf;
    }

    fn shorten_payload(self: *DNSLayer, offset: usize, shorten_len: usize) !void {
        switch (self.owner) {
            .packet_layer => |layer| {
                try layer.packet.shorten_layer(layer, offset, shorten_len);
            },
            .owned_buffer => |*buffer| {
                try buffer.shorten(offset, shorten_len);
            },
        }
    }

    /// call when creating DNS layer from existing data
    pub fn get_queries(self: *DNSLayer) !void {
        var allocator = self.get_allocator();
        const data = self.get_data();
        var offset: usize = DNSHeaderSize;

        const hdr = self.get_immutable_header();
        const qdcount = hdr.get_qdcount();

        var i: u32 = 0;
        while (i < qdcount) : (i += 1) {
            const qname_start = offset;

            // Walk labels
            while (offset < data.len and data[offset] != 0) {
                const len = data[offset];
                offset += 1;

                if (offset + len > data.len)
                    return LayerError.LayerInvalid;

                offset += len;
            }

            if (offset >= data.len)
                return LayerError.LayerInvalid;

            offset += 1; // skip null terminator

            // Skip QTYPE + QCLASS (4 bytes)
            if (offset + 4 > data.len)
                return LayerError.LayerInvalid;

            const qtype = std.mem.readInt(u16, @ptrCast(data[offset .. offset + 2]), .big);
            const qclass = std.mem.readInt(u16, @ptrCast(data[offset + 2 .. offset + 4]), .big);

            const whole_record_end = offset + 4;
            const whole_record = data[qname_start..whole_record_end];

            const query = try allocator.create(Query);

            const qclass_e: DnsClass = @enumFromInt(qclass);
            const qtype_e: QueryType = @enumFromInt(qtype);

            // Store the starting offset of this query
            query.* = Query.init(qname_start, whole_record.len, qtype_e, qclass_e, self);

            // Link queries together
            const last_query = self.get_last_query();
            if (last_query) |last| {
                last.next_query = query;
            } else {
                self.first_query = query;
            }

            offset = whole_record_end; // Move to next query position
        }
    }

    pub fn get_remaining(self: *DNSLayer) !usize {
        var offset: usize = DNSHeaderSize;

        const q_sec_size: usize = try self.get_q_section_sz();
        offset += q_sec_size;

        return offset;
    }

    fn get_q_section_sz(self: *DNSLayer) !usize {
        var size: usize = 0;
        var query = self.get_first_query();

        while (query) |q| {
            size += q.get_data().len;
            size += 4;
            query = q.next_query;
        }

        return size;
    }

    pub fn get_first_query(self: DNSLayer) ?*Query {
        return self.first_query;
    }

    fn get_last_query(self: *DNSLayer) ?*Query {
        var cur = self.first_query;
        while (cur) |query| {
            if (query.next_query) |next| {
                cur = next;
            } else {
                return query;
            }
        }

        return null;
    }

    pub fn get_first_answer(self: *DNSLayer) ?*AnswerRecord {
        return self.first_answer;
    }

    pub fn get_last_answer(self: *DNSLayer) ?*AnswerRecord {
        return self.last_answer;
    }

    pub fn print_answers_meta(self: *DNSLayer) void {
        var cur = self.first_answer;
        while (cur) |ans| {
            print("answer: {s}\n\toffset: {}\n\tlength: {}\n\tdata: {x}\n", .{ @tagName(ans.get_rr_type()), ans.get_offset(), ans.get_length(), ans.get_data() });
            cur = ans.get_next_record();
        }
    }

    pub fn get_answer_count(self: *DNSLayer) usize {
        var count: usize = 0;
        var cur = self.first_answer;
        while (cur) |ans| {
            count += 1;
            cur = ans.get_next_record();
        }

        return count;
    }

    /// call when creating DNS layer from existing data
    pub fn get_answers(self: *DNSLayer) !void {
        var allocator = self.get_allocator();
        const data = self.get_data();
        var offset: usize = DNSHeaderSize;
        if (self.get_last_query()) |last| {
            offset += last.length;
        } else {
            try self.get_queries();
            if (self.get_last_query()) |last| {
                offset += last.length;
            } else {
                return error.GetQueriesFailed;
            }
        }

        const hdr = self.get_immutable_header();

        const ancount = hdr.get_ancount();

        var i: u32 = 0;
        while (i < ancount) : (i += 1) {
            if (offset + 12 > data.len) // minimum RR header size: NAME(2) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
                return error.InvalidPacket;

            // Parse NAME
            const name_offset = offset;
            //            _ = name_offset;
            // This can be a pointer/offset compression (0xC0..) or raw labels
            // decode_name function to handle pointers and labels
            const name_slice = try decode_name(data, &offset);
            _ = name_slice;

            // Parse TYPE
            const rtype = std.mem.readInt(u16, @ptrCast(data[offset .. offset + 2].ptr), .big);
            offset += 2;

            // Parse CLASS
            const rclass = std.mem.readInt(u16, @ptrCast(data[offset .. offset + 2].ptr), .big);
            offset += 2;

            // Parse TTL
            const ttl = std.mem.readInt(u32, @ptrCast(data[offset .. offset + 4].ptr), .big);
            offset += 4;

            _ = ttl;

            // Parse RDLENGTH
            const rdlength = std.mem.readInt(u16, @ptrCast(data[offset .. offset + 2].ptr), .big);
            offset += 2;

            if (offset + rdlength > data.len) {
                return error.InvalidPacket;
            }

            offset += rdlength;

            const whole_record = data[name_offset..offset];

            // Create a AnswerRecord "node" for AnswerRecord linkedlist
            const answer = try allocator.create(AnswerRecord);

            const rtype_e: QueryType = QueryType.from_u16(rtype);
            const class_e: DnsClass = @enumFromInt(rclass);

            answer.* = AnswerRecord.init(name_offset, whole_record.len, rtype_e, class_e, self);

            const last_answer = self.last_answer;

            // append to linkedlist
            if (last_answer) |last| { // if the last answer is not null
                last.set_next_record(answer); // set the last answer next answer to the answer created (answer being added)
                answer.set_prev_record(last); // set the answer created (answer being added)'s prev answer to the last answer
                self.last_answer = answer; // the last answer is now the answer that's being added
            } else { // there was no last answer
                self.first_answer = answer; // set first answer to this answer being added
                self.last_answer = answer; // set last answer to this answer being added
            }
        }
    }

    fn decompress(self: *DNSLayer) !void {
        self.find_cmprs_ptrs();
    }

    fn find_cmprs_ptrs(self: *DNSLayer) void {
        var record: ?*AnswerRecord = self.first_answer;
        while (record) |rec| {
            switch (rec.get_rr_type()) {
                .A => {
                    find_compression_ptrs_in_answer(rec.a.get_data()[0..2]);
                },
                .CNAME => {
                    find_compression_ptrs_in_answer(rec.cname.get_data());
                },
                else => {
                    record = rec.get_next_record();
                },
            }
            record = rec.get_next_record();
        }
    }

    fn find_compression_ptrs_in_answer(data: []const u8) void {
        var offset: usize = 0;

        while (offset < data.len - 1) {
            if (data[offset] & 0xC0 == 0xC0) {
                const ptr = data[offset .. offset + 2];
                const pointer: u16 = (@as(u16, data[offset] & 0x3F) << 8) | @as(u16, data[offset + 1]);
                std.debug.print("found compression ptr: ({}) {x} {}\n", .{ ptr.len, ptr, pointer });
            }

            offset += 1;
        }
    }

    pub fn to_string(self: *DNSLayer, allocator: Allocator) []const u8 {
        const hdr = self.get_mutable_header();
        const flags = hdr.get_flags();

        const id: u16 = std.mem.bigToNative(u16, hdr.id);

        const qr = flags.qr;
        const opcode = flags.opcode;
        const aa = flags.aa;
        const tc = flags.tc;
        const rd = flags.rd;
        const ra = flags.ra;
        const z = flags.z;
        const rcode = flags.rcode;

        const qdcount: u16 = std.mem.bigToNative(u16, hdr.qdcount);
        const ancount: u16 = std.mem.bigToNative(u16, hdr.ancount);
        const nscount: u16 = std.mem.bigToNative(u16, hdr.nscount);
        const arcount: u16 = std.mem.bigToNative(u16, hdr.arcount);

        const result = std.fmt.allocPrint(
            allocator,
            "DNS Layer: id: {} qr: {} opcode: {}  aa: {} tc: {} rd: {} ra: {} z: {} rcode: {} qdcount: {} ancount: {} nscount: {} arcount: {}",
            .{ id, qr, opcode, aa, tc, rd, ra, z, rcode, qdcount, ancount, nscount, arcount },
        ) catch |err| {
            std.debug.print("DNS allocPrint failed: {s}\n", .{@errorName(err)});
            return "";
        };

        return result;
    }

    pub fn get_protocol(self: *DNSLayer) tcp_ip_protocol {
        _ = self;
        return DNSLayer.Protocol;
    }

    fn destroy_queries(self: *DNSLayer) void {
        var allocator = self.get_allocator();
        var cur = self.first_query;

        while (cur) |query| {
            const next = query.next_query;
            allocator.destroy(query);
            cur = next;
        }
    }

    fn destroy_answers(self: *DNSLayer) void {
        var allocator = self.get_allocator();
        var cur = self.first_answer;

        while (cur) |answer| {
            const next = answer.get_next_record();
            allocator.destroy(answer);
            cur = next;
        }
    }

    pub fn get_next_layer_type(self: *DNSLayer, layer: *Layer) !?LayerIface {
        _ = self;
        _ = layer;
        return null;
    }

    pub fn deinit(self: *DNSLayer) void {
        self.destroy_queries(); // always destroy the query structs
        self.destroy_answers(); // always destroy the answer structs
        self.owner.deinit();
    }
};

/// Creates a domain name from a DNS label. The allocator creates an ArrayList to store the bytes and returns a mutable slice
/// The ArrayList is deinit'd before return but you must free the slice that is returned (it returns an ownedSlice)
pub fn decodeQname(allocator: Allocator, dns_label: []const u8) ![]u8 {
    var list = try std.ArrayList(u8).initCapacity(allocator, dns_label.len);
    defer list.deinit(allocator);

    var offset: usize = 0;
    var first = true;

    while (offset < dns_label.len and dns_label[offset] != 0) {
        const len = dns_label[offset];
        offset += 1;

        if (offset + len > dns_label.len) {
            print("offset + len: {} exceeds packet.\n", .{offset + len});
            return error.InvalidPacket;
        }

        if (!first) try list.append(allocator, '.');
        first = false;

        try list.appendSlice(allocator, dns_label[offset .. offset + len]);
        offset += len;
    }

    // if we never saw the terminating 0 byte, reject
    if (offset >= dns_label.len or dns_label[offset] != 0) return error.InvalidPacket;

    return list.toOwnedSlice(allocator);
}

comptime {
    if (@bitSizeOf(DNSHeader) != 96)
        @compileError("DNSHeaderBits must be exactly 96 bits (12 bytes)");
}
