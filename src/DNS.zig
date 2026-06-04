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
const NSRecord = DNSRecordTypes.NSRecord;
const SOARecord = DNSRecordTypes.SOARecord;

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

    comptime {
        if (@bitSizeOf(DNSHeader) != 96)
            @compileError("DNSHeaderBits must be exactly 96 bits (12 bytes)");
    }

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

    pub fn init(offset: usize, length: usize, qtype: QueryType, qclass: DnsClass, layer: *DNSLayer) AnswerRecord {
        switch (qtype) {
            // TODO: reduce repeating code
            .A => {
                return .{ .a = .{ .offset = offset, .length = length, .qclass = qclass, .layer = layer } };
            },

            .AAAA => {
                return .{ .aaaa = .{ .offset = offset, .length = length, .qclass = qclass, .layer = layer } };
            },

            .CNAME => {
                return .{ .cname = .{ .offset = offset, .length = length, .qclass = qclass, .layer = layer } };
            },

            .TXT => {
                return .{ .txt = .{ .offset = offset, .length = length, .qclass = qclass, .layer = layer } };
            },

            .MX => {
                return .{ .mx = .{ .offset = offset, .length = length, .qclass = qclass, .layer = layer } };
            },

            .PTR => {
                return .{ .ptr = .{ .offset = offset, .length = length, .qclass = qclass, .layer = layer } };
            },

            .NS => {
                return .{ .ns = .{ .offset = offset, .length = length, .qclass = qclass, .layer = layer } };
            },

            .SOA => {
                return .{ .soa = .{ .offset = offset, .length = length, .qclass = qclass, .layer = layer } };
            },

            .GENERIC => {
                return .{ .generic = .{ .offset = offset, .length = length, .qtype = qtype, .qclass = qclass, .layer = layer } };
            },

            else => return .{ .generic = .{ .offset = offset, .length = length, .qtype = qtype, .qclass = qclass, .layer = layer } },
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

        var offset: usize = 0;

        _ = DNSLayer.advance_past_name(self.get_data(), &offset) catch {
            print("error decoding name.\n", .{});
            return 0;
        };

        offset += 4; //  rrtype (2 bytes), class (2bytes)

        const ttl: u32 = std.mem.bytesToValue(u32, data[offset .. offset + @sizeOf(u32)]);

        return @byteSwap(ttl);
    }

    pub fn set_ttl(self: *AnswerRecord, ttl: u32) void {
        const data = self.get_data_mut();

        var offset: usize = 0;

        _ = DNSLayer.advance_past_name(self.get_data(), &offset) catch {
            print("error decoding name.\n", .{});
            return;
        };

        offset += 4; //  rrtype (2 bytes), class (2bytes)

        const ttl_ptr = std.mem.bytesAsValue(u32, data[offset .. offset + @sizeOf(u32)]);

        ttl_ptr.* = @byteSwap(ttl);
    }

    pub fn get_rr_type(self: *AnswerRecord) QueryType {
        return switch (self.*) {
            inline else => |*rr| rr.get_rr_type(),
        };
    }

    pub fn get_class_type(self: *AnswerRecord) DnsClass {
        return switch (self.*) {
            inline else => |*rr| rr.qclass,
        };
    }
};

/// A doubly linked list containing RR-Records
/// Calling deinit does not free any data in the DNSLayer - Only the structs are destroyed
pub const AnswerRecords = struct {
    first: ?*AnswerRecord = null,
    last: ?*AnswerRecord = null,
    answer_count: usize = 0,

    pub fn deinit(self: *AnswerRecords, allocator: Allocator) void {
        var cur = self.last;
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

pub const Queries = struct {
    first: ?*Query = null,
    query_count: usize = 0,

    pub fn deinit(self: *Queries, allocator: Allocator) void {
        var cur = self.first;
        while (cur) |query| {
            const next = query.next_query;
            allocator.destroy(query);
            cur = next;
        }

        self.first = null;
        self.query_count = 0;
    }
};

pub const DNSLayer = struct { // TODO: Handle Additional Records, Authoritative Records
    owner: LayerOwner,

    pub fn init(owner: LayerOwner) (LayerError || Allocator.Error)!DNSLayer {
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

    /// Sets DNS Header values to reflect Query and Answer count and perform byte swap for NBE order.
    /// Call this if you intend to send dns packet over the network or you need to undertake further analysis of the DNSHeader post modification
    pub fn validate_layer(self: *DNSLayer) void {
        var hdr = self.get_mutable_header();
        hdr.flags = @byteSwap(hdr.flags);
    }

    /// Append a DNS Query to the Queries section of the DNSLayer.
    /// Extends the layer, converts the name to DNS labels and copies the data at correct offset.
    /// Increases the qdcount value in the header by 1.
    pub fn add_query(self: *DNSLayer, name: []const u8, qtype: QueryType, qclass: DnsClass) (LayerError || Allocator.Error)!void {
        const extend_len = name.len + 6; // 2 byte qtype, 2 byte qclass, 1 byte first label, 1 byte null terminator

        var start_offset = DNSHeaderSize;

        if (try self.find_last_q_offset()) |last_q_offset| {
            start_offset = last_q_offset;
        }

        var query_buf = try self.owner.extend_layer(start_offset, extend_len);

        // Slice buffer starting at offset
        var qbuffer = query_buf[0..];

        // Write QNAME (labels)
        var buf_offset: usize = 0;
        var it = std.mem.splitScalar(u8, name, '.');
        while (it.next()) |label| {
            qbuffer[buf_offset] = @intCast(label.len);
            buf_offset += 1;
            @memmove(qbuffer[buf_offset .. buf_offset + label.len], label);
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

        var hdr = self.get_mutable_header();
        var qdcount = hdr.get_qdcount();

        qdcount += 1;
        hdr.set_qdcount(qdcount);
    }

    /// Remove the specified query.
    /// Decreases qdcount value in the header by 1.
    /// Warning: RR-Records which are pointing to this query name (compression ptr) might become malformed,
    /// in this case, it's safer create a seperate DNSLayer and perform a selective manual copy
    pub fn remove_query(self: *DNSLayer, query: *Query) Allocator.Error!void { // TODO: destroy the Query struct and rejoin
        const start_offset = query.offset;

        try self.owner.shorten_layer(start_offset, query.length);

        var hdr = self.get_mutable_header();
        var qdcount = hdr.get_qdcount();

        qdcount -= 1;
        hdr.set_qdcount(qdcount);

        var next_query = query.next_query;
        while (next_query) |next| {
            next.offset -= query.length;
            next_query = next.next_query;
        }
    }

    pub const DNSParseError = error{
        InvalidPacket,
        LabelOOB,
        LabelTooLong,
        LabelTooShort,
        RecordTooShort,
    };

    // this is primarily being used to advance offsets when names (queries or answers)
    pub fn decode_name(raw: []const u8, offset: *usize) DNSParseError![]const u8 {
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

    fn find_last_q_offset(self: *DNSLayer) (LayerError || Allocator.Error)!?usize {
        const data = self.get_data();
        if (data.len < DNSHeaderSize) {
            return null;
        }
        var offset: usize = DNSHeaderSize;

        const hdr = self.get_immutable_header();
        const qdcount = hdr.get_qdcount();

        var i: u32 = 0;
        while (i < qdcount) : (i += 1) { // trusting the header is not ideal
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

            const whole_record_end = offset + 4;
            offset = whole_record_end; // Move to next query position
        }

        return offset;
    }

    /// return Queries struct which contains singly linkedlist of queries
    /// caller must call deinit on the returned Queries struct using allocator provided
    pub fn get_queries(self: *DNSLayer, allocator: Allocator) (LayerError || Allocator.Error)!?Queries {
        const data = self.get_data();

        if (data.len < DNSHeaderSize) {
            return null;
        }

        var offset: usize = DNSHeaderSize;

        const hdr = self.get_immutable_header();
        const qdcount = hdr.get_qdcount();

        if (qdcount == 0) {
            return null;
        }

        var queries: Queries = (.{});

        var cur: ?*Query = null;

        var i: u32 = 0;
        while (i < qdcount) : (i += 1) { // trusting the header is not ideal
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
            if (cur) |q| {
                q.next_query = query;
            }

            cur = query;

            if (queries.first == null) {
                queries.first = cur;
            }

            queries.query_count += 1;

            offset = whole_record_end; // Move to next query position
        }

        return queries;
    }

    pub fn advance_past_name(slice: []const u8, offset: *usize) DNSParseError!void {
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

    /// Returns AnswerRecords (doubly linkedlist)
    /// null-opt is returned when there are no answers
    pub fn get_answers(self: *DNSLayer, allocator: Allocator) (DNSParseError || Allocator.Error || LayerError)!?AnswerRecords {
        const data = self.get_data();

        var offset: usize = DNSHeaderSize;

        if (try self.find_last_q_offset()) |last_q_offset| {
            offset = last_q_offset;
        }

        const hdr = self.get_immutable_header();

        const ancount = hdr.get_ancount();

        if (ancount == 0) {
            return null;
        }

        var ansrecords: AnswerRecords = (.{});

        var cur: ?*AnswerRecord = null;

        var i: u32 = 0;
        while (i < ancount) : (i += 1) {
            if (offset + 12 > data.len) // minimum RR header size: NAME(2) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
                return error.InvalidPacket;

            // Parse NAME
            const name_offset = offset;
            // This can be a pointer/offset compression (0xC0..) or raw labels
            // decode_name function to handle pointers and labels
            _ = try advance_past_name(data, &offset);

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

            // append to linkedlist
            if (cur) |ans| { // if the last answer is not null
                ans.set_next_record(answer); // set the last answer next answer to the answer created (answer being added)
                answer.set_prev_record(ans); // set the answer created (answer being added)'s prev answer to the last answer

            }

            cur = answer; // the last answer is now the answer that's being added
            if (ansrecords.first == null) {
                ansrecords.first = cur;
            }

            ansrecords.answer_count += 1;
        }

        ansrecords.last = cur;

        return ansrecords;
    }

    fn find_last_ans_offset(self: *DNSLayer) (DNSParseError || LayerError)!?usize {
        const data = self.get_data();
        var offset = DNSHeaderSize;

        if (try self.find_last_q_offset()) |last_q_off| {
            offset = last_q_off;
        }

        const hdr = self.get_immutable_header();
        const ancount = hdr.get_ancount();

        var i: u32 = 0;
        while (i < ancount) : (i += 1) {
            if (offset + 12 > data.len) // minimum RR header size: NAME(2) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
                return error.InvalidPacket;

            // Parse NAME
            _ = try advance_past_name(data, &offset); // advances the offset

            // QTYPE
            offset += 2;

            // QCLASS
            offset += 2;

            // TTL
            offset += 4;

            // RDLENGTH
            const rdlength = std.mem.readInt(u16, @ptrCast(data[offset .. offset + 2].ptr), .big);
            offset += 2;

            if (offset + rdlength > data.len) {
                return error.InvalidPacket;
            }

            offset += rdlength;
        }

        return offset;
    }

    /// append an answer to the DNSLayer in the Answers section
    /// for A, AAAA answers, pass answer as &ipv4_addr.array or &ipv6.array to coerce as slice
    /// all values will be copied
    /// Note: Compression pointer support not yet implemented
    /// Note: SOA records need to be built manually and passed as a slice (answer) - helper implmentation coming soon
    pub fn add_answer(self: *DNSLayer, name: []const u8, qtype: QueryType, qclass: DnsClass, ttl: u32, answer: []const u8) (LayerError || Allocator.Error || DNSParseError)!void {
        var start_offset: usize = DNSHeaderSize;

        if (try self.find_last_ans_offset()) |off| {
            start_offset = off;
        }

        // Calculate how many bytes the DNS-encoded name will take
        var dns_encoded_name_len: usize = 0;
        var it = std.mem.splitScalar(u8, name, '.');
        while (it.next()) |label| {
            dns_encoded_name_len += 1 + label.len; // length byte + label
        }
        dns_encoded_name_len += 1; // final null terminator

        var dns_encoded_answer_len: usize = 0;
        switch (qtype) {
            .A, .AAAA, .SOA => {
                dns_encoded_answer_len = answer.len;
            },
            else => {

                // Calculate encoded answer length (if answer is also a domain name)
                var ans_it = std.mem.splitScalar(u8, answer, '.');
                while (ans_it.next()) |label| {
                    dns_encoded_answer_len += 1 + label.len; // length byte + label
                }
                dns_encoded_answer_len += 1; // final null terminator

            },
        }

        const qtype_len = @sizeOf(QueryType);
        const class_len = @sizeOf(DnsClass);
        const ttl_len = @sizeOf(u32);
        const rd_len = @sizeOf(u16);

        const extend_len: usize = dns_encoded_name_len + qtype_len + class_len + ttl_len + rd_len + dns_encoded_answer_len;

        // extend the payload
        var ans_buf = try self.owner.extend_layer(start_offset, extend_len);
        var abuffer = ans_buf[0..];
        var buf_offset: usize = 0;

        // Write the encoded NAME
        it = std.mem.splitScalar(u8, name, '.');
        while (it.next()) |label| {
            abuffer[buf_offset] = @intCast(label.len);
            buf_offset += 1;
            @memcpy(abuffer[buf_offset .. buf_offset + label.len], label);
            buf_offset += label.len;
        }
        abuffer[buf_offset] = 0; // null terminator
        buf_offset += 1;

        // Write QTYPE
        std.mem.writeInt(u16, abuffer[buf_offset .. buf_offset + 2][0..2], @intFromEnum(qtype), .big);
        buf_offset += 2;

        // Write QCLASS
        std.mem.writeInt(u16, abuffer[buf_offset .. buf_offset + 2][0..2], @intFromEnum(qclass), .big);
        buf_offset += 2;

        // Write TTL
        std.mem.writeInt(u32, abuffer[buf_offset .. buf_offset + 4][0..4], ttl, .big);
        buf_offset += 4;

        // Write RD LENGTH (length of encoded answer)
        const rdlength: u16 = @intCast(dns_encoded_answer_len);
        std.mem.writeInt(u16, abuffer[buf_offset .. buf_offset + 2][0..2], rdlength, .big);
        buf_offset += 2;

        // handle record type

        switch (qtype) {
            .A, .AAAA, .SOA => {
                @memmove(abuffer[buf_offset..], answer);
            },
            else => {
                // Write encoded RDATA (the answer as a domain name)
                var ans_it = std.mem.splitScalar(u8, answer, '.');
                while (ans_it.next()) |label| {
                    abuffer[buf_offset] = @intCast(label.len);
                    buf_offset += 1;
                    @memcpy(abuffer[buf_offset .. buf_offset + label.len], label);
                    buf_offset += label.len;
                }
                abuffer[buf_offset] = 0; // null terminator for answer
            },
        }

        // Update header
        var hdr = self.get_mutable_header();
        var ancount = hdr.get_ancount();
        ancount += 1;
        hdr.set_ancount(ancount);
    }

    pub fn find_last_a_ans_offset(self: *DNSLayer) DNSParseError!?usize {
        const data = self.get_data();
        var offset = DNSHeaderSize;

        if (try self.find_last_ans_offset()) |last_q_off| {
            offset = last_q_off;
        }

        const hdr = self.get_immutable_header();
        const ancount = hdr.get_ancount();

        var i: u32 = 0;
        while (i < ancount) : (i += 1) {
            if (offset + 12 > data.len) // minimum RR header size: NAME(2) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
                return error.InvalidPacket;

            // Parse NAME
            _ = try advance_past_name(data, &offset); // advances the offset

            // QTYPE
            offset += 2;

            // QCLASS
            offset += 2;

            // TTL
            offset += 4;

            // RDLENGTH
            const rdlength = std.mem.readInt(u16, @ptrCast(data[offset .. offset + 2].ptr), .big);
            offset += 2;

            if (offset + rdlength > data.len) {
                return error.InvalidPacket;
            }

            offset += rdlength;
        }

        return offset;
    }

    /// Returns AnswerRecords (doubly linkedlist)
    /// null-opt is returned when there are no answers
    pub fn get_auth_answers(self: *DNSLayer, allocator: Allocator) (DNSParseError || Allocator.Error || LayerError)!?AnswerRecords {
        const data = self.get_data();

        var offset: usize = DNSHeaderSize;

        if (try self.find_last_ans_offset()) |last_q_offset| {
            offset = last_q_offset;
        }

        const hdr = self.get_immutable_header();

        const ancount = hdr.get_ancount();

        if (ancount == 0) {
            return null;
        }

        var ansrecords: AnswerRecords = (.{});

        var cur: ?*AnswerRecord = null;

        var i: u32 = 0;
        while (i < ancount) : (i += 1) {
            if (offset + 12 > data.len) // minimum RR header size: NAME(2) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
                return error.InvalidPacket;

            // Parse NAME
            const name_offset = offset;
            // This can be a pointer/offset compression (0xC0..) or raw labels
            // decode_name function to handle pointers and labels
            _ = try advance_past_name(data, &offset);

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

            // append to linkedlist
            if (cur) |ans| { // if the last answer is not null
                ans.set_next_record(answer); // set the last answer next answer to the answer created (answer being added)
                answer.set_prev_record(ans); // set the answer created (answer being added)'s prev answer to the last answer

            }

            cur = answer; // the last answer is now the answer that's being added
            if (ansrecords.first == null) {
                ansrecords.first = cur;
            }

            ansrecords.answer_count += 1;
        }

        ansrecords.last = cur;

        return ansrecords;
    }

    fn decompress(self: *DNSLayer) void {
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
        return tcp_ip_protocol.dns;
    }

    pub fn get_next_layer_type(self: *DNSLayer, layer: *Layer) LayerError!?LayerIface {
        _ = self;
        _ = layer;
        return null;
    }

    pub fn deinit(self: *DNSLayer) void {
        self.owner.deinit();
    }
};

/// Creates a domain name from a DNS label. The allocator creates an ArrayList to store the bytes and returns a mutable slice
/// The ArrayList is deinit'd before return but you must free the slice that is returned (it returns an ownedSlice)
pub fn decodeQname(allocator: Allocator, dns_label: []const u8) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
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
