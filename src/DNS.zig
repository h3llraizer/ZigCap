const std = @import("std");
const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;
const LayerError = @import("ProtocolEnums.zig").LayerError;
const Owner = @import("Owner.zig");
const LayerOwner = Owner.LayerOwner;
const TLVOwner = Owner.TLVOwner;
const Layer = @import("Packet.zig").Layer;
const LayerIface = @import("LayerIface.zig").LayerIface;
const init_layer = @import("LayerIface.zig").init_layer;
const Buffer = @import("Buffer.zig").Buffer;
const IPv4 = @import("IPv4.zig");
const IPv6 = @import("IPv6.zig");
const IPAddress = @import("IPAddress.zig").IPAddress;
const DNSEnums = @import("DNSEnums.zig");
const DNSRecordTypes = @import("DNSRecordTypes.zig");

const print = std.debug.print;
const Allocator = std.mem.Allocator;

pub const QueryType = DNSEnums.QueryType;
pub const DnsClass = DNSEnums.DnsClass;

pub const AnswerRecord = DNSRecordTypes.AnswerRecord;
pub const AnswerRecords = DNSRecordTypes.AnswerRecords;

pub const GenericRecord = DNSRecordTypes.GenericRecord;
pub const ARecord = DNSRecordTypes.ARecord;
pub const AAAARecord = DNSRecordTypes.AAAARecord;
pub const CNAMERecord = DNSRecordTypes.CNAMERecord;
pub const TXTRecord = DNSRecordTypes.TXTRecord;
pub const MXRecord = DNSRecordTypes.MXRecord;
pub const PTRRecord = DNSRecordTypes.PTRRecord;
pub const NSRecord = DNSRecordTypes.NSRecord;
pub const SOARecord = DNSRecordTypes.SOARecord;

pub const DNSHeaderSize: usize = 12;

pub const QUERY_TYPE_LENGTH = @sizeOf(QueryType);
pub const CLASS_TYPE_LENGTH = @sizeOf(DnsClass);
pub const TTL_LENGTH = @sizeOf(u32);
pub const RD_LENGTH = @sizeOf(u16);

const default_hdr = DNSHeader{
    .id = .{0x00} ** 2,
    .flags = .{0x00} ** 2,
    .qdcount = .{0x00} ** 2,
    .ancount = .{0x00} ** 2,
    .nscount = .{0x00} ** 2,
    .arcount = .{0x00} ** 2,
};

/// Standard DNS Header.
/// Setters take native values and byteswap before set
/// Getters return byteswapped values
pub const DNSHeader = extern struct {
    /// Identification / Transaction ID
    id: [2]u8 = .{0x00} ** 2,
    /// QR, Opcode, AA, TC, RD, RA, Z, RCODE packed - see DNSHeaderFlags
    flags: [2]u8 = .{0x00} ** 2,
    /// Number of questions
    qdcount: [2]u8 = .{0x00} ** 2,
    /// Number of answer ResponseRecords
    ancount: [2]u8 = .{0x00} ** 2,
    /// Number of authority ResponseRecords
    nscount: [2]u8 = .{0x00} ** 2,
    /// Number of additional ResponseRecords
    arcount: [2]u8 = .{0x00} ** 2,

    comptime {
        if (@bitSizeOf(DNSHeader) != 96)
            @compileError("DNSHeaderBits must be exactly 96 bits (12 bytes)");
    }

    pub fn set_id(self: *DNSHeader, id: u16) void {
        std.mem.writeInt(u16, &self.id, id, .big);
    }

    pub fn get_id(self: *const DNSHeader) u16 {
        return std.mem.readInt(u16, &self.id, .big);
    }

    /// sets qdcount to the value provided as BE
    pub fn set_qdcount(self: *DNSHeader, qdcount: u16) void {
        std.mem.writeInt(u16, &self.qdcount, qdcount, .big);
    }

    /// returns the qdcount as LE
    pub fn get_qdcount(self: *const DNSHeader) u16 {
        return std.mem.readInt(u16, &self.qdcount, .big);
    }

    pub fn set_ancount(self: *DNSHeader, ancount: u16) void {
        std.mem.writeInt(u16, &self.ancount, ancount, .big);
    }

    pub fn get_ancount(self: *const DNSHeader) u16 {
        return std.mem.readInt(u16, &self.ancount, .big);
    }

    pub fn set_nscount(self: *DNSHeader, nscount: u16) void {
        std.mem.writeInt(u16, &self.nscount, nscount, .big);
    }

    pub fn get_nscount(self: *const DNSHeader) u16 {
        return std.mem.readInt(u16, &self.nscount, .big);
    }

    pub fn set_arcount(self: *DNSHeader, arcount: u16) void {
        std.mem.writeInt(u16, &self.arcount, arcount, .big);
    }

    pub fn get_arcount(self: *const DNSHeader) u16 {
        return std.mem.readInt(u16, &self.arcount, .big);
    }

    /// Get the raw flags as a u16 (big-endian)
    pub fn get_flags_raw(self: *const DNSHeader) u16 {
        return std.mem.readInt(u16, &self.flags, .big);
    }

    /// Set the raw flags from a u16 (big-endian)
    pub fn set_flags_raw(self: *DNSHeader, value: u16) void {
        std.mem.writeInt(u16, &self.flags, value, .big);
    }

    // Individual flag getters/setters

    /// QR - Query/Response (bit 15)
    /// 0 = query, 1 = response
    pub fn get_qr(self: *const DNSHeader) bool {
        const flags = self.get_flags_raw();
        return (flags >> 15) & 1 == 1;
    }

    pub fn set_qr(self: *DNSHeader, is_response: bool) void {
        var flags = self.get_flags_raw();
        if (is_response) {
            flags |= (1 << 15);
        } else {
            flags &= ~(@as(u16, 1) << 15);
        }
        self.set_flags_raw(flags);
    }

    /// OPCODE - Operation Code (bits 11-14)
    /// 0 = standard query, 1 = inverse query, 2 = server status, etc.
    pub fn get_opcode(self: *const DNSHeader) u4 {
        const flags = self.get_flags_raw();
        return @as(u4, @truncate((flags >> 11) & 0xF));
    }

    pub fn set_opcode(self: *DNSHeader, opcode: u4) void {
        var flags = self.get_flags_raw();
        flags &= ~(@as(u16, 0xF) << 11); // Clear bits 11-14
        flags |= (@as(u16, opcode) << 11);
        self.set_flags_raw(flags);
    }

    /// AA - Authoritative Answer (bit 10)
    pub fn get_aa(self: *const DNSHeader) bool {
        const flags = self.get_flags_raw();
        return (flags >> 10) & 1 == 1;
    }

    pub fn set_aa(self: *DNSHeader, authoritative: bool) void {
        var flags = self.get_flags_raw();
        if (authoritative) {
            flags |= (1 << 10);
        } else {
            flags &= ~(@as(u16, 1) << 10);
        }
        self.set_flags_raw(flags);
    }

    /// TC - Truncation (bit 9)
    pub fn get_tc(self: *const DNSHeader) bool {
        const flags = self.get_flags_raw();
        return (flags >> 9) & 1 == 1;
    }

    pub fn set_tc(self: *DNSHeader, truncated: bool) void {
        var flags = self.get_flags_raw();
        if (truncated) {
            flags |= (1 << 9);
        } else {
            flags &= ~(@as(u16, 1) << 9);
        }
        self.set_flags_raw(flags);
    }

    /// RD - Recursion Desired (bit 8)
    pub fn get_rd(self: *const DNSHeader) bool {
        const flags = self.get_flags_raw();
        return (flags >> 8) & 1 == 1;
    }

    pub fn set_rd(self: *DNSHeader, recursion_desired: bool) void {
        var flags = self.get_flags_raw();
        if (recursion_desired) {
            flags |= (1 << 8);
        } else {
            flags &= ~(@as(u16, 1) << 8);
        }
        self.set_flags_raw(flags);
    }

    /// RA - Recursion Available (bit 7)
    pub fn get_ra(self: *const DNSHeader) bool {
        const flags = self.get_flags_raw();
        return (flags >> 7) & 1 == 1;
    }

    pub fn set_ra(self: *DNSHeader, recursion_available: bool) void {
        var flags = self.get_flags_raw();
        if (recursion_available) {
            flags |= (1 << 7);
        } else {
            flags &= ~(@as(u16, 1) << 7);
        }
        self.set_flags_raw(flags);
    }

    /// Z - Reserved (bits 4-6) - Must be zero
    pub fn get_z(self: *const DNSHeader) u3 {
        const flags = self.get_flags_raw();
        return @as(u3, @truncate((flags >> 4) & 0x7));
    }

    pub fn set_z(self: *DNSHeader, z: u3) void {
        std.debug.assert(z == 0); // Z field must be zero according to DNS spec
        var flags = self.get_flags_raw();
        flags &= ~(@as(u16, 0x7) << 4); // Clear bits 4-6
        flags |= (@as(u16, z) << 4);
        self.set_flags_raw(flags);
    }

    /// RCODE - Response Code (bits 0-3)
    /// 0 = no error, 1 = format error, 2 = server failure, 3 = name error, etc.
    pub fn get_rcode(self: *const DNSHeader) u4 {
        const flags = self.get_flags_raw();
        return @as(u4, @truncate(flags & 0xF));
    }

    pub fn set_rcode(self: *DNSHeader, rcode: u4) void {
        var flags = self.get_flags_raw();
        flags &= ~(@as(u16, 0xF)); // Clear bits 0-3
        flags |= rcode;
        self.set_flags_raw(flags);
    }
};

// TODO: Handle Additional Records, Authoritative Records
pub const DNSLayer = struct {
    owner: LayerOwner,

    pub fn init(owner: LayerOwner) (LayerError || Allocator.Error)!DNSLayer {
        return try init_layer(DNSLayer, owner, DNSHeader, default_hdr);
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

        return @ptrCast(data.ptr);
    }

    pub fn get_immutable_header(self: *const DNSLayer) *const DNSHeader {
        const data: []const u8 = self.get_data();

        if (data.len < DNSHeaderSize) {
            std.debug.panic("DNS data len ({}) less than DNSHeaderSize", .{data.len});
        }

        return @ptrCast(data.ptr);
    }

    pub fn is_response(self: *DNSLayer) bool {
        const hdr = self.get_immutable_header();
        return hdr.get_qr();
    }

    /// Sets DNS Header values to reflect Query and Answer count and perform byte swap for NBE order.
    /// Call this if you intend to send dns packet over the network or you need to undertake further analysis of the DNSHeader post modification
    pub fn validate_layer(self: *DNSLayer) void {
        _ = self;
    }

    /// Append a DNS Query to the Queries section of the DNSLayer.
    /// Extends the layer, converts the name to DNS labels and copies the data at correct offset.
    /// Increases the qdcount value in the header by 1.
    pub fn add_query(self: *DNSLayer, query: *Query) (LayerError || Allocator.Error)!void {
        const extend_len = query.get_data().len;

        var start_offset = DNSHeaderSize;

        if (try self.get_last_query_offset()) |last_q_offset| {
            start_offset = last_q_offset;
        }

        const query_buf = try self.owner.extend_layer(start_offset, extend_len);

        @memmove(query_buf, query.get_data());

        const qcount = self.get_immutable_header().get_qdcount();

        self.get_mutable_header().set_qdcount(qcount + 1);
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

    fn get_last_query_offset(self: *DNSLayer) LayerError!?usize {
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
            if (offset + (QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH) > data.len)
                return LayerError.LayerInvalid;

            const whole_record_end = offset + (QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH);
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

        var queries: Queries = (.{
            .owner = TLVOwner{
                .layer = &self.owner,
            },
        });

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
            if (offset + (QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH) > data.len)
                return LayerError.LayerInvalid;

            const qtype = std.mem.readInt(
                u16,
                @ptrCast(data[offset .. offset + QUERY_TYPE_LENGTH]),
                .big,
            );

            offset += QUERY_TYPE_LENGTH;

            const qclass = std.mem.readInt(
                u16,
                @ptrCast(data[offset .. offset + CLASS_TYPE_LENGTH]),
                .big,
            );

            offset += CLASS_TYPE_LENGTH;

            const whole_record_end = offset;
            const whole_record = data[qname_start..whole_record_end];

            const query = try allocator.create(Query);

            const qclass_e: DnsClass = @enumFromInt(qclass);
            const qtype_e: QueryType = @enumFromInt(qtype);

            // Store the starting offset of this query
            query.* = .{
                .offset = qname_start,
                .length = whole_record.len,
                .qtype = qtype_e,
                .qclass = qclass_e,
                .owner = TLVOwner{ .layer = &self.owner },
            };

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

    /// Increases the offset while iterating string/slice type until null-terminator or compression-ptr is encountered.
    /// Asserts that the offset is within bounds before return - if not in bounds then panic will happen in debug mode.
    pub fn advance_past_name(slice: []const u8, offset: *usize) void {
        while (offset.* < slice.len) {
            const byte = slice[offset.*];
            if (byte == 0) {
                offset.* += 1;
                std.debug.assert(slice.len >= offset.*);
                return;
            }
            if ((byte & 0xC0) == 0xC0) {
                offset.* += 2;
                std.debug.assert(slice.len >= offset.*);
                return;
            }
            offset.* += 1 + byte; // Skip length byte and label
        }
    }

    /// Returns AnswerRecords (doubly linkedlist)
    /// null-opt is returned when there are no answers
    pub fn get_answers(self: *DNSLayer, allocator: Allocator) (DNSParseError || Allocator.Error || LayerError)!?AnswerRecords {
        const data = self.get_data();

        var offset: usize = DNSHeaderSize;

        if (try self.get_last_query_offset()) |last_q_offset| {
            offset = last_q_offset;
        }

        const hdr = self.get_immutable_header();

        const ancount = hdr.get_ancount();

        var ansrecords: AnswerRecords = (.{ .owner = TLVOwner{
            .layer = &self.owner,
        } });

        var cur: ?*AnswerRecord = null;

        var i: u32 = 0;
        while (i < ancount) : (i += 1) {
            if (offset + 12 > data.len) // minimum RR header size: NAME(2) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
                return error.InvalidPacket;

            // Parse NAME
            const name_offset = offset;
            // This can be a pointer/offset compression (0xC0..) or raw labels
            // decode_name function to handle pointers and labels
            _ = advance_past_name(data, &offset);

            // Parse TYPE
            const rtype = std.mem.readInt(u16, @ptrCast(data[offset .. offset + QUERY_TYPE_LENGTH].ptr), .big);
            offset += QUERY_TYPE_LENGTH;

            // Parse CLASS
            const rclass = std.mem.readInt(u16, @ptrCast(data[offset .. offset + CLASS_TYPE_LENGTH].ptr), .big);
            offset += CLASS_TYPE_LENGTH;

            // Parse TTL
            const ttl = std.mem.readInt(u32, @ptrCast(data[offset .. offset + TTL_LENGTH].ptr), .big);
            offset += TTL_LENGTH;

            _ = ttl;

            // Parse RDLENGTH
            const rdlength = std.mem.readInt(u16, @ptrCast(data[offset .. offset + RD_LENGTH].ptr), .big);
            offset += RD_LENGTH;

            if (offset + rdlength > data.len) {
                return error.InvalidPacket;
            }

            offset += rdlength;

            const whole_record = data[name_offset..offset];

            // Create a AnswerRecord "node" for AnswerRecord linkedlist
            const answer = try allocator.create(AnswerRecord);

            const rtype_e: QueryType = QueryType.from_u16(rtype);
            const class_e: DnsClass = @enumFromInt(rclass);

            answer.* = AnswerRecord.init(name_offset, whole_record.len, rtype_e, class_e, TLVOwner{
                .layer = &self.owner,
            });

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

    fn get_last_answer_offset(self: *DNSLayer) (DNSParseError || LayerError)!?usize {
        const data = self.get_data();
        var offset = DNSHeaderSize;

        if (try self.get_last_query_offset()) |last_q_off| {
            offset = last_q_off;
        }

        const hdr = self.get_immutable_header();
        const ancount = hdr.get_ancount();

        var i: u32 = 0;
        while (i < ancount) : (i += 1) {
            if (offset + 12 > data.len) // minimum RR header size: NAME(2) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
                return LayerError.LayerInvalid;

            // Parse NAME
            _ = advance_past_name(data, &offset); // advances the offset

            // QTYPE
            offset += QUERY_TYPE_LENGTH;

            // QCLASS
            offset += CLASS_TYPE_LENGTH;

            // TTL
            offset += TTL_LENGTH;

            // RDLENGTH
            const rdlength = std.mem.readInt(u16, @ptrCast(data[offset .. offset + RD_LENGTH].ptr), .big);
            offset += RD_LENGTH;

            if (offset + rdlength > data.len) {
                return LayerError.LayerInvalid;
            }

            offset += rdlength;
        }

        return offset;
    }

    pub fn add_ans(self: *DNSLayer, record: *AnswerRecord) (LayerError || Allocator.Error || DNSParseError)!void {
        var start_offset: usize = DNSHeaderSize;

        if (try self.get_last_answer_offset()) |off| {
            start_offset = off;
        }

        const extend_len = record.get_data().len;

        const buf = try self.owner.extend_layer(start_offset, extend_len);

        @memmove(buf, record.get_data());

        const cur_an_count = self.get_immutable_header().get_ancount();

        self.get_mutable_header().set_ancount(cur_an_count + 1);
    }

    /// append an answer to the DNSLayer in the Answers section
    /// for A, AAAA answers, pass answer as &ipv4_addr.array or &ipv6.array to coerce as slice
    /// all values will be copied
    /// Note: Compression pointer support not yet implemented
    /// Note: SOA records need to be built manually and passed as a slice (answer) - helper implmentation coming soon
    pub fn add_answer(self: *DNSLayer, name: []const u8, qtype: QueryType, qclass: DnsClass, ttl: u32, answer: []const u8) (LayerError || Allocator.Error || DNSParseError)!void {
        var start_offset: usize = DNSHeaderSize;

        if (try self.get_last_answer_offset()) |off| {
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

        const qtype_len = QUERY_TYPE_LENGTH;
        const class_len = CLASS_TYPE_LENGTH;
        const ttl_len = TTL_LENGTH;
        const rd_len = RD_LENGTH;

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
        std.mem.writeInt(u16, abuffer[buf_offset .. buf_offset + QUERY_TYPE_LENGTH][0..2], @intFromEnum(qtype), .big);
        buf_offset += QUERY_TYPE_LENGTH;

        // Write QCLASS
        std.mem.writeInt(u16, abuffer[buf_offset .. buf_offset + CLASS_TYPE_LENGTH][0..2], @intFromEnum(qclass), .big);
        buf_offset += CLASS_TYPE_LENGTH;

        // Write TTL
        std.mem.writeInt(u32, abuffer[buf_offset .. buf_offset + TTL_LENGTH][0..4], ttl, .big);
        buf_offset += TTL_LENGTH;

        // Write RD LENGTH (length of encoded answer)
        const rdlength: u16 = @intCast(dns_encoded_answer_len);
        std.mem.writeInt(u16, abuffer[buf_offset .. buf_offset + RD_LENGTH][0..2], rdlength, .big);
        buf_offset += RD_LENGTH;

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

    fn get_last_auth_answer_offset(self: *DNSLayer) DNSParseError!?usize {
        const data = self.get_data();
        var offset = DNSHeaderSize;

        if (try self.get_last_answer_offset()) |last_q_off| {
            offset = last_q_off;
        }

        const hdr = self.get_immutable_header();
        const ancount = hdr.get_ancount();

        var i: u32 = 0;
        while (i < ancount) : (i += 1) {
            if (offset + 12 > data.len) // minimum RR header size: NAME(2) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
                return error.InvalidPacket;

            // Parse NAME
            _ = advance_past_name(data, &offset); // advances the offset

            // QTYPE
            offset += QUERY_TYPE_LENGTH;

            // QCLASS
            offset += CLASS_TYPE_LENGTH;

            // TTL
            offset += TTL_LENGTH;

            // RDLENGTH
            const rdlength = std.mem.readInt(u16, @ptrCast(data[offset .. offset + RD_LENGTH].ptr), .big);
            offset += RD_LENGTH;

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

        if (try self.get_last_answer_offset()) |last_q_offset| {
            offset = last_q_offset;
        }

        const hdr = self.get_immutable_header();

        const nscount = hdr.get_nscount();

        //print("nscount: {}\n", .{nscount});

        //    if (nscount == 0) {
        //        return null;
        //    }

        var ansrecords: AnswerRecords = (.{ .owner = TLVOwner{ .layer = &self.owner } });

        var cur: ?*AnswerRecord = null;

        var i: u32 = 0;
        while (i < nscount) : (i += 1) {
            if (offset + 12 > data.len) // minimum RR header size: NAME(2) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
                return error.InvalidPacket;

            // Parse NAME
            const name_offset = offset;
            // This can be a pointer/offset compression (0xC0..) or raw labels
            // decode_name function to handle pointers and labels
            advance_past_name(data, &offset);

            // Parse TYPE
            const rtype = std.mem.readInt(u16, @ptrCast(data[offset .. offset + QUERY_TYPE_LENGTH].ptr), .big);
            offset += QUERY_TYPE_LENGTH;

            // Parse CLASS
            const rclass = std.mem.readInt(u16, @ptrCast(data[offset .. offset + CLASS_TYPE_LENGTH].ptr), .big);
            offset += CLASS_TYPE_LENGTH;

            // Parse TTL
            const ttl = std.mem.readInt(u32, @ptrCast(data[offset .. offset + TTL_LENGTH].ptr), .big);
            offset += TTL_LENGTH;

            _ = ttl;

            // Parse RDLENGTH
            const rdlength = std.mem.readInt(u16, @ptrCast(data[offset .. offset + RD_LENGTH].ptr), .big);
            offset += RD_LENGTH;

            if (offset + rdlength > data.len) {
                return error.InvalidPacket;
            }

            offset += rdlength;

            const whole_record = data[name_offset..offset];

            // Create a AnswerRecord "node" for AnswerRecord linkedlist
            const answer = try allocator.create(AnswerRecord);

            const rtype_e: QueryType = QueryType.from_u16(rtype);
            const class_e: DnsClass = @enumFromInt(rclass);

            answer.* = AnswerRecord.init(
                name_offset,
                whole_record.len,
                rtype_e,
                class_e,
                TLVOwner{ .layer = &self.owner },
            );

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

        const id = hdr.get_id();
        const qr = hdr.get_qr();
        const opcode = hdr.get_opcode();
        const aa = hdr.get_aa();
        const tc = hdr.get_tc();
        const rd = hdr.get_rd();
        const ra = hdr.get_ra();
        const z = hdr.get_z();
        const rcode = hdr.get_rcode();
        const qdcount = hdr.get_qdcount();
        const ancount = hdr.get_ancount();
        const nscount = hdr.get_nscount();
        const arcount = hdr.get_arcount();

        return std.fmt.allocPrint(
            allocator,
            "DNS Layer: id={} qr={} opcode={} aa={} tc={} rd={} ra={} z={} rcode={} qdcount={} ancount={} nscount={} arcount={}",
            .{ id, qr, opcode, aa, tc, rd, ra, z, rcode, qdcount, ancount, nscount, arcount },
        ) catch return "Error.";
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

pub const Query = struct {
    offset: usize,
    length: usize,
    qtype: QueryType,
    qclass: DnsClass,
    owner: TLVOwner,
    next_query: ?*Query = null,
    prev_query: ?*Query = null,

    /// Init a new DNS Query.
    /// Name provided must be an encoded name (use DNS.encode_name method).
    /// Allocates name length + 4 bytes (qtype + qclass).
    pub fn init(name: []const u8, qtype: QueryType, qclass: DnsClass, allocator: Allocator) Allocator.Error!Query {
        const initial_len = name.len + QUERY_TYPE_LENGTH + CLASS_TYPE_LENGTH;

        var query = Query{
            .offset = 0,
            .length = initial_len,
            .qtype = qtype,
            .qclass = qclass,
            .owner = TLVOwner{ .owned_buffer = .init_empty(allocator) },
        };

        const buf = try query.owner.extend_buffer(0, initial_len);

        @memmove(buf[0..name.len], name);

        const query_type_offset = name.len;

        std.mem.writeInt(
            u16,
            @ptrCast(buf[query_type_offset .. query_type_offset + QUERY_TYPE_LENGTH].ptr),
            @intFromEnum(qtype),
            .big,
        );

        const class_type_offset = query_type_offset + QUERY_TYPE_LENGTH;

        std.mem.writeInt(
            u16,
            @ptrCast(buf[class_type_offset .. class_type_offset + CLASS_TYPE_LENGTH].ptr),
            @intFromEnum(qclass),
            .big,
        );

        return query;
    }

    pub fn get_data(self: *Query) []const u8 {
        return self.get_data_mut();
    }

    pub fn get_data_mut(self: *Query) []u8 {
        return self.owner.get_data()[self.offset .. self.offset + self.length];
    }

    /// Name provided must be an encoded name (use DNS.encode_name method).
    pub fn set_name(self: *Query, name: []const u8) Allocator.Error!void {
        const data = self.get_data();

        var offset: usize = 0;

        DNSLayer.advance_past_name(data, &offset);

        const cur_name_len = offset;

        if (cur_name_len < name.len) {
            const extend_len = name.len - cur_name_len;
            _ = try self.owner.extend_buffer(cur_name_len, extend_len);

            self.length += extend_len;

            // increase the proceeding records offsets by the extend_len
            var next_query = self.next_query;
            while (next_query) |q| {
                q.offset = q.offset + extend_len;
                next_query = q.next_query;
            }
        }

        if (cur_name_len > name.len) {
            const shorten_len = cur_name_len - name.len;

            try self.owner.shorten_buffer(cur_name_len, shorten_len);

            self.length -= shorten_len;

            // decrease the proceeding records offsets by the shorten_len
            var next_query = self.next_query;
            while (next_query) |q| {
                q.offset = q.offset - shorten_len;
                next_query = q.next_query;
            }
        }

        // if name is same length as current it can just be copied over

        @memmove(self.get_data_mut()[0..name.len], name);
    }

    pub fn decode_qname(self: *Query, allocator: Allocator) ![]const u8 {
        return try DNSRecordTypes.decode_name(
            self.owner.get_data(),
            self.get_data(),
            allocator,
        );
    }

    pub fn get_qtype(self: *Query) QueryType {
        const data = self.get_data();

        var offset: usize = 0;

        DNSLayer.advance_past_name(data, &offset);

        return @enumFromInt(std.mem.readInt(
            u16,
            @ptrCast(data[offset .. offset + QUERY_TYPE_LENGTH].ptr),
            .big,
        ));
    }

    pub fn set_qtype(self: *Query, qtype: QueryType) void {
        const data = self.get_data_mut();

        var offset: usize = 0;

        DNSLayer.advance_past_name(data, &offset);

        std.mem.writeInt(
            u16,
            @ptrCast(data[offset .. offset + QUERY_TYPE_LENGTH].ptr),
            @intFromEnum(qtype),
            .big,
        );
    }

    pub fn get_class(self: *Query) DnsClass {
        const data = self.get_data();

        var offset: usize = 0;

        DNSLayer.advance_past_name(data, &offset);

        offset += QUERY_TYPE_LENGTH;

        return @enumFromInt(std.mem.readInt(
            u16,
            @ptrCast(data[offset .. offset + CLASS_TYPE_LENGTH].ptr),
            .big,
        ));
    }

    pub fn set_class(self: *Query, class: DnsClass) void {
        const data = self.get_data_mut();

        var offset: usize = 0;

        DNSLayer.advance_past_name(data, &offset);

        offset += QUERY_TYPE_LENGTH;

        return std.mem.writeInt(
            u16,
            @ptrCast(data[offset .. offset + CLASS_TYPE_LENGTH].ptr),
            @intFromEnum(class),
            .big,
        );
    }

    pub fn deinit(self: *Query) void {
        self.owner.deinit();
    }
};

pub const Queries = struct {
    first: ?*Query = null,
    owner: TLVOwner,
    query_count: usize = 0,

    pub fn add_query(self: *Queries, query: *Query, allocator: Allocator) (LayerError || Allocator.Error)!void {
        const extend_len = query.get_data().len;

        var start_offset = if (self.owner.is_layer_owned()) DNSHeaderSize else 0;

        var cur: ?*Query = self.first;
        var last: ?*Query = null;

        while (cur) |q| {
            if (q.next_query == null) {
                start_offset = q.offset + q.length;
                last = q;
                break;
            } else {
                last = q.next_query;
            }

            cur = q.next_query;
        }

        const query_buf = try self.owner.extend_buffer(start_offset, extend_len);

        @memmove(query_buf, query.get_data());

        const added_query = try allocator.create(Query);

        added_query.* = .{
            .offset = start_offset,
            .length = extend_len,
            .qtype = query.get_qtype(),
            .qclass = query.get_class(),
            .owner = self.owner,
        };

        if (last) |last_query| {
            last_query.next_query = added_query;
            added_query.prev_query = last_query;
        } else {
            self.first = added_query;
        }

        self.query_count += 1;

        if (self.owner.is_layer_owned()) {
            var hdr: *DNSHeader = @ptrCast(self.owner.get_data()[0..12]);
            var qdcount = hdr.get_qdcount();

            qdcount += 1;
            hdr.set_qdcount(qdcount);
        }
    }

    pub fn remove_query(self: *Queries, query: *Query, allocator: Allocator) !void {
        var cur: ?*Query = if (self.first != null) self.first else return error.QueryListEmpty;

        while (cur) |q| {
            if (q == query) {
                const start_offset = query.offset;

                try self.owner.shorten_buffer(start_offset, query.length);

                var next_query = query.next_query;
                while (next_query) |next| {
                    next.offset -= query.length;
                    next_query = next.next_query;
                }

                self.query_count -= 1;

                if (self.owner.is_layer_owned()) {
                    const hdr: *DNSHeader = @ptrCast(self.owner.get_data()[0..12]);
                    var qdcount = hdr.get_qdcount();
                    qdcount -= 1;
                    hdr.set_qdcount(qdcount);
                }

                // Update the list pointers BEFORE destroying
                // Update first pointer if necessary
                if (self.first == q) {
                    self.first = q.next_query;
                }

                if (q.next_query) |next| {
                    next.prev_query = q.prev_query;
                }

                if (q.prev_query) |prev| {
                    prev.next_query = q.next_query;
                }

                allocator.destroy(query);
                return;
            }
            cur = q.next_query;
        }
        return error.QueryNotFound;
    }

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

pub const ipv4_ptr_query_trailer = ".in-addr.arpa";

pub const ipv6_ptr_query_trailer = ".ip6.arpa";

/// Encode IP (IPv4Address) into DNS Wire Formatted ptr query ready for DNS request transmission
/// examples:
/// calling with IPv4Address 142.251.30.113 encodes and returns "113.30.251.142.in-addr.arpa" encoded
/// calling with IPv6Address 2a00:1450:4009:0c17:0000:0000:0000:0065 returns "5.6.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.1.c.0.9.0.0.4.0.5.4.1.0.0.a.2.ip6.arpa"
/// Caller must free the returned name.
pub fn encode_ip_ptr_query(ip: IPAddress, allocator: Allocator) Allocator.Error![]const u8 {
    const ip_str = try ip.to_string(allocator);
    defer allocator.free(ip_str);

    var rvrs_ip_str: std.ArrayList(u8) = try .initCapacity(allocator, ip_str.len);
    defer rvrs_ip_str.deinit(allocator);

    if (std.meta.activeTag(ip) == IPAddress.ipv4) {
        var it = std.mem.splitBackwardsScalar(u8, ip_str, '.');

        while (it.next()) |oct| {
            try rvrs_ip_str.appendSlice(allocator, oct);
            try rvrs_ip_str.append(allocator, '.');
        }

        try rvrs_ip_str.appendSlice(allocator, ipv4_ptr_query_trailer[1..]);
    }

    if (std.meta.activeTag(ip) == IPAddress.ipv6) {
        var it = std.mem.splitBackwardsScalar(u8, ip_str, ':');
        while (it.next()) |hextet| {
            var it0 = std.mem.reverseIterator(hextet);
            while (it0.next()) |digit| {
                try rvrs_ip_str.append(allocator, digit);
                try rvrs_ip_str.append(allocator, '.');
            }
        }

        try rvrs_ip_str.appendSlice(allocator, ipv6_ptr_query_trailer[1..]);
    }

    return try encode_name(rvrs_ip_str.items, allocator);
}

/// Decodes a ptr query string.
/// example return is 113.30.251.142.in-addr.arpa
pub fn decode_ip_ptr_query(ptr_str: []const u8, allocator: Allocator) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
    return try decode_name(allocator, ptr_str);
}

/// return IPaddress from decoded ptr query string
/// examples:
/// "5.6.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.1.c.0.9.0.0.4.0.5.4.1.0.0.a.2.ip6.arpa" will return IPAddress with IPv6Address "2a00:1450:4009:0c17:0000:0000:0000:0065" as active tag
/// "113.30.251.142.in-addr.arpa" will return IPAddress with IPv4Address "142.251.30.113" as active tag
pub fn extract_ip_from_ptr(ptr_str: []const u8) (std.fmt.ParseIntError || DNSLayer.DNSParseError || IPv4.IPv4Address.Error || Allocator.Error)!IPAddress {
    if (ptr_str.len < 15) {
        return IPv4.IPv4Address.Error.TooFewOctets;
    }

    var ip_end: usize = 0;

    if (std.mem.indexOf(u8, ptr_str, ipv4_ptr_query_trailer)) |idx| {
        ip_end = idx;

        var it = std.mem.splitBackwardsScalar(u8, ptr_str[0..ip_end], '.');

        var ip_buf: [4]u8 = .{0} ** 4;

        var oct_count: usize = 0;

        while (it.next()) |oct| {
            if (oct_count > ip_buf.len - 1) break;
            ip_buf[oct_count] = try std.fmt.parseInt(u8, oct, 10);
            oct_count += 1;
        }

        return IPAddress{ .ipv4 = IPv4.IPv4Address.init_from_array(ip_buf) };
    }
    if (std.mem.indexOf(u8, ptr_str, ipv6_ptr_query_trailer)) |idx| {
        ip_end = idx;

        var it = std.mem.splitBackwardsScalar(u8, ptr_str[0..ip_end], '.');

        var ip_buf: [16]u8 = .{0} ** 16;

        var hextet: u16 = 0;
        var nibble_count: u3 = 0;
        var ip_index: usize = 0;

        while (it.next()) |digit| {
            const v = try std.fmt.parseInt(u8, digit, 16);

            hextet = (hextet << 4) | v;
            nibble_count += 1;

            if (nibble_count == 4) {
                std.mem.writeInt(u16, @ptrCast(ip_buf[ip_index .. ip_index + 1].ptr), hextet, .big);

                ip_index += 2;
                hextet = 0;
                nibble_count = 0;
            }
        }

        return IPAddress{
            .ipv6 = IPv6.IPv6Address.init_from_array(ip_buf),
        };
    } else {
        return DNSLayer.DNSParseError.LabelTooShort;
    }
}

/// Encode names (domain names) into DNS Wire Format for DNS Layer.
/// Caller must free the returned name.
pub fn encode_name(name: []const u8, allocator: Allocator) Allocator.Error![]const u8 {
    // Calculate how many bytes the DNS-encoded name will take
    var dns_encoded_name_len: usize = 0;
    var it = std.mem.splitScalar(u8, name, '.');
    while (it.next()) |label| {
        dns_encoded_name_len += 1 + label.len; // length byte + label
    }
    dns_encoded_name_len += 1; // final null terminator

    const encoded_name = try allocator.alloc(u8, dns_encoded_name_len);

    var buf_offset: usize = 0;

    it = std.mem.splitScalar(u8, name, '.');
    while (it.next()) |label| {
        encoded_name[buf_offset] = @intCast(label.len);
        buf_offset += 1;
        @memcpy(encoded_name[buf_offset .. buf_offset + label.len], label);
        buf_offset += label.len;
    }
    encoded_name[buf_offset] = 0; // null terminator

    return encoded_name;
}

/// Creates a domain name from a DNS label. The allocator creates an ArrayList to store the bytes and returns a mutable slice
/// The ArrayList is deinit'd before return but you must free the slice that is returned (it returns an ownedSlice)
pub fn decode_name(allocator: Allocator, dns_label: []const u8) (DNSLayer.DNSParseError || Allocator.Error)![]u8 {
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
