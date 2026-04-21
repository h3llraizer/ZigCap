const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;
const LayerError = @import("ProtocolEnums.zig").LayerError;

const LayerOwner = @import("Layer.zig").LayerOwner;

const Layer = @import("Packet.zig").Layer;

const LayerIface = @import("LayerIface.zig").LayerIface;

const Buffer = @import("Buffer.zig").Buffer;

const IPv4 = @import("IPv4.zig");
const IPv6 = @import("IPv6.zig");

const DNSRecordTypes = @import("DNSRecordTypes.zig");
const GenericRecord = DNSRecordTypes.GenericRecord;
const ARecord = DNSRecordTypes.ARecord;
const AAAARecord = DNSRecordTypes.AAAARecord;
const CNAMERecord = DNSRecordTypes.CNAMERecord;
const TXTRecord = DNSRecordTypes.TXTRecord;
const MXRecord = DNSRecordTypes.MXRecord;
const PTRRecord = DNSRecordTypes.PTRRecord;

pub const QueryType = enum(u16) {
    A = 1, // IPv4 address record
    NS = 2, // Name Server record
    MD = 3, // Obsolete, replaced by MX
    MF = 4, // Obsolete, replaced by MX
    CNAME = 5, // Canonical name record
    SOA = 6, // Start of Authority record
    MB = 7, // Mailbox domain name record
    MG = 8, // Mail group member record
    MR = 9, // Mail rename domain name record
    NULL_R = 10, // Null record
    WKS = 11, // Well known service description record
    PTR = 12, // Pointer record
    HINFO = 13, // Host information record
    MINFO = 14, // Mailbox or mail list information record
    MX = 15, // Mail exchanger record
    TXT = 16, // Text record
    RP = 17, // Responsible person record
    AFSDB = 18, // AFS database record
    X25 = 19, // DNS X25 resource record
    ISDN = 20, // Integrated Services Digital Network record
    RT = 21, // Route Through record
    NSAP = 22, // Network service access point address record
    NSAP_PTR = 23, // Network service access point address pointer record
    SIG = 24, // Signature record
    KEY = 25, // Key record
    PX = 26, // Mail Mapping Information record
    GPOS = 27, // DNS Geographical Position record
    AAAA = 28, // IPv6 address record
    LOC = 29, // Location record
    NXT = 30, // Obsolete record
    EID = 31, // DNS Endpoint Identifier record
    NIMLOC = 32, // DNS Nimrod Locator record
    SRV = 33, // Service locator record
    ATMA = 34, // Asynchronous Transfer Mode address record
    NAPTR = 35, // Naming Authority Pointer record
    KX = 36, // Key eXchanger record
    CERT = 37, // Certificate record
    A6 = 38, // Obsolete, replaced by AAAA type
    DNAM = 39, // Delegation Name record
    SINK = 40, // Kitchen sink record
    OPT = 41, // Option record
    APL = 42, // Address Prefix List record
    DS = 43, // Delegation signer record
    SSHFP = 44, // SSH Public Key Fingerprint record
    IPSECKEY = 45, // IPsec Key record
    RRSIG = 46, // DNSSEC signature record
    NSEC = 47, // Next-Secure record
    DNSKEY = 48, // DNS Key record
    DHCID = 49, // DHCP identifier record
    NSEC3 = 50, // NSEC record version 3
    NSEC3PARAM = 51, // NSEC3 parameters
    ALL = 255, // All cached records
    GENERIC = 256,

    pub fn from_u16(value: u16) QueryType {
        return std.enums.fromInt(QueryType, value) orelse {
            return .GENERIC;
        };
    }
};

pub const DnsClass = enum(u16) {
    IN = 1, // Internet
    CS = 2, // CSNET (obsolete)
    CH = 3, // Chaos
    HS = 4, // Hesiod
    ANY = 255, // Any class

    pub fn fromU16(value: u16) DnsClass {
        switch (value) {
            1 => return .IN,
            2 => return .CS,
            3 => return .CH,
            4 => return .HS,
            255 => return .ANY,
            else => return @intCast(value), // unknown class, keep as raw
        }
    }

    pub fn toString(self: DnsClass) []const u8 {
        return switch (self) {
            .IN => "IN",
            .CS => "CS",
            .CH => "CH",
            .HS => "HS",
            .ANY => "ANY",
            else => "UNKNOWN",
        };
    }
};

pub const QueryOwner = union(enum) {
    dns_layer: *DNSLayer,
    buffer: Buffer,
};

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
        //        InvalidPacket, // Generic malformed DNS packet
        LabelTooLong, // A label length exceeds the remaining buffer
        //        UnexpectedEndOfPacket, // Reached end of packet unexpectedly
        MemoryAllocationFailed, // Allocator failed to create a node
        //        TooManyQuestions, // qdcount is unusually large
        InvalidQType, // QTYPE field invalid
        InvalidQClass, // QCLASS field invalid
    };
};

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

const DNSRcode = enum(u4) {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
    YXDomain = 6,
    YXRRSet = 7,
    NXRRSet = 8,
    NotAuth = 9,
    NotZone = 10,
    Reserved11 = 11,
    Reserved12 = 12,
    Reserved13 = 13,
    Reserved14 = 14,
    Reserved15 = 15,
    _,

    pub fn name(self: DNSRcode) []const u8 {
        return switch (self) {
            .NoError => "NOERROR",
            .FormatError => "FORMERR",
            .ServerFailure => "SERVFAIL",
            .NameError => "NXDOMAIN",
            .NotImplemented => "NOTIMP",
            .Refused => "REFUSED",
            .YXDomain => "YXDOMAIN",
            .YXRRSet => "YXRRSET",
            .NXRRSet => "NXRRSET",
            .NotAuth => "NOTAUTH",
            .NotZone => "NOTZONE",
            else => "RESERVED",
        };
    }
};

const DNSOpcode = enum(u4) {
    Query = 0,
    IQuery = 1,
    Status = 2,
    Reserved3 = 3,
    Notify = 4,
    Update = 5,
    Dso = 6,
    // 7-15 are reserved

    pub fn name(self: DNSOpcode) []const u8 {
        return switch (self) {
            .Query => "QUERY",
            .IQuery => "IQUERY",
            .Status => "STATUS",
            .Notify => "NOTIFY",
            .Update => "UPDATE",
            .Dso => "DSO",
            else => "RESERVED",
        };
    }

    pub fn description(self: DNSOpcode) []const u8 {
        return switch (self) {
            .Query => "Standard query",
            .IQuery => "Inverse query (obsolete)",
            .Status => "Server status request",
            .Notify => "Zone change notification",
            .Update => "Dynamic update",
            .Dso => "DNS Stateful Operations",
            else => "Reserved for future use",
        };
    }
};

pub const DNSHeaderFlags = packed struct {
    rcode: u4 = 0, // Response Code
    z: u3 = 0, // Reserved (must be 0)
    ra: u1 = 0, // Recursion Available
    rd: u1 = 0, // Recursion Desired
    tc: u1 = 0, // Truncation
    aa: u1 = 0, // Authoritative Answer
    opcode: u4 = 0, // Operaiton Code
    qr: u1 = 0, // Query/Response

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

const DNSHeaderSize: usize = 12;

pub const DNSHeader = extern struct {
    id: u16, // Identification
    flags: u16, // QR, Opcode, AA, TC, RD, RA, Z, RCODE packed
    qdcount: u16, // Number of questions
    ancount: u16, // Number of answer RRs
    nscount: u16, // Number of authority RRs
    arcount: u16, // Number of additional RRs

    pub fn set_id(self: *DNSHeader, id: u16) void {
        self.id = @byteSwap(id);
    }

    pub fn get_id(self: *DNSHeader) u16 {
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

    pub fn get_nscount(self: *DNSHeader) u16 {
        return @byteSwap(self.nscount);
    }

    pub fn set_arcount(self: *DNSHeader, arcount: u16) void {
        self.arcount = @byteSwap(arcount);
    }

    pub fn get_arcount(self: *DNSHeader) u16 {
        return @byteSwap(self.arcount);
    }

    //TODO: implement get_flags_mutable
    pub fn get_flags(self: *DNSHeader) *DNSHeaderFlags {
        return @ptrCast(&self.flags);
    }

    //TODO: implement get_flags_immutable
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

                //try self.get_queries();

                return self;
            },
            .owned_buffer => {
                var self = DNSLayer{ .owner = owner };
                //              print("DNSLayer (self) on init: {*}\n", .{&self});
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < DNSHeaderSize) {
                    const dns_data = try self.owner.owned_buffer.extend(buffer_len, DNSHeaderSize);

                    @memset(dns_data, 0);
                } else {
                    //try self.get_queries(); // calling this here causes
                }

                return self;
            },
        }
    }

    fn get_allocator(self: *DNSLayer) Allocator {
        switch (self.owner) {
            .packet_layer => |layer| {
                return layer.packet.layer_allocator;
            },
            .owned_buffer => |*buffer| {
                return buffer.allocator;
            },
        }
    }

    pub fn get_data(self: *const DNSLayer) []u8 {
        switch (self.owner) {
            .packet_layer => {
                //               print("getting data from packet.\n", .{});
                return self.owner.packet_layer.get_data(); // Layer in packet
            },
            .owned_buffer => |*buffer| {
                //                print("DNSLayer (self) in get_data: {*}\n", .{self});
                return buffer.buffer.items; // standalone layer
            },
        }
    }

    /// Get the payload (data after DNS header)
    pub fn get_payload(self: *DNSLayer) ?[]const u8 {
        const data = self.get_data();

        if (data.len > DNSHeaderSize) {
            return data[DNSHeaderSize..]; // return remaining bytes after the header
        } else {
            return null;
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

    pub fn addQuery(self: *DNSLayer, query: *DNSQuery) !void {
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

    //pub fn extract_query(self: *DNSLayer, query: *Query, allocator: Allocator) ?DNSQuery {
    //    var cur = self.first_query;
    //    while (cur) |q| {
    //        if (query == q) {
    //
    //        }
    //    }
    //}

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

    //    fn find_by_() {}

    pub fn extend_payload(self: *DNSLayer, offset: usize, extend_len: usize) ![]u8 {
        var buf: []u8 = undefined;
        switch (self.owner) {
            .packet_layer => |layer| {
                buf = try layer.packet.extend_layer(layer, extend_len);
            },
            .owned_buffer => |*buffer| {
                buf = try buffer.extend(offset, extend_len);
            },
        }

        return buf;
    }

    //TODO: remove domain, qtype, class and allocator as required params and just pass DNSQuery struct
    pub fn add_query(self: *DNSLayer, domain: []const u8, qtype: QueryType, class: DnsClass) !void {
        var hdr = self.get_mutable_header();

        var qdcount = hdr.get_qdcount();

        const extend_len = domain.len + 6;

        var query_buf = try self.extend_payload(self.get_data().len, extend_len);

        // Slice buffer starting at offset
        var qbuffer = query_buf[0..];

        // Write QNAME (labels)
        var buf_offset: usize = 0;
        var it = std.mem.splitScalar(u8, domain, '.');
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
        std.mem.writeInt(u16, @ptrCast(qbuffer[buf_offset .. buf_offset + 2]), @intCast(@intFromEnum(class)), .big);
        buf_offset += 2;

        // Increment QDCOUNT
        qdcount += 1;
        hdr.set_qdcount(qdcount);
    }

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

    pub fn get_q_section_sz(self: *DNSLayer) !usize {
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

    pub fn get_answer_count(self: *DNSLayer) usize {
        var count: usize = 0;
        var cur = self.first_answer;
        while (cur) |ans| {
            count += 1;
            cur = ans.get_next_record();
        }

        return count;
    }

    pub fn get_answers(self: *DNSLayer) !void {
        var allocator = self.get_allocator();
        const data = self.get_data();
        var offset: usize = DNSHeaderSize;
        if (self.get_last_query()) |last| {
            offset += last.length;
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

            // Create a DNSAnswer node
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
                //answer.offset = last.offset + last.length; // set answer added offset to the last offset + last length
            } else { // there was no last answer
                self.first_answer = answer; // set first answer to this answer being added
                self.last_answer = answer; // set last answer to this answer being added
                //answer.offset = ans_offset;
            }
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
            .{
                id,
                qr,
                opcode,
                aa,
                tc,
                rd,
                ra,
                z,
                rcode,
                qdcount,
                ancount,
                nscount,
                arcount,
            },
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

    pub fn destroy_queries(self: *DNSLayer) void {
        var allocator = self.get_allocator();
        var cur = self.first_query;

        while (cur) |query| {
            const next = query.next_query;
            allocator.destroy(query);
            cur = next;
        }
    }

    pub fn destroy_answers(self: *DNSLayer) void {
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
        switch (self.owner) {
            .packet_layer => {
                return; // Layer in packet - don't free
            },
            .owned_buffer => |*buffer| {
                buffer.deinit(); // standalone layer - it is mutable by default
            },
        }
    }
};

/// Creates a domain name from a DNS label. The allocator creates an ArrayList to store the bytes and returns a mutable slice
/// The ArrayList is deinit'd before return
pub fn decodeQname(allocator: Allocator, payload: []const u8) ![]u8 {
    var list = try std.ArrayList(u8).initCapacity(allocator, payload.len);
    defer list.deinit(allocator);

    var offset: usize = 0;
    var first = true;

    while (offset < payload.len and payload[offset] != 0) {
        const len = payload[offset];
        offset += 1;

        if (offset + len > payload.len) return error.InvalidPacket;

        if (!first) try list.append(allocator, '.');
        first = false;

        try list.appendSlice(allocator, payload[offset .. offset + len]);
        offset += len;
    }

    // if we never saw the terminating 0 byte, reject
    if (offset >= payload.len or payload[offset] != 0) return error.InvalidPacket;

    return list.toOwnedSlice(allocator);
}

comptime {
    if (@bitSizeOf(DNSHeader) != 96)
        @compileError("DNSHeaderBits must be exactly 96 bits (12 bytes)");
}
