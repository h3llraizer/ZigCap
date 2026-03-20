const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

const LayerProtocols = @import("Layer.zig").LayerProtocols;
const Layer = @import("Layer.zig").Layer;

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

    _,

    pub fn get(value: u16) ?QueryType {
        return std.enums.fromInt(QueryType, value);
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

pub const DNSHeader = packed struct {
    id: u16 = 0, // 16 bits
    rcode: u4 = 0, // 4 bits
    z: u3 = 0, // 3 bits
    ra: u1 = 0, // 1 bit
    rd: u1 = 0, // 1 bit
    tc: u1 = 0, // 1 bit
    aa: u1 = 0, // 1 bit
    opcode: u4 = 0, // 4 bits
    qr: u1 = 0, // 1 bit
    qdcount: u16 = 0, // 16 bits
    ancount: u16 = 0, // 16 bits
    nscount: u16 = 0, // 16 bits
    arcount: u16 = 0, // 16 bits

};

const DNSQuery = struct {
    qname: []u8,
    qtype: u16,
    qclass: u16,
    next: ?*DNSQuery,
};

pub const DNSAnswer = struct {
    rtype: u16,
    class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: []u8,
    next: ?*DNSAnswer,
};

const DNSHeaderSize: usize = 12;

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

pub const DNSQueryError = error{
    InvalidPacket, // Generic malformed DNS packet
    LabelTooLong, // A label length exceeds the remaining buffer
    UnexpectedEndOfPacket, // Reached end of packet unexpectedly
    MemoryAllocationFailed, // Allocator failed to create a node
    TooManyQuestions, // qdcount is suspiciously large
    InvalidQType, // QTYPE field is invalid
    InvalidQClass, // QCLASS field is invalid

};

pub const DNSLayer = struct {
    raw: []u8,
    DnsHeader: ?*align(1) DNSHeader,
    queries: ?*DNSQuery,
    answers: ?*DNSAnswer,

    const Protocol = LayerProtocols{ .Application = .DNS };

    //// Creates a DNS layer from an existing buffer // rename this to from_buf
    pub fn init(raw: []u8, allocator: std.mem.Allocator) !*DNSLayer {
        if (raw.len < DNSHeaderSize) {
            return error.InitialBufferSizeTooSmall;
        }

        var dns_layer = try allocator.create(DNSLayer);
        dns_layer.raw = raw;
        const DnsHdr: *align(1) DNSHeader = @ptrCast(&raw[0]);
        dns_layer.DnsHeader = DnsHdr;
        dns_layer.queries = null;
        try DNSLayer.get_queries(dns_layer, allocator);
        dns_layer.answers = null;
        try DNSLayer.get_answers(dns_layer, allocator);
        return dns_layer;
    }

    //// Creates an empty DNS layer with default initialised dns header values - remove size requirement
    pub fn create(allocator: std.mem.Allocator, initial_size: usize) !*DNSLayer {
        if (initial_size < DNSHeaderSize) {
            return error.InitialBufferSizeTooSmall;
        }

        var dns_layer = try allocator.create(DNSLayer);

        // Allocate raw packet buffer
        dns_layer.raw = try allocator.alloc(u8, initial_size);

        // Allocate header struct with defaults
        dns_layer.DnsHeader = try allocator.create(DNSHeader); // create the struct

        dns_layer.DnsHeader.?.* = std.mem.zeroInit(DNSHeader, DNSHeader{}); // zero the struct members

        dns_layer.queries = null;
        dns_layer.answers = null;

        return dns_layer;
    }

    pub fn to_string(self: *DNSLayer, allocator: Allocator) []const u8 {
        const hdr = self.get_header();

        const id: u16 = std.mem.bigToNative(u16, hdr.id);

        const qr = hdr.qr;
        const opcode = hdr.opcode;
        const aa = hdr.aa;
        const tc = hdr.tc;
        const rd = hdr.rd;
        const ra = hdr.ra;
        const z = hdr.z;
        const rcode = hdr.rcode;

        const qdcount: u16 = std.mem.bigToNative(u16, hdr.qdcount);
        const ancount: u16 = std.mem.bigToNative(u16, hdr.ancount);
        const nscount: u16 = std.mem.bigToNative(u16, hdr.nscount);
        const arcount: u16 = std.mem.bigToNative(u16, hdr.arcount);

        const result = std.fmt.allocPrint(
            allocator,
            \\DNS Layer:
            \\  id: {}
            \\  qr: {}
            \\  opcode: {}
            \\  aa: {}
            \\  tc: {}
            \\  rd: {}
            \\  ra: {}
            \\  z: {}
            \\  rcode: {}
            \\  qdcount: {}
            \\  ancount: {}
            \\  nscount: {}
            \\  arcount: {}
        ,
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
            size += q.qname.len;
            size += 4;
            query = q.next;
        }

        return size;
    }

    pub fn get_first_query(self: DNSLayer) ?*DNSQuery {
        return self.queries;
    }

    fn get_answers(self: *DNSLayer, allocator: std.mem.Allocator) !void {
        var offset: usize = DNSHeaderSize;

        const q_sec_size: usize = try self.get_q_section_sz();
        offset += q_sec_size;

        const ancount = @as(u32, std.mem.bigToNative(u16, self.DnsHeader.?.ancount));

        var i: u32 = 0;
        while (i < ancount) : (i += 1) {
            if (offset + 12 > self.raw.len) // minimum RR header size: NAME(2) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
                return error.InvalidPacket;

            // Parse NAME
            const name_offset = offset;
            _ = name_offset;
            // This can be a pointer/offset compression (0xC0..) or raw labels
            // decode_name function to handle pointers and labels
            const name_slice = try decode_name(self.raw, &offset);
            _ = name_slice;

            // Parse TYPE
            const rtype = std.mem.readInt(u16, @ptrCast(self.raw[offset .. offset + 2].ptr), .big);
            offset += 2;

            // Parse CLASS
            const rclass = std.mem.readInt(u16, @ptrCast(self.raw[offset .. offset + 2].ptr), .big);
            offset += 2;

            // Parse TTL
            const ttl = std.mem.readInt(u32, @ptrCast(self.raw[offset .. offset + 4].ptr), .big);
            offset += 4;

            // Parse RDLENGTH
            const rdlength = std.mem.readInt(u16, @ptrCast(self.raw[offset .. offset + 2].ptr), .big);
            offset += 2;

            if (offset + rdlength > self.raw.len) {
                return error.InvalidPacket;
            }

            const rdata = self.raw[offset .. offset + rdlength];
            offset += rdlength;

            // Create a DNSAnswer node
            var node = try allocator.create(DNSAnswer);
            node.rdata = rdata;
            node.rtype = rtype;
            node.class = rclass;
            node.ttl = ttl;
            node.next = null;

            // Append to linked list
            if (self.answers) |ans| {
                var tail = ans;
                while (tail.next) |n| tail = n;
                tail.next = node;
            } else {
                self.answers = node;
            }
        }
    }

    pub fn get_first_answer(self: *DNSLayer) ?*DNSAnswer {
        return self.answers;
    }

    pub fn add_query(self: *DNSLayer, domain: []const u8, qtype: QueryType, class: DnsClass, allocator: std.mem.Allocator) !void {
        var qdcount = std.mem.bigToNative(u16, self.DnsHeader.?.qdcount);

        // Calculate offset to append new query
        var offset: usize = DNSHeaderSize; // DNS header is 12 bytes
        if (qdcount != 0) {
            var query = self.queries;
            while (query) |q| {
                offset += q.qname.len + 1 + 4; // +1 for null terminator, +4 for QTYPE+QCLASS
                query = q.next;
            }
        }

        // Slice buffer starting at offset
        var qbuffer = self.raw[offset..];

        // Write QNAME (labels)
        var buf_offset: usize = 0;
        var it = std.mem.splitScalar(u8, domain, '.');
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
        std.mem.writeInt(u16, @ptrCast(qbuffer[buf_offset .. buf_offset + 2]), @intCast(@intFromEnum(class)), .big);
        buf_offset += 2;

        // Increment QDCOUNT
        qdcount += 1;
        self.DnsHeader.?.qdcount = std.mem.nativeToBig(u16, qdcount);

        // Optional: append new query to linked list
        var node = try allocator.create(DNSQuery);
        node.qname = qbuffer[0..buf_offset]; // slice of newly written query

        node.qtype = @intFromEnum(qtype);
        node.qclass = @intFromEnum(class);

        node.next = null;

        if (self.queries) |first| {
            var last = first;
            while (last.next) |n| {
                last = n;
            }
            last.next = node;
        } else {
            self.queries = node;
        }
    }

    fn get_queries(self: *DNSLayer, allocator: std.mem.Allocator) !void {
        // Questions parsing / printing loop
        var offset: usize = DNSHeaderSize;

        var i: u32 = 0;
        const qdcount = @as(u32, std.mem.bigToNative(u16, self.DnsHeader.?.qdcount));
        while (i < qdcount) : (i += 1) {
            const qname_start = offset;

            // Walk labels
            while (offset < self.raw.len and self.raw[offset] != 0) {
                const len = self.raw[offset];
                offset += 1;

                if (offset + len > self.raw.len)
                    return error.InvalidPacket;

                offset += len;
            }

            if (offset >= self.raw.len)
                return error.InvalidPacket;

            offset += 1; // skip null terminator

            const qname_slice = self.raw[qname_start..offset];

            // Skip QTYPE + QCLASS (4 bytes)
            if (offset + 4 > self.raw.len)
                return error.InvalidPacket;

            const qtype = std.mem.readInt(u16, @ptrCast(self.raw[offset .. offset + 2].ptr), .big);
            const qclass = std.mem.readInt(u16, @ptrCast(self.raw[offset + 2 .. offset + 4].ptr), .big);
            offset += 4;

            var node = try allocator.create(DNSQuery);
            node.qname = qname_slice;
            node.qclass = qclass;
            node.qtype = qtype;
            node.next = null;

            if (self.queries) |query| {
                var curr = query;
                while (curr.next) |n| {
                    curr = n;
                }
                curr.next = node;
            } else {
                self.queries = node;
            }
        }
    }

    /// get slice of data (hdr+payload)
    pub fn get_data(self: *DNSLayer) []u8 {
        return self.raw;
    }

    /// Does nothing for this layer
    pub fn parse_next_layer(self: *DNSLayer, allocator: std.mem.Allocator) ?*Layer {
        _ = self;
        _ = allocator;
        return null;
    }

    pub fn get_payload(self: *DNSLayer) []u8 {
        return self.raw;
    }

    pub fn set_payload(self: *DNSLayer, data: []u8) void {
        self.raw = data;
    }

    pub fn get_protocol(self: *DNSLayer) LayerProtocols {
        _ = self;
        return DNSLayer.Protocol;
    }

    pub fn get_header(self: *DNSLayer) *DNSHeader {
        return @ptrCast(@alignCast(self.raw[0..12]));
    }

    pub fn deinit(self: *DNSLayer, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }
};

/// Creates a domain name from a DNS label. The allocator creates an ArrayList to store the bytes and returns a mutable slice
/// The ArrayList is deinit'd before return
pub fn decodeQname(
    allocator: std.mem.Allocator,
    payload: []const u8,
) ![]u8 {
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

pub fn build_layer() !void {
    var buffer: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const fallocor = fba.allocator();

    const dns_layer = try DNSLayer.create(fallocor, 512);

    try dns_layer.add_query("southwest-sites.co.uk", QueryType.A, DnsClass.IN, fallocor);

    var query = dns_layer.get_first_query();
    while (query) |q| {
        const qname = try decodeQname(fallocor, q.qname);

        std.debug.print("{s} : {s}\n", .{ qname, q.qtype });
        query = q.next;
    }

    try dns_layer.to_string();
}

const dns_packet: [36]u8 = .{ 0xb8, 0x2e, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x74, 0x69, 0x6d, 0x65, 0x0a, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x66, 0x6c, 0x61, 0x72, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01 };

const test_response: [69]u8 = .{
    0xb8, 0x2e, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x00, 0x04, 0x74, 0x69, 0x6d,
    0x65, 0x0a, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x66,
    0x6c, 0x61, 0x72, 0x65, 0x03, 0x63, 0x6f, 0x6d,
    0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xd1, 0x00,
    0x04, 0xa2, 0x9f, 0xc8, 0x7b, 0xc0, 0x0c, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xd1, 0x00,
    0x04, 0xa2, 0x9f, 0xc8, 0x01,
};

test "DNS parser with Cloudflare response" {
    var buffer: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const fallocor = fba.allocator();

    const response_pkt = try fallocor.alloc(u8, test_response.len);
    std.mem.copyForwards(u8, response_pkt, &test_response);

    const dns_layer = try DNSLayer.init(response_pkt, fallocor);

    // Expect header values
    try std.testing.expectEqual(0xb82e, std.mem.bigToNative(u16, dns_layer.DnsHeader.?.id));
    try std.testing.expectEqual(1, std.mem.bigToNative(u16, dns_layer.DnsHeader.?.qdcount));
    try std.testing.expectEqual(2, std.mem.bigToNative(u16, dns_layer.DnsHeader.?.ancount));

    // Expect query name
    const query = dns_layer.get_first_query();
    try std.testing.expect(query != null);
    if (query) |q| {
        const qname = try decodeQname(fallocor, q.qname);
        try std.testing.expectEqualStrings("time.cloudflare.com", qname);
        try std.testing.expectEqual(1, q.qtype); // TYPE A
    }

    // Expect answer IPs
    var answer = dns_layer.get_first_answer();
    try std.testing.expect(answer != null);
    if (answer) |ans| {
        if (ans.rtype == 1 and ans.rdata.len == 4) {
            try std.testing.expectEqual(162, ans.rdata[0]);
            try std.testing.expectEqual(159, ans.rdata[1]);
            try std.testing.expectEqual(200, ans.rdata[2]);
            try std.testing.expectEqual(123, ans.rdata[3]);
        }

        answer = ans.next;
        try std.testing.expect(answer != null);
        if (answer) |anss| {
            if (anss.rtype == 1 and anss.rdata.len == 4) {
                try std.testing.expectEqual(162, anss.rdata[0]);
                try std.testing.expectEqual(159, anss.rdata[1]);
                try std.testing.expectEqual(200, anss.rdata[2]);
                try std.testing.expectEqual(1, anss.rdata[3]);
            }
        }
    }

    // Query section size and remaining
    const qsize = try dns_layer.get_q_section_sz();
    try std.testing.expectEqual(25, qsize);

    const rem = try dns_layer.get_remaining();
    try std.testing.expectEqual(37, rem);

    try std.testing.expectEqual(69, dns_layer.raw.len);
}

comptime {
    if (@bitSizeOf(DNSHeader) != 96)
        @compileError("DNSHeaderBits must be exactly 96 bits (12 bytes)");
}

//pub fn parseHeader(payload: []const u8) !void {
//    if (payload.len < 12) {
//        return error.InvalidPacket;
//    }
//
//    // DNS fields are big-endian (network byte order)
//    const transaction_id = std.mem.readInt(u16, payload[0..2], .big);
//    const flags = getFlags(std.mem.readInt(u16, payload[2..4], .big));
//    const qdcount = std.mem.readInt(u16, payload[4..6], .big);
//    const ancount = std.mem.readInt(u16, payload[6..8], .big);
//    const nscount = std.mem.readInt(u16, payload[8..10], .big);
//    const arcount = std.mem.readInt(u16, payload[10..12], .big);
//
//    std.debug.print("DNS Header:\n", .{});
//    std.debug.print("Transaction ID: {d}\n", .{transaction_id});
//    //std.debug.print("Flags: {x}\n", .{flags});
//    std.debug.print("QR Type: {s}\n", .{if (flags.QR == 0) "query" else "response"});
//    std.debug.print("Questions: {d}, Answers: {d}, Authority: {d}, Additional: {d}\n", .{ qdcount, ancount, nscount, arcount });
//}
