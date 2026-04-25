const std = @import("std");

const ProtocolEnums = @import("ProtocolEnums.zig");
const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;
const LayerError = ProtocolEnums.LayerError;
const LayerIface = @import("LayerIface.zig").LayerIface;
const LayerOwner = @import("Layer.zig").LayerOwner;

const Packet = @import("Packet.zig");

const ApplicationLayer = @import("GenericLayer.zig").ApplicationLayer;

const print = std.debug.print;
const panic = std.debug.print;

const Allocator = std.mem.Allocator;

pub const TCPHeaderMinSize = 20;
pub const TCPHeaderMaxSize = 40;

const TCPOption = enum(u8) {
    EOL = 0x00, // End of Options List
    NOP = 0x01, // No-Operation (padding)
    MSS = 0x02, // Maximum Segment Size
    WS = 0x03, // Window Scale
    SACK_PERM = 0x04, // SACK Permitted
    SACK = 0x05, // SACK Block (Selective ACK)
    TS = 0x08, // Timestamp
    TCP_FASTOPEN = 0x0f, // TCP Fast Open (TFO)
    EXP_FASTOPEN = 0x1a, // Experimental Fast Open (draft-ietf-tcp-fastopen)
    MULTIPATH_TCP = 0x1e, // Multipath TCP (MPTCP)
    AUTH = 0x1f, // TCP Authentication Option (TCP-AO) - replaces MD5
    MD5 = 0x13, // TCP MD5 Signature (deprecated by TCP-AO)
    SC_PS = 0x1c, // Sender - Specific Congestion/Pacing Scheme (experimental)
    VS_DATA = 0x1d, // VS Data (experimental)
    NUM = 0x1b, // TCP NUM Option (Nonce Update Mechanism, experimental)
    CLARK = 0x09, // Clark's timestamp echo (obsolete)
    TSN = 0x0a, // TCP TSN (Transport Sequence Number, experimental)
    SIG = 0x0b, // TCP Signature (obsolete)
    //UTO = 0x1c, // TCP User Timeout Option (both UTO and SC-PS share 0x1c)

    _,

    pub fn length(self: TCPOption) ?u8 {
        return switch (self) {
            .EOL, .NOP => null, // Single byte, no length field
            .MSS, .WS, .SACK_PERM, .TCP_FASTOPEN, .MD5, .AUTH, .SACK, .TS, .MULTIPATH_TCP, .SC_PS, .VS_DATA, .NUM, .CLARK, .TSN, .SIG, .UTO => null, // Length varies, check actual value
            // For most options, you need to read the length byte at offset+1
        };
    }

    pub fn has_length_byte(self: TCPOption) bool {
        return self != .EOL and self != .NOP;
    }

    pub fn minimum_length(self: TCPOption) u8 {
        return switch (self) {
            .EOL, .NOP => 1,
            .SACK_PERM => 2, // Kind + Length only, no value
            else => 3, // Kind + Length + at least 1 value byte
        };
    }

    // Alternative naming aliases (can be added as methods or constants)
    pub fn name(self: TCPOption) []const u8 {
        return switch (self) {
            .EOL => "End of Options",
            .NOP => "No-Operation",
            .MSS => "Maximum Segment Size",
            .WS => "Window Scale",
            .SACK_PERM => "SACK Permitted",
            .SACK => "Selective ACK",
            .TS => "Timestamp",
            .TCP_FASTOPEN => "TCP Fast Open",
            .EXP_FASTOPEN => "Experimental Fast Open",
            .MULTIPATH_TCP => "Multipath TCP",
            .AUTH => "TCP Authentication",
            .MD5 => "TCP MD5 Signature",
            .SC_PS => "Sender-Specific Congestion/Pacing",
            .VS_DATA => "VS Data",
            .NUM => "Nonce Update",
            .CLARK => "Clark's Timestamp Echo",
            .TSN => "Transport Sequence Number",
            .SIG => "TCP Signature",
            else => "Unknown",
            //.UTO => "User Timeout",
        };
    }
};

const TCPFlags = packed struct {
    fin: u1,
    syn: u1,
    rst: u1,
    psh: u1,
    ack: u1,
    urg: u1,
    ece: u1,
    cwr: u1,
};

/// Standard TCPHeader (20 bytes)
/// seq and ack num are specified as 4 byte u8 arrays for alignment purposes
pub const TCPHeader = extern struct {
    src_port: u16,
    dst_port: u16,
    seq_num: [4]u8,
    ack_num: [4]u8,
    data_offset_reserved_flags: [2]u8, // high bit is offset + reserved. low bit is TCPFlags
    window: u16,
    checksum: u16,
    urgent_ptr: u16,

    pub fn init_default() TCPHeader {
        return .{
            .src_port = 0,
            .dst_port = 0,
            .seq_num = [_]u8{0} ** 4,
            .ack_num = [_]u8{0} ** 4,
            .data_offset_reserved_flags = [_]u8{0} ** 2,
            .window = 0,
            .checksum = 0,
            .urgent_ptr = 0,
        };
    }

    /// Get Source Port of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn get_src_port(self: *const TCPHeader) u16 {
        const src_port = self.src_port;
        return std.mem.bigToNative(u16, src_port);
    }

    /// Get Destination Port of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn get_dst_port(self: *const TCPHeader) u16 {
        const dst_port = self.dst_port;
        return std.mem.bigToNative(u16, dst_port);
    }

    /// Get Source Port of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn set_src_port(self: *TCPHeader, port: u16) void {
        self.src_port = std.mem.nativeToBig(u16, port);
    }

    /// Get Destination Port of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn set_dst_port(self: *TCPHeader, port: u16) void {
        self.dst_port = std.mem.nativeToBig(u16, port);
    }

    /// returns sequence number in little endian
    pub fn get_seq_num(self: *const TCPHeader) u32 {
        const sq = self.seq_num;
        const seq_num = std.mem.readInt(u32, &sq, .little);

        return seq_num;
    }

    /// writes sequence number in big endian
    pub fn set_seq_num(self: *TCPHeader, seq_num: u32) void {
        std.mem.writeInt(u32, &self.seq_num, seq_num, .big);
    }

    /// return acknowledgement number in little endian
    pub fn get_ack_num(self: *const TCPHeader) u32 {
        const ack = self.ack_num;
        const ack_num = std.mem.readInt(u32, &ack, .little);

        return ack_num;
    }

    /// writes acknowledgement number in big endian
    pub fn set_ack_num(self: *TCPHeader, ack_num: u32) void {
        std.mem.writeInt(u32, &self.ack_num, ack_num, .big);
    }

    pub fn get_window(self: *const TCPHeader) u16 {
        return @byteSwap(self.window);
    }

    pub fn set_window(self: *TCPHeader, window: u16) void {
        self.window = @byteSwap(window);
    }

    pub fn get_checksum(self: *const TCPHeader) u16 {
        return @byteSwap(self.checksum);
    }

    pub fn set_checksum(self: *TCPHeader, checksum: u16) void {
        self.checksum = @byteSwap(checksum);
    }

    pub fn get_urgent_ptr(self: *const TCPHeader) u16 {
        return @byteSwap(self.urgent_ptr);
    }

    pub fn set_urgent_ptr(self: *TCPHeader, urgent_ptr: u16) void {
        self.urgent_ptr = @byteSwap(urgent_ptr);
    }

    pub fn get_hdr_length(self: *const TCPHeader) u8 {
        const high_byte = self.data_offset_reserved_flags[0];

        const data_offset = (high_byte >> 4) & 0xF; // shift down top 4 bits
        const tcp_header_length = data_offset * 4; // in bytes
        return tcp_header_length;
    }

    pub fn get_flags_immutable(self: *const TCPHeader) *const TCPFlags {
        return @ptrCast(&self.data_offset_reserved_flags[1]);
    }

    pub fn get_flags_mutable(self: *TCPHeader) *TCPFlags {
        return @ptrCast(&self.data_offset_reserved_flags[1]);
    }
};

pub const TCPLayer = struct {
    owner: LayerOwner,
    const Protocol = tcp_ip_protocol.tcp;

    /// Creates layer from ptr to minimum 20 byte length buffer
    pub fn init(owner: LayerOwner) LayerError!TCPLayer {
        switch (owner) {
            .packet_layer => {
                return TCPLayer{
                    .owner = owner,
                };
            },
            .owned_buffer => {
                var self = TCPLayer{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < TCPHeaderMinSize) {
                    const tcp_data = try self.owner.owned_buffer.extend(buffer_len, TCPHeaderMinSize);

                    @memset(tcp_data, 0);

                    var header = TCPHeader.init_default();

                    @memcpy(tcp_data[0..TCPHeaderMinSize], std.mem.asBytes(&header));
                }

                return self;
            },
        }
    }

    /// Get Checksum of the TCPPHeader - converts u16 value from Big to Native and returns
    pub fn get_checksum(self: *const TCPLayer) u16 {
        const hdr = self.get_immutable_header();

        return std.mem.bigToNative(u16, hdr.checksum);
    }

    /// Get Length of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn get_length(self: *const TCPLayer) u16 {
        const hdr = self.get_header();

        return std.mem.bigToNative(u16, hdr.length);
    }

    /// Calculate the checksum of the TCPHeader - not yet implemented
    pub fn calculate_checksum(self: *TCPLayer) void {
        _ = self;
        return;
    }

    pub fn parse_tcp_options(self: *TCPLayer) void {
        var offset: usize = TCPHeaderMinSize; // Start after fixed header
        const header_len = self.get_immutable_header().get_hdr_length();

        const tcp_ops_header = self.get_data();

        while (offset < header_len) {
            const kind_val = tcp_ops_header[offset];

            const kind: TCPOption = @enumFromInt(kind_val);

            //    const name = kind.name();

            //     print("{s}\n", .{name});

            switch (kind) {
                .EOL => { // EOL
                    //           print("EOL at offset {}\n", .{offset});
                    offset += 1; // must increment
                },
                .NOP => { // NOP
                    //          print("NOP padding at offset {}\n", .{offset});
                    offset += 1;
                },
                .MSS => { // MSS
                    const len = tcp_ops_header[offset + 1];
                    if (len >= 4) {
                        const mss: u16 = @as(u16, @intCast(tcp_ops_header[offset + 2])) << 8 | @as(u16, (@intCast(tcp_ops_header[offset + 3])));
                        //             print("MSS = {} bytes\n", .{mss});
                        _ = mss;
                    }
                    offset += len;
                },
                .WS => { // Window Scale
                    const len = tcp_ops_header[offset + 1];
                    if (len >= 3) {
                        const shift = tcp_ops_header[offset + 2];
                        _ = shift;
                        //print("Window Scale = {}\n", .{shift});
                    }
                    offset += len;
                },
                .SACK_PERM => { // SACK Permitted
                    //print("SACK Permitted\n", .{});
                    offset += 2;
                },
                .TS => { // Timestamp
                    const len = tcp_ops_header[offset + 1];
                    if (len >= 10) {
                        const tsval = @as(u32, @intCast(tcp_ops_header[offset + 2])) << 24 |
                            @as(u32, @intCast(tcp_ops_header[offset + 3])) << 16 |
                            @as(u32, @intCast(tcp_ops_header[offset + 4])) << 8 |
                            @as(u32, @intCast(tcp_ops_header[offset + 5]));

                        const tsecr = @as(u32, @intCast(tcp_ops_header[offset + 6])) << 24 |
                            @as(u32, @intCast(tcp_ops_header[offset + 7])) << 16 |
                            @as(u32, @intCast(tcp_ops_header[offset + 8])) << 8 |
                            @as(u32, @intCast(tcp_ops_header[offset + 9]));

                        _ = tsval;
                        _ = tsecr;

                        //print("TSval={}, TSecr={}\n", .{ tsval, tsecr });
                    }
                    offset += len;
                },
                else => { // possibly break here to avoid unsafe/innacurate parsing
                    const len = tcp_ops_header[offset + 1];
                    offset += len;
                },
            }
        }
    }

    /// at the moment, this will always return a generic application layer because no application layer protocols have been fully implemented
    pub fn get_next_layer_type(self: *TCPLayer, layer: *Packet.Layer) !?LayerIface {
        const data: []const u8 = self.get_data();

        if (data.len < TCPHeaderMinSize) {
            return LayerError.BufferTooSmall;
        }

        if (self.get_payload().len > 0) {
            return try LayerIface.init(ApplicationLayer, LayerOwner{ .packet_layer = layer });
        }

        return null;
    }

    pub fn get_mutable_header(self: *TCPLayer) *TCPHeader {
        const data = self.get_data();
        const aligned_ptr: [*]align(@alignOf(TCPHeader)) u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    pub fn get_immutable_header(self: *const TCPLayer) *const TCPHeader {
        const data: []const u8 = self.get_data();

        if (data.len < TCPHeaderMinSize) {
            panic("TCP Raw Data len ({}) less than TCPHeaderSize", .{data.len});
        }

        const aligned_ptr: [*]align(@alignOf(TCPHeader)) const u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    //// Calculate the length of the TCPHeader
    pub fn calculate_length(self: *TCPLayer) u16 {
        const hdr = self.get_immutable_header();
        const raw = std.mem.bigToNative(u16, hdr.data_offset_reserved_flags);
        const data_offset = (raw >> 12) & 0xF; // top 4 bits
        return data_offset * 4; // in bytes
    }

    /// Get slice of data (header + payload)
    pub fn get_data(self: *const TCPLayer) []u8 {
        return self.owner.get_data();
    }

    /// Get the payload (data after TCP header)
    pub fn get_payload(self: *TCPLayer) []const u8 {
        const data = self.get_data();
        const hdr_len = self.get_immutable_header().get_hdr_length();

        if (data.len > hdr_len) { // TODO: calculate the TCP header length
            return data[hdr_len..]; // return remaining bytes after the header
        } else {
            return "";
        }
    }

    pub fn to_string(self: *TCPLayer, allocator: Allocator) []const u8 {
        const hdr = self.get_immutable_header();

        const src_port: u16 = std.mem.bigToNative(u16, hdr.src_port);
        const dst_port: u16 = std.mem.bigToNative(u16, hdr.dst_port);
        const seq: u32 = std.mem.readInt(u32, &hdr.seq_num, .little);
        const ack: u32 = std.mem.readInt(u32, &hdr.ack_num, .little);

        //       const data_offset_reserved_flags: u16 = std.mem.bigToNative(u16, hdr.data_offset_reserved_flags);
        //
        //       // TCP data offset is top 4 bits (in 32-bit words)
        //       const data_offset: u8 = @intCast(data_offset_reserved_flags >> 12);
        //
        //       // Lower 12 bits contain flags + reserved bits (depending on your layout)
        //       const flags: u16 = data_offset_reserved_flags & 0x0FFF;

        const data_offset: u16 = 0;
        const flags: u16 = 0;
        const window_size: u16 = std.mem.bigToNative(u16, hdr.window);
        const checksum: u16 = std.mem.bigToNative(u16, hdr.checksum);
        const urgent_pointer: u16 = std.mem.bigToNative(u16, hdr.urgent_ptr);

        const result = std.fmt.allocPrint(
            allocator,
            "TCP Layer: src_port: {} dst_port: {} seq: {} ack: {} data_offset: {} flags: 0x{x} window_size: {} checksum: 0x{x} urgent_pointer: {}",
            .{ src_port, dst_port, seq, ack, data_offset, flags, window_size, checksum, urgent_pointer },
        ) catch |err| {
            std.debug.print("TCP allocPrint failed: {s}\n", .{@errorName(err)});
            return "";
        };

        return result;
    }

    pub fn get_protocol(self: *TCPLayer) tcp_ip_protocol {
        _ = self;
        return TCPLayer.Protocol;
    }

    pub fn deinit(self: *TCPLayer) void {
        switch (self.owner) {
            .packet_layer => {
                return; // Layer in packet - don't free
            },
            .owned_buffer => |*buffer| {
                return buffer.deinit(); // standalone layer - it is mutable by default
            },
        }
    }
};
