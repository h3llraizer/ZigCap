const std = @import("std");
const print = std.debug.print;
const panic = std.debug.print;

const Allocator = std.mem.Allocator;

const ProtocolEnums = @import("ProtocolEnums.zig");
const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;
const LayerError = ProtocolEnums.LayerError;
const LayerIface = @import("LayerIface.zig").LayerIface;
const LayerOwner = @import("Layer.zig").LayerOwner;

const Packet = @import("Packet.zig");

const ApplicationLayer = @import("GenericLayer.zig").ApplicationLayer;

const RawData = @import("RawData.zig").RawData;

pub const TCPHeaderMinSize = 20;
pub const TCPHeaderMaxSize = 40;

/// Standard TCPHeader (20 bytes)
/// seq and ack num are specified as 4 byte u8 arrays for alignment purposes
pub const TCPHeader = extern struct {
    src_port: u16,
    dst_port: u16,
    seq_num: [4]u8,
    ack_num: [4]u8,
    data_offset_reserved_flags: u16,
    window: u16,
    checksum: u16,
    urgent_ptr: u16,

    pub fn init_default() TCPHeader {
        return .{
            .src_port = 0,
            .dst_port = 0,
            .seq_num = [_]u8{0} ** 4,
            .ack_num = [_]u8{0} ** 4,
            .data_offset_reserved_flags = 0,
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

    pub fn get_seq_num(self: *TCPHeader) u32 {
        const sq = self.seq_num;
        const seq_num = std.mem.readInt(u32, &sq, .little);

        return seq_num;
    }

    pub fn set_seq_num(self: *TCPHeader, seq_num: u32) void {
        std.mem.writeInt(u32, &self.seq_num, seq_num, .big);
    }

    pub fn get_window(self: *TCPHeader) u16 {
        return @byteSwap(self.window);
    }

    pub fn set_window(self: *TCPHeader, window: u16) void {
        self.window = @byteSwap(window);
    }

    pub fn get_urgent_ptr(self: *TCPHeader) u16 {
        return @byteSwap(self.urgent_ptr);
    }

    pub fn set_urgent_ptr(self: *TCPHeader, urgent_ptr: u16) void {
        self.urgent_ptr = @byteSwap(urgent_ptr);
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

    /// at the moment, this will always return a generic application layer because no application layer protocols have been fully implemented
    pub fn get_next_layer_type(self: *TCPLayer, layer: *Packet.Layer) !?LayerIface {
        const data: []const u8 = self.get_data();

        if (data.len < TCPHeaderMinSize) {
            return LayerError.BufferTooSmall;
        }

        return try LayerIface.init(ApplicationLayer, LayerOwner{ .packet_layer = layer });
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
        switch (self.owner) {
            .packet_layer => {
                return self.owner.packet_layer.get_data();
            },
            .owned_buffer => {
                return self.owner.owned_buffer.buffer.items; // standalone layer
            },
        }
    }

    /// Get the payload (data after TCP header)
    pub fn get_payload(self: *TCPLayer) ?[]const u8 {
        const data = self.get_data();

        if (data.len > TCPHeaderMinSize) { // TODO: calculate the TCP header length
            return data[TCPHeaderMinSize..]; // return remaining bytes after the header
        } else {
            return null;
        }
    }

    pub fn to_string(self: *TCPLayer, allocator: Allocator) []const u8 {
        const hdr = self.get_immutable_header();

        const src_port: u16 = std.mem.bigToNative(u16, hdr.src_port);
        const dst_port: u16 = std.mem.bigToNative(u16, hdr.dst_port);
        const seq: u32 = std.mem.readInt(u32, &hdr.seq_num, .little);
        const ack: u32 = std.mem.readInt(u32, &hdr.ack_num, .little);

        const data_offset_reserved_flags: u16 = std.mem.bigToNative(u16, hdr.data_offset_reserved_flags);

        // TCP data offset is top 4 bits (in 32-bit words)
        const data_offset: u8 = @intCast(data_offset_reserved_flags >> 12);

        // Lower 12 bits contain flags + reserved bits (depending on your layout)
        const flags: u16 = data_offset_reserved_flags & 0x0FFF;

        const window_size: u16 = std.mem.bigToNative(u16, hdr.window);
        const checksum: u16 = std.mem.bigToNative(u16, hdr.checksum);
        const urgent_pointer: u16 = std.mem.bigToNative(u16, hdr.urgent_ptr);

        const result = std.fmt.allocPrint(
            allocator,
            \\TCP Layer:
            \\  src_port: {}
            \\  dst_port: {}
            \\  seq: {}
            \\  ack: {}
            \\  data_offset: {}
            \\  flags: 0x{x}
            \\  window_size: {}
            \\  checksum: 0x{x}
            \\  urgent_pointer: {}
        ,
            .{
                src_port,
                dst_port,
                seq,
                ack,
                data_offset,
                flags,
                window_size,
                checksum,
                urgent_pointer,
            },
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
