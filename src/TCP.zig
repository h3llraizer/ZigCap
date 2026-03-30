const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

const LayerProtocols = @import("ProtocolHelpers.zig").LayerProtocols;
const LayerError = @import("ProtocolHelpers.zig").LayerError;
const Packet = @import("Packet.zig");

pub const TCPHeaderMinSize = 20;
pub const TCPHeaderMaxSize = 40;

pub const TCPHeader = packed struct {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    data_offset_reserved_flags: u16,
    window: u16,
    checksum: u16,
    urgent_ptr: u16,
};

pub fn get_next_layer_type(buffer: []u8) !Packet.Layer {
    if (buffer.len < TCPHeaderMinSize) {
        return LayerError.BufferTooSmall;
    }

    // Verify alignment (optional)
    const alignment = @alignOf(TCPHeader);
    const addr = @intFromPtr(buffer.ptr);
    if (addr % alignment != 0) {
        return LayerError.MisalignedBuffer;
    }

    //const hdr: *TCPHeader = @ptrCast(@alignCast(buffer[0..20]));

    var layer = Packet.Layer{ .protocol = undefined, .offset = 0, .length = 0, .next_layer = null };

    layer.length = buffer.len - TCPHeaderMinSize;

    layer.protocol = LayerProtocols{ .Application = .Generic };

    return layer;
    //    return LayerProtocols{ .Application = .Generic };
}

pub const TCPLayer = struct {
    data: []u8,
    const Protocol = LayerProtocols{ .Transport = .TCP };

    //// Creates layer from ptr to minimum 20 byte length buffer - ensure that the buffer outlives the TCPLayer or UB occurs
    pub fn init(buffer: []u8) LayerError!TCPLayer {
        if (buffer.len < 20) {
            return LayerError.BufferTooSmall;
        }

        // Verify alignment (optional)
        const alignment = @alignOf(TCPHeader);
        const addr = @intFromPtr(buffer.ptr);
        if (addr % alignment != 0) {
            return LayerError.MisalignedBuffer;
        }

        return TCPLayer{ .data = buffer };
    }

    //// Get Source Port of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn get_src_port(self: TCPLayer) u16 {
        const hdr = self.get_header();
        return std.mem.bigToNative(u16, hdr.src_port);
    }

    //// Get Destination Port of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn get_dst_port(self: TCPLayer) u16 {
        const hdr = self.get_header();
        return std.mem.bigToNative(u16, hdr.dst_port);
    }

    //// Get Checksum of the TCPPHeader - converts u16 value from Big to Native and returns
    pub fn get_checksum(self: TCPLayer) u16 {
        const hdr = self.get_header();

        return std.mem.bigToNative(u16, hdr.checksum);
    }

    //// Get Length of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn get_length(self: TCPLayer) u16 {
        const hdr = self.get_header();

        return std.mem.bigToNative(u16, hdr.length);
    }

    //// Get Source Port of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn set_src_port(self: TCPLayer, port: u16) void {
        var hdr = self.get_header();

        hdr.src_port = std.mem.nativeToBig(u16, port);
    }

    //// Get Destination Port of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn set_dst_port(self: TCPLayer, port: u16) void {
        var hdr = self.get_header();
        hdr.dst_port = std.mem.nativeToBig(u16, port);
    }

    //// Calculate the checksum of the TCPHeader
    pub fn calculate_checksum(self: TCPLayer) void {
        _ = self;
        return;
    }

    //// Calculate the length of the TCPHeader
    pub fn calculate_length(self: TCPLayer) void {
        _ = self;
        return;
    }

    pub fn to_string(self: *TCPLayer, allocator: Allocator) []const u8 {
        const hdr = self.get_header();

        const src_port: u16 = std.mem.bigToNative(u16, hdr.src_port);
        const dst_port: u16 = std.mem.bigToNative(u16, hdr.dst_port);
        const seq: u32 = std.mem.bigToNative(u32, hdr.seq_num);
        const ack: u32 = std.mem.bigToNative(u32, hdr.ack_num);

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

    /// get slice of data (hdr+payload)
    pub fn get_data(self: *TCPLayer) []u8 {
        return self.data;
    }

    /// return mutable slice of the payload
    pub fn get_payload(self: *TCPLayer) []u8 {
        return self.data[20..];
    }

    pub fn get_next_layer_type(self: *TCPLayer) LayerProtocols {
        _ = self;
        return LayerProtocols{ .Application = .Generic };
    }

    pub fn get_header(self: *TCPLayer) *TCPHeader {
        return @ptrCast(@alignCast(self.data[0..20]));
    }

    pub fn get_protocol(self: *TCPLayer) LayerProtocols {
        _ = self;
        return TCPLayer.Protocol;
    }

    pub fn deinit(self: *TCPLayer, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }
};
