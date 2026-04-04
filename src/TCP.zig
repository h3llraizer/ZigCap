const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

const ProtocolHelpers = @import("ProtocolHelpers.zig");
const LayerProtocols = ProtocolHelpers.LayerProtocols;
const LayerError = ProtocolHelpers.LayerError;
const LayerImpl = ProtocolHelpers.LayerImpl;
const LayerOwner = @import("Layer.zig").LayerOwner;

const Packet = @import("Packet.zig");

const ApplicationLayer = @import("GenericLayer.zig").ApplicationLayer;

pub const TCPHeaderMinSize = 20;
pub const TCPHeaderMaxSize = 40;

pub const TCPHeader = extern struct {
    src_port: u16,
    dst_port: u16,
    seq_num: [4]u8,
    ack_num: [4]u8,
    data_offset_reserved_flags: u16,
    window: u16,
    checksum: u16,
    urgent_ptr: u16,
};

pub fn get_next_layer_type(buffer: []u8) !Packet.Layer {
    if (buffer.len < TCPHeaderMinSize) {
        return LayerError.BufferTooSmall;
    }

    const alignment = @alignOf(TCPHeader);
    const addr = @intFromPtr(buffer.ptr);
    if (addr % alignment != 0) {
        return LayerError.MisalignedBuffer;
    }

    var tcp_layer = try TCPLayer.init(buffer[0..]);

    const hdr_len = tcp_layer.calculate_length();

    var layer = Packet.Layer{ .protocol = undefined, .offset = 0, .length = 0, .next_layer = null };

    layer.offset = hdr_len;

    if ((buffer.len - hdr_len) > 0) {
        layer.length = (buffer.len - hdr_len);
    }

    layer.protocol = LayerProtocols{ .Application = .Generic };

    return layer;
}

pub const TCPLayer = struct {
    owner: LayerOwner,
    const Protocol = LayerProtocols{ .Transport = .TCP };

    //// Creates layer from ptr to minimum 20 byte length buffer - ensure that the buffer outlives the TCPLayer or UB occurs
    pub fn init(owner: LayerOwner) LayerError!TCPLayer {
        switch (owner) {
            .packet_layer => {
                return TCPLayer{
                    .owner = owner,
                };
            },
            .allocator_owned => {
                var self = TCPLayer{ .owner = owner };
                // Allocate directly into the struct's data field
                self.owner.allocator_owned.data = try self.owner.allocator_owned.allocator.alloc(u8, TCPHeaderMinSize);

                //var header = TCPHeader.init_default();
                //@memcpy(self.owner.allocator_owned.data[0..TCPHeaderMinSize], std.mem.asBytes(&header));

                return self;
            },
        }
    }

    //// Get Source Port of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn get_src_port(self: *TCPLayer) u16 {
        const hdr = self.get_header();
        return std.mem.bigToNative(u16, hdr.src_port);
    }

    //// Get Destination Port of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn get_dst_port(self: *TCPLayer) u16 {
        const hdr = self.get_header();
        return std.mem.bigToNative(u16, hdr.dst_port);
    }

    //// Get Checksum of the TCPPHeader - converts u16 value from Big to Native and returns
    pub fn get_checksum(self: *TCPLayer) u16 {
        const hdr = self.get_header();

        return std.mem.bigToNative(u16, hdr.checksum);
    }

    //// Get Length of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn get_length(self: *TCPLayer) u16 {
        const hdr = self.get_header();

        return std.mem.bigToNative(u16, hdr.length);
    }

    //// Get Source Port of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn set_src_port(self: *TCPLayer, port: u16) void {
        var hdr = self.get_header();

        hdr.src_port = std.mem.nativeToBig(u16, port);
    }

    //// Get Destination Port of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn set_dst_port(self: *TCPLayer, port: u16) void {
        var hdr = self.get_header();
        hdr.dst_port = std.mem.nativeToBig(u16, port);
    }

    //// Calculate the checksum of the TCPHeader
    pub fn calculate_checksum(self: *TCPLayer) void {
        _ = self;
        return;
    }

    pub fn get_next_layer_type(self: *TCPLayer, layer: *Packet.Layer) !LayerImpl {
        const data = self.get_data();

        if (data.len < TCPHeaderMinSize) {
            return LayerError.BufferTooSmall;
        }

        const alignment = @alignOf(TCPHeader);
        const addr = @intFromPtr(data.ptr);
        if (addr % alignment != 0) {
            return LayerError.MisalignedBuffer;
        }

        return try LayerImpl.init(ApplicationLayer, LayerOwner{ .packet_layer = layer });
    }

    //// Calculate the length of the TCPHeader
    pub fn calculate_length(self: *TCPLayer) u16 {
        const hdr = self.get_header();
        const raw = std.mem.bigToNative(u16, hdr.data_offset_reserved_flags);
        const data_offset = (raw >> 12) & 0xF; // top 4 bits
        return data_offset * 4; // in bytes
    }

    pub fn to_string(self: *TCPLayer, allocator: Allocator) []const u8 {
        const hdr = self.get_header();

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

    /// get slice of data (hdr+payload)
    pub fn get_data(self: *const TCPLayer) []u8 {
        switch (self.owner) {
            .packet_layer => {
                print("getting self ({*}) data from packet\n", .{self});
                const tcp_data = self.owner.packet_layer.packet.find_layer_ptr(@ptrCast(@constCast(self))) orelse {
                    std.debug.panic("ipv4 layer ptr ({*}) not found in packet\n", .{self});
                };
                return tcp_data;
            },
            else => {
                print("getting self ({*}) data from allocator\n", .{self});
                return self.owner.allocator_owned.data;
            },
        }
    }

    /// return mutable slice of the payload
    pub fn get_payload(self: *TCPLayer) ?[]u8 {
        const hdr_len = self.calculate_length();

        const data = self.get_data();

        if (data.len > hdr_len) {
            return data[hdr_len..];
        } else {
            return null;
        }
    }

    pub fn get_header(self: *TCPLayer) *TCPHeader {
        // return the full header if it exceeds 20 bytes
        return @ptrCast(@alignCast(self.get_data()[0..20])); // need to change this
    }

    pub fn get_protocol(self: *TCPLayer) LayerProtocols {
        _ = self;
        return TCPLayer.Protocol;
    }

    pub fn deinit(self: *TCPLayer, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }
};
