const std = @import("std");
const print = std.debug.print;
const panic = std.debug.print;

const Allocator = std.mem.Allocator;

const ProtocolHelpers = @import("ProtocolHelpers.zig");
const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;
const LayerError = ProtocolHelpers.LayerError;
const LayerIface = @import("LayerIface.zig").LayerIface;
const LayerOwner = @import("Layer.zig").LayerOwner;

const Packet = @import("Packet.zig");

const ApplicationLayer = @import("GenericLayer.zig").ApplicationLayer;

const RawData = @import("RawData.zig").RawData;

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

pub const TCPLayer = struct {
    owner: LayerOwner,
    const Protocol = tcp_ip_protocol.tcp;

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
                if (self.owner.allocator_owned.data.len < TCPHeaderMinSize) {
                    self.owner.allocator_owned.data = try self.owner.allocator_owned.allocator.alloc(u8, TCPHeaderMinSize);
                    //var header = TCPHeader.init_default(); // need to implement this
                    //@memcpy(self.owner.allocator_owned.data[0..TCPHeaderMinSize], std.mem.asBytes(&header));
                }

                return self;
            },
            .immutable_layer => return {
                return TCPLayer{ .owner = owner };
            },
        }
    }

    //// Get Source Port of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn get_src_port(self: *const TCPLayer) u16 {
        const hdr = self.get_immutable_header();
        return std.mem.bigToNative(u16, hdr.src_port);
    }

    //// Get Destination Port of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn get_dst_port(self: *const TCPLayer) u16 {
        const hdr = self.get_immutable_header();
        return std.mem.bigToNative(u16, hdr.dst_port);
    }

    //// Get Checksum of the TCPPHeader - converts u16 value from Big to Native and returns
    pub fn get_checksum(self: *const TCPLayer) u16 {
        const hdr = self.get_immutable_header();

        return std.mem.bigToNative(u16, hdr.checksum);
    }

    //// Get Length of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn get_length(self: *const TCPLayer) u16 {
        const hdr = self.get_header();

        return std.mem.bigToNative(u16, hdr.length);
    }

    //// Get Source Port of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn set_src_port(self: *TCPLayer, port: u16) void {
        var hdr = self.get_mutable_header();

        hdr.src_port = std.mem.nativeToBig(u16, port);
    }

    //// Get Destination Port of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn set_dst_port(self: *TCPLayer, port: u16) void {
        var hdr = self.get_mutable_header();
        hdr.dst_port = std.mem.nativeToBig(u16, port);
    }

    //// Calculate the checksum of the TCPHeader - not yet implemented
    pub fn calculate_checksum(self: *TCPLayer) void {
        _ = self;
        return;
    }

    pub fn get_next_layer_type(self: *TCPLayer, layer: *Packet.Layer) !?LayerIface {
        const data = self.get_data().get_immutable();

        if (data.len < TCPHeaderMinSize) {
            return LayerError.BufferTooSmall;
        }

        const alignment = @alignOf(TCPHeader);
        const addr = @intFromPtr(data.ptr);
        if (addr % alignment != 0) {
            return LayerError.MisalignedBuffer;
        }

        return try LayerIface.init(ApplicationLayer, LayerOwner{ .packet_layer = layer });
    }

    /// return mutable slice of the payload
    pub fn get_payload(self: *TCPLayer) ?[]const u8 {
        const hdr_len = self.calculate_length();

        const data = self.get_data().get_immutable();

        if (data.len > hdr_len) {
            return data[hdr_len..];
        } else {
            print("udp data too small. data len={}\n", .{data.len});
            return null;
        }
    }

    fn get_mutable_header(self: *TCPLayer) *TCPHeader {
        const data = self.get_data().mutable;
        const aligned_ptr: [*]align(@alignOf(TCPHeader)) u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    fn get_immutable_header(self: *const TCPLayer) *const TCPHeader {
        var data: []const u8 = undefined;

        if (self.get_data().is_mutable()) { // if the data is actually mutable - we just need immutable in this case anyway
            data = self.get_data().get_mutable();
        } else {
            data = self.get_data().get_immutable();
        }

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

    /// get slice of data (hdr+payload)
    pub fn get_data(self: *const TCPLayer) RawData {
        switch (self.owner) {
            .packet_layer => {
                print("getting data from packet.\n", .{});

                const udp_data = self.owner.packet_layer.get_data(); // Layer in packet - it might be mutable or immutable
                return udp_data;
            },
            .allocator_owned => {
                return RawData{ .mutable = self.owner.allocator_owned.data }; // standalone layer - it is mutable by default
            },
            .immutable_layer => {
                return RawData{ .immutable = self.owner.immutable_layer.raw_data };
            },
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

    pub fn deinit(self: *TCPLayer, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }
};
