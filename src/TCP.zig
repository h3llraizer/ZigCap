const std = @import("std");
const print = std.debug.print;

const LayerProtocols = @import("Layer.zig").LayerProtocols;

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

/// TCPLayer wraps mutable pointer to TCPHeader and functions to work on the header.
/// If header values are changed manually or via setter then ensure calculate_length and calculate_checksum are called to avoid invalidating the layer after all desired changes are made.
pub const TCPLayer = struct {
    hdr: *align(1) TCPHeader,
    const Protocol = LayerProtocols{ .Transport = .TCP };
    // add pointer to packet it's attached to?

    //// Creates layer from ptr to 8 byte length buffer - ensure that the buffer outlives the TCPLayer or UB occurs
    pub fn init(raw: *[20]u8, allocator: std.mem.Allocator) !*TCPLayer {
        const t = try allocator.create(TCPLayer);
        t.hdr = @ptrCast(raw);
        return t;
    }

    //// Create empty TCP layer. TCPHeader values are Zero initialised
    pub fn create(allocator: std.mem.Allocator) !TCPLayer {
        const self = try allocator.create(TCPLayer);
        self.hdr = try allocator.create(TCPHeader);
        self.hdr.* = std.mem.zeroInit(TCPHeader, TCPHeader{}); // zero the struct members

        return self.*;
    }

    //// Get Source Port of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn get_src_port(self: TCPLayer) u16 {
        return std.mem.bigToNative(u16, self.hdr.src_port);
    }

    //// Get Destination Port of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn get_dst_port(self: TCPLayer) u16 {
        return std.mem.bigToNative(u16, self.hdr.dst_port);
    }

    //// Get Checksum of the TCPPHeader - converts u16 value from Big to Native and returns
    pub fn get_checksum(self: TCPLayer) u16 {
        return std.mem.bigToNative(u16, self.hdr.checksum);
    }

    //// Get Length of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn get_length(self: TCPLayer) u16 {
        return std.mem.bigToNative(u16, self.hdr.length);
    }

    //// Get Source Port of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn set_src_port(self: TCPLayer, port: u16) void {
        self.hdr.src_port = std.mem.nativeToBig(u16, port);
    }

    //// Get Destination Port of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn set_dst_port(self: TCPLayer, port: u16) void {
        self.hdr.dst_port = std.mem.nativeToBig(u16, port);
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

    pub fn deinit(self: *TCPLayer, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
        print("deinited.\n", .{});
    }

    pub fn get_protocol(self: *TCPLayer) LayerProtocols {
        _ = self;
        return TCPLayer.Protocol;
    }
};
