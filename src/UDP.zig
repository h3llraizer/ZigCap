const std = @import("std");
const print = std.debug.print;

const LayerProtocols = @import("Layer.zig").LayerProtocols;

pub const UDPHeader = packed struct {
    src_port: u16 = 0,
    dst_port: u16 = 0,
    length: u16 = 0,
    checksum: u16 = 0,
};

/// UDPLayer wraps mutable pointer to UDPHeader and functions to work on the header.
/// If header values are changed manually or via setter then ensure calculate_length and calculate_checksum are called to avoid invalidating the layer after all desired changes are made.
pub const UDPLayer = struct {
    hdr: *align(1) UDPHeader,
    const Protocol = LayerProtocols{ .Transport = .UDP };
    // add pointer to packet it's attached to?

    //// Creates layer from ptr to 8 byte length buffer - ensure that the buffer outlives the UDPLayer or UB occurs
    pub fn init(raw: *[8]u8, allocator: std.mem.Allocator) !*UDPLayer {
        const u = try allocator.create(UDPLayer);
        u.hdr = @ptrCast(raw);
        return u;
    }

    //// Create empty UDP layer. UDPHeader values are Zero initialised
    pub fn create(allocator: std.mem.Allocator) !UDPLayer {
        const self = try allocator.create(UDPLayer);
        self.hdr = try allocator.create(UDPHeader);
        self.hdr.* = std.mem.zeroInit(UDPHeader, UDPHeader{}); // zero the struct members

        return self.*;
    }

    //// Get Source Port of the UDPHeader - converts u16 value from Big to Native and returns
    pub fn get_src_port(self: UDPLayer) u16 {
        return std.mem.bigToNative(u16, self.hdr.src_port);
    }

    //// Get Destination Port of the UDPHeader - converts u16 value from Big to Native and returns
    pub fn get_dst_port(self: UDPLayer) u16 {
        return std.mem.bigToNative(u16, self.hdr.dst_port);
    }

    //// Get Checksum of the UDPHeader - converts u16 value from Big to Native and returns
    pub fn get_checksum(self: UDPLayer) u16 {
        return std.mem.bigToNative(u16, self.hdr.checksum);
    }

    //// Get Length of the UDPHeader - converts u16 value from Big to Native and returns
    pub fn get_length(self: UDPLayer) u16 {
        return std.mem.bigToNative(u16, self.hdr.length);
    }

    //// Get Source Port of the UDPHeader - converts u16 value from Big to Native and returns
    pub fn set_src_port(self: UDPLayer, port: u16) void {
        self.hdr.src_port = std.mem.nativeToBig(u16, port);
    }

    //// Get Destination Port of the UDPHeader - converts u16 value from Big to Native and returns
    pub fn set_dst_port(self: UDPLayer, port: u16) void {
        self.hdr.dst_port = std.mem.nativeToBig(u16, port);
    }

    //// Calculate the checksum of the UDPHeader
    pub fn calculate_checksum(self: UDPLayer) void {
        _ = self;
        return;
    }

    //// Calculate the length of the UDPHeader
    pub fn calculate_length(self: UDPLayer) void {
        _ = self;
        return;
    }

    pub fn deinit(self: *UDPLayer, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
        print("deinited.\n", .{});
    }

    pub fn get_protocol(self: *UDPLayer) LayerProtocols {
        _ = self;
        return UDPLayer.Protocol;
    }
};
