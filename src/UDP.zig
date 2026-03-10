const std = @import("std");
const print = std.debug.print;

const LayerProtocols = @import("Layer.zig").LayerProtocols;
const Layer = @import("Layer.zig").Layer;

const DNSLayer = @import("DNS.zig").DNSLayer;

pub const UDPHeader = packed struct {
    src_port: u16 = 0,
    dst_port: u16 = 0,
    length: u16 = 0,
    checksum: u16 = 0,
};

pub const UDPHeaderSize = 8;

/// UDPLayer wraps mutable pointer to UDPHeader and functions to work on the header.
/// If header values are changed manually or via setter then ensure calculate_length and calculate_checksum are called to avoid invalidating the layer after all desired changes are made.
pub const UDPLayer = struct {
    hdr: *align(1) UDPHeader,
    payload: []u8,
    const Protocol = LayerProtocols{ .Transport = .UDP };
    // add pointer to packet it's attached to?

    //// Creates layer from ptr to 8 byte length buffer - ensure that the buffer outlives the UDPLayer or UB occurs
    pub fn init(raw: []u8, allocator: std.mem.Allocator) !*UDPLayer {
        if (raw.len < UDPHeaderSize) return error.RawTooSmallForUDP;

        const self = try allocator.create(UDPLayer);
        self.hdr = @ptrCast(raw[0..UDPHeaderSize]);
        self.payload = raw[UDPHeaderSize..];
        return self;
    }

    //// Create empty UDP layer. UDPHeader values are Zero initialised
    pub fn create(allocator: std.mem.Allocator) !*UDPLayer {
        const self = try allocator.create(UDPLayer);
        self.hdr = try allocator.create(UDPHeader);
        self.hdr.* = std.mem.zeroInit(UDPHeader, UDPHeader{}); // zero the struct members

        return self;
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
    pub fn calculate_checksum(self: UDPLayer, network_layer: *Layer) void {
        _ = self;
        switch (network_layer.get_protocol()) {
            .IPv4 => print("IPv4 layer.\n", {}),
            .IPv6 => print("IPv4 Layer.\n", .{}),
        }
        return;
    }

    //// Calculate the length of the UDPHeader
    pub fn calculate_length(self: UDPLayer) void {
        _ = self;
        return;
    }

    pub fn to_string(self: *UDPLayer) void {
        inline for (@typeInfo(UDPHeader).@"struct".fields) |f| {
            print("{s} : {any} : ", .{
                f.name,
                f.type,
            });
            if (f.type == u16) {
                print("{d}\n", .{std.mem.bigToNative(f.type, @field(self.hdr, f.name))});
            } else {
                print("{d}\n", .{@field(self.hdr, f.name)});
            }
        }
    }

    pub fn parse_next_layer(self: *UDPLayer, allocator: std.mem.Allocator) ?*Layer {
        const packet_layer: *Layer = allocator.create(Layer) catch return null;

        if (self.get_dst_port() == 53 or self.get_src_port() == 53) {
            const dns_layer = DNSLayer.init(self.payload[0..], allocator) catch return null;
            packet_layer.* = Layer.implBy(dns_layer);
            return packet_layer;
        }

        return null;
    }

    pub fn get_protocol(self: *UDPLayer) LayerProtocols {
        _ = self;
        return UDPLayer.Protocol;
    }

    pub fn deinit(self: *UDPLayer, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }
};
