const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;
const EthHeader = @import("Eth.zig").EthHeader;
const IPv4Header = @import("IPv4.zig").IPv4Header;
const UDPHeader = @import("UDPLayer.zig").UDPHeader;

/// ApplicationProtocols values are defined with their well-known port number - this makes the transport layers parse_next_layer simpler
pub const ApplicationProtocols = enum(u16) {
    HTTP = 80,
    DNS = 53,
    Generic = 0,
};

pub const TransportProtocols = enum(u8) {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    Generic = 0,
};

pub const NetworkProtocols = enum(u16) {
    IPv4 = 4,
    IPv6 = 6,
    Generic = 0,
};

pub const LinkLayerProtocols = enum(u16) {
    NULL = 0, // Loopback (BSD/macOS)
    ETHERNET = 1, // Ethernet (most common)
    RAW = 101, // Raw IP (no link header)
    // Point-to-point / tunnels
    PPP = 9,
    PPP_ETHER = 51, // PPPoE
    // Wireless
    IEEE802_11 = 105, // WiFi
    IEEE802_11_RADIOTAP = 127, // WiFi + metadata (monitor mode)
    // Linux-specific captures
    LINUX_SLL = 113, // "cooked" capture (tcpdump on Linux)
    LINUX_SLL2 = 276, // newer version
    // Less common but still seen
    LOOP = 108, // Loopback (OpenBSD)
    SLIP = 8, // legacy serial IP
    INVALID = 0xFFFF,
};

pub const LayerProtocols = union(enum) {
    LinkLayer: LinkLayerProtocols,
    Network: NetworkProtocols,
    Transport: TransportProtocols,
    Application: ApplicationProtocols,
};

pub const LayerError = error{ OutOfMemory, BufferTooSmall, MisalignedBuffer };

/// Layer interface
pub const Layer = struct {
    layer_type: *anyopaque,

    next_layer: ?*Layer,
    prev_layer: ?*Layer,

    v_get_data: *const fn (*anyopaque) []u8,
    v_get_payload: *const fn (*anyopaque) []u8,
    v_to_string: *const fn (*anyopaque, Allocator) []const u8,
    v_get_next_layer_type: *const fn (*anyopaque) LayerProtocols,
    v_get_protocol: *const fn (*anyopaque) LayerProtocols,
    v_deinit: *const fn (*anyopaque, Allocator) void,

    // link the protocol layer pointer to the vtable functions
    pub fn implBy(layer_type: anytype) Layer {
        const delegate = LayerDelegate(layer_type);
        return .{
            .layer_type = layer_type,
            .next_layer = null,
            .prev_layer = null,
            .v_get_data = delegate.get_data,
            .v_get_payload = delegate.get_payload,
            .v_to_string = delegate.to_string,
            .v_get_next_layer_type = delegate.get_next_layer_type,

            .v_get_protocol = delegate.get_protocol,
            .v_deinit = delegate.deinit,
        };
    }

    /// get slice of data (hdr+payload)
    pub fn get_data(self: *Layer) []u8 {
        return self.v_get_data(self.layer_type);
    }

    /// return mutable slice of the payload
    pub fn get_payload(self: *Layer) []u8 {
        return self.v_get_payload(self.layer_type);
    }

    // Public functions
    pub fn get_next_layer(self: *Layer) ?*Layer {
        return self.next_layer;
    }

    pub fn get_prev_layer(self: *Layer) ?*Layer {
        return self.prev_layer;
    }

    pub fn set_next_layer(self: *Layer, next_layer: *Layer) void {
        self.next_layer = next_layer;
        next_layer.prev_layer = self;
    }

    pub fn set_prev_layer(self: *Layer, prev_layer: *Layer) void {
        self.prev_layer = prev_layer;
    }

    pub fn to_string(self: *Layer, allocator: Allocator) []const u8 {
        return self.v_to_string(self.layer_type, allocator);
    }

    pub fn get_next_layer_type(self: *Layer) LayerProtocols {
        return self.v_get_next_layer_type(self.layer_type);
    }

    pub fn get_protocol(self: *Layer) LayerProtocols {
        return self.v_get_protocol(self.layer_type);
    }

    pub fn deinit(self: *Layer, allocator: Allocator) void {
        self.v_deinit(self.layer_type, allocator);
    }
};

/// Links a Layer to the implementation functions
inline fn LayerDelegate(layer_type: anytype) type { // VTable Link
    const LayerType = @TypeOf(layer_type);

    return struct {
        pub fn get_data(layer: *anyopaque) []u8 {
            const ptr = TPtr(LayerType, layer);
            const result = ptr.get_data();
            return result;
        }

        pub fn get_payload(layer: *anyopaque) []u8 {
            return TPtr(LayerType, layer).get_payload();
        }

        pub fn to_string(layer: *anyopaque, allocator: Allocator) []const u8 {
            return TPtr(LayerType, layer).to_string(allocator);
        }

        pub fn get_next_layer_type(layer: *anyopaque) LayerProtocols {
            return TPtr(LayerType, layer).get_next_layer_type();
        }

        pub fn get_protocol(layer: *anyopaque) LayerProtocols {
            return TPtr(LayerType, layer).get_protocol();
        }

        pub fn deinit(layer: *anyopaque, allocator: Allocator) void {
            TPtr(LayerType, layer).deinit(allocator);
        }
    };
}

/// Converts an opaque pointer back to the implementation
pub fn TPtr(T: type, opaque_ptr: *anyopaque) T {
    return @as(T, @ptrCast(@alignCast(opaque_ptr)));
}
