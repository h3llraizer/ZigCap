const std = @import("std");
const zigcap = @import("zigcap");

const print = std.debug.print;
const expect = std.testing.expect;

const Packet = zigcap.Packet.Packet;
const link_layer_type = zigcap.ProtocolEnums.link_layer_type;
const LayerOwner = zigcap.Owner.LayerOwner;
const TLVOwner = zigcap.Owner.TLVOwner;
const LayerIface = zigcap.LayerIface;
const IPv4 = zigcap.IPv4;
const Eth = zigcap.Eth;
const UDP = zigcap.UDP;

const IPProtocol = zigcap.ProtocolEnums.IPProtocol;

pub fn init_layer(concrete_type: anytype, owner: LayerOwner, header: anytype, default_hdr: anytype) !concrete_type {
    switch (owner) {
        .packet_layer => {
            return concrete_type{
                .owner = owner,
            };
        },
        .owned_buffer => {
            var self = concrete_type{ .owner = owner };
            const buffer_len = owner.get_data().len;

            if (buffer_len < @sizeOf(header)) {
                const diff = @sizeOf(header) - buffer_len;

                const ipv4_data = try self.owner.extend_layer(buffer_len, diff);

                @memset(ipv4_data, 0);

                @memcpy(ipv4_data[0..@sizeOf(header)], std.mem.asBytes(&default_hdr));
            }

            return self;
        },
    }
}

test "ipv4 init" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    const tmp_owner = LayerOwner{ .owned_buffer = .init_empty(allocator) };

    var ipv4_layer: IPv4.IPv4Layer = try IPv4.IPv4Layer.init(tmp_owner);

    defer ipv4_layer.deinit();

    print("{x}\n", .{ipv4_layer.owner.get_data()});

    print("{x}\n", .{ipv4_layer.get_data()});

    var str = ipv4_layer.to_string(allocator);
    print("{s}\n", .{str});
    allocator.free(str);

    var ipv4_layer_iface: LayerIface = try LayerIface.init(IPv4.IPv4Layer, tmp_owner);

    defer ipv4_layer_iface.deinit();

    print("{x}\n", .{ipv4_layer_iface.get_data()});

    str = ipv4_layer_iface.to_string(allocator);
    print("{s}\n", .{str});
    allocator.free(str);
}
