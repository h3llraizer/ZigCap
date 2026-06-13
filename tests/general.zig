const std = @import("std");
const zigcap = @import("zigcap");

const LayerOwner = zigcap.Owner.LayerOwner;
const LayerIface = zigcap.LayerIface;
const Eth = zigcap.Eth;
const IPv4 = zigcap.IPv4;
const ICMP = zigcap.ICMP;
const DNS = zigcap.DNS;
const Packet = zigcap.Packet.Packet;
const Layer = zigcap.Packet.Layer;
const IPProtocol = zigcap.ProtocolEnums.IPProtocol;
const link_layer_type = zigcap.ProtocolEnums.link_layer_type;
const print = std.debug.print;
const expect = std.testing.expect;

test "sizes" {
    const layeriface = @sizeOf(LayerIface);

    print("layeriface: {}\n", .{layeriface});

    inline for (std.meta.fields(LayerIface)) |field| {
        std.debug.print(
            "name={s}, type={any} size={}\n",
            .{ field.name, field.type, @sizeOf(field.type) },
        );
    }

    const layerowner = @sizeOf(LayerOwner);
    print("layer owner: {}\n", .{layerowner});

    const packet = @sizeOf(Packet);
    print("packet: {}\n", .{packet});

    const layer = @sizeOf(Layer);
    print("layer: {}\n", .{layer});

    print("ARecord: {}\n", .{@sizeOf(DNS.ARecord)});
}
