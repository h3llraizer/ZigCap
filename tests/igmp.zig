const std = @import("std");
const zigcap = @import("zigcap");

const LayerOwner = zigcap.Owner.LayerOwner;
const Layer = zigcap.Layer;
const Eth = zigcap.Eth;
const IPv4 = zigcap.IPv4;
const IGMP = zigcap.IGMP;
const Packet = zigcap.Packet;
const IPProtocol = zigcap.ProtocolEnums.IPProtocol;
const link_layer_type = zigcap.ProtocolEnums.link_layer_type;
const print = std.debug.print;
const expect = std.testing.expect;

test "build igmp layer" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var igmp_layer_iface: Layer = try Layer.init(IGMP.IGMPv3Layer, allocator);
    defer igmp_layer_iface.deinit();

    const igmp_type: IGMP.IGMPType = igmp_layer_iface.igmpv3Layer.get_type();

    try expect(igmp_type == IGMP.IGMPType.membership_query);

    const igmp_hdr: *IGMP.IGMPv3Header = igmp_layer_iface.igmpv3Layer.get_mutable_header();

    igmp_hdr.max_resp_time = 10;

    const igmp_type_hdr: IGMP.IGMP_type = igmp_layer_iface.igmpv3Layer.get_igmp_type_hdr() orelse {
        try expect(false); // failed to get igmp_type_hdr
        return;
    };

    igmp_type_hdr.igmpv3_gry_ext.set_s_flag(0);
    igmp_type_hdr.igmpv3_gry_ext.set_qrv(2);
    igmp_type_hdr.igmpv3_gry_ext.qqic = 125;

    igmp_layer_iface.igmpv3Layer.validate_layer();

    //   const checksum = @byteSwap(igmp_layer_iface.igmpv3Layer.get_immutable_header().checksum);
    //
    //   _ = checksum;
}
