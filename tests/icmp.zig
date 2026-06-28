const std = @import("std");
const zigcap = @import("zigcap");

const LayerOwner = zigcap.Owner.LayerOwner;
const Layer = zigcap.Layer;
const Eth = zigcap.Eth;
const IPv4 = zigcap.IPv4;
const ICMP = zigcap.ICMP;
const Packet = zigcap.Packet;
const IPProtocol = zigcap.ProtocolEnums.IPProtocol;
const link_layer_type = zigcap.ProtocolEnums.link_layer_type;
const print = std.debug.print;
const expect = std.testing.expect;

fn gen_random(int_type: type) !int_type {
    var prng: std.Random.DefaultPrng = .init(blk: {
        var seed: u64 = undefined;
        try std.posix.getrandom(std.mem.asBytes(&seed));
        break :blk seed;
    });

    const rand = prng.random();

    const c = rand.int(int_type);

    return c;
}

fn getMillisecondsSinceMidnight() u32 {
    // Get current UTC time using system clock
    const now = std.time.timestamp();

    // This is an approximation - it calculates time since epoch midnight
    // For strict RFC compliance, you'd need UTC midnight, not epoch midnight
    const ms_per_day: u64 = 86_400_000; // 24 * 60 * 60 * 1000
    const ms_since_epoch = @as(u64, @intCast(now)) * 1000;

    return @as(u32, @intCast(ms_since_epoch % ms_per_day));
}

test "build icmp layer" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var icmp_layer_iface: Layer = try Layer.init(ICMP.ICMPLayer, allocator);
    defer icmp_layer_iface.deinit();

    //const hdr: *ICMP.ICMPHeader = icmp_layer_iface.icmpLayer.get_mutable_header();

    try icmp_layer_iface.icmpLayer.set_type(.TimestampRequest);

    const type_hdr: ICMP.ICMP_type = icmp_layer_iface.icmpLayer.get_icmp_type_hdr() orelse {
        try expect(false); // failed to get icmp type header
        return;
    };

    const timestamp_hdr: *ICMP.ICMPTimestamp = type_hdr.timestamp;

    const id: u16 = try gen_random(u16);

    const origin_timestamp: u32 = @intCast(getMillisecondsSinceMidnight());

    timestamp_hdr.set_identifier(id);

    timestamp_hdr.set_original_timestamp(origin_timestamp);

    try expect(timestamp_hdr.get_identifier() == id);
    try expect(timestamp_hdr.get_original_timestamp() == origin_timestamp);
}

test "parse icmp ttl exceeded packet" {
    const icmp_ttl_exceeded: [86]u8 = [_]u8{ 0x14, 0x4f, 0x8a, 0xa4, 0x15, 0x7d, 0x38, 0x6, 0xe6, 0x92, 0x63, 0xac, 0x81, 0x0, 0x0, 0x0, 0x8, 0x0, 0x45, 0xc0, 0x0, 0x44, 0x2, 0xe, 0x0, 0x0, 0x40, 0x1, 0xf2, 0xbb, 0xc0, 0xa8, 0x1, 0xfe, 0xc0, 0xa8, 0x1, 0xe1, 0xb, 0x0, 0xf8, 0xc0, 0x0, 0x0, 0x0, 0x0, 0x45, 0x0, 0x0, 0x28, 0x0, 0x1, 0x0, 0x0, 0x1, 0x6, 0xb6, 0x29, 0xc0, 0xa8, 0x1, 0xe1, 0xc2, 0xa4, 0x7e, 0x78, 0x0, 0x14, 0x0, 0x50, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x50, 0x2, 0x20, 0x0, 0x8b, 0xd8, 0x0, 0x0 };

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var raw_packet_buffer: std.ArrayList(u8) = .empty;

    try raw_packet_buffer.appendSlice(allocator, &icmp_ttl_exceeded);

    var packet = Packet.create(allocator, allocator);
    try packet.from_raw(allocator, &raw_packet_buffer, link_layer_type.ETHERNET, null);
    defer packet.deinit();

    try expect(packet.has_protocol_layer(.icmp));

    if (packet.get_layer_of_type(ICMP.ICMPLayer)) |icmp_layer| {
        const hdr: *const ICMP.ICMPHeader = icmp_layer.get_immutable_header();
        try expect(hdr.get_type() == .TimeExceeded);
    }

    //_ = packet.get_layer_as(ICMP.ICMPLayer);
}

test "build icmp request" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var icmp_layer_iface: Layer = try Layer.init(ICMP.ICMPLayer, allocator);
    defer icmp_layer_iface.deinit();

    var icmp_hdr: *ICMP.ICMPHeader = icmp_layer_iface.icmpLayer.get_mutable_header();

    icmp_hdr.set_type(ICMP.ICMPType.Redirect);

    var icmp_type_hdr: ICMP.ICMP_type = icmp_layer_iface.icmpLayer.get_icmp_type_hdr() orelse {
        try expect(false); // failed to get ICMP type hdr
        return;
    };

    icmp_type_hdr.redirect.gateway = (try IPv4.IPv4Address.init_from_string("192.168.1.254")).array;
}

test "build icmp request with redirect" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var eth_layer_iface: Layer = try Layer.init(Eth.EthLayer, allocator);
    defer eth_layer_iface.deinit();

    var eth_hdr: *Eth.EthHeader = eth_layer_iface.ethLayer.get_mutable_header();

    eth_hdr.set_src_mac(try Eth.MacAddress.init_from_string("14:4f:8a:a4:15:7d"));
    eth_hdr.set_dst_mac(try Eth.MacAddress.init_from_string("38:06:e6:92:63:ac"));
    eth_hdr.set_eth_type(Eth.EthType.IP);

    var ipv4_layer_iface: Layer = try Layer.init(IPv4.IPv4Layer, allocator);
    defer ipv4_layer_iface.deinit();

    var ipv4_hdr: *IPv4.IPv4Header = ipv4_layer_iface.ipv4Layer.get_mutable_header();

    ipv4_hdr.set_src_ip(try IPv4.IPv4Address.init_from_string("192.168.1.225"));
    ipv4_hdr.set_dst_ip(try IPv4.IPv4Address.init_from_string("192.168.1.254"));
    ipv4_layer_iface.ipv4Layer.set_ip_proto(IPProtocol.ICMP);

    var icmp_layer_iface: Layer = try Layer.init(ICMP.ICMPLayer, allocator);

    defer icmp_layer_iface.deinit();

    var icmp_hdr: *const ICMP.ICMPHeader = icmp_layer_iface.icmpLayer.get_immutable_header();

    _ = &icmp_hdr;

    try icmp_layer_iface.icmpLayer.set_type(ICMP.ICMPType.Redirect);

    var icmp_type_hdr: ICMP.ICMP_type = icmp_layer_iface.icmpLayer.get_icmp_type_hdr() orelse {
        try expect(false); // failed to get ICMP type hdr
        return;
    };

    icmp_type_hdr.redirect.gateway = (try IPv4.IPv4Address.init_from_string("192.168.1.254")).array;

    var packet = Packet.create(allocator, allocator);
    defer packet.deinit();

    _ = try packet.add_layer(&eth_layer_iface);
    _ = try packet.add_layer(&ipv4_layer_iface);
    _ = try packet.add_layer(&icmp_layer_iface);
}

test "build icmp echo" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.detectLeaks();

    const allocator = debug_allocator.allocator();

    var icmp_layer_iface: Layer = try Layer.init(ICMP.ICMPLayer, allocator);
    defer icmp_layer_iface.deinit();

    try icmp_layer_iface.icmpLayer.set_type(.EchoRequest);

    const type_hdr: ICMP.ICMP_type = icmp_layer_iface.icmpLayer.get_icmp_type_hdr() orelse {
        try expect(false); // failed to get icmp type
        return;
    };

    const info_hdr: *ICMP.ICMPEcho = type_hdr.echo;

    const id: u16 = try gen_random(u16);

    const seq_num: u16 = try gen_random(u16);

    info_hdr.set_identifier(id);

    info_hdr.set_seq_num(seq_num);

    try icmp_layer_iface.icmpLayer.remove_payload();

    const payload: []const u8 = "abcdefghijklmnopqrstuvwabcdefghi";

    try icmp_layer_iface.icmpLayer.set_payload(payload);

    const payload1: []const u8 = "not today";
    try icmp_layer_iface.icmpLayer.set_payload(payload1);

    const payload2: []const u8 = "yes txduy";
    try icmp_layer_iface.icmpLayer.set_payload(payload2);
}
