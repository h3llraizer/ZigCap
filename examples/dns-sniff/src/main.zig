const std = @import("std");
const zigcap = @import("zigcap");

const Allocator = std.mem.Allocator;

const Packet = zigcap.Packet;
const DNS = zigcap.DNS;
const Pcap = zigcap.PcapWrapper;
const link_layer_type = zigcap.ProtocolEnums.link_layer_type;

pub fn main() !void {
    var dba: std.heap.DebugAllocator(.{}) = .init;

    _ = dba.detectLeaks();

    const allocator = dba.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        std.debug.print("Please provide an interface name.\n", .{});

        return;
    }

    const provided_iface_name = args[1];

    var ifaces = Pcap.Interfaces.init(allocator) catch |err| {
        std.debug.print("Failed to open interfaces: {s}\n", .{@errorName(err)});
        return;
    };
    defer ifaces.deinit();

    const ifaces_profiles = ifaces.get_all() catch |err| {
        std.debug.print("Failed to open interfaces: {s}\n", .{@errorName(err)});
        return;
    };

    _ = ifaces_profiles;

    var iface: *Pcap.Interface = ifaces.find_by_name(provided_iface_name) orelse {
        std.debug.print("Failed to find interface with the IPv4 Address provided.\n", .{});
        return;
    };

    iface.open(allocator) catch |err| {
        std.debug.print("Failed to open interface: {s}\n", .{@errorName(err)});
        return;
    };

    var backing_buffer: [10240]u8 = .{0x00} ** 10240;

    var fba: std.heap.FixedBufferAllocator = .init(&backing_buffer);

    const fba_allocator = fba.allocator();

    while (true) {
        defer fba.reset();

        const raw_pkt = try iface.capture_one_raw(fba_allocator) orelse continue;

        var packet = Packet.create(fba_allocator, fba_allocator);

        try packet.fromSlice(raw_pkt, link_layer_type.ETHERNET, null);

        var dns_layer = packet.get_layer_of_type(DNS.DNSLayer) orelse continue;

        const str = dns_layer.to_string(allocator);
        std.debug.print("{s}\n", .{str});
        allocator.free(str);

        try print_query_section(&dns_layer, fba_allocator);
        try print_answer_section(&dns_layer, fba_allocator);
        try print_auth_section(&dns_layer, fba_allocator);

        defer packet.deinit();
    }
}

fn print_query_section(dns_layer: *DNS.DNSLayer, allocator: Allocator) !void {
    var queries: DNS.Queries = try dns_layer.get_queries(allocator) orelse {
        return;
    };

    defer queries.deinit(allocator);

    var query = queries.first;
    if (query != null) std.debug.print("\nQUESTION SECTION:\n", .{});
    while (query) |q| {
        const str = try q.to_string(allocator);
        std.debug.print("{s}\n", .{str});
        allocator.free(str);
        query = q.next_query;
    }
}

fn print_answer_section(dns_layer: *DNS.DNSLayer, allocator: Allocator) !void {
    var answers: DNS.AnswerRecords = try dns_layer.get_answers(allocator) orelse {
        return;
    };

    defer answers.deinit(allocator);

    var answer = answers.first;

    if (answer != null) std.debug.print("\nANSWER SECTION:\n", .{});
    while (answer) |ans| {
        const str = try ans.to_string(allocator);
        std.debug.print("{s}\n", .{str});
        allocator.free(str);
        answer = ans.next();
    }
}

fn print_auth_section(dns_layer: *DNS.DNSLayer, allocator: Allocator) !void {
    var auth_answers: DNS.AnswerRecords = try dns_layer.get_auth_answers(allocator) orelse {
        return;
    };

    defer auth_answers.deinit(allocator);

    var auth_answer = auth_answers.first;
    if (auth_answer != null) std.debug.print("\nAUTHORITY SECTION:\n", .{});
    while (auth_answer) |ans| {
        const str = try ans.to_string(allocator);
        std.debug.print("{s}\n", .{str});
        allocator.free(str);
        auth_answer = ans.next();
    }
}
