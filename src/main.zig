const std = @import("std");
const print = std.debug.print;
const PacketStructs = @import("PacketStructs.zig");
const PcapWrapper = @import("PcapWrapper.zig");

const PacketArena = struct {
    arena: std.heap.ArenaAllocator,

    pub fn init(backing_allocator: std.mem.Allocator) PacketArena {
        return PacketArena{
            .arena = std.heap.ArenaAllocator.init(backing_allocator),
        };
    }

    pub fn deinit(self: *PacketArena) void {
        _ = self.arena.deinit();
    }

    pub fn allocOne(self: *PacketArena, packet: PacketStructs.RawPacket) !*PacketStructs.RawPacket {
        const p = try self.arena.allocator().create(PacketStructs.RawPacket);
        p.* = packet; // copy into arena
        return p;
    }
};

pub fn main() !void {
    print("starting...", .{});

    const wifiIfaceDesc: [*:0]const u8 = "Intel(R) Dual Band Wireless-AC 3165";

    const wifiIfaceName: ?[*:0]const u8 = undefined;

    var allocator = std.heap.page_allocator;

    print("wifi_Iface_Desc: {s} WiFi_iface_name {any} allocator {any}", .{ wifiIfaceDesc, wifiIfaceName, allocator.ptr });

    const interfaces = PcapWrapper.Interfaces.init();

    if (interfaces) |ifaces| {
        const device_list = try ifaces.array_list(&allocator);

        if (device_list.items.len > 0) {
            for (device_list.items) |device| {
                print("{s}\n", .{device});
            }
        } else {
            print("failed to get devices.\n", .{});
        }
    } else {
        print("failed to initialise pcap interfaces.\n", .{});
        return;
    }
}
