const std = @import("std");
const ProtocolEnums = @import("ProtocolEnums.zig");
const Packet = @import("Packet.zig");
const TLVOwner = @import("Layer.zig").TLVOwner;
const IPv4 = @import("IPv4.zig");

const print = std.debug.print;
const Allocator = std.mem.Allocator;
const panic = std.debug.panic;

const LayerError = ProtocolEnums.LayerError;

pub const IPv4Options = union(enum) {
    record_route: RecordRoute,
    loose_route: LooseSourceRoute,
    strict_route: StrictSourceRoute,
    router_alert: RouterAlert,

    pub fn init(
        opt: IPv4.IPOptionType,
        owner: TLVOwner,
        length: usize,
        prev: ?*IPv4Options,
        next: ?*IPv4Options,
    ) IPv4Options {
        switch (opt) {
            .RecordRoute => {
                return IPv4Options{ .record_route = RecordRoute{
                    .owner = owner,
                    .length = length,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },
            .LooseSourceRoute => {
                return IPv4Options{ .loose_route = LooseSourceRoute{
                    .owner = owner,
                    .length = length,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },
            .StrictSourceRoute => {
                return IPv4Options{ .strict_route = StrictSourceRoute{
                    .owner = owner,
                    .length = length,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },
            .RouterAlert => {
                return IPv4Options{ .router_alert = RouterAlert{
                    .owner = owner,
                    .length = length,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },
            else => panic("opt not handled.\n", .{}),
        }
    }

    pub fn get_data(self: *IPv4Options) []const u8 {
        return switch (self.*) {
            inline else => |*opt| opt.get_data(),
        };
    }

    pub fn get_length(self: *IPv4Options) usize {
        return switch (self.*) {
            inline else => |*opt| opt.length,
        };
    }

    pub fn get_next(self: *IPv4Options) ?*IPv4Options {
        return switch (self.*) {
            inline else => |*opt| opt.next_op,
        };
    }

    pub fn set_next_opt(self: *IPv4Options, next_opt: *IPv4Options) void {
        switch (self.*) {
            inline else => |*opt| opt.next_op = next_opt,
        }
    }

    pub fn get_prev(self: *IPv4Options) ?*IPv4Options {
        return switch (self.*) {
            inline else => |*opt| opt.prev_op,
        };
    }

    pub fn set_prev_opt(self: *IPv4Options, prev_opt: *IPv4Options) void {
        switch (self.*) {
            inline else => |*opt| opt.prev_op = prev_opt,
        }
    }

    pub fn deinit(self: *IPv4Options) void {
        return switch (self.*) {
            inline else => |*opt| opt.deinit(),
        };
    }
};

fn get_ips_list(data: []const u8, allocator: Allocator) !?[]IPv4.IPv4Address {
    if (data.len < 7) {
        return null;
    }

    var ip_count: usize = 0;

    var offset: usize = 3;

    var oct_count: usize = 0;

    while (offset < data.len) {
        if (oct_count == 3) {
            ip_count += 1;
            oct_count = 0;
        }

        oct_count += 1;
        offset += 1;
    }

    const ip_list: []IPv4.IPv4Address = try allocator.alloc(IPv4.IPv4Address, ip_count);

    offset = 3;

    var ips_added: usize = 0;

    while (offset < data.len) {
        var ip_arr: [4]u8 = undefined;
        @memmove(&ip_arr, data[offset .. offset + 4]);
        ip_list[ips_added] = IPv4.IPv4Address.init_from_array(ip_arr);
        ips_added += 1;
        offset += 4;
    }

    return ip_list;
}

fn get_ips_count(data: []const u8) usize {
    if (data.len < 7) {
        return 0;
    }

    var ip_count: usize = 0;

    var offset: usize = 3;

    var oct_count: usize = 0;

    while (offset < data.len) {
        if (oct_count == 3) {
            ip_count += 1;
            oct_count = 0;
        }

        oct_count += 1;
        offset += 1;
    }

    return ip_count;
}

fn add_ip_to_buf(data: []u8, owner: *TLVOwner, ip: IPv4.IPv4Address) !void {
    if (data.len == 0) {
        var buf = try owner.extend_buffer(0, 3);
        buf[0] = @intFromEnum(IPv4.IPOptionType.RecordRoute);
        buf[1] = 3; // min length for RecordRoute Opt - 1byte type, 1 byte length, 1byte ptr
        buf[2] = 4; // default ptr byte set to index after ptr byte
    }

    const buf = try owner.extend_buffer(owner.get_data().len, @sizeOf(IPv4.IPv4Address));
    @memmove(buf, &ip.array); // copy the ip

    owner.get_data()[1] += @sizeOf(IPv4.IPv4Address); // increase the length
}

pub fn remove_ip_from_list(owner: *TLVOwner, ip: IPv4.IPv4Address) !void {
    var data = owner.get_data();
    var data_len: usize = data.len;

    if (data.len < 7) {
        return;
    }

    var offset: usize = 3;

    var oct_count: usize = 0;

    var count: u8 = 0;

    while (offset < data_len) {
        if (oct_count == 3) {
            oct_count = 0;

            if (std.mem.eql(u8, data[offset - 3 .. offset + 1], &ip.array)) {
                try owner.shorten_buffer(offset - 3, @sizeOf(IPv4.IPv4Address));
                data_len = owner.get_data().len;
                offset -= 3;
                oct_count = 0;
                data = owner.get_data();
                count += 1;
            }
        } else {
            oct_count += 1;

            offset += 1;
        }
    }

    owner.get_data()[1] -= count * @sizeOf(IPv4.IPv4Address);
}

pub const RecordRoute = struct {
    owner: TLVOwner,
    length: usize,
    prev_op: ?*IPv4Options = null,
    next_op: ?*IPv4Options = null,

    fn get_offset(self: *RecordRoute) usize {
        var offset: usize = 0;

        if (self.owner.is_layer_owned()) {
            offset = IPv4.MinHeaderLength;
        }

        var cur = self.prev_op;
        while (cur) |prev_op| {
            offset += prev_op.get_length();
            cur = prev_op.get_prev();
        }

        return offset;
    }

    pub fn get_data(self: *RecordRoute) []const u8 {
        const data = self.owner.get_data();

        return data[self.get_offset()..];
    }

    fn get_data_mut(self: *RecordRoute) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();

        if (data.len >= absolute_offset and self.length <= data.len) {
            return data[absolute_offset .. absolute_offset + self.length];
        }

        return "";
    }

    pub fn get_ip_list(self: *RecordRoute, allocator: Allocator) !?[]IPv4.IPv4Address {
        const data = self.get_data();

        return get_ips_list(data, allocator);
    }

    pub fn get_ip_count(self: *RecordRoute) usize {
        const data = self.get_data();
        return get_ips_count(data);
    }

    pub fn add_ip(self: *RecordRoute, ip: IPv4.IPv4Address) !void {
        return add_ip_to_buf(self.get_data_mut(), &self.owner, ip);
    }

    pub fn remove_ip(self: *RecordRoute, ip: IPv4.IPv4Address) !void {
        return remove_ip_from_list(&self.owner, ip);
    }

    pub fn deinit(self: *RecordRoute) void {
        self.owner.deinit();
    }
};

pub const LooseSourceRoute = struct {
    owner: TLVOwner,
    length: usize,
    prev_op: ?*IPv4Options = null,
    next_op: ?*IPv4Options = null,

    fn get_offset(self: *LooseSourceRoute) usize {
        var offset: usize = 0;

        if (self.owner.is_packet_owned()) {
            offset = IPv4.MinHeaderLength;
        }

        var cur = self.prev_op;
        while (cur) |prev_op| {
            offset += prev_op.get_length();
            cur = prev_op.get_prev();
        }

        return offset;
    }

    pub fn get_data(self: *LooseSourceRoute) []const u8 {
        const data = self.owner.get_data();

        return data;
    }

    fn get_data_mut(self: *LooseSourceRoute) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();

        if (data.len >= absolute_offset and self.length <= data.len) {
            return data[absolute_offset .. absolute_offset + self.length];
        }

        return "";
    }

    pub fn get_ip_list(self: *LooseSourceRoute, allocator: Allocator) !?[]IPv4.IPv4Address {
        const data = self.get_data();

        return get_ips_list(data, allocator);
    }

    pub fn get_ip_count(self: *LooseSourceRoute) usize {
        const data = self.get_data();
        return get_ips_count(data);
    }

    pub fn add_ip(self: *LooseSourceRoute, ip: IPv4.IPv4Address) !void {
        return add_ip_to_buf(self.get_data_mut(), &self.owner, ip);
    }

    pub fn remove_ip(self: *LooseSourceRoute, ip: IPv4.IPv4Address) !void {
        return remove_ip_from_list(&self.owner, ip);
    }

    pub fn deinit(self: *LooseSourceRoute) void {
        self.owner.deinit();
    }
};

pub const StrictSourceRoute = struct {
    owner: TLVOwner,
    length: usize,
    prev_op: ?*IPv4Options = null,
    next_op: ?*IPv4Options = null,

    fn get_offset(self: *StrictSourceRoute) usize {
        var offset: usize = 0;

        if (self.owner.is_layer_owned()) {
            offset = IPv4.MinHeaderLength;
        }

        var cur = self.prev_op;
        while (cur) |prev_op| {
            offset += prev_op.get_length();
            cur = prev_op.get_prev();
        }

        return offset;
    }

    pub fn get_data(self: *StrictSourceRoute) []const u8 {
        const data = self.owner.get_data();

        return data[self.get_offset()..];
    }

    fn get_data_mut(self: *StrictSourceRoute) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();

        if (data.len >= absolute_offset and self.length <= data.len) {
            return data[absolute_offset .. absolute_offset + self.length];
        }

        return "";
    }

    pub fn get_ip_list(self: *StrictSourceRoute, allocator: Allocator) !?[]IPv4.IPv4Address {
        const data = self.get_data();

        return get_ips_list(data, allocator);
    }

    pub fn get_ip_count(self: *StrictSourceRoute) usize {
        const data = self.get_data();
        return get_ips_count(data);
    }

    pub fn add_ip(self: *StrictSourceRoute, ip: IPv4.IPv4Address) !void {
        return add_ip_to_buf(self.get_data_mut(), &self.owner, ip);
    }

    pub fn remove_ip(self: *StrictSourceRoute, ip: IPv4.IPv4Address) !void {
        return remove_ip_from_list(&self.owner, ip);
    }

    pub fn deinit(self: *StrictSourceRoute) void {
        self.owner.deinit();
    }
};

pub const RouterAlert = struct {
    owner: TLVOwner,
    length: usize,
    prev_op: ?*IPv4Options = null,
    next_op: ?*IPv4Options = null,

    fn get_offset(self: *RouterAlert) usize {
        var offset: usize = 0;

        if (self.owner.is_layer_owned()) {
            print("this opt is packet owned.\n", .{});
            offset = IPv4.MinHeaderLength;
        }

        var cur = self.prev_op;
        while (cur) |prev_op| {
            offset += prev_op.get_length();
            cur = prev_op.get_prev();
        }

        return offset;
    }

    pub fn get_data(self: *RouterAlert) []const u8 {
        print("offset: {}\n", .{self.get_offset()});
        const data = self.owner.get_data();

        return data[self.get_offset()..];
    }

    fn get_data_mut(self: *RouterAlert) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();

        if (data.len >= absolute_offset and self.length <= data.len) {
            return data[absolute_offset .. absolute_offset + self.length];
        }

        return "";
    }

    pub fn set_ra_val(self: *RouterAlert, val: u16) !void {
        if (self.get_data().len != 4) {
            var buf = try self.owner.extend_buffer(self.get_data().len, 4 - self.get_data().len);
            buf[0] = @intFromEnum(IPv4.IPOptionType.RouterAlert);
            buf[1] = 4; // min length for RecordRoute Opt - 1byte type, 1 byte length, 1byte ptr
        }

        //const buf = try self.owner.extend_payload(self.owner.get_data().len, @sizeOf(u16));
        @memmove(self.get_data_mut()[2..4], &std.mem.toBytes(val)); // copy the ip
    }

    pub fn deinit(self: *RouterAlert) void {
        self.owner.deinit();
    }
};
