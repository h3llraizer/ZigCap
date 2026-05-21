const std = @import("std");
const ProtocolEnums = @import("ProtocolEnums.zig");
const Packet = @import("Packet.zig");
const TLVOwner = @import("Layer.zig").TLVOwner;
const IPv4 = @import("IPv4.zig");

const print = std.debug.print;
const Allocator = std.mem.Allocator;
const panic = std.debug.panic;

const LayerError = ProtocolEnums.LayerError;

pub const IPv4Option = union(enum) {
    record_route: RecordRoute,
    loose_route: LooseSourceRoute,
    strict_route: StrictSourceRoute,
    router_alert: RouterAlert,
    timestamp: Timestamp,

    pub fn init(
        opt: IPv4.IPOptionType,
        owner: TLVOwner,
        length: usize,
        prev: ?*IPv4Option,
        next: ?*IPv4Option,
    ) IPv4Option {
        switch (opt) {
            .RecordRoute => {
                //const len = owner.get_data().len;
                //if (!owner.is_layer_owned()) {
                //    if (len < 3) {
                //        try owner.extend_buffer(len, 3 - len);
                //    }
                //}

                return IPv4Option{ .record_route = RecordRoute{
                    .owner = owner,
                    .length = length,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },
            .LooseSourceRoute => {
                return IPv4Option{ .loose_route = LooseSourceRoute{
                    .owner = owner,
                    .length = length,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },
            .StrictSourceRoute => {
                return IPv4Option{ .strict_route = StrictSourceRoute{
                    .owner = owner,
                    .length = length,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },
            .RouterAlert => {
                return IPv4Option{ .router_alert = RouterAlert{
                    .owner = owner,
                    .length = length,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },
            .Timestamp => {
                return IPv4Option{ .timestamp = Timestamp{
                    .owner = owner,
                    .length = length,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },
            else => panic("opt not handled.\n", .{}),
        }
    }

    pub fn get_data(self: *IPv4Option) []const u8 {
        return switch (self.*) {
            inline else => |*opt| opt.get_data(),
        };
    }

    pub fn get_length(self: *IPv4Option) usize {
        return switch (self.*) {
            inline else => |*opt| opt.length,
        };
    }

    pub fn get_next(self: *IPv4Option) ?*IPv4Option {
        return switch (self.*) {
            inline else => |*opt| opt.next_op,
        };
    }

    pub fn set_next_opt(self: *IPv4Option, next_opt: *IPv4Option) void {
        switch (self.*) {
            inline else => |*opt| opt.next_op = next_opt,
        }
    }

    pub fn get_prev(self: *IPv4Option) ?*IPv4Option {
        return switch (self.*) {
            inline else => |*opt| opt.prev_op,
        };
    }

    pub fn set_prev_opt(self: *IPv4Option, prev_opt: *IPv4Option) void {
        switch (self.*) {
            inline else => |*opt| opt.prev_op = prev_opt,
        }
    }

    pub fn get_opt_type(self: *IPv4Option) IPv4.IPOptionType {
        const opt_type_v = self.get_data()[0];

        return @enumFromInt(opt_type_v);
    }

    pub fn deinit(self: *IPv4Option) void {
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
        @memmove(&ip_arr, data[offset .. offset + @sizeOf(IPv4.IPv4Address)]);
        ip_list[ips_added] = IPv4.IPv4Address.init_from_array(ip_arr);
        ips_added += 1;
        offset += @sizeOf(IPv4.IPv4Address);
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

fn add_ip_to_buffer(offset: usize, owner: *TLVOwner, ip: IPv4.IPv4Address, opt_type: IPv4.IPOptionType) !void {
    if (owner.get_data()[offset..].len == 0) {
        if (opt_type == .Timestamp) {
            var buf = try owner.extend_buffer(offset, 4);
            buf[0] = @intFromEnum(opt_type);
            buf[1] = 4;
            buf[2] = 0;
            buf[3] = 5;
        } else {
            var buf = try owner.extend_buffer(0, 3);
            buf[0] = @intFromEnum(opt_type);
            buf[1] = 3; // min length for RR/LSR/SSR Opt - 1byte type, 1 byte length, 1byte ptr
            buf[2] = 4; // default ptr byte set to index after ptr byte
        }
    }

    const buf = try owner.extend_buffer(
        owner.get_data().len, // not good - when layer owned this extends at the last option or worse packet end
        @sizeOf(IPv4.IPv4Address),
    );
    @memmove(buf, &ip.array); // copy the ip

    // This is the cause of the dscp length increase
    // dscp is at offset 1 in the ipv4 header
    // so each time this is called, it's increasing by 4
    owner.get_data()[offset + 1] += @sizeOf(IPv4.IPv4Address); // increase the length
}

fn remove_ip_from_list(owner: *TLVOwner, ip: IPv4.IPv4Address) !void {
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

fn get_ip_offset(owner: *TLVOwner, ip: IPv4.IPv4Address, cur_offset: usize) ?usize {
    var data = owner.get_data();
    var data_len: usize = data.len;

    if (data.len < 7) {
        return null;
    }

    var offset: usize = cur_offset;

    var oct_count: usize = 0;

    //var count: u8 = 0;

    while (offset < data_len) {
        if (oct_count == 3) {
            oct_count = 0;

            if (std.mem.eql(u8, data[offset - 3 .. offset + 1], &ip.array)) {
                data_len = owner.get_data().len;
                offset -= 3;
                return offset;
                //  oct_count = 0;
                //   data = owner.get_data();
                //   count += 1;
            }
        } else {
            oct_count += 1;

            offset += 1;
        }
    }

    return null;
}

fn add_timestamp_to_buffer(offset: usize, owner: *TLVOwner, timestamp: u32, opt_type: IPv4.IPOptionType) !void {
    if (owner.get_data()[offset..].len == 0) {
        var buf = try owner.extend_buffer(0, 4);
        buf[0] = @intFromEnum(opt_type);
        buf[1] = 4; // min length for RecordRoute Opt - 1byte type, 1 byte length, 1byte ptr
        buf[2] = @intFromEnum(TimestampMode.ts_only); // default ptr byte set to index after ptr byte
        buf[3] = 5;
    }

    const buf = try owner.extend_buffer(owner.get_data().len, @sizeOf(u32));
    @memmove(buf, &std.mem.toBytes(@byteSwap(timestamp))); // copy the ip

    owner.get_data()[offset + 1] += @sizeOf(u32); // increase the length
}

pub const RecordRoute = struct {
    owner: TLVOwner,
    length: usize,
    prev_op: ?*IPv4Option = null,
    next_op: ?*IPv4Option = null,

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
        return add_ip_to_buffer(self.get_offset(), &self.owner, ip, IPv4.IPOptionType.RecordRoute);
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
    prev_op: ?*IPv4Option = null,
    next_op: ?*IPv4Option = null,

    fn get_offset(self: *LooseSourceRoute) usize {
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

    pub fn get_data(self: *LooseSourceRoute) []const u8 {
        const data = self.owner.get_data();

        return data[self.get_offset()..];
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
        return add_ip_to_buffer(self.get_offset(), &self.owner, ip, IPv4.IPOptionType.LooseSourceRoute);
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
    prev_op: ?*IPv4Option = null,
    next_op: ?*IPv4Option = null,

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
        return add_ip_to_buffer(self.get_offset(), &self.owner, ip, IPv4.IPOptionType.StrictSourceRoute);
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
    prev_op: ?*IPv4Option = null,
    next_op: ?*IPv4Option = null,

    fn get_offset(self: *RouterAlert) usize {
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

    pub fn get_data(self: *RouterAlert) []const u8 {
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

        @memmove(self.get_data_mut()[2..4], &std.mem.toBytes(val)); // copy the ip
    }

    pub fn deinit(self: *RouterAlert) void {
        self.owner.deinit();
    }
};

pub const TimestampMode = enum(u4) {
    /// Timestamps only. No Addresses
    ts_only = 0,
    /// Timestamps and Addresses are append by each host
    append_addrs = 1,
    /// Timestamps and Addresses are appended by specified hosts only
    specified_addr = 3,
};

pub const TimestampRecord = struct {
    ip: ?IPv4.IPv4Address = null,
    timestamp: u32,
    next_record: ?*TimestampRecord = null,
    prev_record: ?*TimestampRecord = null,
};

pub const TimestampRecords = struct {
    first: ?*TimestampRecord = null,
    last: ?*TimestampRecord = null,

    pub fn deinit(self: *TimestampRecords, allocator: Allocator) void {
        var cur = self.first;
        while (cur) |record| {
            const next = record.next_record;
            allocator.destroy(record);
            cur = next;
        }

        self.first = null;
        self.last = null;
    }
};

pub const Timestamp = struct {
    owner: TLVOwner,
    length: usize,
    prev_op: ?*IPv4Option = null,
    next_op: ?*IPv4Option = null,

    pub fn get_offset(self: *Timestamp) usize {
        var offset: usize = 0;

        if (self.owner.is_layer_owned()) {
            offset = IPv4.MinHeaderLength;

            var cur = self.prev_op;
            while (cur) |prev_op| {
                offset += prev_op.get_length();
                cur = prev_op.get_prev();
            }
        }

        return offset;
    }

    pub fn get_data(self: *Timestamp) []const u8 {
        const data = self.owner.get_data();

        return data[self.get_offset()..];
    }

    fn get_data_mut(self: *Timestamp) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();

        if (data.len >= absolute_offset and self.length <= data.len) {
            return data[absolute_offset .. absolute_offset + self.length];
        }

        return "";
    }

    pub fn set_mode_flag(self: *Timestamp, flag: TimestampMode) !void {
        if (self.get_data().len < 4) {
            var buf = try self.owner.extend_buffer(
                self.get_data().len,
                4 - self.get_data().len,
            );

            buf[0] = @intFromEnum(IPv4.IPOptionType.Timestamp);
            buf[1] = 4;
            buf[2] = 5;
        }

        self.get_data_mut()[3] =
            (self.get_data_mut()[3] & 0b1111_0000) |
            (@as(u8, @intFromEnum(flag)) & 0b0000_1111);
    }

    pub fn get_mode_flag(self: *Timestamp) TimestampMode {
        return @enumFromInt(self.get_data()[3] & 0b0000_1111);
    }

    pub fn get_overflow(self: *Timestamp) u4 {
        return @intCast((self.get_data()[3] & 0b1111_0000) >> 4);
    }

    pub fn set_overflow(self: *Timestamp, of: u4) !void {
        if (self.get_data().len < 4) {
            var buf = try self.owner.extend_buffer(
                self.get_data().len,
                4 - self.get_data().len,
            );

            buf[0] = @intFromEnum(IPv4.IPOptionType.Timestamp);
            buf[1] = 4;
            buf[2] = 5;
        }

        self.get_data_mut()[3] =
            (self.get_data_mut()[3] & 0b0000_1111) |
            (@as(u8, of) << 4);
    }

    fn add_timestamp(self: *Timestamp, timestamp: u32) !void {
        try add_timestamp_to_buffer(self.get_offset(), &self.owner, timestamp, IPv4.IPOptionType.Timestamp);
    }

    pub fn get_records(self: *Timestamp, allocator: Allocator) !?TimestampRecords {
        const data = self.get_data();
        if (data.len < 7) {
            return null;
        }

        var cur: ?*TimestampRecord = null;

        var records: TimestampRecords = .{};

        var offset: usize = 4; // 1byte type, 1byte length, 1byte flag/of, 1byte ptr

        const offset_inc: usize = if (self.get_mode_flag() == .ts_only) 4 else 8;

        while (offset + offset_inc <= data.len) {
            const record = try allocator.create(TimestampRecord);

            if (self.get_mode_flag() == .ts_only) {
                const timestamp: u32 = std.mem.bytesToValue(u32, self.get_data()[offset .. offset + offset_inc]);

                record.* = .{ .timestamp = @byteSwap(timestamp) };
            } else {
                var ip: IPv4.IPv4Address = .init_from_u32(0x00000000);
                const timestamp: u32 = std.mem.bytesToValue(u32, self.get_data()[offset + 4 .. offset + offset_inc]);

                @memmove(&ip.array, self.get_data()[offset .. offset + 4]);

                record.* = .{ .ip = ip, .timestamp = @byteSwap(timestamp) };
            }

            if (records.first == null) {
                records.first = record;
            }

            if (cur) |rec| {
                rec.next_record = record;
                record.prev_record = rec;
                cur = record;
                offset += offset_inc;
                continue;
            }

            cur = record;

            offset += offset_inc;
        }

        records.last = cur;

        if (records.first == null) {
            return null;
        }

        return records;
    }

    pub fn get_ip_list(self: *Timestamp, allocator: Allocator) !?[]IPv4.IPv4Address {
        const data = self.get_data();

        return get_ips_list(data, allocator);
    }

    pub fn get_ip_count(self: *Timestamp) usize {
        const data = self.get_data();
        return get_ips_count(data);
    }

    fn add_ip(self: *Timestamp, ip: IPv4.IPv4Address) !void {
        return add_ip_to_buffer(self.get_offset(), &self.owner, ip, IPv4.IPOptionType.Timestamp);
    }

    fn remove_ip(self: *Timestamp, ip: IPv4.IPv4Address) !void {
        return remove_ip_from_list(&self.owner, ip);
    }

    pub fn remove_ts_record(self: *Timestamp, record: TimestampRecord) !void {
        const data = self.get_data()[4..];
        if (record.ip == null) {
            const bytes: [4]u8 = std.mem.toBytes(@byteSwap(record.timestamp));
            if (std.mem.indexOf(u8, data, &bytes)) |offset| {
                try self.owner.shorten_buffer(offset, @sizeOf(u32));
                self.get_data_mut()[1] -= 4;
                self.set_hdr_vals(-4);
                return;
            }
        }

        const ip_bytes: [4]u8 = record.ip.?.array;
        const ts_bytes: [4]u8 = std.mem.toBytes(@byteSwap(record.timestamp));
        var full_rec: [8]u8 = .{0x00} ** 8;

        @memmove(full_rec[0..4], &ip_bytes);
        @memmove(full_rec[4..8], &ts_bytes);

        if (std.mem.indexOf(u8, data, &full_rec)) |offset| {
            try self.owner.shorten_buffer(self.get_offset() + 4 + offset, 8);
            self.get_data_mut()[1] -= 8;
            self.set_hdr_vals(-8);
            return;
        }

        print("no action.\n", .{});
    }

    fn get_mutable_hdr(self: *Timestamp) *IPv4.IPv4Header {
        const data = self.owner.get_data();

        if (data.len < IPv4.MinHeaderLength) {
            panic("IPv4 data len ({}) less than IPv4HeaderSize", .{data.len});
        }

        const aligned_ptr: [*]align(@alignOf(IPv4.IPv4Header)) u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    fn set_hdr_vals(self: *Timestamp, len: isize) void {
        if (self.owner.is_layer_owned()) {
            const hdr = self.get_mutable_hdr();
            const new_len: isize = hdr.get_length() + len;
            hdr.set_length(@intCast(new_len));
            hdr.set_ihl(@intCast(hdr.get_length()));
        }
    }

    pub fn add_ts_record(self: *Timestamp, record: TimestampRecord) !void {
        if (self.get_mode_flag() == .ts_only) {
            if (record.ip != null) {
                return error.InvalidTimestampOnlyRecord; // TS Only does not contain IP addresses
            }
            try self.add_timestamp(record.timestamp);
            self.set_hdr_vals(4);
            return;
        }

        if (record.ip == null) {
            return error.IPRequiredForNonTSOnlyRecord; // caller must provide an IP, even if 0.0.0.0 for place holder
        }

        print("adding record. owner is layer: {any}\n", .{self.owner.is_layer_owned()});

        try self.add_ip(record.ip.?);
        try self.add_timestamp(record.timestamp);
        self.set_hdr_vals(8);
    }

    pub fn deinit(self: *Timestamp) void {
        self.owner.deinit();
    }
};
