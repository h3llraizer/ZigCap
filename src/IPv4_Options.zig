const std = @import("std");
const TLVOwner = @import("Layer.zig").TLVOwner;
const IPv4 = @import("IPv4.zig");

const print = std.debug.print;
const Allocator = std.mem.Allocator;
const panic = std.debug.panic;

// TODO: implement helpers for all of these and unit test them
// ✅ Security (130) - length 11 bytes (type + len + 9 data)
// Example data: all zeros (unclassified)
//&[_]u8{130, 11, 0,0,0,0,0,0,0,0,0}

// ✅LooseSourceRoute (131) - example: route through 192.0.2.1 and 192.0.2.2
// length = 3 + (n * 4) where n=2 → 11 bytes
//&[_]u8{131, 11, 4, 192,0,2,1, 192,0,2,2}
// (3rd byte = pointer to next addr, starts at 4)

// ✅Timestamp (68) - length 4+ bytes, example: overflow=0, flags=1 (timestamp only)
//&[_]u8{68, 4, 0, 1}

// ✅ ExtendedSecurity (133) - length 6 (example minimal data)
//&[_]u8{133, 6, 0,0,0,0}

// ✅ CommercialSecurity (134) - length 6 (example minimal data)
//&[_]u8{134, 6, 0,0,0,0}

// ✅RecordRoute (7) - example: pointer=4, space for 1 IP (4 bytes)
//&[_]u8{7, 8, 4, 0,0,0,0}

// ✅ StreamID (136) - length 4 (type + len + 2-byte stream ID)
//&[_]u8{136, 4, 0x12, 0x34}

// ✅StrictSourceRoute (137) - same format as LSRR, example: 192.0.2.1
//&[_]u8{137, 8, 4, 192,0,2,1}

// ✅ ExperimentalMeasurement (10) - length 4 (example data 0x01 0x02)
//&[_]u8{10, 4, 0x01, 0x02}

// ✅ MTUProbe (11) - length 4 (example 2-byte probe value)
//&[_]u8{11, 4, 0x00, 0x40}

// ✅ MTUReply (12) - length 4 (example 2-byte MTU value 1500)
//&[_]u8{12, 4, 0x05, 0xDC}

// ✅ ExperimentalFlowControl (205) - length 4 (example data)
//&[_]u8{205, 4, 0xAA, 0xBB}

// ✅ ExperimentalAccessControl (142) - length 6 (example)
//&[_]u8{142, 6, 0x01,0x02,0x03,0x04}

// ✅ ExtendedInternet (145) - length 4 (example)
//&[_]u8{145, 4, 0x00, 0x01}

// ✅RouterAlert (148) - length 4 (value usually 0x0000)
//&[_]u8{148, 4, 0x00, 0x00}

// ✅ SelectiveDirectedBroadcast (149) - length 8 (example: mask + 1 IP)
//&[_]u8{149, 8, 0xFF,0xFF,0xFF,0x00, 192,0,2,255}

// ✅ DynamicPacketState (151) - length 4 (example)
//&[_]u8{151, 4, 0x00, 0x10}

// ✅ UpstreamMulticast (152) - length 4 (example)
//&[_]u8{152, 4, 0x00, 0x01}

// QuickStart (25) - length 8 (example: rate=0x0100, ttl diff=1)
//&[_]u8{25, 8, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00}

// RFC3692Exp1 (30) - length 4 (experimental data)
//&[_]u8{30, 4, 0xCA, 0xFE}

// RFC3692Exp2 (94) - length 4
//&[_]u8{94, 4, 0xDE, 0xAD}

// RFC3692Exp3 (158) - length 6
//&[_]u8{158, 6, 0xBE, 0xEF, 0x12, 0x34}

// RFC3692Exp4 (222) - length 8
//&[_]u8{222, 8, 0x00,0x11,0x22,0x33,0x44,0x55}

/// IPv4 Option Types
pub const IPOptionType = enum(u8) {
    EndOfOptions = 0,
    NoOperation = 1,
    Security = 130,
    LooseSourceRoute = 131,
    Timestamp = 68,
    ExtendedSecurity = 133,
    CommercialSecurity = 134,
    RecordRoute = 7,
    StreamID = 136,
    StrictSourceRoute = 137,
    ExperimentalMeasurement = 10,
    MTUProbe = 11,
    MTUReply = 12,
    ExperimentalFlowControl = 205,
    ExperimentalAccessControl = 142,
    ExtendedInternet = 145,
    RouterAlert = 148,
    SelectiveDirectedBroadcast = 149,
    DynamicPacketState = 151,
    UpstreamMulticast = 152,
    QuickStart = 25,
    RFC3692Exp1 = 30,
    RFC3692Exp2 = 94,
    RFC3692Exp3 = 158,
    RFC3692Exp4 = 222,
    _,

    pub fn requires_ptr_byte(opt: IPOptionType) bool {
        switch (opt) {
            .RecordRoute, .LooseSourceRoute, .StrictSourceRoute, .Timestamp => {
                return true;
            },
            else => return false,
        }
    }
};

/// LinkedList container for retrieving IPv4Options list from IPv4Layer
pub const IPv4Options = struct {
    first: ?*IPv4Option = null,
    last: ?*IPv4Option = null,

    pub fn deinit(self: *IPv4Options, allocator: Allocator) void {
        var cur = self.first;
        while (cur) |opt| {
            const next = opt.get_next();
            allocator.destroy(opt);
            cur = next;
        }

        self.first = null;
        self.last = null;
    }
};

/// Tagged Union of supported IPv4 Options
/// RFC* options will be parsed under GenericOption
pub const IPv4Option = union(enum) {
    record_route: RecordRoute,
    loose_route: LooseSourceRoute,
    strict_route: StrictSourceRoute,
    router_alert: RouterAlert,
    timestamp: Timestamp,
    mtu_probe: MTUProbe,
    mtu_reply: MTUReply,
    security: Security,
    extended_security: ExtendedSecurity,
    commercial_security: CommercialSecurity,
    stream_id: StreamID,
    experimental_measurement: ExperimentalMeasurement,
    experimental_flow_control: ExperimentalFlowControl,
    experimental_access_control: ExperimentalAccessControl,
    extended_internet: ExtendedInternet,
    selective_directed_broadcast: SelectiveDirectedBroadcast,
    dynamic_packet_state: DynamicPacketState,
    upstream_multicast: UpstreamMulticast,
    quick_start: QuickStart,
    generic: GenericOption,

    pub fn init(
        opt: IPv4.IPOptionType,
        owner: TLVOwner,
        length: usize,
        prev: ?*IPv4Option,
        next: ?*IPv4Option,
    ) IPv4Option {
        switch (opt) {
            .RecordRoute => {
                return IPv4Option{ .record_route = RecordRoute{
                    .owner = owner,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },
            .LooseSourceRoute => {
                return IPv4Option{ .loose_route = LooseSourceRoute{
                    .owner = owner,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },
            .StrictSourceRoute => {
                return IPv4Option{ .strict_route = StrictSourceRoute{
                    .owner = owner,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },
            .RouterAlert => {
                return IPv4Option{ .router_alert = RouterAlert{
                    .owner = owner,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },
            .Timestamp => {
                return IPv4Option{ .timestamp = Timestamp{
                    .owner = owner,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },
            .MTUProbe => {
                return IPv4Option{ .mtu_probe = MTUProbe{
                    .owner = owner,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },
            .MTUReply => {
                return IPv4Option{ .mtu_reply = MTUReply{
                    .owner = owner,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },
            .Security => {
                return IPv4Option{ .security = Security{
                    .owner = owner,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },
            .ExtendedSecurity => {
                return IPv4Option{ .extended_security = ExtendedSecurity{
                    .owner = owner,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },

            .CommericalSecurity => {
                return IPv4Option{ .commercial_security = CommercialSecurity{
                    .owner = owner,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },

            .StreamID => {
                return IPv4Option{ .stream_id = StreamID{
                    .owner = owner,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },

            .ExperimentalMeasurement => {
                return IPv4Option{ .experimental_measurement = ExperimentalMeasurement{
                    .owner = owner,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },

            .ExperimentalFlowControl => {
                return IPv4Option{ .experimental_flow_control = ExperimentalFlowControl{
                    .owner = owner,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },
            .ExperimentalAccessControl => {
                return IPv4Option{ .experimental_access_control = ExperimentalAccessControl{
                    .owner = owner,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },

            .ExtendedInternet => {
                return IPv4Option{ .extended_internet = ExtendedInternet{
                    .owner = owner,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },

            .SelectiveDirectedBroadcast => {
                return IPv4Option{ .selective_directed_broadcast = SelectiveDirectedBroadcast{
                    .owner = owner,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },

            .DynamicPacketState => {
                return IPv4Option{ .dynamic_packet_state = DynamicPacketState{
                    .owner = owner,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },
            .UpstreamMulticast => {
                return IPv4Option{ .upstream_multicast = UpstreamMulticast{
                    .owner = owner,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },
            .QuickStart => {
                return IPv4Option{ .quick_start = QuickStart{
                    .owner = owner,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },
            else => {
                return IPv4Option{ .generic = GenericOption{
                    .owner = owner,
                    .length = length,
                    .prev_op = prev,
                    .next_op = next,
                } };
            },
        }
    }

    pub fn get_data(self: *IPv4Option) []const u8 {
        return switch (self.*) {
            inline else => |*opt| opt.get_data(),
        };
    }

    pub fn get_length(self: *IPv4Option) usize {
        return switch (self.*) {
            inline else => |*opt| @intCast(opt.get_data()[1]),
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

    pub fn get_tlv_length(self: *IPv4Option) usize {
        return switch (self.*) {
            .record_route => {
                return RecordRoute.TLVHeaderLength;
            },

            .loose_route => {
                return LooseSourceRoute.TLVHeaderLength;
            },

            .strict_route => {
                return StrictSourceRoute.TLVHeaderLength;
            },

            .router_alert => {
                return RouterAlert.TLVHeaderLength;
            },

            .timestamp => {
                return Timestamp.TLVHeaderLength;
            },
            .generic => {
                return GenericOption.TLVHeaderLength;
            },
        };
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
    _ = opt_type;

    const cur_length: usize = @intCast(owner.get_data()[offset + 1]);

    std.debug.assert(cur_length <= owner.get_data()[offset..].len);

    const buf = try owner.extend_buffer(
        offset + cur_length,
        @sizeOf(IPv4.IPv4Address),
    );

    @memmove(buf, &ip.array); // copy the ip

    owner.get_data()[offset + 1] += @sizeOf(IPv4.IPv4Address); // increase the length
    try set_hdr_vals(owner, @sizeOf(IPv4.IPv4Address));
}

fn remove_ip_from_list(offset: usize, owner: *TLVOwner, ip: IPv4.IPv4Address) !void {
    var data = owner.get_data()[offset..];
    var data_len: usize = @intCast(data[1]);

    if (data.len < 7) {
        return;
    }

    var relative_offset: usize = 3;

    var oct_count: usize = 0;

    var count: u8 = 0;

    while (relative_offset < data_len) {
        if (oct_count == 3) {
            oct_count = 0;

            //
            const ip_bytes = data[relative_offset - 3 .. relative_offset + 1];

            if (std.mem.eql(u8, ip_bytes, &ip.array)) {
                // shorten the owning buffer at the offset by the size of the IPv4 address
                try owner.shorten_buffer(offset + (relative_offset - 3), @sizeOf(IPv4.IPv4Address));

                // decrease data_len by size of IPv4 Address (4 bytes)
                data_len -= @sizeOf(IPv4.IPv4Address);

                // decrease offset by size of IPv4 Address (4 bytes)
                relative_offset -= @sizeOf(IPv4.IPv4Address);

                // reset oct_count to 0
                oct_count = 0;

                // reset the ptr
                data = owner.get_data()[relative_offset..];

                // increase count by 1
                count += 1;
            }
        } else {
            // increase oct count by 1
            oct_count += 1;

            // increase offset by 1
            relative_offset += 1;
        }
    }

    owner.get_data()[offset..][1] -= count * @sizeOf(IPv4.IPv4Address); // decrease length byte value in TLV by bytes removed

    try set_hdr_vals(owner, -(@as(isize, @intCast(count * @sizeOf(IPv4.IPv4Address))))); // update the IPv4 header vals
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
    _ = opt_type;
    const buf = try owner.extend_buffer(owner.get_data().len, @sizeOf(u32));
    @memmove(buf, &std.mem.toBytes(@byteSwap(timestamp))); // copy the ip

    owner.get_data()[offset + 1] += @sizeOf(u32); // increase the length
    try set_hdr_vals(owner, @sizeOf(u32));
}

fn add_pad(owner: *TLVOwner) !void {
    _ = owner;
}

fn get_mutable_hdr(owner: *TLVOwner) *IPv4.IPv4Header {
    const data = owner.get_data();

    if (data.len < IPv4.MinHeaderLength) {
        panic("IPv4 data len ({}) less than IPv4HeaderSize", .{data.len});
    }

    const aligned_ptr: [*]align(@alignOf(IPv4.IPv4Header)) u8 = @alignCast(data.ptr);
    return @ptrCast(aligned_ptr);
}

fn set_hdr_vals(owner: *TLVOwner, len: isize) !void {
    if (owner.is_layer_owned()) {
        var hdr = get_mutable_hdr(owner);

        const current_ihl: u8 = hdr.get_ihl();

        const current_header_len: isize = current_ihl * 4;

        var new_header_len: usize = @intCast(current_header_len + len);

        const pad_required = if (new_header_len % IPv4.HeaderAlignment == 0) 0 else IPv4.HeaderAlignment - (new_header_len % IPv4.HeaderAlignment);

        if (pad_required > 0) {
            _ = try owner.extend_buffer(owner.get_data().len, pad_required);
            new_header_len += pad_required;
            hdr = get_mutable_hdr(owner);
        }

        hdr.set_length(@intCast(new_header_len));
        hdr.set_ihl(@intCast(hdr.get_length()));
    }
}

pub const RecordRoute = struct {
    owner: TLVOwner,
    prev_op: ?*IPv4Option = null,
    next_op: ?*IPv4Option = null,

    pub const TLVHeaderLength = 3;

    pub fn init(owner: TLVOwner) !RecordRoute {
        switch (owner) {
            .owned_buffer => {
                var self = RecordRoute{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < RecordRoute.TLVHeaderLength) {
                    const rr_data = try self.owner.owned_buffer.extend(buffer_len, RecordRoute.TLVHeaderLength);

                    @memset(rr_data, 0);

                    rr_data[0] = @intFromEnum(IPOptionType.RecordRoute);
                    rr_data[1] = RecordRoute.TLVHeaderLength;
                    rr_data[2] = 4;
                } else {
                    if (self.owner.owned_buffer.buffer.items[0] != @intFromEnum(IPOptionType.RecordRoute)) {
                        return error.TypeByteInvalid;
                    }
                }

                return self;
            },
            else => {
                return error.UseTUInstead;
            },
        }
    }

    fn get_offset(self: *RecordRoute) usize {
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

    pub fn get_data(self: *RecordRoute) []const u8 {
        const data = self.owner.get_data();

        const offset: usize = self.get_offset();
        const length: usize = @intCast(data[offset + 1]);

        return data[offset .. offset + length];
    }

    fn get_data_mut(self: *RecordRoute) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();
        const length = self.get_data()[absolute_offset + 1];

        if (data.len >= absolute_offset and length <= data.len) {
            return data[absolute_offset .. absolute_offset + length];
        }

        return "";
    }

    /// Returns the length of the Option from its TLV-Header
    pub fn get_length(self: *RecordRoute) u8 {
        return self.get_data()[1];
    }

    pub fn get_ptr(self: *RecordRoute) u8 {
        return self.get_data()[2];
    }

    /// Throws exception when the ptr value exceeds the length of the option or points to TLV header
    pub fn set_ptr(self: *RecordRoute, ptr: u8) !void {
        const ptr_u: usize = @intCast(ptr); // ptr byte val as usize
        if (ptr_u > self.get_data().len) {
            return error.PtrOutOfRange;
        }

        if (ptr_u < 4) {
            return error.PtrPointsToTLVHeader;
        }

        self.get_data()[2] = ptr;
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
        return remove_ip_from_list(self.get_offset(), &self.owner, ip);
    }

    pub fn deinit(self: *RecordRoute) void {
        self.owner.deinit();
    }
};

pub const LooseSourceRoute = struct {
    owner: TLVOwner,
    prev_op: ?*IPv4Option = null,
    next_op: ?*IPv4Option = null,

    pub const TLVHeaderLength = 3;

    pub fn init(owner: TLVOwner) !LooseSourceRoute {
        switch (owner) {
            .owned_buffer => {
                var self = LooseSourceRoute{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < LooseSourceRoute.TLVHeaderLength) {
                    const lsr_data = try self.owner.owned_buffer.extend(buffer_len, LooseSourceRoute.TLVHeaderLength);

                    @memset(lsr_data, 0);

                    lsr_data[0] = @intFromEnum(IPOptionType.LooseSourceRoute);
                    lsr_data[1] = LooseSourceRoute.TLVHeaderLength;
                    lsr_data[2] = 4;
                } else {
                    if (self.owner.owned_buffer.buffer.items[0] != @intFromEnum(IPOptionType.LooseSourceRoute)) {
                        return error.TypeByteInvalid;
                    }
                }

                return self;
            },
            else => {
                return error.UseTUInstead;
            },
        }
    }

    fn get_offset(self: *LooseSourceRoute) usize {
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

    pub fn get_data(self: *LooseSourceRoute) []const u8 {
        const data = self.owner.get_data();

        const offset: usize = self.get_offset();
        const length: usize = @intCast(data[offset + 1]);

        return data[offset .. offset + length];
    }

    fn get_data_mut(self: *LooseSourceRoute) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();
        const length = self.get_data()[absolute_offset + 1];

        if (data.len >= absolute_offset and length <= data.len) {
            return data[absolute_offset .. absolute_offset + length];
        }

        return "";
    }

    /// Returns the length of the Option from its TLV-Header
    pub fn get_length(self: *LooseSourceRoute) u8 {
        return self.get_data()[1];
    }

    pub fn get_ptr(self: *LooseSourceRoute) u8 {
        return self.get_data()[2];
    }

    /// Throws exception when the ptr value exceeds the length of the option or points to TLV header
    pub fn set_ptr(self: *LooseSourceRoute, ptr: u8) !void {
        const ptr_u: usize = @intCast(ptr); // ptr byte val as usize
        if (ptr_u > self.get_data().len) {
            return error.PtrOutOfRange;
        }

        if (ptr_u < 4) {
            return error.PtrPointsToTLVHeader;
        }

        self.get_data()[2] = ptr;
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
        return remove_ip_from_list(self.get_offset(), &self.owner, ip);
    }

    pub fn deinit(self: *LooseSourceRoute) void {
        self.owner.deinit();
    }
};

pub const StrictSourceRoute = struct {
    owner: TLVOwner,
    prev_op: ?*IPv4Option = null,
    next_op: ?*IPv4Option = null,

    pub const TLVHeaderLength = 3;

    pub fn init(owner: TLVOwner) !StrictSourceRoute {
        switch (owner) {
            .owned_buffer => {
                var self = StrictSourceRoute{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < StrictSourceRoute.TLVHeaderLength) {
                    const ssr_data = try self.owner.owned_buffer.extend(buffer_len, StrictSourceRoute.TLVHeaderLength);

                    @memset(ssr_data, 0);

                    ssr_data[0] = @intFromEnum(IPOptionType.StrictSourceRoute);
                    ssr_data[1] = StrictSourceRoute.TLVHeaderLength;
                    ssr_data[2] = 4;
                } else {
                    if (self.owner.owned_buffer.buffer.items[0] != @intFromEnum(IPOptionType.StrictSourceRoute)) {
                        return error.TypeByteInvalid;
                    }
                }

                return self;
            },
            else => {
                return error.UseTUInstead;
            },
        }
    }

    fn get_offset(self: *StrictSourceRoute) usize {
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

    pub fn get_data(self: *StrictSourceRoute) []const u8 {
        const data = self.owner.get_data();

        const offset: usize = self.get_offset();
        const length: usize = @intCast(data[offset + 1]);

        return data[offset .. offset + length];
    }

    fn get_data_mut(self: *StrictSourceRoute) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();
        const length = self.get_data()[absolute_offset + 1];

        if (data.len >= absolute_offset and length <= data.len) {
            return data[absolute_offset .. absolute_offset + length];
        }

        return "";
    }

    /// Returns the length of the Option from its TLV-Header
    pub fn get_length(self: *StrictSourceRoute) u8 {
        return self.get_data()[1];
    }

    pub fn get_ptr(self: *StrictSourceRoute) u8 {
        return self.get_data()[2];
    }

    /// Throws exception when the ptr value exceeds the length of the option or points to TLV header
    pub fn set_ptr(self: *StrictSourceRoute, ptr: u8) !void {
        const ptr_u: usize = @intCast(ptr); // ptr byte val as usize
        if (ptr_u > self.get_data().len) {
            return error.PtrOutOfRange;
        }

        if (ptr_u < 4) {
            return error.PtrPointsToTLVHeader;
        }

        self.get_data()[2] = ptr;
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
        try add_ip_to_buffer(self.get_offset(), &self.owner, ip, IPv4.IPOptionType.StrictSourceRoute);
        //const hdr = get_mutable_hdr();

    }

    pub fn remove_ip(self: *StrictSourceRoute, ip: IPv4.IPv4Address) !void {
        return remove_ip_from_list(self.get_offset(), &self.owner, ip);
    }

    pub fn deinit(self: *StrictSourceRoute) void {
        self.owner.deinit();
    }
};

pub const RouterAlert = struct {
    owner: TLVOwner,
    prev_op: ?*IPv4Option = null,
    next_op: ?*IPv4Option = null,

    pub const TLVHeaderLength = 4;

    pub fn init(owner: TLVOwner) !RouterAlert {
        switch (owner) {
            .owned_buffer => {
                var self = RouterAlert{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < RouterAlert.TLVHeaderLength) {
                    const ra_data = try self.owner.owned_buffer.extend(buffer_len, RouterAlert.TLVHeaderLength);

                    @memset(ra_data, 0);

                    ra_data[0] = @intFromEnum(IPOptionType.RouterAlert);
                    ra_data[1] = RouterAlert.TLVHeaderLength;
                    ra_data[2] = 0;
                    ra_data[3] = 0;
                } else {
                    if (self.owner.owned_buffer.buffer.items[0] != @intFromEnum(IPOptionType.RouterAlert)) {
                        return error.TypeByteInvalid;
                    }
                }

                return self;
            },
            else => {
                return error.UseTUInstead;
            },
        }
    }

    fn get_offset(self: *RouterAlert) usize {
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

    pub fn get_data(self: *RouterAlert) []const u8 {
        const data = self.owner.get_data();

        const offset: usize = self.get_offset();
        const length: usize = @intCast(data[offset + 1]);

        return data[offset .. offset + length];
    }

    fn get_data_mut(self: *RouterAlert) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();
        const length = self.get_data()[absolute_offset + 1];

        if (data.len >= absolute_offset and length <= data.len) {
            return data[absolute_offset .. absolute_offset + length];
        }

        return "";
    }

    /// Returns the length of the Option from its TLV-Header
    pub fn get_length(self: *RouterAlert) u8 {
        return self.get_data()[1];
    }

    pub fn set_ra_val(self: *RouterAlert, val: u16) !void {
        @memmove(self.get_data_mut()[2..4], &std.mem.toBytes(val)); // copy the ip
    }

    pub fn deinit(self: *RouterAlert) void {
        self.owner.deinit();
    }
};

pub const StreamID = struct {
    owner: TLVOwner,
    prev_op: ?*IPv4Option = null,
    next_op: ?*IPv4Option = null,

    pub const TLVHeaderLength = 4;

    pub fn init(owner: TLVOwner) !StreamID {
        switch (owner) {
            .owned_buffer => {
                var self = StreamID{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < StreamID.TLVHeaderLength) {
                    const ra_data = try self.owner.owned_buffer.extend(buffer_len, StreamID.TLVHeaderLength);

                    @memset(ra_data, 0);

                    ra_data[0] = @intFromEnum(IPOptionType.StreamID);
                    ra_data[1] = StreamID.TLVHeaderLength;
                } else {
                    if (self.owner.owned_buffer.buffer.items[0] != @intFromEnum(IPOptionType.StreamID)) {
                        return error.TypeByteInvalid;
                    }
                }

                return self;
            },
            else => {
                return error.UseTUInstead;
            },
        }
    }

    fn get_offset(self: *StreamID) usize {
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

    pub fn get_data(self: *StreamID) []const u8 {
        const data = self.owner.get_data();

        const offset: usize = self.get_offset();
        const length: usize = @intCast(data[offset + 1]);

        return data[offset .. offset + length];
    }

    fn get_data_mut(self: *StreamID) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();
        const length = self.get_data()[absolute_offset + 1];

        if (data.len >= absolute_offset and length <= data.len) {
            return data[absolute_offset .. absolute_offset + length];
        }

        return "";
    }

    /// Returns the length of the Option from its TLV-Header
    pub fn get_length(self: *StreamID) u8 {
        return self.get_data()[1];
    }

    pub fn set_stream_id(self: *StreamID, val: u16) !void {
        @memmove(self.get_data_mut()[2..4], &std.mem.toBytes(val)); // copy the ip
    }

    pub fn deinit(self: *StreamID) void {
        self.owner.deinit();
    }
};

pub const DynamicPacketState = struct {
    owner: TLVOwner,
    prev_op: ?*IPv4Option = null,
    next_op: ?*IPv4Option = null,

    pub const TLVHeaderLength = 4;

    pub fn init(owner: TLVOwner) !DynamicPacketState {
        switch (owner) {
            .owned_buffer => {
                var self = DynamicPacketState{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < DynamicPacketState.TLVHeaderLength) {
                    const ra_data = try self.owner.owned_buffer.extend(buffer_len, DynamicPacketState.TLVHeaderLength);

                    @memset(ra_data, 0);

                    ra_data[0] = @intFromEnum(IPOptionType.DynamicPacketState);
                    ra_data[1] = DynamicPacketState.TLVHeaderLength;
                } else {
                    if (self.owner.owned_buffer.buffer.items[0] != @intFromEnum(IPOptionType.DynamicPacketState)) {
                        return error.TypeByteInvalid;
                    }
                }

                return self;
            },
            else => {
                return error.UseTUInstead;
            },
        }
    }

    fn get_offset(self: *DynamicPacketState) usize {
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

    pub fn get_data(self: *DynamicPacketState) []const u8 {
        const data = self.owner.get_data();

        const offset: usize = self.get_offset();
        const length: usize = @intCast(data[offset + 1]);

        return data[offset .. offset + length];
    }

    fn get_data_mut(self: *DynamicPacketState) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();
        const length = self.get_data()[absolute_offset + 1];

        if (data.len >= absolute_offset and length <= data.len) {
            return data[absolute_offset .. absolute_offset + length];
        }

        return "";
    }

    /// Returns the length of the Option from its TLV-Header
    pub fn get_length(self: *DynamicPacketState) u8 {
        return self.get_data()[1];
    }

    pub fn set_data(self: *DynamicPacketState, val: u16) !void {
        @memmove(self.get_data_mut()[2..4], &std.mem.toBytes(val)); // copy the ip
    }

    pub fn deinit(self: *DynamicPacketState) void {
        self.owner.deinit();
    }
};

pub const UpstreamMulticast = struct {
    owner: TLVOwner,
    prev_op: ?*IPv4Option = null,
    next_op: ?*IPv4Option = null,

    pub const TLVHeaderLength = 4;

    pub fn init(owner: TLVOwner) !UpstreamMulticast {
        switch (owner) {
            .owned_buffer => {
                var self = UpstreamMulticast{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < UpstreamMulticast.TLVHeaderLength) {
                    const ra_data = try self.owner.owned_buffer.extend(buffer_len, UpstreamMulticast.TLVHeaderLength);

                    @memset(ra_data, 0);

                    ra_data[0] = @intFromEnum(IPOptionType.UpstreamMulticast);
                    ra_data[1] = UpstreamMulticast.TLVHeaderLength;
                } else {
                    if (self.owner.owned_buffer.buffer.items[0] != @intFromEnum(IPOptionType.UpstreamMulticast)) {
                        return error.TypeByteInvalid;
                    }
                }

                return self;
            },
            else => {
                return error.UseTUInstead;
            },
        }
    }

    fn get_offset(self: *UpstreamMulticast) usize {
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

    pub fn get_data(self: *UpstreamMulticast) []const u8 {
        const data = self.owner.get_data();

        const offset: usize = self.get_offset();
        const length: usize = @intCast(data[offset + 1]);

        return data[offset .. offset + length];
    }

    fn get_data_mut(self: *UpstreamMulticast) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();
        const length = self.get_data()[absolute_offset + 1];

        if (data.len >= absolute_offset and length <= data.len) {
            return data[absolute_offset .. absolute_offset + length];
        }

        return "";
    }

    /// Returns the length of the Option from its TLV-Header
    pub fn get_length(self: *UpstreamMulticast) u8 {
        return self.get_data()[1];
    }

    pub fn set_data(self: *UpstreamMulticast, val: u16) !void {
        @memmove(self.get_data_mut()[2..4], &std.mem.toBytes(val)); // copy the ip
    }

    pub fn deinit(self: *UpstreamMulticast) void {
        self.owner.deinit();
    }
};

pub const QuickStart = struct {
    owner: TLVOwner,
    prev_op: ?*IPv4Option = null,
    next_op: ?*IPv4Option = null,

    pub const TLVHeaderLength = 8;

    pub fn init(owner: TLVOwner) !QuickStart {
        switch (owner) {
            .owned_buffer => {
                var self = QuickStart{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < QuickStart.TLVHeaderLength) {
                    const ra_data = try self.owner.owned_buffer.extend(buffer_len, QuickStart.TLVHeaderLength);

                    @memset(ra_data, 0);

                    ra_data[0] = @intFromEnum(IPOptionType.QuickStart);
                    ra_data[1] = QuickStart.TLVHeaderLength;
                } else {
                    if (self.owner.owned_buffer.buffer.items[0] != @intFromEnum(IPOptionType.QuickStart)) {
                        return error.TypeByteInvalid;
                    }
                }

                return self;
            },
            else => {
                return error.UseTUInstead;
            },
        }
    }

    fn get_offset(self: *QuickStart) usize {
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

    pub fn get_data(self: *QuickStart) []const u8 {
        const data = self.owner.get_data();

        const offset: usize = self.get_offset();
        const length: usize = @intCast(data[offset + 1]);

        return data[offset .. offset + length];
    }

    fn get_data_mut(self: *QuickStart) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();
        const length = self.get_data()[absolute_offset + 1];

        if (data.len >= absolute_offset and length <= data.len) {
            return data[absolute_offset .. absolute_offset + length];
        }

        return "";
    }

    /// Returns the length of the Option from its TLV-Header
    pub fn get_length(self: *QuickStart) u8 {
        return self.get_data()[1];
    }

    pub fn set_requested_rate(self: *QuickStart, val: u16) !void {
        @memmove(self.get_data_mut()[2..4], &std.mem.toBytes(val)); // copy the ip
    }

    pub fn set_ttl(self: *QuickStart, val: u16) !void {
        @memmove(self.get_data_mut()[4..6], &std.mem.toBytes(val)); // copy the ip
    }

    pub fn deinit(self: *QuickStart) void {
        self.owner.deinit();
    }
};

pub const ExperimentalMeasurement = struct {
    owner: TLVOwner,
    prev_op: ?*IPv4Option = null,
    next_op: ?*IPv4Option = null,

    pub const TLVHeaderLength = 4;

    pub fn init(owner: TLVOwner) !ExperimentalMeasurement {
        switch (owner) {
            .owned_buffer => {
                var self = ExperimentalMeasurement{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < ExperimentalMeasurement.TLVHeaderLength) {
                    const ra_data = try self.owner.owned_buffer.extend(buffer_len, ExperimentalMeasurement.TLVHeaderLength);

                    @memset(ra_data, 0);

                    ra_data[0] = @intFromEnum(IPOptionType.ExperimentalMeasurement);
                    ra_data[1] = ExperimentalMeasurement.TLVHeaderLength;
                    ra_data[2] = 0;
                    ra_data[3] = 0;
                } else {
                    if (self.owner.owned_buffer.buffer.items[0] != @intFromEnum(IPOptionType.ExperimentalMeasurement)) {
                        return error.TypeByteInvalid;
                    }
                }

                return self;
            },
            else => {
                return error.UseTUInstead;
            },
        }
    }

    fn get_offset(self: *ExperimentalMeasurement) usize {
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

    pub fn get_data(self: *ExperimentalMeasurement) []const u8 {
        const data = self.owner.get_data();

        const offset: usize = self.get_offset();
        const length: usize = @intCast(data[offset + 1]);

        return data[offset .. offset + length];
    }

    fn get_data_mut(self: *ExperimentalMeasurement) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();
        const length = self.get_data()[absolute_offset + 1];

        if (data.len >= absolute_offset and length <= data.len) {
            return data[absolute_offset .. absolute_offset + length];
        }

        return "";
    }

    /// Returns the length of the Option from its TLV-Header
    pub fn get_length(self: *ExperimentalMeasurement) u8 {
        return self.get_data()[1];
    }

    pub fn set_measurement(self: *ExperimentalMeasurement, val: u16) !void {
        @memmove(self.get_data_mut()[2..4], &std.mem.toBytes(val)); // copy the ip
    }

    pub fn deinit(self: *ExperimentalMeasurement) void {
        self.owner.deinit();
    }
};

pub const ExperimentalFlowControl = struct {
    owner: TLVOwner,
    prev_op: ?*IPv4Option = null,
    next_op: ?*IPv4Option = null,

    pub const TLVHeaderLength = 4;

    pub fn init(owner: TLVOwner) !ExperimentalFlowControl {
        switch (owner) {
            .owned_buffer => {
                var self = ExperimentalFlowControl{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < ExperimentalFlowControl.TLVHeaderLength) {
                    const ra_data = try self.owner.owned_buffer.extend(buffer_len, ExperimentalFlowControl.TLVHeaderLength);

                    @memset(ra_data, 0);

                    ra_data[0] = @intFromEnum(IPOptionType.ExperimentalFlowControl);
                    ra_data[1] = ExperimentalFlowControl.TLVHeaderLength;
                    ra_data[2] = 0;
                    ra_data[3] = 0;
                } else {
                    if (self.owner.owned_buffer.buffer.items[0] != @intFromEnum(IPOptionType.ExperimentalFlowControl)) {
                        return error.TypeByteInvalid;
                    }
                }

                return self;
            },
            else => {
                return error.UseTUInstead;
            },
        }
    }

    fn get_offset(self: *ExperimentalFlowControl) usize {
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

    pub fn get_data(self: *ExperimentalFlowControl) []const u8 {
        const data = self.owner.get_data();

        const offset: usize = self.get_offset();
        const length: usize = @intCast(data[offset + 1]);

        return data[offset .. offset + length];
    }

    fn get_data_mut(self: *ExperimentalFlowControl) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();
        const length = self.get_data()[absolute_offset + 1];

        if (data.len >= absolute_offset and length <= data.len) {
            return data[absolute_offset .. absolute_offset + length];
        }

        return "";
    }

    /// Returns the length of the Option from its TLV-Header
    pub fn get_length(self: *ExperimentalFlowControl) u8 {
        return self.get_data()[1];
    }

    pub fn set_data(self: *ExperimentalFlowControl, val: u16) !void {
        @memmove(self.get_data_mut()[2..4], &std.mem.toBytes(val)); // copy the ip
    }

    pub fn deinit(self: *ExperimentalFlowControl) void {
        self.owner.deinit();
    }
};

pub const ExperimentalAccessControl = struct {
    owner: TLVOwner,
    prev_op: ?*IPv4Option = null,
    next_op: ?*IPv4Option = null,

    pub const TLVHeaderLength = 6;

    pub fn init(owner: TLVOwner) !ExperimentalAccessControl {
        switch (owner) {
            .owned_buffer => {
                var self = ExperimentalAccessControl{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < ExperimentalAccessControl.TLVHeaderLength) {
                    const ra_data = try self.owner.owned_buffer.extend(buffer_len, ExperimentalAccessControl.TLVHeaderLength);

                    @memset(ra_data, 0);

                    ra_data[0] = @intFromEnum(IPOptionType.ExperimentalAccessControl);
                    ra_data[1] = ExperimentalAccessControl.TLVHeaderLength;
                    ra_data[2] = 0;
                    ra_data[3] = 0;
                } else {
                    if (self.owner.owned_buffer.buffer.items[0] != @intFromEnum(IPOptionType.ExperimentalAccessControl)) {
                        return error.TypeByteInvalid;
                    }
                }

                return self;
            },
            else => {
                return error.UseTUInstead;
            },
        }
    }

    fn get_offset(self: *ExperimentalAccessControl) usize {
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

    pub fn get_data(self: *ExperimentalAccessControl) []const u8 {
        const data = self.owner.get_data();

        const offset: usize = self.get_offset();
        const length: usize = @intCast(data[offset + 1]);

        return data[offset .. offset + length];
    }

    fn get_data_mut(self: *ExperimentalAccessControl) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();
        const length = self.get_data()[absolute_offset + 1];

        if (data.len >= absolute_offset and length <= data.len) {
            return data[absolute_offset .. absolute_offset + length];
        }

        return "";
    }

    /// Returns the length of the Option from its TLV-Header
    pub fn get_length(self: *ExperimentalAccessControl) u8 {
        return self.get_data()[1];
    }

    pub fn set_data(self: *ExperimentalAccessControl, val: u32) !void {
        @memmove(self.get_data_mut()[2..6], &std.mem.toBytes(val)); // copy the ip
    }

    pub fn deinit(self: *ExperimentalAccessControl) void {
        self.owner.deinit();
    }
};

pub const ExtendedInternet = struct {
    owner: TLVOwner,
    prev_op: ?*IPv4Option = null,
    next_op: ?*IPv4Option = null,

    pub const TLVHeaderLength = 4;

    pub fn init(owner: TLVOwner) !ExtendedInternet {
        switch (owner) {
            .owned_buffer => {
                var self = ExtendedInternet{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < ExtendedInternet.TLVHeaderLength) {
                    const ra_data = try self.owner.owned_buffer.extend(buffer_len, ExtendedInternet.TLVHeaderLength);

                    @memset(ra_data, 0);

                    ra_data[0] = @intFromEnum(IPOptionType.ExtendedInternet);
                    ra_data[1] = ExtendedInternet.TLVHeaderLength;
                    ra_data[2] = 0;
                    ra_data[3] = 0;
                } else {
                    if (self.owner.owned_buffer.buffer.items[0] != @intFromEnum(IPOptionType.ExtendedInternet)) {
                        return error.TypeByteInvalid;
                    }
                }

                return self;
            },
            else => {
                return error.UseTUInstead;
            },
        }
    }

    fn get_offset(self: *ExtendedInternet) usize {
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

    pub fn get_data(self: *ExtendedInternet) []const u8 {
        const data = self.owner.get_data();

        const offset: usize = self.get_offset();
        const length: usize = @intCast(data[offset + 1]);

        return data[offset .. offset + length];
    }

    fn get_data_mut(self: *ExtendedInternet) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();
        const length = self.get_data()[absolute_offset + 1];

        if (data.len >= absolute_offset and length <= data.len) {
            return data[absolute_offset .. absolute_offset + length];
        }

        return "";
    }

    /// Returns the length of the Option from its TLV-Header
    pub fn get_length(self: *ExtendedInternet) u8 {
        return self.get_data()[1];
    }

    pub fn set_data(self: *ExtendedInternet, val: u16) !void {
        @memmove(self.get_data_mut()[2..4], &std.mem.toBytes(val)); // copy the ip
    }

    pub fn deinit(self: *ExtendedInternet) void {
        self.owner.deinit();
    }
};

pub const SelectiveDirectedBroadcast = struct {
    owner: TLVOwner,
    prev_op: ?*IPv4Option = null,
    next_op: ?*IPv4Option = null,

    pub const TLVHeaderLength = 10;

    pub fn init(owner: TLVOwner) !SelectiveDirectedBroadcast {
        switch (owner) {
            .owned_buffer => {
                var self = SelectiveDirectedBroadcast{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < SelectiveDirectedBroadcast.TLVHeaderLength) {
                    const ra_data = try self.owner.owned_buffer.extend(buffer_len, SelectiveDirectedBroadcast.TLVHeaderLength);

                    @memset(ra_data, 0);

                    ra_data[0] = @intFromEnum(IPOptionType.SelectiveDirectedBroadcast);
                    ra_data[1] = SelectiveDirectedBroadcast.TLVHeaderLength;
                } else {
                    if (self.owner.owned_buffer.buffer.items[0] != @intFromEnum(IPOptionType.SelectiveDirectedBroadcast)) {
                        return error.TypeByteInvalid;
                    }
                }

                return self;
            },
            else => {
                return error.UseTUInstead;
            },
        }
    }

    fn get_offset(self: *SelectiveDirectedBroadcast) usize {
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

    pub fn get_data(self: *SelectiveDirectedBroadcast) []const u8 {
        const data = self.owner.get_data();

        const offset: usize = self.get_offset();
        const length: usize = @intCast(data[offset + 1]);

        return data[offset .. offset + length];
    }

    fn get_data_mut(self: *SelectiveDirectedBroadcast) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();
        const length = self.get_data()[absolute_offset + 1];

        if (data.len >= absolute_offset and length <= data.len) {
            return data[absolute_offset .. absolute_offset + length];
        }

        return "";
    }

    /// Returns the length of the Option from its TLV-Header
    pub fn get_length(self: *SelectiveDirectedBroadcast) u8 {
        return self.get_data()[1];
    }

    pub fn set_ip_mask(self: *SelectiveDirectedBroadcast, ip: IPv4.IPv4Address) !void {
        @memmove(self.get_data_mut()[2..6], &ip.array); // copy the ip
    }

    pub fn set_ip(self: *SelectiveDirectedBroadcast, ip: IPv4.IPv4Address) !void {
        @memmove(self.get_data_mut()[6..10], &ip.array); // copy the ip
    }

    pub fn deinit(self: *SelectiveDirectedBroadcast) void {
        self.owner.deinit();
    }
};

pub const MTUProbe = struct {
    owner: TLVOwner,
    prev_op: ?*IPv4Option = null,
    next_op: ?*IPv4Option = null,

    pub const TLVHeaderLength = 4;

    pub fn init(owner: TLVOwner) !MTUProbe {
        switch (owner) {
            .owned_buffer => {
                var self = MTUProbe{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < MTUProbe.TLVHeaderLength) {
                    const ra_data = try self.owner.owned_buffer.extend(buffer_len, MTUProbe.TLVHeaderLength);

                    @memset(ra_data, 0);

                    ra_data[0] = @intFromEnum(IPOptionType.MTUProbe);
                    ra_data[1] = MTUProbe.TLVHeaderLength;
                    ra_data[2] = 0;
                    ra_data[3] = 0;
                } else {
                    if (self.owner.owned_buffer.buffer.items[0] != @intFromEnum(IPOptionType.MTUProbe)) {
                        return error.TypeByteInvalid;
                    }
                }

                return self;
            },
            else => {
                return error.UseTUInstead;
            },
        }
    }

    fn get_offset(self: *MTUProbe) usize {
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

    pub fn get_data(self: *MTUProbe) []const u8 {
        const data = self.owner.get_data();

        const offset: usize = self.get_offset();
        const length: usize = @intCast(data[offset + 1]);

        return data[offset .. offset + length];
    }

    fn get_data_mut(self: *MTUProbe) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();
        const length = self.get_data()[absolute_offset + 1];

        if (data.len >= absolute_offset and length <= data.len) {
            return data[absolute_offset .. absolute_offset + length];
        }

        return "";
    }

    /// Returns the length of the Option from its TLV-Header
    pub fn get_length(self: *MTUProbe) u8 {
        return self.get_data()[1];
    }

    pub fn set_mtu_val(self: *MTUProbe, val: u16) !void {
        @memmove(self.get_data_mut()[2..4], &std.mem.toBytes(val)); // copy the ip
    }

    pub fn deinit(self: *MTUProbe) void {
        self.owner.deinit();
    }
};

pub const MTUReply = struct {
    owner: TLVOwner,
    prev_op: ?*IPv4Option = null,
    next_op: ?*IPv4Option = null,

    pub const TLVHeaderLength = 4;

    pub fn init(owner: TLVOwner) !MTUReply {
        switch (owner) {
            .owned_buffer => {
                var self = MTUReply{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < MTUReply.TLVHeaderLength) {
                    const ra_data = try self.owner.owned_buffer.extend(buffer_len, MTUReply.TLVHeaderLength);

                    @memset(ra_data, 0);

                    ra_data[0] = @intFromEnum(IPOptionType.MTUReply);
                    ra_data[1] = MTUReply.TLVHeaderLength;
                    ra_data[2] = 0;
                    ra_data[3] = 0;
                } else {
                    if (self.owner.owned_buffer.buffer.items[0] != @intFromEnum(IPOptionType.MTUReply)) {
                        return error.TypeByteInvalid;
                    }
                }

                return self;
            },
            else => {
                return error.UseTUInstead;
            },
        }
    }

    fn get_offset(self: *MTUReply) usize {
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

    pub fn get_data(self: *MTUReply) []const u8 {
        const data = self.owner.get_data();

        const offset: usize = self.get_offset();
        const length: usize = @intCast(data[offset + 1]);

        return data[offset .. offset + length];
    }

    fn get_data_mut(self: *MTUReply) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();
        const length = self.get_data()[absolute_offset + 1];

        if (data.len >= absolute_offset and length <= data.len) {
            return data[absolute_offset .. absolute_offset + length];
        }

        return "";
    }

    /// Returns the length of the Option from its TLV-Header
    pub fn get_length(self: *MTUReply) u8 {
        return self.get_data()[1];
    }

    pub fn set_mtu_val(self: *MTUReply, val: u16) !void {
        @memmove(self.get_data_mut()[2..4], &std.mem.toBytes(val)); // copy the ip
    }

    pub fn deinit(self: *MTUReply) void {
        self.owner.deinit();
    }
};

pub const Security = struct {
    owner: TLVOwner,
    prev_op: ?*IPv4Option = null,
    next_op: ?*IPv4Option = null,

    pub const TLVHeaderLength = 11;

    pub fn init(owner: TLVOwner) !Security {
        switch (owner) {
            .owned_buffer => {
                var self = Security{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < Security.TLVHeaderLength) {
                    const ra_data = try self.owner.owned_buffer.extend(buffer_len, Security.TLVHeaderLength);

                    @memset(ra_data, 0);

                    ra_data[0] = @intFromEnum(IPOptionType.Security);
                    ra_data[1] = Security.TLVHeaderLength;
                } else {
                    if (self.owner.owned_buffer.buffer.items[0] != @intFromEnum(IPOptionType.Security)) {
                        return error.TypeByteInvalid;
                    }

                    if (self.owner.owned_buffer.buffer.items[1] > self.owner.owned_buffer.buffer.items.len) {
                        return error.LengthByteInvalid;
                    }
                }

                return self;
            },
            else => {
                return error.UseTUInstead;
            },
        }
    }

    fn get_offset(self: *Security) usize {
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

    pub fn get_data(self: *Security) []const u8 {
        const data = self.owner.get_data();

        const offset: usize = self.get_offset();
        const length: usize = @intCast(data[offset + 1]);

        return data[offset .. offset + length];
    }

    fn get_data_mut(self: *Security) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();
        const length = self.get_data()[absolute_offset + 1];

        if (data.len >= absolute_offset and length <= data.len) {
            return data[absolute_offset .. absolute_offset + length];
        }

        return "";
    }

    /// Returns the length of the Option from its TLV-Header
    pub fn get_length(self: *Security) u8 {
        return self.get_data()[1];
    }

    pub fn set_data(self: *Security, data: []const u8) !void {
        @memmove(self.get_data_mut()[2..], data); // copy the ip
    }

    pub fn deinit(self: *Security) void {
        self.owner.deinit();
    }
};

pub const ExtendedSecurity = struct {
    owner: TLVOwner,
    prev_op: ?*IPv4Option = null,
    next_op: ?*IPv4Option = null,

    pub const TLVHeaderLength = 6;

    pub fn init(owner: TLVOwner) !ExtendedSecurity {
        switch (owner) {
            .owned_buffer => {
                var self = ExtendedSecurity{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < ExtendedSecurity.TLVHeaderLength) {
                    const ra_data = try self.owner.owned_buffer.extend(buffer_len, ExtendedSecurity.TLVHeaderLength);

                    @memset(ra_data, 0);

                    ra_data[0] = @intFromEnum(IPOptionType.ExtendedSecurity);
                    ra_data[1] = ExtendedSecurity.TLVHeaderLength;
                } else {
                    if (self.owner.owned_buffer.buffer.items[0] != @intFromEnum(IPOptionType.ExtendedSecurity)) {
                        return error.TypeByteInvalid;
                    }

                    if (self.owner.owned_buffer.buffer.items[1] > self.owner.owned_buffer.buffer.items.len) {
                        return error.LengthByteInvalid;
                    }
                }

                return self;
            },
            else => {
                return error.UseTUInstead;
            },
        }
    }

    fn get_offset(self: *ExtendedSecurity) usize {
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

    pub fn get_data(self: *ExtendedSecurity) []const u8 {
        const data = self.owner.get_data();

        const offset: usize = self.get_offset();
        const length: usize = @intCast(data[offset + 1]);

        return data[offset .. offset + length];
    }

    fn get_data_mut(self: *ExtendedSecurity) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();
        const length = self.get_data()[absolute_offset + 1];

        if (data.len >= absolute_offset and length <= data.len) {
            return data[absolute_offset .. absolute_offset + length];
        }

        return "";
    }

    /// Returns the length of the Option from its TLV-Header
    pub fn get_length(self: *ExtendedSecurity) u8 {
        return self.get_data()[1];
    }

    pub fn set_data(self: *ExtendedSecurity, data: []const u8) !void {
        @memmove(self.get_data_mut()[2..], data); // copy the ip
    }

    pub fn deinit(self: *ExtendedSecurity) void {
        self.owner.deinit();
    }
};

pub const CommercialSecurity = struct {
    owner: TLVOwner,
    prev_op: ?*IPv4Option = null,
    next_op: ?*IPv4Option = null,

    pub const TLVHeaderLength = 6;

    pub fn init(owner: TLVOwner) !CommercialSecurity {
        switch (owner) {
            .owned_buffer => {
                var self = CommercialSecurity{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < CommercialSecurity.TLVHeaderLength) {
                    const ra_data = try self.owner.owned_buffer.extend(buffer_len, CommercialSecurity.TLVHeaderLength);

                    @memset(ra_data, 0);

                    ra_data[0] = @intFromEnum(IPOptionType.CommercialSecurity);
                    ra_data[1] = CommercialSecurity.TLVHeaderLength;
                } else {
                    if (self.owner.owned_buffer.buffer.items[0] != @intFromEnum(IPOptionType.CommercialSecurity)) {
                        return error.TypeByteInvalid;
                    }

                    if (self.owner.owned_buffer.buffer.items[1] > self.owner.owned_buffer.buffer.items.len) {
                        return error.LengthByteInvalid;
                    }
                }

                return self;
            },
            else => {
                return error.UseTUInstead;
            },
        }
    }

    fn get_offset(self: *CommercialSecurity) usize {
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

    pub fn get_data(self: *CommercialSecurity) []const u8 {
        const data = self.owner.get_data();

        const offset: usize = self.get_offset();
        const length: usize = @intCast(data[offset + 1]);

        return data[offset .. offset + length];
    }

    fn get_data_mut(self: *CommercialSecurity) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();
        const length = self.get_data()[absolute_offset + 1];

        if (data.len >= absolute_offset and length <= data.len) {
            return data[absolute_offset .. absolute_offset + length];
        }

        return "";
    }

    /// Returns the length of the Option from its TLV-Header
    pub fn get_length(self: *CommercialSecurity) u8 {
        return self.get_data()[1];
    }

    pub fn set_data(self: *CommercialSecurity, data: []const u8) !void {
        @memmove(self.get_data_mut()[2..], data); // copy the ip
    }

    pub fn deinit(self: *CommercialSecurity) void {
        self.owner.deinit();
    }
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
    prev_op: ?*IPv4Option = null,
    next_op: ?*IPv4Option = null,

    pub const Mode = enum(u4) {
        /// Timestamps only. No Addresses
        TIMESTAMP_ONLY = 0,
        /// Timestamps and Addresses are append by each host
        APPEND_ADDRESSES = 1,
        /// Timestamps and Addresses are appended by specified hosts only
        SPECIFIC_ADDRESSES = 3,
    };

    pub const TLVHeaderLength = 4;

    /// extends buffer of TLVOwner if it is not atleast 4 bytes and sets type to Timestamp (44), length to 4, mode to TIMESTAMP_ONLY, ptr to 5
    pub fn init(owner: TLVOwner) !Timestamp {
        switch (owner) {
            .owned_buffer => {
                var self = Timestamp{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < Timestamp.TLVHeaderLength) {
                    const ts_data = try self.owner.owned_buffer.extend(buffer_len, Timestamp.TLVHeaderLength);

                    @memset(ts_data, 0);

                    ts_data[0] = @intFromEnum(IPOptionType.Timestamp);
                    ts_data[1] = Timestamp.TLVHeaderLength;
                    ts_data[2] = 5;
                    ts_data[3] = 0;
                } else {
                    if (self.owner.owned_buffer.buffer.items[0] != @intFromEnum(IPOptionType.Timestamp)) {
                        return error.TypeByteInvalid;
                    }
                }

                try self.set_mode_flag(.TIMESTAMP_ONLY);

                return self;
            },
            else => {
                return error.UseTUInstead;
            },
        }
    }

    fn get_offset(self: *Timestamp) usize {
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

        const offset: usize = self.get_offset();

        const length: usize = @intCast(data[offset + 1]);

        return data[offset .. offset + length];
    }

    fn get_data_mut(self: *Timestamp) []u8 {
        const data = self.owner.get_data();

        const absolute_offset: usize = self.get_offset();

        const length = self.get_data()[absolute_offset + 1];

        if (data.len >= absolute_offset and length <= data.len) {
            return data[absolute_offset .. absolute_offset + length];
        }

        panic("Timetamp option is invalid.\n", .{});
    }

    /// Returns the length of the Option from its TLV-Header
    pub fn get_length(self: *Timestamp) u8 {
        return self.get_data()[1];
    }

    pub fn get_ptr(self: *Timestamp) u8 {
        return self.get_data()[2];
    }

    /// Throws exception when the ptr value exceeds the length of the option or points to TLV header
    pub fn set_ptr(self: *Timestamp, ptr: u8) !void {
        const ptr_u: usize = @intCast(ptr); // ptr byte val as usize
        if (ptr_u > self.get_data().len) {
            return error.PtrOutOfRange;
        }

        if (ptr_u < 5) {
            return error.PtrPointsToTLVHeader;
        }

        self.get_data()[2] = ptr;
    }

    pub fn set_mode_flag(self: *Timestamp, flag: Timestamp.Mode) !void {
        self.get_data_mut()[3] =
            (self.get_data_mut()[3] & 0b1111_0000) |
            (@as(u8, @intFromEnum(flag)) & 0b0000_1111);
    }

    pub fn get_mode_flag(self: *Timestamp) Timestamp.Mode {
        return @enumFromInt(self.get_data()[3] & 0b0000_1111);
    }

    pub fn get_overflow(self: *Timestamp) u4 {
        return @intCast((self.get_data()[3] & 0b1111_0000) >> 4);
    }

    pub fn set_overflow(self: *Timestamp, of: u4) !void {
        self.get_data_mut()[3] =
            (self.get_data_mut()[3] & 0b0000_1111) |
            (@as(u8, of) << 4);
    }

    fn add_timestamp(self: *Timestamp, timestamp: u32) !void {
        try add_timestamp_to_buffer(self.get_offset(), &self.owner, timestamp, IPv4.IPOptionType.Timestamp);
    }

    fn add_ip(self: *Timestamp, ip: IPv4.IPv4Address) !void {
        return add_ip_to_buffer(self.get_offset(), &self.owner, ip, IPv4.IPOptionType.Timestamp);
    }

    fn remove_ip(self: *Timestamp, ip: IPv4.IPv4Address) !void {
        return remove_ip_from_list(&self.owner, ip);
    }

    pub fn add_ts_record(self: *Timestamp, record: TimestampRecord) !void {
        if (self.get_mode_flag() == .TIMESTAMP_ONLY) {
            if (record.ip != null) {
                return error.InvalidTimestampOnlyRecord; // TS Only does not contain IP addresses
            }
            try self.add_timestamp(record.timestamp);
            try set_hdr_vals(&self.owner, @sizeOf(u32));
            //self.get_data_mut()[1] += @sizeOf(u32);
            return;
        }

        if (record.ip == null) {
            return error.IPRequiredForNonTSOnlyRecord; // caller must provide an IP, even if 0.0.0.0 for place holder
        }

        try self.add_ip(record.ip.?);
        try self.add_timestamp(record.timestamp);
        //try set_hdr_vals(&self.owner, (@sizeOf(u32) + @sizeOf(IPv4.IPv4Address)));
        //self.get_data_mut()[1] += (@sizeOf(u32) + @sizeOf(IPv4.IPv4Address));
    }

    pub fn remove_ts_record(self: *Timestamp, record: TimestampRecord) !void {
        const data = self.get_data()[4..];
        if (record.ip == null) {
            const bytes: [4]u8 = std.mem.toBytes(@byteSwap(record.timestamp));
            if (std.mem.indexOf(u8, data, &bytes)) |offset| {
                try self.owner.shorten_buffer(offset, @sizeOf(u32));
                //self.get_data_mut()[1] -= @sizeOf(u32);

                const absolute_offset = self.get_offset();
                self.owner.get_data()[absolute_offset + 1] -= @sizeOf(u32);
                try set_hdr_vals(&self.owner, -@sizeOf(u32));
                return;
            }
        }

        const ip_bytes: [4]u8 = record.ip.?.array;
        const ts_bytes: [4]u8 = std.mem.toBytes(@byteSwap(record.timestamp));
        var full_rec: [8]u8 = .{0x00} ** 8;

        @memmove(full_rec[0..4], &ip_bytes);
        @memmove(full_rec[4..8], &ts_bytes);

        if (std.mem.indexOf(u8, data, &full_rec)) |offset| {
            try self.owner.shorten_buffer(self.get_offset() + 4 + offset, (@sizeOf(u32) + @sizeOf(IPv4.IPv4Address)));
            const absolute_offset = self.get_offset();
            self.owner.get_data()[absolute_offset + 1] -= (@sizeOf(u32) + @sizeOf(IPv4.IPv4Address));

            //self.get_data_mut()[1] -= (@sizeOf(u32) + @sizeOf(IPv4.IPv4Address));

            try set_hdr_vals(&self.owner, -(@sizeOf(u32) + @sizeOf(IPv4.IPv4Address)));
            return;
        }
    }

    pub fn get_records(self: *Timestamp, allocator: Allocator) !?TimestampRecords {
        const data = self.get_data();
        if (data.len < 8) {
            return null;
        }

        var cur: ?*TimestampRecord = null;

        var records: TimestampRecords = .{};

        var offset: usize = 4; // 1byte type, 1byte length, 1byte flag/of, 1byte ptr

        const offset_inc: usize = if (self.get_mode_flag() == .TIMESTAMP_ONLY) @sizeOf(u32) else (@sizeOf(u32) + @sizeOf(IPv4.IPv4Address));

        while (offset + offset_inc <= data.len) {
            const record = try allocator.create(TimestampRecord);

            if (self.get_mode_flag() == .TIMESTAMP_ONLY) {
                const timestamp: u32 = std.mem.bytesToValue(u32, self.get_data()[offset .. offset + offset_inc]);

                record.* = .{ .timestamp = @byteSwap(timestamp) };
            } else {
                var ip: IPv4.IPv4Address = .init_from_u32(0x00000000);
                const timestamp: u32 = std.mem.bytesToValue(u32, self.get_data()[offset + @sizeOf(IPv4.IPv4Address) .. offset + offset_inc]);

                @memmove(&ip.array, self.get_data()[offset .. offset + @sizeOf(IPv4.IPv4Address)]);

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

    pub fn deinit(self: *Timestamp) void {
        self.owner.deinit();
    }
};

pub const GenericOption = struct {
    owner: TLVOwner,
    length: usize,
    prev_op: ?*IPv4Option = null,
    next_op: ?*IPv4Option = null,

    pub const TLVHeaderLength = 2;

    pub fn init(owner: TLVOwner, opt_type: IPOptionType) !GenericOption {
        switch (opt_type) {
            .RecordRoute, .StrictSourceRoute, .LooseSourceRoute, .Timestamp, .RouterAlert => {
                return error.UseCorrectType;
            },
            else => {},
        }

        switch (owner) {
            .owned_buffer => {
                var self = GenericOption{ .owner = owner, .length = GenericOption.TLVHeaderLength };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < GenericOption.TLVHeaderLength) {
                    const go_data = try self.owner.owned_buffer.extend(buffer_len, GenericOption.TLVHeaderLength);

                    @memset(go_data, 0);

                    go_data[0] = @intFromEnum(opt_type);
                    go_data[1] = GenericOption.TLVHeaderLength;
                }

                return self;
            },
            else => {
                return error.UseTUInstead;
            },
        }
    }

    fn get_offset(self: *GenericOption) usize {
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

    pub fn get_data(self: *GenericOption) []const u8 {
        return self.get_data_mut();
    }

    fn get_data_mut(self: *GenericOption) []u8 {
        const data = self.owner.get_data();

        const offset: usize = self.get_offset();
        const length: usize = @intCast(data[offset + 1]);

        return data[offset .. offset + length];
    }

    pub fn set_data(self: *GenericOption, data: []const u8) !void {
        const buf = try self.owner.extend_buffer(self.get_data().len, data.len);

        @memmove(buf, data); // copy the ip
    }

    pub fn set_type(self: *GenericOption, opt_type: IPOptionType) !void {
        switch (opt_type) {
            .RecordRoute, .StrictSourceRoute, .LooseSourceRoute, .Timestamp, .RouterAlert => {
                return error.UseCorrectType;
            },
        }
        self.get_data_mut()[0] = @intFromEnum(opt_type);
    }

    /// Returns the length of the Option from its TLV-Header
    pub fn get_length(self: *GenericOption) u8 {
        return self.get_data()[1];
    }

    pub fn deinit(self: *GenericOption) void {
        self.owner.deinit();
    }
};
