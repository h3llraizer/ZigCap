const std = @import("std");

const ProtocolEnums = @import("ProtocolEnums.zig");
const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;
const LayerError = ProtocolEnums.LayerError;
const Layer = @import("LayerIface.zig").Layer;
const init_layer = @import("LayerIface.zig").init_layer;
const initLayerFromSlice = @import("LayerIface.zig").initFromSlice;
const LayerOwner = @import("Owner.zig").LayerOwner;
const Packet = @import("Packet.zig");
const ApplicationLayer = @import("GenericLayer.zig").ApplicationLayer;
const TCPOptions = @import("TCP_Options.zig");
const IPv4 = @import("IPv4.zig");
const PacketLayer = @import("PacketLayer.zig").Layer;

const print = std.debug.print;
const panic = std.debug.print;
const Allocator = std.mem.Allocator;
pub const TCPOption = TCPOptions.TCPOption;

pub const TCPHeaderMinSize = 20;
pub const TCPHeaderMaxSize = 40;
const HeaderAlignment = 4;

//   const default_hdr = TCPHeader{
//       .src_port = .{ 0x00, 0x00 },
//       .dst_port = .{ 0x00, 0x00 },
//       .seq_num = [_]u8{0} ** 4,
//       .ack_num = [_]u8{0} ** 4,
//       .data_offset_reserved_flags = [_]u8{0} ** 2,
//       .window = .{ 0x00, 0x00 },
//       .checksum = .{ 0x00, 0x00 },
//       .urgent_ptr = .{ 0x00, 0x00 },
//   };

const default_hdr = TCPHeader.init_default();

const TCPFlags = packed struct {
    fin: u1,
    syn: u1,
    rst: u1,
    psh: u1,
    ack: u1,
    urg: u1,
    ece: u1,
    cwr: u1,
};

/// Standard TCPHeader (20 bytes)
/// seq and ack num are specified as 4 byte u8 arrays for alignment purposes
pub const TCPHeader = extern struct {
    src_port: [2]u8,
    dst_port: [2]u8,
    seq_num: [4]u8,
    ack_num: [4]u8,
    data_offset_reserved_flags: [2]u8, // high bit is offset + reserved. low bit is TCPFlags
    window: [2]u8,
    checksum: [2]u8,
    urgent_ptr: [2]u8,

    pub fn init_default() TCPHeader {
        var tcp_hdr = TCPHeader{
            .src_port = .{ 0x00, 0x00 },
            .dst_port = .{ 0x00, 0x00 },
            .seq_num = [_]u8{0} ** 4,
            .ack_num = [_]u8{0} ** 4,
            .data_offset_reserved_flags = [_]u8{0} ** 2,
            .window = .{ 0x00, 0x00 },
            .checksum = .{ 0x00, 0x00 },
            .urgent_ptr = .{ 0x00, 0x00 },
        };

        tcp_hdr.set_hdr_length(20);

        return tcp_hdr;
    }

    /// Get Source Port of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn get_src_port(self: *const TCPHeader) u16 {
        return std.mem.readInt(u16, &self.src_port, .big);
    }

    /// Get Destination Port of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn get_dst_port(self: *const TCPHeader) u16 {
        return std.mem.readInt(u16, &self.dst_port, .big);
    }

    /// Get Source Port of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn set_src_port(self: *TCPHeader, port: u16) void {
        std.mem.writeInt(u16, &self.src_port, port, .big);
    }

    /// Get Destination Port of the TCPHeader - converts u16 value from Big to Native and returns
    pub fn set_dst_port(self: *TCPHeader, port: u16) void {
        std.mem.writeInt(u16, &self.dst_port, port, .big);
    }

    /// returns sequence number in little endian
    pub fn get_seq_num(self: *const TCPHeader) u32 {
        const sq = self.seq_num;
        const seq_num = std.mem.readInt(u32, &sq, .little);

        return seq_num;
    }

    /// writes sequence number in big endian
    pub fn set_seq_num(self: *TCPHeader, seq_num: u32) void {
        std.mem.writeInt(u32, &self.seq_num, seq_num, .big);
    }

    /// return acknowledgement number in little endian
    pub fn get_ack_num(self: *const TCPHeader) u32 {
        const ack = self.ack_num;
        const ack_num = std.mem.readInt(u32, &ack, .little);

        return ack_num;
    }

    /// writes acknowledgement number in big endian
    pub fn set_ack_num(self: *TCPHeader, ack_num: u32) void {
        std.mem.writeInt(u32, &self.ack_num, ack_num, .big);
    }

    pub fn get_window(self: *const TCPHeader) u16 {
        return std.mem.readInt(u16, &self.window, .big);
    }

    pub fn set_window(self: *TCPHeader, window: u16) void {
        std.mem.writeInt(u16, &self.window, window, .big);
    }

    pub fn get_checksum(self: *const TCPHeader) u16 {
        return std.mem.readInt(u16, &self.checksum, .big);
    }

    /// Calculate TCP checksum (requires pseudo-header and payload)
    /// For IPv4, the pseudo-header includes: source IP, dest IP, protocol, TCP length
    pub fn calculate_checksum(self: *TCPHeader, src_ip: [4]u8, dst_ip: [4]u8, payload: []const u8) void {
        self.checksum = .{ 0, 0 };
        var sum: u32 = 0;

        const src_w1 = (@as(u16, src_ip[0]) << 8) | src_ip[1];
        const src_w2 = (@as(u16, src_ip[2]) << 8) | src_ip[3];
        sum += src_w1;
        sum += src_w2;

        const dst_w1 = (@as(u16, dst_ip[0]) << 8) | dst_ip[1];
        const dst_w2 = (@as(u16, dst_ip[2]) << 8) | dst_ip[3];
        sum += dst_w1;
        sum += dst_w2;

        sum += @as(u16, 0x0006); // TCP protocol number

        const total_length = @as(u16, self.get_hdr_length() + @as(u16, @intCast(payload.len)));

        sum += total_length;

        const h_src = self.get_src_port();
        const h_dst = self.get_dst_port();
        const h_off = (@as(u16, self.data_offset_reserved_flags[0]) << 8) | self.data_offset_reserved_flags[1];
        const h_win = self.get_window();
        const h_urg = self.get_urgent_ptr();

        sum += h_src;
        sum += h_dst;
        const h_seq_bytes = self.seq_num;
        sum += (@as(u16, h_seq_bytes[0]) << 8) | h_seq_bytes[1];
        sum += (@as(u16, h_seq_bytes[2]) << 8) | h_seq_bytes[3];
        const h_ack_bytes = self.ack_num;
        sum += (@as(u16, h_ack_bytes[0]) << 8) | h_ack_bytes[1];
        sum += (@as(u16, h_ack_bytes[2]) << 8) | h_ack_bytes[3];
        sum += h_off;
        sum += h_win;
        sum += h_urg;

        const hdr_len = self.get_hdr_length();
        if (hdr_len > 20) {
            // Get options bytes starting after the 20-byte fixed header
            const opt_bytes = @as([*]u8, @ptrCast(self))[20..hdr_len];
            var i: usize = 0;
            while (i + 1 < opt_bytes.len) {
                const word = (@as(u16, opt_bytes[i]) << 8) | opt_bytes[i + 1];
                sum += word;
                i += 2;
            }
            // Handle odd byte (should not happen with TCP options)
            if (i < opt_bytes.len) {
                const last = @as(u16, opt_bytes[i]) << 8;
                sum += last;
            }
        }

        var i: usize = 0;
        while (i + 1 < payload.len) {
            const word = (@as(u16, payload[i]) << 8) | payload[i + 1];
            sum += word;
            i += 2;
        }

        if (i < payload.len) {
            const last = @as(u16, payload[i]) << 8;
            sum += last;
        }

        while (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        std.mem.writeInt(u16, &self.checksum, ~@as(u16, @intCast(sum)), .big);

        //self.checksum = @byteSwap(~@as(u16, @intCast(sum)));

        if (std.mem.readInt(u16, &self.checksum, .big) == 0) {
            std.mem.writeInt(u16, &self.checksum, 0xFFFF, .big);
        }
    }

    pub fn get_urgent_ptr(self: *const TCPHeader) u16 {
        return std.mem.readInt(u16, &self.urgent_ptr, .big);
    }

    pub fn set_urgent_ptr(self: *TCPHeader, urgent_ptr: u16) void {
        std.mem.writeInt(u16, &self.urgent_ptr, urgent_ptr, .big);
    }

    pub fn set_hdr_length(self: *TCPHeader, length: u8) void {
        if (length < 20) {
            print("invalid tcp header length.\n", .{});
            return;
        }

        // length in 32-bit words
        const byte_len = length / 4;

        if (byte_len > 0xF) {
            print("header length too large.\n", .{});
            return;
        }

        // preserve lower 4 bits (reserved + flags)
        const low_nibble = self.data_offset_reserved_flags[0] & 0x0F;

        // set top 4 bits to data offset
        self.data_offset_reserved_flags[0] = (byte_len << 4) | low_nibble;
    }

    pub fn get_hdr_length(self: *const TCPHeader) u8 {
        const high_byte = self.data_offset_reserved_flags[0];

        const data_offset = (high_byte >> 4) & 0xF; // shift down top 4 bits
        const tcp_header_length = data_offset * 4; // in bytes
        return tcp_header_length;
    }

    pub fn get_flags_immutable(self: *const TCPHeader) *const TCPFlags {
        return @ptrCast(&self.data_offset_reserved_flags[1]);
    }

    pub fn get_flags_mutable(self: *TCPHeader) *TCPFlags {
        return @ptrCast(&self.data_offset_reserved_flags[1]);
    }
};

pub const TCPLayer = struct {
    owner: LayerOwner,

    /// Creates layer from ptr to minimum 20 byte length buffer
    pub fn init(allocator: Allocator) LayerError!TCPLayer {
        return try init_layer(TCPLayer, allocator, TCPHeader, default_hdr);
    }

    pub fn initFromSlice(slice: []u8, allocator: Allocator) LayerError!TCPLayer {
        if (slice.len < TCPHeaderMinSize) return LayerError.BufferTooSmall;

        const hdr: *TCPHeader = @ptrCast(slice[0..].ptr);

        const hdr_len = hdr.get_hdr_length();

        return try initLayerFromSlice(slice, TCPLayer, hdr_len, TCPHeaderMinSize, TCPHeaderMaxSize, allocator);
    }

    /// Calculate the checksum of the TCPHeader - not yet implemented
    pub fn validate_layer(self: *TCPLayer) void {
        switch (self.owner) {
            .packet_layer => |layer| {
                if (layer.prev_layer) |prev_layer| {
                    if (prev_layer.layer_iface.get_protocol() == tcp_ip_protocol.ipv4) {
                        var ipv4_iface: *Layer = &prev_layer.layer_iface;
                        var ipv4_layer: *IPv4.IPv4Layer = &ipv4_iface.ipv4Layer;
                        const ipv4_hdr: *const IPv4.IPv4Header = ipv4_layer.get_immutable_header();

                        const hdr_length = self.get_immutable_header().get_hdr_length();

                        self.get_mutable_header().calculate_checksum(ipv4_hdr.get_src_ip().array, ipv4_hdr.get_dst_ip().array, self.get_data()[hdr_length..]);
                    } else if (prev_layer.layer_iface.get_protocol() == tcp_ip_protocol.ipv6) {
                        return;
                        //prev_protocol = net_protocol.IPv6;
                    }
                } //else {
                //  print("no prev layer.\n", .{});
                //}
            },
            else => return,
        }
        return;
    }

    pub fn get_opt_buf(self: *TCPLayer) []u8 {
        const data = self.get_data();
        const header_len = self.get_immutable_header().get_hdr_length();

        return data[TCPHeaderMinSize..header_len];
    }

    pub fn has_option(self: *TCPLayer, op: TCPOption) bool {
        const ops_buf = self.get_opt_buf();

        var offset: usize = 0; // Start after fixed header

        while (offset < ops_buf.len) {
            const kind_val = ops_buf[offset];

            const kind: TCPOption = @enumFromInt(kind_val);

            if (kind == op) {
                return true;
            }

            switch (kind) {
                .EOL => {
                    offset += 1;
                },
                .NOP => {
                    offset += 1;
                },
                .MSS => {
                    const len = ops_buf[offset + 1];
                    if (len >= 4) {
                        const mss: u16 = @as(u16, @intCast(ops_buf[offset + 2])) << 8 | @as(u16, (@intCast(ops_buf[offset + 3])));
                        _ = mss;
                    }
                    offset += len;
                },
                .WS => {
                    const len = ops_buf[offset + 1];
                    if (len >= 3) {
                        const shift = ops_buf[offset + 2];
                        _ = shift;
                    }
                    offset += len;
                },
                .SACK_PERM => {
                    offset += 2;
                },
                .TS => {
                    const len = ops_buf[offset + 1];
                    if (len >= 10) {
                        const tsval: u32 = @as(u32, @intCast(ops_buf[offset + 2])) << 24 |
                            @as(u32, @intCast(ops_buf[offset + 3])) << 16 |
                            @as(u32, @intCast(ops_buf[offset + 4])) << 8 |
                            @as(u32, @intCast(ops_buf[offset + 5]));

                        const tsecr: u32 = @as(u32, @intCast(ops_buf[offset + 6])) << 24 |
                            @as(u32, @intCast(ops_buf[offset + 7])) << 16 |
                            @as(u32, @intCast(ops_buf[offset + 8])) << 8 |
                            @as(u32, @intCast(ops_buf[offset + 9]));

                        _ = tsval;
                        _ = tsecr;

                        //print("tsval: {} tsecr: {}\n", .{ tsval, tsecr });
                    }
                    offset += len;
                },
                else => { // possibly break here to avoid unsafe/innacurate parsing
                    const len = ops_buf[offset + 1];
                    offset += len;
                },
            } // switch end
        }

        return false;
    }

    pub fn parse_tcp_options(self: *TCPLayer) void {
        const ops_buf = self.get_opt_buf();

        const tcp_opts = std.enums.values(TCPOption);

        var offset: usize = 0; // Start after fixed header

        while (offset < ops_buf.len) {
            const kind_val = ops_buf[offset];

            for (tcp_opts) |tcp_opt| {
                if (@intFromEnum(tcp_opt) == kind_val) {
                    print("got tcp opt: {any}\n", .{@as(TCPOption, tcp_opt)});
                    break;
                }
            }

            const kind: TCPOption = @enumFromInt(kind_val);

            switch (kind) {
                .EOL => {
                    offset += 1; // must increment
                },
                .NOP => {
                    offset += 1;
                },
                .MSS => {
                    const len = ops_buf[offset + 1];
                    if (len >= 4) {
                        const mss: u16 = @as(u16, @intCast(ops_buf[offset + 2])) << 8 | @as(u16, (@intCast(ops_buf[offset + 3])));
                        _ = mss;
                    }
                    offset += len;
                },
                .WS => {
                    const len = ops_buf[offset + 1];
                    if (len >= 3) {
                        const shift = ops_buf[offset + 2];
                        _ = shift;
                    }
                    offset += len;
                },
                .SACK_PERM => {
                    offset += 2;
                },
                .TS => {
                    const len = ops_buf[offset + 1];
                    if (len >= 10) {
                        const tsval = @as(u32, @intCast(ops_buf[offset + 2])) << 24 |
                            @as(u32, @intCast(ops_buf[offset + 3])) << 16 |
                            @as(u32, @intCast(ops_buf[offset + 4])) << 8 |
                            @as(u32, @intCast(ops_buf[offset + 5]));

                        const tsecr = @as(u32, @intCast(ops_buf[offset + 6])) << 24 |
                            @as(u32, @intCast(ops_buf[offset + 7])) << 16 |
                            @as(u32, @intCast(ops_buf[offset + 8])) << 8 |
                            @as(u32, @intCast(ops_buf[offset + 9]));

                        _ = tsval;
                        _ = tsecr;
                    }
                    offset += len;
                },
                else => { // possibly break here to avoid unsafe/innacurate parsing
                    const len = ops_buf[offset + 1];
                    offset += len;
                },
            } // switch end
        }
    }

    fn check_padding(self: *TCPLayer) usize {
        const ops_buf = self.get_opt_buf();

        if (ops_buf.len == 0) {
            return 0;
        }

        var offset: usize = 0;

        while (offset < ops_buf.len) {
            const option_type = ops_buf[offset];

            // End of Option List
            if (option_type == 0) {
                break;
            }

            // No Operation
            if (option_type == 1) {
                offset += 1;
                continue;
            }

            // Need at least type + length
            if (offset + 1 >= ops_buf.len) {
                return 0;
            }

            const option_len = ops_buf[offset + 1];

            if (option_len < 2) {
                return 0;
            }

            offset += option_len;
        }

        return ops_buf.len - offset;
    }

    pub fn remove_option(self: *TCPLayer, opt: TCPOption) (LayerError || Allocator.Error)!void {
        const opt_buf = self.get_opt_buf();

        if (opt_buf.len == 0) {
            return;
        }

        var offset: usize = 0;

        var found: bool = false;
        while (offset < opt_buf.len - 1) {
            if (opt_buf[offset] == @intFromEnum(opt)) {
                found = true;
                break;
            }

            offset += 1;
        }

        if (!found) {
            return;
        }

        const length = if (opt.has_length_byte()) opt_buf[offset + 1] else 1;

        const original_len = self.get_immutable_header().get_hdr_length();

        try self.owner.shorten_layer(TCPHeaderMinSize + offset, length);

        var new_header_len = original_len - length;

        const pad_required = if (new_header_len % HeaderAlignment == 0) 0 else HeaderAlignment - (new_header_len % HeaderAlignment);

        if (pad_required > 0) {
            _ = try self.owner.extend_layer(TCPHeaderMinSize + (opt_buf.len - length), pad_required);
            new_header_len += pad_required;
        }

        self.get_mutable_header().set_hdr_length(new_header_len);
    }

    pub const TCPError = error{
        OptionsTooLarge,
        DataSuppliedForNonTLVOption,
    };

    pub fn add_option(self: *TCPLayer, opt: TCPOption, data: ?[]const u8) (TCPError || LayerError || Allocator.Error)!void {
        const opt_buf = self.get_opt_buf();

        var expected_tcp_header_len = (opt_buf.len + TCPHeaderMinSize + @sizeOf(TCPOption));

        if (opt.has_length_byte()) expected_tcp_header_len += @sizeOf(u8);

        if (data) |d| expected_tcp_header_len += d.len;

        if (expected_tcp_header_len > TCPHeaderMaxSize) {
            const opts_len_pad_rem = expected_tcp_header_len - self.check_padding();
            if (opts_len_pad_rem > TCPHeaderMaxSize) {
                return error.OptionsTooLarge;
            } else {
                print("potential for pad overwrite.\n", .{});
            }
        }

        var extend_len: usize = @sizeOf(TCPOption);

        switch (opt) {
            .EOL, .NOP, .SACK_PERM => {
                if (data != null) {
                    return error.DataSuppliedForNonTLVOption;
                }
            },
            else => {
                extend_len += @sizeOf(u8);
            },
        }

        if (data) |d| {
            extend_len += d.len;
        }

        const extend_offset = (TCPHeaderMinSize + opt_buf.len) - self.check_padding();

        const buf = try self.owner.extend_layer(extend_offset, extend_len);

        buf[0] = @intFromEnum(opt); // set the type

        if (extend_len > 1) { // the option is at least 2 bytes (SACK_PERM)
            buf[1] = @intCast(extend_len); // set the length
            if (extend_len > 2) { // the option has type length
                if (data) |d| { // unwrap the data supplied
                    @memmove(buf[2..], d); // copy into the buf
                }
            }
        }

        const cur_header_len = self.get_immutable_header().get_hdr_length(); // take the current header length

        const new_header_len = cur_header_len + @as(u8, @intCast(buf.len)); // increase by the extend length

        self.get_mutable_header().set_hdr_length(new_header_len); // set the new length
    }

    /// return data for options which carry data - mutable slice returned for potential mutation
    pub fn get_opt_data(self: *TCPLayer, opt: TCPOption) ?[]u8 {
        const opt_buf = self.get_opt_buf();

        var offset: usize = 0;

        const options = std.enums.values(TCPOption)[1..];

        var offset_increased = false;

        while (offset < opt_buf.len - 1) {
            offset_increased = true;
            for (options) |option| {
                if (opt_buf[offset] == @intFromEnum(option)) {
                    if (option.has_length_byte()) {
                        const length: usize = @intCast(opt_buf[offset + 1]);

                        if (option == opt) {
                            return opt_buf[offset + 2 .. offset + length];
                        } else {
                            offset += length;
                            offset_increased = true;
                        }
                    }
                }
            }

            if (offset_increased) {
                continue;
            }

            offset += 1; // a valid option was not found
        }

        return null;
    }

    pub fn get_next_layer_type(self: *TCPLayer, layer: *PacketLayer) LayerError!?Layer {
        const data: []const u8 = self.get_data();

        if (data.len < TCPHeaderMinSize) {
            return LayerError.BufferTooSmall; // tcp header has been mutated and now the header length is not minimum size
        }

        if (self.get_payload().len > 0) {
            return Layer{ .genericAppLayer = .{ .owner = .{ .packet_layer = layer } } };
        }

        return null;
    }

    pub fn get_mutable_header(self: *TCPLayer) *TCPHeader {
        const data = self.get_data();

        if (data.len < TCPHeaderMinSize) {
            panic("TCP Raw Data len ({}) less than TCPHeaderSize", .{data.len});
        }

        return @ptrCast(data.ptr);
    }

    pub fn get_immutable_header(self: *const TCPLayer) *const TCPHeader {
        const data: []const u8 = self.get_data();

        if (data.len < TCPHeaderMinSize) {
            panic("TCP Raw Data len ({}) less than TCPHeaderSize", .{data.len});
        }

        return @ptrCast(data.ptr);
    }

    /// Get slice of data (header + payload)
    pub fn get_data(self: *const TCPLayer) []u8 {
        return self.owner.get_data();
    }

    /// Get the payload (data after TCP header)
    pub fn get_payload(self: *TCPLayer) []const u8 {
        const data = self.get_data();
        const hdr_len = self.get_immutable_header().get_hdr_length();

        if (data.len > hdr_len) { // TODO: calculate the TCP header length
            return data[hdr_len..]; // return remaining bytes after the header
        } else {
            return "";
        }
    }

    pub fn to_string(self: *TCPLayer, allocator: Allocator) []const u8 {
        const hdr = self.get_immutable_header();

        const src_port: u16 = hdr.get_src_port();
        const dst_port: u16 = hdr.get_dst_port();

        // TODO: add [syn] [syn-ack] [ack] [rst] etc
        const result = std.fmt.allocPrint(allocator, "TCP Layer: src_port: {} dst_port: {}", .{ src_port, dst_port }) catch |err| {
            print("TCP allocPrint failed: {s}\n", .{@errorName(err)});
            return "";
        };

        return result;
    }

    pub fn get_protocol(self: *TCPLayer) tcp_ip_protocol {
        _ = self;
        return tcp_ip_protocol.tcp;
    }

    pub fn deinit(self: *TCPLayer) void {
        self.owner.deinit();
    }
};
