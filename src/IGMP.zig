const std = @import("std");
const ProtocolEnums = @import("ProtocolEnums.zig");
const LayerIface = @import("LayerIface.zig").LayerIface;
const LayerOwner = @import("Layer.zig").LayerOwner;
const Layer = @import("Packet.zig").Layer;
const IPv4 = @import("IPv4.zig");
const tcp_ip_protocol = @import("tcp_ip_protocols.zig").tcp_ip_protocol;

const print = std.debug.print;
const Allocator = std.mem.Allocator;
const panic = std.debug.panic;
const LayerError = ProtocolEnums.LayerError;

/// Helper to interpret the type field
pub const IGMPType = enum(u8) {
    membership_query = 0x11,
    v1_membership_report = 0x12,
    v2_membership_report = 0x16,
    leave_group = 0x17, // v2
    v3_membership_report = 0x22, // v3

    pub fn name(self: IGMPType) []const u8 {
        return switch (self) {
            .membership_query => "Membership Query",
            .v1_membership_report => "v1 Membership Report",
            .v2_membership_report => "v2 Membership Report",
            .leave_group => "Leave Group",
            .v3_membership_report => "v3 Membership Report",
        };
    }

    pub fn is_valid(type_byte: u8) bool {
        switch (type_byte) {
            0x11, 0x12, 0x16, 0x17, 0x22 => {
                return true;
            },
            else => return false,
        }
    }
};

pub const IGMPVersion = enum(u2) {
    v1 = 1,
    v2 = 2,
    v3 = 3,
};

pub const IGMPHeaderSize = 8;

/// IGMPv1 and IGMPv2 Header
/// Used for: Membership Query (v1 & v2), Membership Report (v1 & v2),
/// Leave Group (v2 only)
pub const IGMPv1Header = extern struct {
    type: u8,
    reserved: u8,
    checksum: u16,
    group_address: [4]u8,

    pub fn init_default() IGMPv1Header {
        return .{
            .type = @intFromEnum(.membership_query),
            .reserved = 0,
            .checksum = 0,
            .group_address = [_]u8{0} ** 4,
        };
    }
};

pub const IGMPv2Header = extern struct {
    type: u8,
    max_resp_time: u8,
    checksum: u16,
    group_address: [4]u8,

    pub fn init_default() IGMPv2Header {
        return .{
            .type = @intFromEnum(IGMPType.membership_query),
            .max_resp_time = 0,
            .checksum = 0,
            .group_address = [_]u8{0} ** 4,
        };
    }
};

pub const IGMPv3Header = extern struct {
    type: u8,
    max_resp_time: u8,
    checksum: u16,
    group_address: [4]u8,

    pub fn init_default() IGMPv3Header {
        return .{
            .type = @intFromEnum(IGMPType.membership_query),
            .max_resp_time = 0,
            .checksum = 0,
            .group_address = [_]u8{0} ** 4,
        };
    }

    pub fn calculate_checksum(self: *IGMPv3Header, payload: []const u8) void {
        const old_checksum = self.checksum;
        self.checksum = 0;

        var sum: u32 = 0;

        // Add IGMP header (as 16-bit words)
        const header_ptr: [*]const u8 = @ptrCast(self);
        var i: usize = 0;
        while (i < IGMPHeaderSize) {
            if (i + 1 < IGMPHeaderSize) {
                const word = (@as(u16, header_ptr[i]) << 8) | header_ptr[i + 1];
                sum += word;
            } else {
                sum += @as(u16, header_ptr[i]) << 8;
            }
            i += 2;
        }

        // Add payload
        i = 0;
        while (i < payload.len) {
            if (i + 1 < payload.len) {
                const word = (@as(u16, payload[i]) << 8) | payload[i + 1];
                sum += word;
            } else {
                sum += @as(u16, payload[i]) << 8;
            }
            i += 2;
        }

        // Fold 32-bit sum to 16 bits
        while (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // Take one's complement
        self.checksum = @byteSwap(~@as(u16, @intCast(sum)));

        _ = old_checksum;
    }
};

pub const GroupRecordType = enum(u8) {
    INCLUDE = 1, // Receiver wants traffic **only from listed sources**
    EXCLUDE = 2, // Receiver wants traffic from **all except listed sources**
    CHANGE_TO_INCLUDE = 3, // Filter mode changed to INCLUDE
    CHANGE_TO_EXCLUDE = 4, // Filter mode changed to EXCLUDE
    ALLOW_NEW_SOURCES = 5, // Added new acceptable multicast sources
    BLOCK_OLD_SOURCES = 6, // Removed previously accepted sources

};
/// IGMPv3 Group Record (variable length, appears after base header in REPORTS)
/// Each record describes a single multicast group membership state change.
pub const IGMPv3GroupRecord = extern struct {
    record_type: u8,
    aux_data_len: u8,
    num_sources: u16,
    multicast_address: [4]u8,

    pub fn get_record_type(self: *const IGMPv3GroupRecord) GroupRecordType {
        return @enumFromInt(self.record_type);
    }

    pub fn set_record_type(self: *IGMPv3GroupRecord, rec_type: GroupRecordType) void {
        self.record_type = @intFromEnum(rec_type);
    }

    pub fn get_aux_data_len(self: *const IGMPv3GroupRecord) u8 {
        return self.aux_data_len;
    }

    pub fn set_aux_data_len(self: *IGMPv3GroupRecord, len: u8) void {
        self.aux_data_len = len;
    }

    pub fn get_num_sources(self: *const IGMPv3GroupRecord) u16 {
        return @byteSwap(self.num_sources);
    }

    pub fn set_num_sources(self: *IGMPv3GroupRecord, num: u16) void {
        self.num_sources = @byteSwap(num);
    }

    pub fn get_mcast_address(self: *const IGMPv3GroupRecord) IPv4.IPv4Address {
        return IPv4.IPv4Address.init_from_array(self.multicast_address);
    }

    pub fn set_mcast_address(self: *IGMPv3GroupRecord, addr: IPv4.IPv4Address) void {
        self.multicast_address = addr.array;
    }

    // Note: This struct is followed by 'num_sources' IPv4 addresses (each u32),
    // and then optional auxiliary data (if aux_data_len > 0).
    // The total length of one group record is:
    // 8 bytes (this struct) + (num_sources * 4) + (aux_data_len * 4) bytes
};

/// IGMPv3 Query Extension (appears after the base header when type == 0x11)
/// This only exists for IGMPv3 Membership Queries (not Reports).
pub const IGMPv3QueryExtension = extern struct {
    s_qrv: u8,
    qqic: u8, // Querier's Query Interval Code (encoded value, usually 0x00 = 10 seconds)
    num_sources: u16, // Number of source addresses in this query (N)
    // Followed by 'num_sources' IPv4 source addresses (each u32)

    pub fn set_s_flag(self: *IGMPv3QueryExtension, flag: u1) void {
        self.s_qrv &= 0b1111_0111;
        self.s_qrv |= (@as(u8, flag) << 3);
    }

    pub fn set_qrv(self: *IGMPv3QueryExtension, qrv: u3) void {
        self.s_qrv &= 0b1111_1000;
        self.s_qrv |= qrv;
    }

    pub fn get_s_flag(self: *const IGMPv3QueryExtension) u1 {
        return @truncate((self.s_qrv >> 3) & 0x1);
    }

    pub fn get_qrv(self: *const IGMPv3QueryExtension) u3 {
        return @truncate(self.s_qrv & 0x7);
    }

    pub fn to_string(self: *const IGMPv3QueryExtension, allocator: Allocator) []const u8 {
        return std.fmt.allocPrint(allocator, "IGMPv3QueryExtension :  s_flag: {} qrv: {} qqic: {} num_sources: {}\n", .{
            self.get_s_flag(),
            self.get_qrv(),
            self.qqic,
            @byteSwap(self.num_sources),
        }) catch {
            return "";
        };
    }
};

pub const IGMP_type = union(enum) {
    igmpv1: *IGMPv1Header,
    igmpv2: *IGMPv2Header,
    igmpv3_grp_rec: *IGMPv3GroupRecord,
    igmpv3_gry_ext: *IGMPv3QueryExtension,
};

pub const IGMPv3Layer = struct {
    owner: LayerOwner,

    pub fn init(owner: LayerOwner) LayerError!IGMPv3Layer {
        switch (owner) {
            .packet_layer => {
                return IGMPv3Layer{
                    .owner = owner,
                };
            },
            .owned_buffer => {
                var self = IGMPv3Layer{ .owner = owner };
                const buffer_len = self.owner.owned_buffer.buffer.items.len;
                if (buffer_len < IGMPHeaderSize + 4) {
                    const diff = (IGMPHeaderSize + 4) - buffer_len;
                    const igmp_data = try self.owner.owned_buffer.extend(buffer_len, diff);

                    @memset(igmp_data, 0);

                    var header = IGMPv3Header.init_default(); // creates the IGMP Base Header default

                    @memmove(igmp_data[0..@sizeOf(IGMPv3Header)], std.mem.asBytes(&header));
                }

                return self;
            },
        }
    }

    pub fn get_mutable_header(self: *const IGMPv3Layer) *IGMPv3Header {
        const data = self.get_data();

        if (data.len < IGMPHeaderSize) {
            panic("IGMP data len ({}) less than IGMPHeaderSize", .{data.len});
        }

        const aligned_ptr: [*]align(@alignOf(IGMPv3Header)) u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    pub fn get_immutable_header(self: *const IGMPv3Layer) *const IGMPv3Header {
        const data: []const u8 = self.get_data();

        if (data.len < IGMPHeaderSize) {
            panic("IGMP data len ({}) less than IGMPHeaderSize", .{data.len});
        }

        const aligned_ptr: [*]align(@alignOf(IGMPv3Header)) const u8 = @alignCast(data.ptr);
        return @ptrCast(aligned_ptr);
    }

    pub fn get_igmp_type_hdr(self: *const IGMPv3Layer) ?IGMP_type {
        const data = self.get_data()[IGMPHeaderSize..];

        const hdr = self.get_immutable_header();

        const igmp_type: IGMPType = @enumFromInt(hdr.type);

        switch (igmp_type) {
            .membership_query => {
                const aligned_ptr: [*]align(@alignOf(IGMPv3QueryExtension)) u8 = @alignCast(data.ptr);
                const igmp_header: *IGMPv3QueryExtension = @ptrCast(aligned_ptr);
                return IGMP_type{ .igmpv3_gry_ext = igmp_header };
            },
            else => return null,
        }
    }
    /// returns mutable slice of data (hdr+payload).
    /// this will likely be made private in future to avoid accidental mutations
    pub fn get_data(self: *const IGMPv3Layer) []u8 {
        return self.owner.get_data();
    }

    /// return immutable slice of the payload
    pub fn get_payload(self: *IGMPv3Layer) []const u8 {
        _ = self;
        return "";
    }

    pub fn get_type(self: *const IGMPv3Layer) IGMPType {
        return @enumFromInt(self.get_data()[0]);
    }

    pub fn set_type(self: *IGMPv3Layer, igmp_type: IGMPType) !void {
        const data = self.get_data();

        _ = data;

        switch (igmp_type) {}
    }

    pub fn validate_layer(self: *IGMPv3Layer) void {
        const igmp_type_data = self.get_data()[IGMPHeaderSize..];
        self.get_mutable_header().calculate_checksum(igmp_type_data);
    }

    pub fn set_payload(self: *IGMPv3Layer, payload: []const u8) !void {
        const current_payload_len = self.get_payload().len;

        const header_type_size = self.get_header_type_size();

        const full_header_size = IGMPHeaderSize + header_type_size;

        var buf: []u8 = self.get_data()[full_header_size..];

        if (payload.len > current_payload_len) {
            const extend_len: usize = payload.len - current_payload_len;

            buf = try self.owner.extend_payload(full_header_size, extend_len);
        }

        if (current_payload_len > payload.len) {
            const shorten_len = current_payload_len - payload.len;

            const offset = full_header_size + payload.len;

            try self.owner.shorten_payload(offset, shorten_len);
            buf = self.get_data()[full_header_size..];
        }

        @memmove(buf, payload);
    }

    /// Don't use this.
    pub fn remove_payload(self: *IGMPv3Layer) !void {
        const payload_len = self.get_payload().len;
        if (payload_len > 0) {
            try self.owner.shorten_payload(self.get_data().len - payload_len, payload_len);
        }
    }

    pub fn to_string(self: *IGMPv3Layer, allocator: std.mem.Allocator) []const u8 {
        //const hdr = self.get_immutable_header();
        _ = self;
        _ = allocator;
        //return std.fmt.allocPrint(allocator, "{any}", .{hdr.get_type()}) catch {
        return "";
        //};
    }

    pub fn get_protocol(self: *IGMPv3Layer) tcp_ip_protocol {
        _ = self;
        return tcp_ip_protocol.igmp_v3;
    }

    pub fn get_next_layer_type(self: *IGMPv3Layer, layer: *Layer) !?LayerIface {
        _ = self;
        _ = layer;

        return null;
    }

    pub fn deinit(self: *IGMPv3Layer) void {
        self.owner.deinit();
    }
};

//       pub fn get_igmp_type_hdr(self: *IGMPLayer) ?IGMP_type {
//           const data = self.get_data();
//
//           if (IGMPType.is_valid(data[0])) {
//               const igmp_type: IGMPType = @enumFromInt(data[0]);
//
//               switch (igmp_type) {
//                   .v1_membership_report, .v2_membership_report, .leave_group => {
//                       if (data[1] == 0) {
//                           const aligned_ptr: [*]align(@alignOf(IGMPv1Header)) u8 = @alignCast(data.ptr);
//                           const igmp_header: *IGMPv1Header = @ptrCast(aligned_ptr);
//                           return IGMP_type{ .igmpv1 = igmp_header };
//                       }
//
//                       const aligned_ptr: [*]align(@alignOf(IGMPv2Header)) u8 = @alignCast(data.ptr);
//                       const igmp_header: *IGMPv2Header = @ptrCast(aligned_ptr);
//                       return IGMP_type{ .igmpv2 = igmp_header };
//                   },
//                   .v3_membership_report => {
//                       const aligned_ptr: [*]align(@alignOf(IGMPv3GroupRecord)) u8 = @alignCast(data.ptr);
//                       const igmp_header: *IGMPv3GroupRecord = @ptrCast(aligned_ptr);
//                       return IGMP_type{ .igmpv3_grp_rec = igmp_header };
//                   },
//                   .membership_query => {
//                       const aligned_ptr: [*]align(@alignOf(IGMPv3QueryExtension)) u8 = @alignCast(data.ptr);
//                       const igmp_header: *IGMPv3QueryExtension = @ptrCast(aligned_ptr);
//                       return IGMP_type{ .igmpv3_gry_ext = igmp_header };
//                   },
//               }
//           }
//
//           return null;
//       }
