const std = @import("std");

/// IGMPv1 and IGMPv2 Header
/// Used for: Membership Query (v1 & v2), Membership Report (v1 & v2),
/// Leave Group (v2 only)
pub const IGMPv1v2Header = extern struct {
    type: u8,
    max_resp_time: u8,
    checksum: u16,
    group_address: [4]u8,
};

/// IGMPv3 Fixed Base Header (first 8 bytes)
/// Used for: Membership Query (v3) and Version 3 Membership Report
/// Note: This is always followed by additional variable-length data.
pub const IGMPv3BaseHeader = extern struct {
    type: u8,
    max_resp_time: u8,
    checksum: u16,
    group_address: [4]u8,
};

/// IGMPv3 Group Record (variable length, appears after base header in REPORTS)
/// Each record describes a single multicast group membership state change.
pub const IGMPv3GroupRecord = extern struct {
    record_type: u8,
    aux_data_len: u8,
    num_sources: u16,
    multicast_address: [4]u8,

    // Note: This struct is followed by 'num_sources' IPv4 addresses (each u32),
    // and then optional auxiliary data (if aux_data_len > 0).
    // The total length of one group record is:
    // 8 bytes (this struct) + (num_sources * 4) + (aux_data_len * 4) bytes
};

/// IGMPv3 Query Extension (appears after the base header when type == 0x11)
/// This only exists for IGMPv3 Membership Queries (not Reports).
pub const IGMPv3QueryExtension = packed struct {
    reserved_bits: u4,
    s_flag: u1, // Suppress Router-Side Processing flag
    qrv: u3, // Querier's Robustness Variable
    qqic: u8, // Querier's Query Interval Code (encoded value, usually 0x00 = 10 seconds)
    num_sources: u16, // Number of source addresses in this query (N)
    // Followed by 'num_sources' IPv4 source addresses (each u32)

    pub fn get_s_flag(self: *const IGMPv3QueryExtension) u1 {
        return self.s_flag;
    }

    pub fn set_s_flag(self: *IGMPv3QueryExtension, flag: u1) void {
        self.s_flag = flag;
    }

    pub fn get_qrv(self: *const IGMPv3QueryExtension) u3 {
        return self.qrv;
    }

    pub fn set_qrv(self: *IGMPv3QueryExtension, qrv: u3) void {
        self.qrv = qrv;
    }
};

/// Complete IGMPv3 Query Header (if you want to parse it all at once - note the sources array is unsized)
/// To use this, you would cast to IGMPv3BaseHeader, check type, then if query, cast to this.
pub const IGMPv3FullQuery = extern struct {
    base: IGMPv3BaseHeader,
    extension: IGMPv3QueryExtension,
    // Sources array follows - accessed via @ptrCast based on extension.num_sources
};

/// Helper to interpret the type field
pub const IGMPType = enum(u8) {
    membership_query = 0x11,
    v1_membership_report = 0x12,
    v2_membership_report = 0x16,
    leave_group = 0x17,
    v3_membership_report = 0x22,

    pub fn name(self: IGMPType) []const u8 {
        return switch (self) {
            .membership_query => "Membership Query",
            .v1_membership_report => "v1 Membership Report",
            .v2_membership_report => "v2 Membership Report",
            .leave_group => "Leave Group",
            .v3_membership_report => "v3 Membership Report",
        };
    }
};
