/// Note: TCP option 0x1c is officially assigned to UTO (RFC 5482).
/// Some legacy SCPS implementations also used this value unofficially.
/// This enum treats 0x1c as UTO.
pub const TCPOption = enum(u8) {
    /// End of Options List
    EOL = 0x00,
    /// No-Operation (padding)
    NOP = 0x01,
    /// Maximum Segment Size
    MSS = 0x02,
    /// Window Scale
    WS = 0x03,
    /// SACK Permitted
    SACK_PERM = 0x04,
    /// SACK Block (Selective ACK)
    SACK = 0x05,
    /// Timestamp
    TS = 0x08,
    /// TCP Fast Open (TFO)
    TCP_FASTOPEN = 0x0f,
    /// Experimental Fast Open (draft-ietf-tcp-fastopen)
    EXP_FASTOPEN = 0x1a,
    /// Multipath TCP (MPTCP)
    MULTIPATH_TCP = 0x1e,
    /// TCP Authentication Option (TCP-AO) - replaces MD5
    AUTH = 0x1f,
    /// TCP MD5 Signature (deprecated by TCP-AO)
    MD5 = 0x13,
    /// TCP User Timeout Option (both UTO and SC-PS share 0x1c)
    UTO = 0x1c,
    /// VS Data (experimental)
    VS_DATA = 0x1d,
    /// TCP NUM Option (Nonce Update Mechanism, experimental)
    NUM = 0x1b,
    /// Clark's timestamp echo (obsolete)
    CLARK = 0x09,
    /// TCP TSN (Transport Sequence Number, experimental)
    TSN = 0x0a,
    /// TCP Signature (obsolete)
    SIG = 0x0b,
    _,

    pub fn has_length_byte(self: TCPOption) bool {
        return self != .EOL and self != .NOP;
    }

    pub fn minimum_length(self: TCPOption) u8 {
        return switch (self) {
            .EOL, .NOP => 1,
            .SACK_PERM => 2, // Kind + Length only, no value
            else => 3, // Kind + Length + at least 1 value byte
        };
    }

    // Alternative naming aliases (can be added as methods or constants)
    pub fn name(self: TCPOption) []const u8 {
        return switch (self) {
            .EOL => "End of Options",
            .NOP => "No-Operation",
            .MSS => "Maximum Segment Size",
            .WS => "Window Scale",
            .SACK_PERM => "SACK Permitted",
            .SACK => "Selective ACK",
            .TS => "Timestamp",
            .TCP_FASTOPEN => "TCP Fast Open",
            .EXP_FASTOPEN => "Experimental Fast Open",
            .MULTIPATH_TCP => "Multipath TCP",
            .AUTH => "TCP Authentication",
            .MD5 => "TCP MD5 Signature",
            .UTO => "User Timeout",
            .VS_DATA => "VS Data",
            .NUM => "Nonce Update",
            .CLARK => "Clark's Timestamp Echo",
            .TSN => "Transport Sequence Number",
            .SIG => "TCP Signature",
            else => "Unknown",
        };
    }
};
