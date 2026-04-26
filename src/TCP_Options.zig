pub const TCPOption = enum(u8) {
    EOL = 0x00, // End of Options List
    NOP = 0x01, // No-Operation (padding)
    MSS = 0x02, // Maximum Segment Size
    WS = 0x03, // Window Scale
    SACK_PERM = 0x04, // SACK Permitted
    SACK = 0x05, // SACK Block (Selective ACK)
    TS = 0x08, // Timestamp
    TCP_FASTOPEN = 0x0f, // TCP Fast Open (TFO)
    EXP_FASTOPEN = 0x1a, // Experimental Fast Open (draft-ietf-tcp-fastopen)
    MULTIPATH_TCP = 0x1e, // Multipath TCP (MPTCP)
    AUTH = 0x1f, // TCP Authentication Option (TCP-AO) - replaces MD5
    MD5 = 0x13, // TCP MD5 Signature (deprecated by TCP-AO)
    SC_PS = 0x1c, // Sender - Specific Congestion/Pacing Scheme (experimental)
    VS_DATA = 0x1d, // VS Data (experimental)
    NUM = 0x1b, // TCP NUM Option (Nonce Update Mechanism, experimental)
    CLARK = 0x09, // Clark's timestamp echo (obsolete)
    TSN = 0x0a, // TCP TSN (Transport Sequence Number, experimental)
    SIG = 0x0b, // TCP Signature (obsolete)
    //UTO = 0x1c, // TCP User Timeout Option (both UTO and SC-PS share 0x1c)

    _,

    pub fn length(self: TCPOption) ?u8 {
        return switch (self) {
            .EOL, .NOP => null, // Single byte, no length field
            .MSS, .WS, .SACK_PERM, .TCP_FASTOPEN, .MD5, .AUTH, .SACK, .TS, .MULTIPATH_TCP, .SC_PS, .VS_DATA, .NUM, .CLARK, .TSN, .SIG, .UTO => null, // Length varies, check actual value
            // For most options, you need to read the length byte at offset+1
        };
    }

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
            .SC_PS => "Sender-Specific Congestion/Pacing",
            .VS_DATA => "VS Data",
            .NUM => "Nonce Update",
            .CLARK => "Clark's Timestamp Echo",
            .TSN => "Transport Sequence Number",
            .SIG => "TCP Signature",
            else => "Unknown",
            //.UTO => "User Timeout",
        };
    }
};
