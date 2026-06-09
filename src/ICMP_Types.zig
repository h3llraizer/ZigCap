const std = @import("std");
const IPv4 = @import("IPv4.zig");
const ICMPHeader = @import("ICMP.zig").ICMPHeader;

pub const ICMP_type = union(enum) {
    echo: *ICMPEcho,
    dest_unreachable: *ICMPDestUnr,
    redirect: *ICMPRedirect,
    parameter_problem: *ICMPParamProb,
    router_advertisement: *ICMPRouterAd,
    route_solicitation: *ICMPRouterSol,
    timestamp: *ICMPTimestamp,
    info: *ICMPInfo,
    address_mask: *ICMPAddrMask,
    source_quench: *ICMPSourceQuench,
};

pub const ICMPType = enum(u8) {
    EchoReply = 0,
    DestinationUnreachable = 3,
    SourceQuench = 4, // not used often - need to get working example first
    Redirect = 5,
    EchoRequest = 8,
    RouterAdvertisement = 9, // IPv6
    RouterSolicitation = 10, // IPv6
    TimeExceeded = 11,
    ParameterProblem = 12,
    TimestampRequest = 13,
    TimestampReply = 14,
    InformationRequest = 15,
    InformationReply = 16,
    AddressMaskRequest = 17,
    AddressMaskReply = 18,
};

pub const DestinationUnreachableCode = enum(u8) {
    NetUnreachable = 0,
    HostUnreachable = 1,
    ProtocolUnreachable = 2,
    PortUnreachable = 3,
    FragmentationNeeded = 4,
    SourceRouteFailed = 5,
    DestinationNetworkUnknown = 6,
    DestinationHostUnknown = 7,
    SourceHostIsolated = 8,
    NetworkAdministrativelyProhibited = 9,
    HostAdministrativelyProhibited = 10,
    NetworkUnreachableForTOS = 11,
    HostUnreachableForTOS = 12,
    CommunicationAdministrativelyProhibited = 13,
    HostPrecedenceViolation = 14,
    PrecedenceCutoffInEffect = 15,
};

pub const RedirectCode = enum(u8) {
    /// Redirect datagrams for the Network
    RedirectForNetwork = 0,
    /// Redirect datagrams for the Host
    RedirectForHost = 1,
    /// Redirect datagrams for the Type of Service and Network
    RedirectForTOSAndNetwork = 2,
    /// Redirect datagrams for the Type of Service and Host
    RedirectForTOSAndHost = 3,
};

pub const TimeExceededCode = enum(u8) {
    TTLExceeded = 0,
    FragmentReassemblyTimeExceeded = 1,
};

pub const ParameterProblemCode = enum(u8) {
    PointerIndicatesError = 0,
    MissingOption = 1,
    BadLength = 2,
};

pub const NoCode = enum(u8) {
    None = 0,
};

pub const ICMPCode = union(enum) {
    no: NoCode,
    param_problem: ParameterProblemCode,
    time_exceeded: TimeExceededCode,
    redirect: RedirectCode,
    dest_unreachable: DestinationUnreachableCode,
};

/// ICMP Echo (Request/Response)
pub const ICMPEcho = extern struct {
    identifier: u16,
    sequence: u16,

    pub fn set_identifier(self: *ICMPEcho, id: u16) void {
        self.identifier = @byteSwap(id);
    }

    pub fn get_identifier(self: *const ICMPEcho) u16 {
        return @byteSwap(self.identifier);
    }

    pub fn set_seq_num(self: *ICMPEcho, seq: u16) void {
        self.sequence = @byteSwap(seq);
    }

    pub fn get_seq_num(self: *const ICMPEcho) u16 {
        return @byteSwap(self.sequence);
    }
};

/// ICMP Destination Unreachable
/// used in TTL timeouts
pub const ICMPDestUnr = extern struct {
    unused: [4]u8,
};

/// ICMP Redirect
pub const ICMPRedirect = extern struct {
    gateway: [4]u8,

    pub fn set_gateway(self: *ICMPRedirect, gateway: IPv4.IPv4Address) void {
        self.redirect.gateway = gateway.array;
    }

    pub fn get_gateway(self: *const ICMPRedirect) IPv4.IPv4Address {
        return IPv4.IPv4Address.init_from_array(self.redirect.gateway);
    }
};

/// ICMP Parameter Problem
pub const ICMPParamProb = extern struct {
    pointer: u8,
    unused: [3]u8,

    pub fn set_pointer(self: *ICMPHeader, pointer: u8) void {
        self.param_problem.pointer = pointer;
    }

    pub fn get_pointer(self: *const ICMPHeader) u8 {
        return self.param_problem.pointer;
    }
};

/// ICMP Router Advertisement
pub const ICMPRouterAd = extern struct {
    num_addresses: u8,
    addr_entry_size: u8,
    lifetime: u16,

    pub fn get_num_addresses(self: *ICMPRouterAd) u8 {
        return self.num_addresses;
    }

    pub fn set_num_addresses(self: *ICMPRouterAd, num_addresses: u8) void {
        self.num_addresses = num_addresses;
    }

    pub fn get_addr_entry_size(self: *ICMPRouterAd) u8 {
        return self.get_addr_entry_size;
    }

    pub fn set_addr_entry_size(self: *ICMPRouterAd, entry_size: u8) void {
        self.set_addr_entry_size = entry_size;
    }

    pub fn get_lifetime(self: *ICMPRouterAd) u16 {
        return @byteSwap(self.lifetime);
    }

    pub fn set_lifetime(self: *ICMPRouterAd, lifetime: u16) void {
        self.lifetime = @byteSwap(lifetime);
    }
};

/// ICMP Router Solicitation
pub const ICMPRouterSol = extern struct {
    reserved: [4]u8,
};

/// ICMP Timestamp Request/Reply message header.
pub const ICMPTimestamp = extern struct {
    /// Used to match requests with replies (like a port number)
    identifier: u16,
    /// Incremented per request to match replies
    sequence_number: u16,
    /// Time (ms since midnight UTC) when sender last touched the message before sending
    originate_timestamp: [4]u8,
    /// Time (ms since midnight UTC) when receiver first received the request
    receive_timestamp: [4]u8,
    /// Time (ms since midnight UTC) when receiver last touched the reply before sending
    transmit_timestamp: [4]u8,

    pub fn get_identifier(self: *ICMPTimestamp) u16 {
        return @byteSwap(self.identifier);
    }

    pub fn set_identifier(self: *ICMPTimestamp, id: u16) void {
        self.identifier = @byteSwap(id);
    }

    pub fn get_seq_num(self: *ICMPTimestamp) u16 {
        return @byteSwap(self.sequence_number);
    }

    pub fn set_seq_num(self: *ICMPTimestamp, seq_num: u16) void {
        self.sequence_number = @byteSwap(seq_num);
    }

    pub fn get_original_timestamp(self: *ICMPTimestamp) u32 {
        const val = std.mem.bytesToValue(u32, &self.originate_timestamp);
        return @byteSwap(val);
    }

    pub fn set_original_timestamp(self: *ICMPTimestamp, timestamp: u32) void {
        const bytes = std.mem.toBytes(@byteSwap(timestamp));
        self.originate_timestamp = bytes;
    }

    pub fn get_receive_timestamp(self: *ICMPTimestamp) u32 {
        const val = std.mem.bytesToValue(u32, &self.receive_timestamp);
        return @byteSwap(val);
    }

    pub fn set_receive_timestamp(self: *ICMPTimestamp, timestamp: u32) void {
        const bytes = std.mem.toBytes(@byteSwap(timestamp));
        self.receive_timestamp = bytes;
    }

    pub fn get_transmit_timestamp(self: *ICMPTimestamp) u32 {
        const val = std.mem.bytesToValue(u32, &self.transmit_timestamp);
        return @byteSwap(val);
    }

    pub fn set_transmit_timestamp(self: *ICMPTimestamp, timestamp: u32) void {
        const bytes = std.mem.toBytes(@byteSwap(timestamp));
        self.transmit_timestamp = bytes;
    }
};

/// ICMP Info (Request/Response)
pub const ICMPInfo = extern struct {
    identifier: u16,
    sequence: u16,

    pub fn set_identifier(self: *ICMPInfo, id: u16) void {
        self.identifier = @byteSwap(id);
    }

    pub fn get_identifier(self: *const ICMPInfo) u16 {
        return @byteSwap(self.identifier);
    }

    pub fn set_seq_num(self: *ICMPInfo, seq: u16) void {
        self.sequence = @byteSwap(seq);
    }

    pub fn get_seq_num(self: *const ICMPInfo) u16 {
        return @byteSwap(self.sequence);
    }
};

/// ICMP AddrMask (Request/Response)
pub const ICMPAddrMask = extern struct {
    identifier: u16,
    sequence: u16,
    address_mask: [4]u8,

    pub fn set_identifier(self: *ICMPAddrMask, id: u16) void {
        self.identifier = @byteSwap(id);
    }

    pub fn get_identifier(self: *const ICMPAddrMask) u16 {
        return @byteSwap(self.identifier);
    }

    pub fn set_seq_num(self: *ICMPAddrMask, seq: u16) void {
        self.sequence = @byteSwap(seq);
    }

    pub fn get_seq_num(self: *const ICMPAddrMask) u16 {
        return @byteSwap(self.sequence);
    }

    pub fn get_address_mask(self: *const ICMPAddrMask) IPv4.IPv4Address {
        return IPv4.IPv4Address.init_from_array(self.address_mask);
    }

    pub fn set_address_mask(self: *const ICMPAddrMask, mask: IPv4.IPv4Address) void {
        self.address_mask = mask.array;
    }
};

pub const ICMPSourceQuench = extern struct {
    unused: [4]u8,
    original_datagram_data_start: [8]u8,
};
