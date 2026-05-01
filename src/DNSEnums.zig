const std = @import("std");

pub const QueryType = enum(u16) {
    A = 1, // IPv4 address record
    NS = 2, // Name Server record
    MD = 3, // Obsolete, replaced by MX
    MF = 4, // Obsolete, replaced by MX
    CNAME = 5, // Canonical name record
    SOA = 6, // Start of Authority record
    MB = 7, // Mailbox domain name record
    MG = 8, // Mail group member record
    MR = 9, // Mail rename domain name record
    NULL_R = 10, // Null record
    WKS = 11, // Well known service description record
    PTR = 12, // Pointer record
    HINFO = 13, // Host information record
    MINFO = 14, // Mailbox or mail list information record
    MX = 15, // Mail exchanger record
    TXT = 16, // Text record
    RP = 17, // Responsible person record
    AFSDB = 18, // AFS database record
    X25 = 19, // DNS X25 resource record
    ISDN = 20, // Integrated Services Digital Network record
    RT = 21, // Route Through record
    NSAP = 22, // Network service access point address record
    NSAP_PTR = 23, // Network service access point address pointer record
    SIG = 24, // Signature record
    KEY = 25, // Key record
    PX = 26, // Mail Mapping Information record
    GPOS = 27, // DNS Geographical Position record
    AAAA = 28, // IPv6 address record
    LOC = 29, // Location record
    NXT = 30, // Obsolete record
    EID = 31, // DNS Endpoint Identifier record
    NIMLOC = 32, // DNS Nimrod Locator record
    SRV = 33, // Service locator record
    ATMA = 34, // Asynchronous Transfer Mode address record
    NAPTR = 35, // Naming Authority Pointer record
    KX = 36, // Key eXchanger record
    CERT = 37, // Certificate record
    A6 = 38, // Obsolete, replaced by AAAA type
    DNAM = 39, // Delegation Name record
    SINK = 40, // Kitchen sink record
    OPT = 41, // Option record
    APL = 42, // Address Prefix List record
    DS = 43, // Delegation signer record
    SSHFP = 44, // SSH Public Key Fingerprint record
    IPSECKEY = 45, // IPsec Key record
    RRSIG = 46, // DNSSEC signature record
    NSEC = 47, // Next-Secure record
    DNSKEY = 48, // DNS Key record
    DHCID = 49, // DHCP identifier record
    NSEC3 = 50, // NSEC record version 3
    NSEC3PARAM = 51, // NSEC3 parameters
    HTTPS = 65,
    ALL = 255, // All cached records
    GENERIC = 256,

    pub fn from_u16(value: u16) QueryType {
        return std.enums.fromInt(QueryType, value) orelse {
            return .GENERIC;
        };
    }
};

pub const DnsClass = enum(u16) {
    IN = 1, // Internet
    CS = 2, // CSNET (obsolete)
    CH = 3, // Chaos
    HS = 4, // Hesiod
    ANY = 255, // Any class

    pub fn fromU16(value: u16) DnsClass {
        switch (value) {
            1 => return .IN,
            2 => return .CS,
            3 => return .CH,
            4 => return .HS,
            255 => return .ANY,
            else => return @intCast(value), // unknown class, keep as raw
        }
    }

    pub fn toString(self: DnsClass) []const u8 {
        return switch (self) {
            .IN => "IN",
            .CS => "CS",
            .CH => "CH",
            .HS => "HS",
            .ANY => "ANY",
            else => "UNKNOWN",
        };
    }
};

const DNSRcode = enum(u4) {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
    YXDomain = 6,
    YXRRSet = 7,
    NXRRSet = 8,
    NotAuth = 9,
    NotZone = 10,
    Reserved11 = 11,
    Reserved12 = 12,
    Reserved13 = 13,
    Reserved14 = 14,
    Reserved15 = 15,
    _,

    pub fn name(self: DNSRcode) []const u8 {
        return switch (self) {
            .NoError => "NOERROR",
            .FormatError => "FORMERR",
            .ServerFailure => "SERVFAIL",
            .NameError => "NXDOMAIN",
            .NotImplemented => "NOTIMP",
            .Refused => "REFUSED",
            .YXDomain => "YXDOMAIN",
            .YXRRSet => "YXRRSET",
            .NXRRSet => "NXRRSET",
            .NotAuth => "NOTAUTH",
            .NotZone => "NOTZONE",
            else => "RESERVED",
        };
    }
};

const DNSOpcode = enum(u4) {
    Query = 0,
    IQuery = 1,
    Status = 2,
    Reserved3 = 3,
    Notify = 4,
    Update = 5,
    Dso = 6,
    // 7-15 are reserved

    pub fn name(self: DNSOpcode) []const u8 {
        return switch (self) {
            .Query => "QUERY",
            .IQuery => "IQUERY",
            .Status => "STATUS",
            .Notify => "NOTIFY",
            .Update => "UPDATE",
            .Dso => "DSO",
            else => "RESERVED",
        };
    }

    pub fn description(self: DNSOpcode) []const u8 {
        return switch (self) {
            .Query => "Standard query",
            .IQuery => "Inverse query (obsolete)",
            .Status => "Server status request",
            .Notify => "Zone change notification",
            .Update => "Dynamic update",
            .Dso => "DNS Stateful Operations",
            else => "Reserved for future use",
        };
    }
};
