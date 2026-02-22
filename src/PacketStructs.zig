const std = @import("std");
const print = std.debug.print;

pub const RawPacket = struct {
    timestamp_s: u32,
    timestamp_ms: u32,
    raw_data: *u8,
    raw_len: u32,

    pub fn init() RawPacket {
        var p: RawPacket = undefined;
        p.raw_data = undefined;
        p.timestamp_s = undefined;
        p.timestamp_ms = undefined;

        return p;
    }

    pub fn init_cpy(tm_s: u32, tm_ms: u32, raw_data: *u8, raw_len: u32) RawPacket {
        const raw: *u8 = undefined;

        @memmove(raw, std.mem.asBytes(raw_data));

        return RawPacket{ .timestamp_s = tm_s, .timestamp_ms = tm_ms, .raw_data = raw, .raw_len = raw_len };
    }

    pub fn copyInit(buf: [*]u8, len: usize, timestamp_sec: u32, timestamp_msec: u32) RawPacket {
        var p: RawPacket = undefined;
        const n = @min(len, 65536);
        for (buf, 0..n) |byte, index| {
            p.raw[index] = byte;
        }

        p.raw_len = len;

        p.timestamp_s = timestamp_sec;
        p.timestamp_ms = timestamp_msec;
        return p;
    }
};

pub const EthHeader = struct {
    dst: [6]u8,
    src: [6]u8,
    ethertype: u16, // network byte order (big-endian)
};

pub const Packet = struct {
    raw_packet: *RawPacket,

    pub fn init(rawPacket: *RawPacket) Packet {
        var p: Packet = undefined;
        p.raw_packet = rawPacket; // pointer back to the original raw_packet

        // parse packet here

        return p;
    }

    pub fn printEthHeader(self: Packet) void {
        if (self.raw_len < @sizeOf(EthHeader)) {
            print("Packet too short!\n", .{});
            return;
        }

        const header: *EthHeader = @alignCast(self.raw_data);

        //const header: *EthHeader = @ptrCast(self.raw_data);

        //const header: *EthHeader = @ptrCast(@alignCast(@alignOf(self.raw_data)));

        // Step 1: ensure pointer alignment
        //const aligned_ptr: *EthHeader = @alignCast(self.raw_data);

        // Step 2: cast to target struct
        //const header: *EthHeader = @ptrCast(aligned_ptr);

        const offset = @offsetOf(*EthHeader, self.raw_data);

        print("offsetof ethheader: {d}", .{offset});

        print("Src MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n", .{ header.src[0], header.src[1], header.src[2], header.src[3], header.src[4], header.src[5] });

        print("Dst MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n", .{ header.dst[0], header.dst[1], header.dst[2], header.dst[3], header.dst[4], header.dst[5] });

        const ethertype = std.mem.bigEndianToHost(u16, header.ethertype);
        print("EtherType: 0x{:04x}\n", .{ethertype});
    }
};
