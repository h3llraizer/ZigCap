const std = @import("std");
const zigcap = @import("zigcap");

const Allocator = std.mem.Allocator;
const windows = std.os.windows;

const IPv4Address = zigcap.IPv4.IPv4Address;

const WinDivert = zigcap.WinDivertWrapper;
const CaptureLayer = WinDivert.CaptureLayer;
const WINDIVERT_ADDRESS = WinDivert.WINDIVERT_ADDRESS;
const Event = WinDivert.Event;

const getNameAlloc = @import("ProcessInfo.zig").getNameAlloc;

pub const PacketSocket = struct {
    localPort: u16 = 0,
    localAddr: IPv4Address = .{ .array = .{0x00} ** 4 },
    remotePort: u16 = 0,
    remoteAddr: IPv4Address = .{ .array = .{0x00} ** 4 },

    pub fn to_string(self: PacketSocket, allocator: Allocator) []const u8 {
        const local_addr = self.localAddr.to_string(allocator) catch "";
        defer allocator.free(local_addr);

        const remote_addr = self.remoteAddr.to_string(allocator) catch "";
        defer allocator.free(remote_addr);
        return std.fmt.allocPrint(allocator, "{s}:{} {s}:{}\n", .{
            local_addr,
            self.localPort,
            remote_addr,
            self.remotePort,
        }) catch "allocPrint failed\n";
    }
};

/// Alias for hashmap of key (SocketID) and PacketSocket
pub const PacketSocketTable = std.AutoHashMap(u64, PacketSocket);

pub const PacketProcessAttributes = struct {
    processName: []const u8 = "",
    sockets: PacketSocketTable,
};

/// Alias for hashmap of key (u32/PID) and ProcessAttributes (process name and PacketSocket / metadata)
pub const PacketProcessTable = std.AutoHashMap(u32, PacketProcessAttributes);

pub const UINT8 = u8;
pub const UINT16 = u16;
pub const UINT32 = u32;
pub const UINT64 = u64;
pub const INT16 = i16;
pub const INT64 = i64;

pub const SocketMonitor = struct {
    const Self = @This();

    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    // Process monitor handles
    hBindFilter: ?windows.HANDLE = null,
    hConnectFilter: ?windows.HANDLE = null,
    hCloseFilter: ?windows.HANDLE = null,

    bindMonitorThread: ?std.Thread = null,
    connectMonitorThread: ?std.Thread = null,
    closeMonitorThread: ?std.Thread = null,

    processes: PacketProcessTable,
    processTableMutex: std.Thread.Mutex = .{},
    processTableCv: std.Thread.Condition = .{},

    allocator: std.mem.Allocator,

    const bind_filter = "event == BIND";
    const connect_filter = "event == CONNECT";
    const close_filter = "event == CLOSE";
    const priority = 0;
    const flags = @intFromEnum(WinDivert.CaptureMode.WINDIVERT_FLAG_RECV_ONLY) | @intFromEnum(WinDivert.CaptureMode.WINDIVERT_FLAG_SNIFF);

    // Constructor
    pub fn init(allocator: std.mem.Allocator) !Self {
        var self = Self{
            .allocator = allocator,
            .processes = PacketProcessTable.init(allocator),
        };

        // Open filters using WinDivert
        self.hBindFilter = try WinDivert.open(bind_filter, CaptureLayer.WINDIVERT_LAYER_SOCKET, priority, flags);

        self.hConnectFilter = try WinDivert.open(connect_filter, CaptureLayer.WINDIVERT_LAYER_SOCKET, priority, flags);

        self.hCloseFilter = try WinDivert.open(close_filter, CaptureLayer.WINDIVERT_LAYER_SOCKET, priority, flags);

        // Check filters opened successfully
        if (self.hBindFilter == null or self.hConnectFilter == null or self.hCloseFilter == null) {
            std.debug.print("Failed to open WinDivert filters. Make sure you're running as Administrator.\n", .{});
            // Clean up any that did open
            if (self.hBindFilter) |h| _ = WinDivert.close(h);
            if (self.hConnectFilter) |h| _ = WinDivert.close(h);
            if (self.hCloseFilter) |h| _ = WinDivert.close(h);
            return error.WinDivertOpenFailed;
        }

        std.debug.print("WinDivert filters opened successfully!\n", .{});
        return self;
    }

    // Destructor
    pub fn deinit(self: *Self) void {
        self.stop();

        if (self.hBindFilter) |h| _ = WinDivert.close(h);
        if (self.hConnectFilter) |h| _ = WinDivert.close(h);
        if (self.hCloseFilter) |h| _ = WinDivert.close(h);

        self.processes.deinit();
    }

    pub fn start(self: *Self) !void {
        if (self.running.load(.acquire)) return;

        self.running.store(true, .release);

        self.bindMonitorThread = try std.Thread.spawn(.{}, bindMonitor, .{self});
        self.connectMonitorThread = try std.Thread.spawn(.{}, connectMonitor, .{self});
        self.closeMonitorThread = try std.Thread.spawn(.{}, closeMonitor, .{self});

        {
            self.processTableMutex.lock();
            defer self.processTableMutex.unlock();
        }
        self.processTableCv.signal();

        std.debug.print("Socket monitoring started. Waiting for events...\n", .{});
    }

    fn stop(self: *Self) void {
        self.running.store(false, .release);

        if (self.bindMonitorThread) |t| {
            t.join();
            self.bindMonitorThread = null;
        }
        if (self.connectMonitorThread) |t| {
            t.join();
            self.connectMonitorThread = null;
        }
        if (self.closeMonitorThread) |t| {
            t.join();
            self.closeMonitorThread = null;
        }
    }

    pub fn matchProcess(self: *Self, port: u16) struct { pid: u32, name: []const u8 } {
        self.processTableMutex.lock();
        var processesCopy = self.processes.clone() catch {
            self.processTableMutex.unlock();
            return .{ .pid = 0, .name = "" };
        };
        self.processTableMutex.unlock();
        defer processesCopy.deinit();

        var it = processesCopy.iterator();
        while (it.next()) |entry| {
            const pid = entry.key_ptr.*;
            const attributes = entry.value_ptr.*;

            var socketIt = attributes.sockets.iterator();
            while (socketIt.next()) |socketEntry| {
                if (socketEntry.value_ptr.localPort == port) {
                    return .{ .pid = pid, .name = attributes.processName };
                }
            }
        }

        return .{ .pid = 0, .name = "" };
    }

    // Thread functions
    fn bindMonitor(self: *Self) void {
        while (self.running.load(.acquire)) {
            var addr: WINDIVERT_ADDRESS = undefined;
            var recvLen: u32 = 0;

            // Buffer can be NULL for SOCKET layer
            if (WinDivert.recv(self.hBindFilter, 0, &recvLen, &addr) != 0) {
                if (addr.getEvent() == @intFromEnum(Event.BIND)) {
                    const socketId: u64 = addr.data.Socket.Endpoint;

                    const socket = PacketSocket{
                        .localPort = addr.data.Socket.LocalPort,
                        .localAddr = IPv4Address.init_from_u32(addr.data.Socket.LocalAddr[0]),
                        .remotePort = 0,
                        .remoteAddr = IPv4Address.init_from_u32(addr.data.Socket.RemoteAddr[0]),
                    };

                    const pid: u32 = addr.data.Socket.ProcessId;

                    self.processTableMutex.lock();
                    const gop = self.processes.getOrPut(pid) catch {
                        self.processTableMutex.unlock();
                        continue;
                    };

                    defer self.processTableMutex.unlock();

                    if (!gop.found_existing) {
                        // New process
                        var pa = PacketProcessAttributes{
                            .processName = "",
                            .sockets = PacketSocketTable.init(self.allocator),
                        };

                        pa.processName = getNameAlloc(self.allocator, pid) catch "Unknown";

                        pa.sockets.put(socketId, socket) catch continue;

                        gop.value_ptr.* = pa;
                        self.processTableCv.signal();

                        std.debug.print("New process tracked: {} ({s})\n", .{ pid, pa.processName });
                    } else {
                        // Existing process
                        gop.value_ptr.sockets.put(socketId, socket) catch {
                            continue;
                        };
                        self.processTableCv.signal();

                        std.debug.print("New socket for process {}: port {}\n", .{ pid, socket.localPort });
                    }
                }
            }
        }

        std.debug.print("Bind monitor thread stopped\n", .{});
    }

    fn connectMonitor(self: *Self) void {
        while (self.running.load(.acquire)) {
            var addr: WINDIVERT_ADDRESS = undefined;
            var recvLen: u32 = 0;

            if (WinDivert.recv(self.hConnectFilter, 0, &recvLen, &addr) != 0) {
                if (addr.getEvent() == @intFromEnum(Event.CONNECT)) {
                    std.debug.print("PID: {}, Local Port: {}, Remote Port: {} Event: CONNECT\n", .{
                        addr.data.Socket.ProcessId,
                        addr.data.Socket.LocalPort,
                        addr.data.Socket.RemotePort,
                    });

                    const socketId: u64 = addr.data.Socket.Endpoint;

                    const socket = PacketSocket{
                        .localPort = addr.data.Socket.LocalPort,
                        .localAddr = IPv4Address.init_from_u32(addr.data.Socket.LocalAddr[0]),
                        .remotePort = addr.data.Socket.RemotePort,
                        .remoteAddr = IPv4Address.init_from_u32(addr.data.Socket.RemoteAddr[0]),
                    };

                    const pid: u32 = addr.data.Socket.ProcessId;

                    self.processTableMutex.lock();
                    const gop = self.processes.getOrPut(pid) catch {
                        self.processTableMutex.unlock();
                        continue;
                    };
                    defer self.processTableMutex.unlock();

                    if (!gop.found_existing) {
                        // New process - implicit bind
                        var pa = PacketProcessAttributes{
                            .processName = "",
                            .sockets = PacketSocketTable.init(self.allocator),
                        };

                        pa.processName = getNameAlloc(self.allocator, pid) catch "Unknown";

                        pa.sockets.put(socketId, socket) catch continue;

                        gop.value_ptr.* = pa;

                        std.debug.print("New process tracked via connect: {} ({s})\n", .{ pid, pa.processName });

                        std.debug.print("New socket for process {} via connect: local port {}\n", .{ pid, socket.localPort });

                        const str0 = socket.to_string(self.allocator);
                        std.debug.print("{s}\n", .{str0});
                        self.allocator.free(str0);
                    } else {
                        // Existing process
                        gop.value_ptr.sockets.put(socketId, socket) catch {
                            continue;
                        };

                        std.debug.print("New socket for process {} via connect: local port {}\n", .{ pid, socket.localPort });
                        const str0 = socket.to_string(self.allocator);
                        std.debug.print("{s}\n", .{str0});
                        self.allocator.free(str0);
                    }
                }
            }
        }

        std.debug.print("Connect monitor thread stopped\n", .{});
    }

    fn closeMonitor(self: *Self) void {
        std.debug.print("Close monitor thread started\n", .{});
        while (self.running.load(.acquire)) {
            var addr: WINDIVERT_ADDRESS = undefined;
            var recvLen: u32 = 0;

            if (WinDivert.recv(self.hCloseFilter, 0, &recvLen, &addr) != 0) {
                if (addr.getEvent() == @intFromEnum(Event.CLOSE)) {
                    const socketId: u64 = addr.data.Socket.Endpoint;
                    const pid: u32 = addr.data.Socket.ProcessId;

                    std.debug.print("PID: {}, Socket: {} Event: CLOSE\n", .{ pid, socketId });

                    self.processTableMutex.lock();
                    const gop = self.processes.getEntry(pid);
                    if (gop) |entry| {
                        _ = entry.value_ptr.sockets.remove(socketId);
                        std.debug.print("Socket {} removed from process {}\n", .{ socketId, pid });
                    }
                    self.processTableMutex.unlock();
                    self.processTableCv.signal();
                }
            }
        }

        std.debug.print("Close monitor thread stopped\n", .{});
    }
};

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const pid = windows.GetCurrentProcessId();
    const name = try getNameAlloc(allocator, pid);
    defer allocator.free(name);

    var socket_monitor = try SocketMonitor.init(allocator);
    defer socket_monitor.deinit();

    try socket_monitor.start();

    // Keep the program running to monitor sockets
    std.debug.print("\nMonitoring sockets... Press Ctrl+C to exit\n", .{});

    // Wait indefinitely or until user interrupts
    while (true) {
        std.Thread.sleep(1 * std.time.ns_per_s);
    }
}
