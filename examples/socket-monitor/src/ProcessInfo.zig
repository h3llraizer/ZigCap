const std = @import("std");
const windows = std.os.windows;

const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
const MAX_PATH = 260;

const PROCESS_QUERY_INFORMATION = 0x0400;
const PROCESS_VM_READ = 0x0010;

// ---------------- Error types ----------------
const ProcessError = error{
    InvalidPid,
    AccessDenied,
    Unspecified,
    InvalidHandle,
    QueryFailed,
};

// ---------------- Function implementations ----------------
fn closeHandle(handle: windows.HANDLE) void {
    _ = windows.CloseHandle(handle);
    // TODO: log failure, monitor handle count
}

extern "kernel32" fn OpenProcess(
    dwDesiredAccess: windows.DWORD,
    bInheritHandle: windows.BOOL,
    dwProcessId: windows.DWORD,
) callconv(.winapi) ?windows.HANDLE;

extern "kernel32" fn CloseHandle(
    hObject: windows.HANDLE,
) callconv(.winapi) windows.BOOL;

pub fn open(pid: windows.DWORD) ?windows.HANDLE {
    return OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        windows.FALSE,
        pid,
    );
}

fn getHandle(pid: u32) !windows.HANDLE {
    const hProcess = open(pid);

    if (hProcess == null) {
        return ProcessError.InvalidHandle;
    }

    return hProcess.?;
}

fn getName(pid: u32) ![]u8 {
    const allocator = std.heap.page_allocator;

    const hProcess = getHandle(pid) catch |err| {
        return err;
    };

    if (hProcess == null) {
        return ProcessError.InvalidHandle;
    }

    var filePath: [MAX_PATH:0]u8 = undefined;
    var size: u32 = MAX_PATH;

    const result = windows.QueryFullProcessImageNameA(
        hProcess,
        0,
        &filePath,
        &size,
    );

    if (result == 0) {
        closeHandle(hProcess);
        const lastError = windows.GetLastError();
        const errorStr = try std.fmt.allocPrint(allocator, "Could not QueryFullProcessImageNameA for process {}. Error {} ({})", .{ pid, lastError, @intFromEnum(lastError) });
        defer allocator.free(errorStr);
        return error.QueryFailed;
    }

    closeHandle(hProcess);

    // Parse file path to get the filename
    const fileName = filePath[0..size];
    const lastSlash = std.mem.lastIndexOfScalar(u8, fileName, '\\') orelse 0;
    const name = fileName[lastSlash + 1 ..];

    // Return a copy of the filename since fileName is stack-allocated
    return try allocator.dupe(u8, name);
}

extern "kernel32" fn QueryFullProcessImageNameA(
    hProcess: windows.HANDLE,
    dwFlags: windows.DWORD,
    lpExeName: [*]u8,
    lpdwSize: *windows.DWORD,
) callconv(.winapi) windows.BOOL;

// Alternative version that returns an owned string (caller must free)
pub fn getNameAlloc(allocator: std.mem.Allocator, pid: u32) ![]u8 {
    const hProcess = try getHandle(pid);

    defer closeHandle(hProcess);

    var filePath: [MAX_PATH:0]u8 = undefined;
    var size: u32 = MAX_PATH;

    const result = QueryFullProcessImageNameA(
        hProcess,
        0,
        &filePath,
        &size,
    );

    if (result == 0) {
        const lastError = windows.GetLastError();
        _ = lastError;
        return error.QueryFailed;
    }

    const fileName = filePath[0..size];
    const lastSlash = std.mem.lastIndexOfScalar(u8, fileName, '\\') orelse 0;
    const name = fileName[lastSlash + 1 ..];

    return try allocator.dupe(u8, name);
}

// Test usage
test "get process name" {
    const allocator = std.testing.allocator;
    const pid = windows.GetCurrentProcessId();
    const name = try getNameAlloc(allocator, pid);
    defer allocator.free(name);
    std.debug.print("Current process: {s}\n", .{name});
}
