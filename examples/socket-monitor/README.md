Here’s a clean, structured **README.md** for your Zig socket monitoring project:

---

# Socket Monitor (Zig + WinDivert)

A Windows-based socket monitoring tool written in **ZigCap's** wrapper for **WinDivert** to track process-level socket events such as:

* `BIND`
* `CONNECT`
* `CLOSE`

It maps active network sockets to their owning **process IDs (PID)** and **process names** and tracks them in real time.

---

## 🚀 Features

* Real-time socket event monitoring (bind, connect, close)
* Process-to-socket mapping
* Tracks local/remote IPs and ports
* Threaded event monitoring (separate threads per event type)
* Thread-safe process table using mutex + condition variable
* Automatic process name resolution via Windows API
* WinDivert socket-layer integration

---

## 🧠 How It Works

The system uses three WinDivert filters:

```zig
bind_filter    = "event == BIND"
connect_filter = "event == CONNECT"
close_filter   = "event == CLOSE"
```

Each filter runs in its own thread:

* **bindMonitor** → detects new listening sockets
* **connectMonitor** → detects outbound connections
* **closeMonitor** → removes closed sockets

All socket data is stored in:

* `PacketProcessTable (PID → process metadata)`
* `PacketSocketTable (socket ID → socket info)`

---

## 🧱 Core Data Structures

### PacketSocket

Represents a single socket:

* Local/remote IP
* Local/remote port

```zig
PacketSocket {
    localPort: u16,
    localAddr: IPv4Address,
    remotePort: u16,
    remoteAddr: IPv4Address
}
```

---

### PacketProcessAttributes

```zig
{
    processName: []const u8,
    sockets: PacketSocketTable
}
```

---

### PacketProcessTable

```zig
AutoHashMap(u32, PacketProcessAttributes)
```

Maps:

```
PID → Process Info + Active Sockets
```

---

## ⚙️ Requirements

* Windows OS
* Administrator privileges (required for WinDivert)
* WinDivert driver installed
* Zig compiler (latest recommended)
* `zigcap` dependency

---

## 📦 Dependencies

* [`zigcap`](https://example.com) (WinDivert + IPv4 helpers)
* WinDivert driver (system-level packet capture)

---

## 🛠️ Build & Run

### Build

```bash
zig build
```

### Run (must be Admin)

```bash
zig build run
```

Or:

```bash
./zig-out/bin/your_binary.exe
```

> ⚠️ Must be run as **Administrator** or WinDivert will fail to open filters.

---

## 📡 Runtime Behavior

When running, the program prints events like:

```
New process tracked: 1234 (chrome.exe)
New socket for process 1234: port 443
PID: 1234, Local Port: 51512, Remote Port: 443 Event: CONNECT
Socket removed from process 1234
```

---

## 🔍 Process Matching

You can query a port to find its owning process:

```zig
matchProcess(port: u16) -> { pid, name }
```

This scans all tracked sockets and returns the matching PID and process name.

---

## 🧵 Concurrency Model

* Each event type runs in its own thread:

  * `bindMonitorThread`
  * `connectMonitorThread`
  * `closeMonitorThread`

* Shared state is protected with:

  * `std.Thread.Mutex`
  * `std.Thread.Condition`

* Atomic flag controls shutdown:

  ```zig
  running: atomic(bool)
  ```

---

## 🧹 Cleanup

On shutdown:

* All WinDivert handles are closed
* Threads are joined
* Process table is freed
* Allocated socket/process names are released

---

## ⚠️ Notes

* Requires elevated privileges (Admin)
* Designed specifically for Windows WinDivert socket layer
* Blocking loop design (no async runtime)

---

## 📌 Example Use Case

* Network debugging per process
* Security monitoring / intrusion detection
* Learning Windows socket behavior
* Traffic attribution (which app opened which port)

---
