import AppKit
import Foundation

/// Blocking line-protocol client for /var/run/hvpn/control.sock.
enum Control {
    static let socketPath = "/var/run/hvpn/control.sock"

    static func send(_ command: String, timeout: TimeInterval = 2.0) -> String {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return "err=cannot open socket" }
        defer { close(fd) }

        var tv = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let pathBytes = Array(socketPath.utf8)
        let cap = MemoryLayout.size(ofValue: addr.sun_path)
        guard pathBytes.count < cap else { return "err=socket path too long" }
        withUnsafeMutablePointer(to: &addr.sun_path) { p in
            p.withMemoryRebound(to: CChar.self, capacity: cap) { dst in
                for i in 0..<pathBytes.count { dst[i] = CChar(bitPattern: pathBytes[i]) }
                dst[pathBytes.count] = 0
            }
        }

        let rc = withUnsafePointer(to: &addr) { p -> Int32 in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                connect(fd, sa, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard rc == 0 else { return "err=daemon not running" }

        let payload = Array((command + "\n").utf8)
        _ = payload.withUnsafeBufferPointer { write(fd, $0.baseAddress, $0.count) }

        var out = Data()
        var buf = [UInt8](repeating: 0, count: 4096)
        while true {
            let n = read(fd, &buf, buf.count)
            if n <= 0 { break }
            out.append(contentsOf: buf[0..<n])
            if out.count >= 4, out.suffix(4) == Data("END\n".utf8) { break }
        }
        var text = String(decoding: out, as: UTF8.self)
        if text.hasSuffix("END\n") { text.removeLast(4) }
        return text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// "key=value\nkey=value" -> [key: value]
    static func parse(_ text: String) -> [String: String] {
        var d: [String: String] = [:]
        for line in text.split(separator: "\n") {
            guard let eq = line.firstIndex(of: "=") else { continue }
            let k = String(line[line.startIndex..<eq])
            let v = String(line[line.index(after: eq)...])
            d[k] = v
        }
        if let e = d["err"] { d["error"] = e }
        return d
    }
}

@MainActor
final class VPNModel: ObservableObject {
    @Published var status: [String: String] = [:]
    @Published var logLines: [String] = []
    @Published var busy = false
    @Published var message: String = ""

    // user settings
    @Published var peer: String = "127.0.0.1:51820"
    @Published var fullTunnel: Bool = false
    @Published var splitRoutes: String = "1.1.1.1/32"

    private var timer: Timer?
    private var tick = 0

    var daemonUp: Bool { status["node"] != nil || status["client"] != nil }
    var clientRunning: Bool { status["client"] == "running" }
    var nodeRunning: Bool { status["node"] == "running" }

    var lastError: String { status["client_error"] ?? "" }

    /// Connected, but the exit node has not sent a single byte back yet.
    var idleWarning: String {
        guard clientRunning, !busy else { return "" }
        let rx = Int(status["client_rx_bytes"] ?? "0") ?? 0
        let up = Int(status["client_uptime"] ?? "0") ?? 0
        if rx == 0 && up > 15 {
            return "Tunnel is up but nothing has come back — check the exit node"
        }
        return ""
    }

    var headline: String {
        if status.isEmpty { return "Helper not running" }
        if clientRunning { return "Connected" }
        if nodeRunning { return "Exit node running" }
        return "Disconnected"
    }

    var detail: String {
        if clientRunning {
            let ip = status["client_tun_ip"] ?? "-"
            let peer = status["client_peer"] ?? ""
            let mode = status["client_full"] == "true" ? "full tunnel" : "split tunnel"
            return "\(ip) → \(peer) · \(mode)"
        }
        if nodeRunning {
            let ip = status["node_ip"] ?? "-"
            let port = (status["node_listen"] ?? "").split(separator: ":").last.map(String.init) ?? "51820"
            return "serving on \(ip):\(port)"
        }
        if status.isEmpty { return "Install the helper daemon to begin" }
        return "Tap Connect to route traffic through the tunnel"
    }

    func start() {
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                self.refresh()
                self.tick += 1
                if self.tick % 3 == 0 { self.loadLog() }
            }
        }
    }

    func refresh() {
        let text = Control.send("STATUS")
        status = Control.parse(text)
    }

    func loadLog() {
        let which = (clientRunning || !lastError.isEmpty) ? "client" : "node"
        let text = Control.send("LOG \(which) 6")
        logLines = text
            .split(separator: "\n")
            .compactMap { line -> String? in
                let s = String(line)
                guard s.hasPrefix("line=") else { return nil }
                return String(s.dropFirst(5))
            }
    }

    func connect() {
        guard !clientRunning else { disconnect(); return }
        busy = true
        message = ""
        // Connecting to loopback with no exit node can never succeed — start one.
        if !nodeRunning && (peer.hasPrefix("127.") || peer.hasPrefix("localhost")) {
            _ = Control.send("NODE START 0.0.0.0:51820", timeout: 20)
            refresh()
        }
        let mode = fullTunnel ? "full" : "split"
        let routes = fullTunnel ? "" : splitRoutes.replacingOccurrences(of: " ", with: "")
        var cmd = "CLIENT START \(peer) \(mode)"
        if !routes.isEmpty { cmd += " \(routes)" }
        let parsed = Control.parse(Control.send(cmd, timeout: 25))
        if let e = parsed["err"] {
            message = e
        } else {
            message = "connected — tunnel is up"
        }
        busy = false
        refresh()
    }

    func disconnect() {
        busy = true
        _ = Control.send("CLIENT STOP", timeout: 15)
        message = "disconnected"
        busy = false
        refresh()
    }

    func toggleNode() {
        busy = true
        message = ""
        if nodeRunning {
            _ = Control.send("NODE STOP", timeout: 20)
            message = "exit node stopped"
        } else {
            let resp = Control.send("NODE START 0.0.0.0:51820", timeout: 20)
            let parsed = Control.parse(resp)
            if let e = parsed["err"] {
                message = e
            } else {
                message = "exit node up · \(parsed["url"] ?? "")"
            }
        }
        busy = false
        refresh()
    }

    func fullKey() -> String { Control.parse(Control.send("KEY"))["key"] ?? "" }

    func copyKey() {
        let k = fullKey()
        guard !k.isEmpty else { message = "no key"; return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(k, forType: .string)
        message = "64-char key copied — paste it on the other Mac"
    }

    func regenerateKey() {
        let resp = Control.parse(Control.send("KEYGEN"))
        if resp["key"] != nil { message = "new key generated — re-copy it to peers" }
        refresh()
    }

    // MARK: formatting helpers for the view

    var rxText: String { bytes(status["client_rx_bytes"]) }
    var txText: String { bytes(status["client_tx_bytes"]) }
    var packetsText: String { status["client_packets"] ?? "0" }
    var uptimeText: String {
        let secs = Int(status["client_uptime"] ?? status["node_uptime"] ?? "0") ?? 0
        if secs < 60 { return "\(secs)s" }
        if secs < 3600 { return "\(secs / 60)m \(secs % 60)s" }
        return "\(secs / 3600)h \((secs % 3600) / 60)m"
    }
    var sessionText: String { status["client_session"] ?? "—" }
    var fingerprint: String { status["key_fingerprint"] ?? "—" }
    var uplinkText: String {
        let i = status["uplink"] ?? "?"
        let ip = status["uplink_ip"] ?? ""
        return ip.isEmpty ? i : "\(i) · \(ip)"
    }

    private func bytes(_ s: String?) -> String {
        guard let n = Double(s ?? "0") else { return "0 B" }
        let units = ["B", "KB", "MB", "GB"]
        var v = n, u = 0
        while v >= 1024 && u < units.count - 1 { v /= 1024; u += 1 }
        return u == 0 ? String(format: "%.0f %@", v, units[u]) : String(format: "%.1f %@", v, units[u])
    }
}
