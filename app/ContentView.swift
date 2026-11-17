import SwiftUI

struct StatCard: View {
    let title: String
    let value: String
    let symbol: String

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 4) {
                Image(systemName: symbol).font(.system(size: 9, weight: .semibold))
                Text(title.uppercased()).font(.system(size: 9, weight: .semibold))
            }
            .foregroundStyle(.secondary)
            Text(value)
                .font(.system(size: 15, weight: .semibold, design: .rounded))
                .lineLimit(1)
                .minimumScaleFactor(0.7)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(9)
        .background(Color.primary.opacity(0.05), in: RoundedRectangle(cornerRadius: 9))
    }
}

struct ContentView: View {
    @ObservedObject var model: VPNModel

    private var connected: Bool { model.clientRunning }
    private var accent: Color { connected ? .green : (model.nodeRunning ? .blue : .secondary) }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Text("TRIPLE B VPN")
                    .font(.system(size: 10, weight: .bold))
                    .tracking(1.6)
                    .foregroundStyle(.secondary)
                Spacer()
                Text("v1.0.0").font(.system(size: 9, design: .monospaced)).foregroundStyle(.tertiary)
            }
            header
            if model.probed && !model.helperInstalled {
                setupCard
            } else {
                connectButton
            }
            if !model.lastError.isEmpty && !connected {
                HStack(alignment: .top, spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill").font(.system(size: 10))
                    Text(model.lastError)
                        .font(.system(size: 10))
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 0)
                }
                .foregroundStyle(.orange)
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
            }
            stats
            if !model.idleWarning.isEmpty {
                HStack(spacing: 5) {
                    Image(systemName: "waveform.path.ecg").font(.system(size: 9))
                    Text(model.idleWarning).font(.system(size: 10))
                }
                .foregroundStyle(.orange)
            }
            Divider()
            settings
            Divider()
            nodeCard
            Divider()
            keyRow
            logBox
            if !model.message.isEmpty {
                Text(model.message)
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
        }
        .padding(14)
        .frame(width: 372)
        .background(.regularMaterial)
    }

    private var header: some View {
        HStack(spacing: 11) {
            ZStack {
                Circle().fill(accent.opacity(0.16)).frame(width: 42, height: 42)
                Image(systemName: connected ? "lock.shield.fill" : "shield.slash")
                    .font(.system(size: 19, weight: .semibold))
                    .foregroundStyle(accent)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(model.headline).font(.system(size: 16, weight: .semibold))
                Text(model.detail).font(.system(size: 10.5)).foregroundStyle(.secondary)
                    .lineLimit(2).fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            Circle().fill(accent).frame(width: 7, height: 7)
        }
    }

    private var setupCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Image(systemName: "wrench.and.screwdriver.fill").font(.system(size: 12))
                Text("Enable the VPN helper").font(.system(size: 12, weight: .semibold))
            }
            Text("Creating a tunnel needs root once. This installs a small launchd "
                 + "helper that runs it for you, so you never see another password prompt.")
                .font(.system(size: 10))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Button {
                model.installHelper()
            } label: {
                HStack(spacing: 6) {
                    if model.busy { ProgressView().controlSize(.small) }
                    Text(model.busy ? "Installing…" : "Enable VPN")
                        .font(.system(size: 12, weight: .semibold))
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 6)
            }
            .buttonStyle(.borderedProminent)
            .disabled(model.busy)
        }
        .padding(10)
        .background(Color.accentColor.opacity(0.10), in: RoundedRectangle(cornerRadius: 10))
    }

    private var connectButton: some View {
        Button {
            model.connect()
        } label: {
            HStack(spacing: 6) {
                if model.busy { ProgressView().controlSize(.small) }
                Text(connected ? "Disconnect" : "Connect")
                    .font(.system(size: 13, weight: .semibold))
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 7)
        }
        .buttonStyle(.borderedProminent)
        .tint(connected ? .red.opacity(0.85) : .accentColor)
        .disabled(model.busy || !model.helperInstalled)
        .help(connected ? "Disconnect the tunnel" : "Connect through the exit node")
    }

    private var stats: some View {
        HStack(spacing: 8) {
            StatCard(title: "Received", value: model.rxText, symbol: "arrow.down")
            StatCard(title: "Sent", value: model.txText, symbol: "arrow.up")
            StatCard(title: "Packets", value: model.packetsText, symbol: "square.stack.3d.up")
            StatCard(title: "Uptime", value: model.uptimeText, symbol: "clock")
        }
    }

    private var settings: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Text("Peer").font(.system(size: 11, weight: .medium)).frame(width: 40, alignment: .leading)
                TextField("host:port", text: $model.peer)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 11, design: .monospaced))
                    .disabled(connected)
            }
            HStack(spacing: 8) {
                Text("Mode").font(.system(size: 11, weight: .medium)).frame(width: 40, alignment: .leading)
                Picker("", selection: $model.fullTunnel) {
                    Text("Split tunnel").tag(false)
                    Text("Full tunnel").tag(true)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .disabled(connected)
            }
            if !model.fullTunnel {
                HStack(spacing: 8) {
                    Text("Routes").font(.system(size: 11, weight: .medium)).frame(width: 40, alignment: .leading)
                    TextField("cidr,cidr", text: $model.splitRoutes)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(size: 11, design: .monospaced))
                        .disabled(connected)
                }
            }
        }
    }

    private var nodeCard: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Image(systemName: "server.rack").font(.system(size: 12))
                Text("Exit node").font(.system(size: 12, weight: .semibold))
                Spacer()
                Toggle("", isOn: Binding(
                    get: { model.nodeRunning },
                    set: { _ in model.toggleNode() }
                ))
                .labelsHidden()
                .toggleStyle(.switch)
                .controlSize(.mini)
                .disabled(model.busy)
            }
            Text(model.nodeRunning
                 ? "\(model.status["node_ip"] ?? "") : \(portOf(model.status["node_listen"] ?? ""))"
                 : "Serve this Mac as an exit node for other devices")
                .font(.system(size: 10))
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
        }
        .padding(9)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.primary.opacity(0.05), in: RoundedRectangle(cornerRadius: 9))
    }

    private var keyRow: some View {
        HStack(spacing: 8) {
            Image(systemName: "key.horizontal").font(.system(size: 11)).foregroundStyle(.secondary)
            Text("PSK \(model.fingerprint)…").font(.system(size: 10, design: .monospaced))
                .foregroundStyle(.secondary)
            Spacer()
            Button("Copy") { model.copyKey() }.controlSize(.small)
            Button("New") { model.regenerateKey() }.controlSize(.small)
        }
    }

    private var logBox: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text("RECENT TUNNEL LOG").font(.system(size: 8.5, weight: .semibold)).foregroundStyle(.secondary)
            ScrollView {
                VStack(alignment: .leading, spacing: 1) {
                    ForEach(Array(model.logLines.enumerated()), id: \.offset) { _, line in
                        Text(line)
                            .font(.system(size: 9, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
            .frame(height: 62)
        }
        .padding(8)
        .background(Color.black.opacity(0.22), in: RoundedRectangle(cornerRadius: 8))
    }

    private func portOf(_ listen: String) -> String {
        listen.split(separator: ":").last.map(String.init) ?? "51820"
    }
}
